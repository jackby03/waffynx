package gateway

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"
	"time"

	"github.com/jackby03/waffynx/internal/config"
	"github.com/jackby03/waffynx/internal/logging"
	"github.com/jackby03/waffynx/internal/policy"
	"github.com/jackby03/waffynx/internal/plugin"
)

type Gateway struct {
	mu       sync.RWMutex
	cfg      *config.Config
	server   *http.Server
	router   *Router
	chain    *plugin.Chain
	engine   policy.Evaluator
	running  bool
}

func New(cfg *config.Config, eval policy.Evaluator, chain *plugin.Chain) *Gateway {
	return &Gateway{
		cfg:    cfg,
		router: NewRouter(),
		chain:  chain,
		engine: eval,
	}
}

func (g *Gateway) Start() error {
	g.mu.Lock()
	defer g.mu.Unlock()

	if g.running {
		return fmt.Errorf("gateway already running")
	}

	for _, route := range g.cfg.Routes {
		if err := g.router.AddRoute(&route); err != nil {
			return fmt.Errorf("adding route %s: %w", route.Name, err)
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", g.handleRequest)
	mux.HandleFunc("/health", g.handleHealth)
	mux.HandleFunc("/metrics", g.handleMetrics)

	g.server = &http.Server{
		Addr:         g.cfg.Listen,
		Handler:      g.wrapWithPlugins(mux),
		ReadTimeout:  time.Duration(g.cfg.Gateway.ReadTimeout) * time.Second,
		WriteTimeout: time.Duration(g.cfg.Gateway.WriteTimeout) * time.Second,
		IdleTimeout:  time.Duration(g.cfg.Gateway.IdleTimeout) * time.Second,
		MaxHeaderBytes: 1 << 20,
	}

	if g.cfg.Nginx.EnableHTTP2 {
		g.server.TLSConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
		}
	}

	ln, err := net.Listen("tcp", g.server.Addr)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", g.server.Addr, err)
	}

	go func() {
		logging.Info().Str("addr", g.server.Addr).Msg("gateway listening")
		if err := g.server.Serve(ln); err != nil && err != http.ErrServerClosed {
			logging.Error().Err(err).Msg("gateway server error")
		}
	}()

	g.running = true
	return nil
}

func (g *Gateway) Stop(ctx context.Context) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	if !g.running {
		return nil
	}

	logging.Info().Msg("shutting down gateway")
	g.running = false
	return g.server.Shutdown(ctx)
}

func (g *Gateway) handleRequest(w http.ResponseWriter, r *http.Request) {
	route, params := g.router.Match(r.Host, r.URL.Path)

	result := g.engine.Evaluate(r.Context(), policy.PhaseRequest, &policy.Request{
		Method:  r.Method,
		Host:    r.Host,
		Path:    r.URL.Path,
		Headers: r.Header,
		RemoteIP: r.RemoteAddr,
	})

	if result.Action == policy.ActionDeny || result.Action == policy.ActionBlock {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"error":"blocked by WAF policy"}`))
		return
	}

	if route == nil {
		http.NotFound(w, r)
		return
	}

	target, err := url.Parse(route.Upstream)
	if err != nil {
		logging.Error().Err(err).Str("route", route.Name).Msg("invalid upstream")
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.Transport = &http.Transport{
		MaxIdleConns:        g.cfg.Gateway.MaxConnections,
		IdleConnTimeout:     time.Duration(g.cfg.Gateway.IdleTimeout) * time.Second,
		DisableCompression:  false,
	}

	r.URL.Path = params["path"]
	proxy.ServeHTTP(w, r)
}

func (g *Gateway) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ok"}`))
}

func (g *Gateway) handleMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte("# waffynx metrics\n"))
}

func (g *Gateway) wrapWithPlugins(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := plugin.NewContext(r.Context(), w, r)
		ctx, err := g.chain.Execute(ctx, plugin.PhasePreRequest)
		if err != nil {
			logging.Error().Err(err).Msg("plugin chain error")
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
