package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/pprof"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/jackby03/waffynx/internal/audit"
	"github.com/jackby03/waffynx/internal/auth"
	"github.com/jackby03/waffynx/internal/config"
	"github.com/jackby03/waffynx/internal/logging"
	"github.com/jackby03/waffynx/internal/marketplace"
	"github.com/jackby03/waffynx/internal/metrics"
	"github.com/jackby03/waffynx/internal/plugin"
	"github.com/jackby03/waffynx/internal/version"
)

func main() {
	var cfgFile string

	rootCmd := &cobra.Command{
		Use:   "waf-api",
		Short: "Waffynx Management API Server",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(cfgFile)
			if err != nil {
				return fmt.Errorf("loading config: %w", err)
			}
			return runAPI(cfg)
		},
	}

	rootCmd.Flags().StringVarP(&cfgFile, "config", "c", "/opt/waffynx/config/waffynx.yaml", "config file path")

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

type apiServer struct {
	configMu sync.RWMutex
	cfg      *config.Config
	authMgr  *auth.Manager
	oidcMgr  *auth.OIDCManager
	store    *marketplace.InMemoryStore
	audit    *audit.Store
}

func runAPI(cfg *config.Config) error {
	logging.Info().Str("listen", cfg.API.Listen).Msg("starting management API")

	auditStore, err := audit.NewStore(2000, "/opt/waffynx/logs/audit.jsonl")
	if err != nil {
		logging.Warn().Err(err).Msg("audit log file unavailable, using memory-only")
		auditStore, _ = audit.NewStore(2000, "")
	}

	srv := &apiServer{
		cfg:     cfg,
		authMgr: auth.NewManager(cfg.API.Auth.JWTSecret, cfg.API.Auth.TokenTTL),
		oidcMgr: auth.NewOIDCManager(),
		store:   marketplace.NewInMemoryStore(),
		audit:   auditStore,
	}

	if len(cfg.API.Auth.OIDC) > 0 {
		if err := srv.oidcMgr.Configure(cfg.API.Auth.OIDC); err != nil {
			logging.Warn().Err(err).Msg("OIDC configuration incomplete")
		}
	}

	mux := http.NewServeMux()

	mux.HandleFunc("GET /health", srv.handleHealth)
	mux.HandleFunc("POST /api/v1/auth/login", srv.handleLogin)

	withAuth := srv.authMiddleware(mux)
	withCORS := srv.corsMiddleware
	mux.HandleFunc("GET /api/v1/status", withCORS(withAuth(srv.handleStatus)))
	mux.HandleFunc("GET /api/v1/config", withCORS(withAuth(srv.handleGetConfig)))
	mux.HandleFunc("PUT /api/v1/config", withCORS(withAuth(srv.handleUpdateConfig)))
	mux.HandleFunc("GET /api/v1/metrics", withCORS(withAuth(srv.handleMetrics)))
	mux.HandleFunc("GET /api/v1/plugins", withCORS(withAuth(srv.handleListPlugins)))
	mux.HandleFunc("GET /api/v1/plugins/{name}", withCORS(withAuth(srv.handleGetPlugin)))
	mux.HandleFunc("GET /api/v1/audit", withCORS(withAuth(srv.handleAuditQuery)))
	mux.HandleFunc("GET /api/v1/events", withCORS(srv.handleSSE))
	mux.HandleFunc("GET /metrics", metrics.Handler().ServeHTTP)
	mux.HandleFunc("GET /debug/pprof/", pprof.Index)
	mux.HandleFunc("GET /debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("GET /debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("GET /debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("GET /debug/pprof/trace", pprof.Trace)

	mux.HandleFunc("GET /", srv.handleRoot)

	server := &http.Server{
		Addr:         cfg.API.Listen,
		Handler:      srv.auditMiddleware(srv.loggingMiddleware(mux)),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  30 * time.Second,
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	go func() {
		logging.Info().Msg("management API ready")
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logging.Error().Err(err).Msg("server error")
		}
	}()

	for sig := range sigCh {
		switch sig {
		case syscall.SIGHUP:
			logging.Info().Msg("reloading config")
			newCfg, err := config.Load(cfg.API.Listen)
			if err != nil {
				logging.Error().Err(err).Msg("reload failed")
				continue
			}
			srv.configMu.Lock()
			srv.cfg = newCfg
			srv.authMgr = auth.NewManager(newCfg.API.Auth.JWTSecret, newCfg.API.Auth.TokenTTL)
			newOIDC := auth.NewOIDCManager()
			if len(newCfg.API.Auth.OIDC) > 0 {
				newOIDC.Configure(newCfg.API.Auth.OIDC)
			}
			srv.oidcMgr = newOIDC
			srv.configMu.Unlock()
		case syscall.SIGINT, syscall.SIGTERM:
			logging.Info().Msg("shutting down API server")
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			server.Shutdown(ctx)
			return nil
		}
	}

	return nil
}

func (s *apiServer) readConfig() *config.Config {
	s.configMu.RLock()
	defer s.configMu.RUnlock()
	return s.cfg
}

func (s *apiServer) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		logging.Debug().
			Str("method", r.Method).
			Str("path", r.URL.Path).
			Dur("duration", time.Since(start)).
			Msg("api request")
	})
}

func (s *apiServer) authMiddleware(mux *http.ServeMux) func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			header := r.Header.Get("Authorization")
			if header == "" {
				s.writeError(w, r, http.StatusUnauthorized, "missing authorization header")
				return
			}

			token := strings.TrimPrefix(header, "Bearer ")
			if token == header {
				s.writeError(w, r, http.StatusUnauthorized, "invalid authorization format")
				return
			}

			if s.oidcMgr.Enabled() {
				username, role, provider, err := s.oidcMgr.ValidateToken(r.Context(), token)
				if err == nil {
					claims := &auth.Claims{
						Username: username,
						Role:     role,
						Scopes:   []string{"read", "write"},
					}
					ctx := context.WithValue(r.Context(), "claims", claims)
					logging.Debug().Str("user", username).Str("provider", provider).Msg("OIDC authenticated")
					next(w, r.WithContext(ctx))
					return
				}
				logging.Debug().Err(err).Msg("OIDC validation failed, trying local JWT")
			}

			claims, err := s.authMgr.ValidateToken(token)
			if err != nil {
				s.writeError(w, r, http.StatusUnauthorized, "invalid token: "+err.Error())
				return
			}

			ctx := context.WithValue(r.Context(), "claims", claims)
			next(w, r.WithContext(ctx))
		}
	}
}

func (s *apiServer) auditMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.audit == nil {
			next.ServeHTTP(w, r)
			return
		}

		rw := &auditResponseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(rw, r)

		actor := "anonymous"
		actorIP := r.RemoteAddr
		if claims, ok := r.Context().Value("claims").(*auth.Claims); ok && claims != nil {
			actor = claims.Username
		}

		result := "allowed"
		if rw.statusCode >= 400 {
			result = "blocked"
		}

		s.audit.Record(audit.Event{
			Actor:   actor,
			ActorIP: actorIP,
			Action:  r.Method + " " + r.URL.Path,
			Result:  result,
			Details: fmt.Sprintf("HTTP %d", rw.statusCode),
		})
	})
}

type auditResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (w *auditResponseWriter) WriteHeader(code int) {
	w.statusCode = code
	w.ResponseWriter.WriteHeader(code)
}

func (s *apiServer) handleAuditQuery(w http.ResponseWriter, r *http.Request) {
	if s.audit == nil {
		s.writeJSON(w, r, http.StatusOK, []audit.Event{})
		return
	}

	limit := 100
	actor := r.URL.Query().Get("actor")
	action := r.URL.Query().Get("action")
	result := r.URL.Query().Get("result")

	events := s.audit.Query(audit.QueryFilter{
		Limit:  limit,
		Actor:  actor,
		Action: action,
		Result: result,
	})

	s.writeJSON(w, r, http.StatusOK, events)
}

func (s *apiServer) corsMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next(w, r)
	}
}

func (s *apiServer) writeJSON(w http.ResponseWriter, r *http.Request, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if data != nil {
		json.NewEncoder(w).Encode(data)
	}
}

func (s *apiServer) writeError(w http.ResponseWriter, r *http.Request, status int, message string) {
	s.writeJSON(w, r, status, map[string]interface{}{
		"error":   http.StatusText(status),
		"message": message,
	})
}

func (s *apiServer) handleRoot(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	s.writeJSON(w, r, http.StatusOK, map[string]interface{}{
		"service":   "waf-api",
		"version":   version.Version,
		"endpoints": []string{"/health", "/metrics", "/api/v1/status", "/api/v1/config", "/api/v1/plugins", "/api/v1/audit", "/api/v1/events", "/debug/pprof/"},
	})
}

func (s *apiServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, r, http.StatusOK, map[string]string{
		"status": "ok",
	})
}

func (s *apiServer) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, r, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Username == "" || req.Password == "" {
		s.writeError(w, r, http.StatusBadRequest, "username and password required")
		return
	}

	token, err := s.authMgr.GenerateToken(req.Username, "admin", []string{"read", "write"})
	if err != nil {
		s.writeError(w, r, http.StatusInternalServerError, "token generation failed")
		return
	}

	s.writeJSON(w, r, http.StatusOK, map[string]string{
		"token": token,
	})
}

func (s *apiServer) handleStatus(w http.ResponseWriter, r *http.Request) {
	cfg := s.readConfig()
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)

	s.writeJSON(w, r, http.StatusOK, map[string]interface{}{
		"version":    version.Version,
		"build_time": version.BuildTime,
		"git_commit": version.GitCommit,
		"go_version": runtime.Version(),
		"goroutines": runtime.NumGoroutine(),
		"memory": map[string]interface{}{
			"alloc_mb":       float64(mem.Alloc) / 1024 / 1024,
			"total_alloc_mb": float64(mem.TotalAlloc) / 1024 / 1024,
		},
		"config": map[string]interface{}{
			"name":           cfg.Name,
			"appsec_enabled": cfg.AppSec.Enabled,
			"engine":         cfg.AppSec.Engine,
			"plugins_count":  len(plugin.GetRegistry().List()),
		},
	})
}

func (s *apiServer) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	cfg := s.readConfig()

	redacted := map[string]interface{}{
		"name":    cfg.Name,
		"version": cfg.Version,
		"listen":  cfg.Listen,
		"logging": cfg.Logging,
		"sidecar": cfg.Sidecar,
		"nginx":   cfg.Nginx,
		"appsec": map[string]interface{}{
			"enabled":       cfg.AppSec.Enabled,
			"engine":        cfg.AppSec.Engine,
			"rules_path":    cfg.AppSec.RulesPath,
			"ml_model_path": cfg.AppSec.MLModelPath,
			"learning_mode": cfg.AppSec.LearningMode,
			"timeout_ms":    cfg.AppSec.TimeoutMs,
		},
		"gateway": cfg.Gateway,
		"api": map[string]interface{}{
			"enabled": cfg.API.Enabled,
			"listen":  cfg.API.Listen,
			"auth": map[string]interface{}{
				"jwt_secret": "***",
				"token_ttl":  cfg.API.Auth.TokenTTL,
			},
		},
		"routes":  cfg.Routes,
		"plugins": cfg.Plugins,
	}

	s.writeJSON(w, r, http.StatusOK, redacted)
}

func (s *apiServer) handleUpdateConfig(w http.ResponseWriter, r *http.Request) {
	var updates map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&updates); err != nil {
		s.writeError(w, r, http.StatusBadRequest, "invalid request body")
		return
	}

	s.configMu.Lock()
	cfg := s.cfg

	if v, ok := updates["appsec_enabled"]; ok {
		if b, ok := v.(bool); ok {
			cfg.AppSec.Enabled = b
		}
	}
	if v, ok := updates["learning_mode"]; ok {
		if b, ok := v.(bool); ok {
			cfg.AppSec.LearningMode = b
		}
	}

	s.configMu.Unlock()

	s.writeJSON(w, r, http.StatusOK, map[string]string{
		"status": "config updated",
	})
}

func (s *apiServer) handleMetrics(w http.ResponseWriter, r *http.Request) {
	cfg := s.readConfig()
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)

	s.writeJSON(w, r, http.StatusOK, map[string]interface{}{
		"go": map[string]interface{}{
			"goroutines":  runtime.NumGoroutine(),
			"heap_alloc":  mem.HeapAlloc,
			"heap_inuse":  mem.HeapInuse,
			"stack_inuse": mem.StackInuse,
			"gc_pause_ns": mem.PauseNs[(mem.NumGC+255)%256],
			"num_gc":      mem.NumGC,
		},
		"engine": map[string]interface{}{
			"appsec_enabled": cfg.AppSec.Enabled,
			"engine":         cfg.AppSec.Engine,
			"plugins_count":  len(plugin.GetRegistry().List()),
		},
	})
}

func (s *apiServer) handleListPlugins(w http.ResponseWriter, r *http.Request) {
	plugins := plugin.GetRegistry().List()
	if plugins == nil {
		plugins = []*plugin.Metadata{}
	}
	s.writeJSON(w, r, http.StatusOK, plugins)
}

func (s *apiServer) handleGetPlugin(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")

	meta, err := plugin.GetRegistry().Get(name)
	if err != nil {
		s.writeError(w, r, http.StatusNotFound, "plugin not found: "+name)
		return
	}

	s.writeJSON(w, r, http.StatusOK, meta)
}

func (s *apiServer) handleSSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		s.writeError(w, r, http.StatusInternalServerError, "streaming not supported")
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	w.Write([]byte(": connected\n\n"))
	flusher.Flush()

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			var mem runtime.MemStats
			runtime.ReadMemStats(&mem)
			cfg := s.readConfig()

			data, _ := json.Marshal(map[string]interface{}{
				"type": "stats",
				"timestamp": time.Now().UTC().Format(time.RFC3339),
				"goroutines": runtime.NumGoroutine(),
				"heap_mb": float64(mem.Alloc) / 1024 / 1024,
				"engine": cfg.AppSec.Engine,
			})
			w.Write([]byte("data: "))
			w.Write(data)
			w.Write([]byte("\n\n"))
			flusher.Flush()
		}
	}
}
