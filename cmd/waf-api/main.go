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
	"unicode"

	"gopkg.in/yaml.v3"

	"github.com/jackby03/waffynx/internal/events"
	"golang.org/x/crypto/bcrypt"

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
			return runAPI(cfg, cfgFile)
		},
	}

	rootCmd.Flags().StringVarP(&cfgFile, "config", "c", "/opt/waffynx/config/waffynx.yaml", "config file path")

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

type apiServer struct {
	configMu   sync.RWMutex
	cfg        *config.Config
	configPath string
	authMgr    *auth.Manager
	oidcMgr    *auth.OIDCManager
	store      *marketplace.InMemoryStore
	audit      *audit.Store
	broker     *events.Broker
}

func runAPI(cfg *config.Config, configPath string) error {
	logging.Info().Str("listen", cfg.API.Listen).Msg("starting management API")

	if cfg.API.Auth.JWTSecret == "" || cfg.API.Auth.JWTSecret == "change-me-in-production" {
		logging.Error().Msg("JWT secret is empty or set to default value, change it in production")
		return fmt.Errorf("insecure JWT secret")
	}

	if len(cfg.API.Auth.JWTSecret) < 32 {
		logging.Error().Msg("JWT secret is too short, must be at least 32 characters")
		return fmt.Errorf("insecure JWT secret")
	}

	auditStore, err := audit.NewStore(2000, "/opt/waffynx/logs/audit.jsonl")
	if err != nil {
		logging.Warn().Err(err).Msg("audit log file unavailable, using memory-only")
		auditStore, _ = audit.NewStore(2000, "")
	}

	srv := &apiServer{
		cfg:        cfg,
		configPath: configPath,
		authMgr:    auth.NewManager(cfg.API.Auth.JWTSecret, cfg.API.Auth.TokenTTL),
		oidcMgr:    auth.NewOIDCManager(),
		store:      marketplace.NewInMemoryStore(),
		audit:      auditStore,
		broker:     events.NewBroker(),
	}

	srv.seedMarketplace()

	if len(cfg.API.Auth.OIDC) > 0 {
		if err := srv.oidcMgr.Configure(cfg.API.Auth.OIDC); err != nil {
			logging.Warn().Err(err).Msg("OIDC configuration incomplete")
		}
	}

	mux := http.NewServeMux()

	withCORS := srv.corsMiddleware

	mux.HandleFunc("GET /health", srv.handleHealth)

	// Use handleLogin for both POST and OPTIONS so that the withCORS middleware can handle the OPTIONS request correctly
	mux.HandleFunc("POST /api/v1/auth/login", withCORS(srv.handleLogin))
	mux.HandleFunc("OPTIONS /api/v1/auth/login", withCORS(srv.handleLogin))

	withAuth := srv.authMiddleware(mux)
	mux.HandleFunc("GET /api/v1/status", withCORS(withAuth(srv.handleStatus)))
	mux.HandleFunc("GET /api/v1/config", withCORS(withAuth(srv.handleGetConfig)))
	mux.HandleFunc("PUT /api/v1/config", withCORS(withAuth(srv.handleUpdateConfig)))
	mux.HandleFunc("GET /api/v1/metrics", withCORS(withAuth(srv.handleMetrics)))
	mux.HandleFunc("GET /api/v1/plugins", withCORS(withAuth(srv.handleListPlugins)))
	mux.HandleFunc("GET /api/v1/plugins/{name}", withCORS(withAuth(srv.handleGetPlugin)))
	mux.HandleFunc("GET /api/v1/audit", withCORS(withAuth(srv.handleAuditQuery)))
	mux.HandleFunc("POST /api/v1/events", withCORS(withAuth(srv.handleIngestEvent)))
	mux.HandleFunc("GET /api/v1/events", withCORS(withAuth(srv.handleSSE)))
	mux.HandleFunc("GET /api/v1/marketplace", withCORS(withAuth(srv.handleMarketplaceList)))
	mux.HandleFunc("GET /api/v1/marketplace/categories", withCORS(withAuth(srv.handleMarketplaceCategories)))
	mux.HandleFunc("GET /api/v1/marketplace/{name}", withCORS(withAuth(srv.handleMarketplaceGet)))
	mux.HandleFunc("POST /api/v1/marketplace/install/{name}", withCORS(withAuth(srv.handleMarketplaceInstall)))
	mux.HandleFunc("DELETE /api/v1/marketplace/uninstall/{name}", withCORS(withAuth(srv.handleMarketplaceUninstall)))
	mux.HandleFunc("GET /metrics", metrics.Handler().ServeHTTP)
	mux.HandleFunc("GET /debug/pprof/", withAuth(pprof.Index))
	mux.HandleFunc("GET /debug/pprof/cmdline", withAuth(pprof.Cmdline))
	mux.HandleFunc("GET /debug/pprof/profile", withAuth(pprof.Profile))
	mux.HandleFunc("GET /debug/pprof/symbol", withAuth(pprof.Symbol))
	mux.HandleFunc("GET /debug/pprof/trace", withAuth(pprof.Trace))

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
			newCfg, err := config.Load(srv.configPath)
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
		origin := r.Header.Get("Origin")
		allowedOrigin := ""
		cfg := s.readConfig()

		if origin != "" {
			w.Header().Add("Vary", "Origin")
		}

		if cfg != nil && len(cfg.API.AllowedOrigins) > 0 && origin != "" {
			for _, o := range cfg.API.AllowedOrigins {
				if o != "*" && o == origin {
					allowedOrigin = o
					break
				}
			}
		}

		if allowedOrigin != "" {
			w.Header().Set("Access-Control-Allow-Origin", allowedOrigin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		}

		if r.Method == http.MethodOptions {
			if allowedOrigin != "" {
				w.WriteHeader(http.StatusNoContent)
			} else {
				w.WriteHeader(http.StatusForbidden)
			}
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

	cfg := s.readConfig()
	if len(cfg.API.Auth.Users) == 0 {
		s.writeError(w, r, http.StatusNotImplemented, "no users configured")
		return
	}

	for _, u := range cfg.API.Auth.Users {
		if u.Username == req.Username {
			if err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(req.Password)); err != nil {
				s.writeError(w, r, http.StatusUnauthorized, "invalid credentials")
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
			return
		}
	}

	s.writeError(w, r, http.StatusUnauthorized, "invalid credentials")
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

	if len(updates) == 0 {
		s.writeError(w, r, http.StatusBadRequest, "empty update body")
		return
	}

	s.configMu.Lock()
	defer s.configMu.Unlock()

	yamlBytes, err := yaml.Marshal(s.cfg)
	if err != nil {
		s.writeError(w, r, http.StatusInternalServerError, "failed to marshal current config")
		return
	}

	var current map[string]interface{}
	if err := yaml.Unmarshal(yamlBytes, &current); err != nil {
		s.writeError(w, r, http.StatusInternalServerError, "failed to unmarshal current config")
		return
	}

	deepMerge(current, normalizeKeys(updates))

	merged, err := yaml.Marshal(current)
	if err != nil {
		s.writeError(w, r, http.StatusInternalServerError, "failed to marshal merged config")
		return
	}

	newCfg, err := config.Parse(merged)
	if err != nil {
		s.writeError(w, r, http.StatusBadRequest, "invalid config: "+err.Error())
		return
	}

	if err := os.WriteFile(s.configPath, merged, 0644); err != nil {
		s.writeError(w, r, http.StatusInternalServerError, "failed to write config file: "+err.Error())
		return
	}

	s.cfg = newCfg
	s.authMgr = auth.NewManager(newCfg.API.Auth.JWTSecret, newCfg.API.Auth.TokenTTL)
	newOIDC := auth.NewOIDCManager()
	if len(newCfg.API.Auth.OIDC) > 0 {
		newOIDC.Configure(newCfg.API.Auth.OIDC)
	}
	s.oidcMgr = newOIDC

	logging.Info().Msg("config updated and written to disk")

	s.writeJSON(w, r, http.StatusOK, map[string]string{
		"status": "config updated",
	})
}

func deepMerge(target, source map[string]interface{}) {
	for key, srcVal := range source {
		if srcMap, ok := srcVal.(map[string]interface{}); ok {
			if tgtMap, ok := target[key].(map[string]interface{}); ok {
				deepMerge(tgtMap, srcMap)
				continue
			}
		}
		target[key] = srcVal
	}
}

func normalizeKeys(m map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(m))
	for k, v := range m {
		key := toSnakeCase(k)
		if sub, ok := v.(map[string]interface{}); ok {
			out[key] = normalizeKeys(sub)
		} else {
			out[key] = v
		}
	}
	return out
}

func toSnakeCase(s string) string {
	var b strings.Builder
	for i, r := range s {
		if i > 0 && unicode.IsUpper(r) {
			b.WriteByte('_')
		}
		b.WriteRune(unicode.ToLower(r))
	}
	return b.String()
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

func (s *apiServer) seedMarketplace() {
	now := time.Now()
	pkgs := []*marketplace.Package{
		{
			ID:          "1",
			Name:        "rate-limit",
			Version:     "1.0.0",
			Description: "Token bucket rate limiting per IP or session with optional Redis backend",
			Author:      "Waffynx Team",
			License:     "MIT",
			Category:    "security",
			Tags:        []string{"rate-limit", "ddos", "redis"},
			Status:      marketplace.StatusPublished,
			PublishedAt: now,
			UpdatedAt:   now,
		},
		{
			ID:          "2",
			Name:        "geo-block",
			Version:     "1.0.0",
			Description: "Block or allow requests based on geographic location using MaxMind GeoLite2",
			Author:      "Waffynx Team",
			License:     "MIT",
			Category:    "security",
			Tags:        []string{"geo-block", "geolocation", "maxmind"},
			Status:      marketplace.StatusPublished,
			PublishedAt: now,
			UpdatedAt:   now,
		},
		{
			ID:          "3",
			Name:        "request-validation",
			Version:     "1.0.0",
			Description: "Validate request headers, query parameters, and JSON body schemas",
			Author:      "Waffynx Team",
			License:     "MIT",
			Category:    "validation",
			Tags:        []string{"validation", "schema", "headers"},
			Status:      marketplace.StatusPublished,
			PublishedAt: now,
			UpdatedAt:   now,
		},
	}
	for _, pkg := range pkgs {
		s.store.AddPackage(pkg)
	}
}

func (s *apiServer) handleMarketplaceList(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	filter := marketplace.Filter{
		Category: q.Get("category"),
		Query:    q.Get("q"),
		Status:   marketplace.PackageStatus(q.Get("status")),
	}
	pkgs, err := s.store.List(filter)
	if err != nil {
		s.writeError(w, r, http.StatusInternalServerError, err.Error())
		return
	}
	if pkgs == nil {
		pkgs = []*marketplace.Package{}
	}
	s.writeJSON(w, r, http.StatusOK, pkgs)
}

func (s *apiServer) handleMarketplaceGet(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	version := r.URL.Query().Get("version")
	if version == "" {
		version = "1.0.0"
	}
	pkg, err := s.store.Get(name, version)
	if err != nil {
		s.writeError(w, r, http.StatusNotFound, err.Error())
		return
	}
	s.writeJSON(w, r, http.StatusOK, pkg)
}

func (s *apiServer) handleMarketplaceInstall(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	version := r.URL.Query().Get("version")
	if version == "" {
		version = "1.0.0"
	}
	if err := s.store.Install(name, version); err != nil {
		s.writeError(w, r, http.StatusNotFound, err.Error())
		return
	}
	s.writeJSON(w, r, http.StatusOK, map[string]string{
		"status":  "installed",
		"name":    name,
		"version": version,
	})
}

func (s *apiServer) handleMarketplaceUninstall(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := s.store.Uninstall(name); err != nil {
		s.writeError(w, r, http.StatusNotFound, err.Error())
		return
	}
	s.writeJSON(w, r, http.StatusOK, map[string]string{
		"status": "uninstalled",
		"name":   name,
	})
}

func (s *apiServer) handleMarketplaceCategories(w http.ResponseWriter, r *http.Request) {
	cats, err := s.store.GetCategories()
	if err != nil {
		s.writeError(w, r, http.StatusInternalServerError, err.Error())
		return
	}
	if cats == nil {
		cats = []string{}
	}
	s.writeJSON(w, r, http.StatusOK, map[string]interface{}{
		"categories": cats,
	})
}

func (s *apiServer) handleIngestEvent(w http.ResponseWriter, r *http.Request) {
	if s.broker == nil {
		s.writeError(w, r, http.StatusServiceUnavailable, "event broker not available")
		return
	}

	var evt events.WafEvent
	if err := json.NewDecoder(r.Body).Decode(&evt); err != nil {
		s.writeError(w, r, http.StatusBadRequest, "invalid event body")
		return
	}
	if evt.Type == "" {
		s.writeError(w, r, http.StatusBadRequest, "event type is required")
		return
	}

	s.broker.Publish(evt)
	s.writeJSON(w, r, http.StatusAccepted, map[string]string{"status": "ingested"})
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

	w.Write([]byte(": connected\n\n"))
	flusher.Flush()

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	var eventCh <-chan []byte
	if s.broker != nil {
		ch := s.broker.Subscribe()
		defer s.broker.Unsubscribe(ch)
		eventCh = ch
	}

	s.writeSSEStats(w, flusher)

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case data := <-eventCh:
			w.Write([]byte("data: "))
			w.Write(data)
			w.Write([]byte("\n\n"))
			flusher.Flush()
		case <-ticker.C:
			s.writeSSEStats(w, flusher)
		}
	}
}

func (s *apiServer) writeSSEStats(w http.ResponseWriter, flusher http.Flusher) {
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	cfg := s.readConfig()
	if cfg == nil {
		cfg = &config.Config{}
	}

	data, _ := json.Marshal(map[string]interface{}{
		"type":       "stats",
		"timestamp":  time.Now().UTC().Format(time.RFC3339),
		"goroutines": runtime.NumGoroutine(),
		"heap_mb":    float64(mem.Alloc) / 1024 / 1024,
		"engine":     cfg.AppSec.Engine,
	})
	w.Write([]byte("data: "))
	w.Write(data)
	w.Write([]byte("\n\n"))
	flusher.Flush()
}
