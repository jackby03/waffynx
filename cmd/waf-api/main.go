package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/jackby03/waffynx/internal/auth"
	"github.com/jackby03/waffynx/internal/config"
	"github.com/jackby03/waffynx/internal/logging"
	"github.com/jackby03/waffynx/internal/marketplace"
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
	store    *marketplace.InMemoryStore
}

func runAPI(cfg *config.Config) error {
	logging.Info().Str("listen", cfg.API.Listen).Msg("starting management API")

	srv := &apiServer{
		cfg:     cfg,
		authMgr: auth.NewManager(cfg.API.Auth.JWTSecret, cfg.API.Auth.TokenTTL),
		store:   marketplace.NewInMemoryStore(),
	}

	mux := http.NewServeMux()

	mux.HandleFunc("GET /health", srv.handleHealth)

	withAuth := srv.authMiddleware(mux)
	mux.HandleFunc("GET /api/v1/status", withAuth(srv.handleStatus))
	mux.HandleFunc("GET /api/v1/config", withAuth(srv.handleGetConfig))
	mux.HandleFunc("PUT /api/v1/config", withAuth(srv.handleUpdateConfig))
	mux.HandleFunc("GET /api/v1/metrics", withAuth(srv.handleMetrics))
	mux.HandleFunc("GET /api/v1/plugins", withAuth(srv.handleListPlugins))
	mux.HandleFunc("GET /api/v1/plugins/{name}", withAuth(srv.handleGetPlugin))

	mux.HandleFunc("POST /api/v1/auth/login", srv.handleLogin)

	server := &http.Server{
		Addr:         cfg.API.Listen,
		Handler:      srv.loggingMiddleware(mux),
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
			cfg := s.readConfig()
			if cfg.API.Auth.JWTSecret == "" {
				next(w, r)
				return
			}

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
