package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/jackby03/waffynx/internal/audit"
	"github.com/jackby03/waffynx/internal/auth"
	"github.com/jackby03/waffynx/internal/config"
	"github.com/jackby03/waffynx/internal/events"
	"github.com/jackby03/waffynx/internal/firewall"
	"github.com/jackby03/waffynx/internal/logging"
	"github.com/jackby03/waffynx/internal/marketplace"
)

// Server represents the Waffynx Management API (Control Plane).
type Server struct {
	configMu   sync.RWMutex
	cfg        *config.Config
	configPath string
	authMgr    *auth.Manager
	oidcMgr    *auth.OIDCManager
	store      *marketplace.InMemoryStore
	audit      *audit.Store
	broker     *events.Broker
	firewallMu sync.RWMutex
	bannedIPs  map[string]BannedIP
	firewall   *firewall.Manager
	uiDir      string
}

// NewServer initializes the management API server with verified security configurations.
func NewServer(cfg *config.Config, configPath string, uiDir string) (*Server, error) {
	if cfg.API.Auth.JWTSecret == "" || cfg.API.Auth.JWTSecret == "change-me-in-production" {
		logging.Error().Msg("JWT secret is empty or set to default value, change it in production")
		return nil, fmt.Errorf("insecure JWT secret")
	}

	if len(cfg.API.Auth.JWTSecret) < 32 {
		logging.Error().Msg("JWT secret is too short, must be at least 32 characters")
		return nil, fmt.Errorf("insecure JWT secret")
	}

	auditStore, err := audit.NewStore(2000, "/opt/waffynx/logs/audit.jsonl")
	if err != nil {
		logging.Warn().Err(err).Msg("audit log file unavailable, using memory-only")
		auditStore, _ = audit.NewStore(2000, "")
	}

	var fwMgr *firewall.Manager
	if cfg.Firewall.Enabled {
		var fwErr error
		fwMgr, fwErr = firewall.NewManager(cfg.Firewall)
		if fwErr != nil {
			logging.Warn().Err(fwErr).Msg("firewall manager initialization failed")
		} else if startErr := fwMgr.Start(); startErr != nil {
			logging.Warn().Err(startErr).Msg("firewall manager start failed")
		}
	}

	srv := &Server{
		cfg:        cfg,
		configPath: configPath,
		authMgr:    auth.NewManager(cfg.API.Auth.JWTSecret, cfg.API.Auth.TokenTTL),
		oidcMgr:    auth.NewOIDCManager(),
		store:      marketplace.NewInMemoryStore(),
		audit:      auditStore,
		broker:     events.NewBroker(),
		bannedIPs:  make(map[string]BannedIP),
		firewall:   fwMgr,
		uiDir:      uiDir,
	}

	srv.seedMarketplace()

	if len(cfg.API.Auth.OIDC) > 0 {
		if err := srv.oidcMgr.Configure(cfg.API.Auth.OIDC); err != nil {
			logging.Warn().Err(err).Msg("OIDC configuration incomplete")
		}
	}

	return srv, nil
}

// Handler compiles and returns the HTTP handler with all registered routes and middleware.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	s.registerRoutes(mux)
	return s.auditMiddleware(s.loggingMiddleware(s.corsMiddleware(mux)))
}

// Run boots the HTTP management API server and orchestrates graceful shutdown and SIGHUP hot reload.
func (s *Server) Run(ctx context.Context) error {
	logging.Info().Str("listen", s.cfg.API.Listen).Msg("starting management API")

	server := &http.Server{
		Addr:         s.cfg.API.Listen,
		Handler:      s.Handler(),
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

	for {
		select {
		case <-ctx.Done():
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			return server.Shutdown(shutdownCtx)
		case sig := <-sigCh:
			switch sig {
			case syscall.SIGHUP:
				logging.Info().Msg("reloading config")
				newCfg, err := config.Load(s.configPath)
				if err != nil {
					logging.Error().Err(err).Msg("reload failed")
					continue
				}
				s.configMu.Lock()
				s.cfg = newCfg
				s.authMgr = auth.NewManager(newCfg.API.Auth.JWTSecret, newCfg.API.Auth.TokenTTL)
				newOIDC := auth.NewOIDCManager()
				if len(newCfg.API.Auth.OIDC) > 0 {
					newOIDC.Configure(newCfg.API.Auth.OIDC)
				}
				s.oidcMgr = newOIDC
				s.configMu.Unlock()
			case syscall.SIGINT, syscall.SIGTERM:
				logging.Info().Msg("shutting down API server")
				shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				return server.Shutdown(shutdownCtx)
			}
		}
	}
}

func (s *Server) readConfig() *config.Config {
	s.configMu.RLock()
	defer s.configMu.RUnlock()
	return s.cfg
}

func (s *Server) writeJSON(w http.ResponseWriter, r *http.Request, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if data != nil {
		_ = json.NewEncoder(w).Encode(data)
	}
}

func (s *Server) writeError(w http.ResponseWriter, r *http.Request, status int, message string) {
	s.writeJSON(w, r, status, map[string]interface{}{
		"error":   http.StatusText(status),
		"message": message,
	})
}
