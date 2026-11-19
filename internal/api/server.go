package api

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/jackby03/waffynx/internal/analytics"
	"github.com/jackby03/waffynx/internal/audit"
	"github.com/jackby03/waffynx/internal/auth"
	"github.com/jackby03/waffynx/internal/catalog"
	"github.com/jackby03/waffynx/internal/config"
	"github.com/jackby03/waffynx/internal/events"
	"github.com/jackby03/waffynx/internal/firewall"
	"github.com/jackby03/waffynx/internal/hotreload"
	"github.com/jackby03/waffynx/internal/logging"
	"github.com/jackby03/waffynx/internal/marketplace"
	"github.com/jackby03/waffynx/internal/ratelimit"
	"github.com/jackby03/waffynx/internal/sites"
	"github.com/jackby03/waffynx/internal/storage"
	"github.com/jackby03/waffynx/internal/xds"
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
	// wafRules enforces bans at the WAF layer. This is the only path that works
	// in container mode, where kernel filtering is unavailable.
	wafRules ruleInjector
	uiDir    string

	// catalog is the managed ruleset, exposed read-only so the dashboard can show
	// what is actually enforced instead of inventing a rule list.
	catalog *catalog.Catalog

	// siteApplier renders the reverse-proxy topology and makes it live. Injected so
	// the HTTP layer can be tested without nginx.
	siteApplier *sites.Applier

	// Optional distributed multi-container Control Plane backends (Constitution §1.3 & §2.3).
	// All remain nil in standalone single-container mode.
	db              storage.Store
	reloadBus       hotreload.Bus
	xdsSrv          *xds.Server
	analyticsReader analytics.Reader
	jailStore       ratelimit.JailStore
	xdsTLS          *tls.Config
	xdsListen       string
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
		catalog:    loadCatalog(),
	}

	// Bans are enforced through the sidecar, which evaluates custom rules on
	// every request. Without it, a ban can only fall back to the host firewall,
	// which does not exist in container deployments.
	if cfg.Sidecar.SocketPath != "" {
		timeout := time.Duration(cfg.Sidecar.TimeoutMs) * time.Millisecond
		if timeout <= 0 {
			timeout = 2 * time.Second
		}
		srv.wafRules = newSidecarClient(cfg.Sidecar.SocketPath, timeout)
	}

	// Site changes are applied by running `nginx -t` and signalling the master
	// through its pid file: the API does not own the nginx process, so it cannot
	// signal a child handle like the engine does.
	if cfg.Nginx.ConfigPath != "" {
		srv.siteApplier = &sites.Applier{
			Dir: filepath.Join(cfg.Nginx.ConfigPath, "sites"),
			Validator: sites.NginxValidator{
				BinaryPath: cfg.Nginx.BinaryPath,
				ConfigPath: cfg.Nginx.ConfigPath,
			},
			Reloader: sites.NginxReloader{
				BinaryPath: cfg.Nginx.BinaryPath,
				ConfigPath: cfg.Nginx.ConfigPath,
			},
		}
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
	// CORS is installed once, around the mux, so every /api/v1/ route gets
	// preflight handling without a per-route OPTIONS mapping.
	return s.auditMiddleware(s.loggingMiddleware(s.corsMiddleware(mux)))
}

// SetDistributedBackends wires optional multi-container Control Plane components
// (PostgreSQL store, Redis hot-reload bus, Envoy xDS server, ClickHouse analytics,
// and Redis IP jail store). Passing nil keeps standalone single-container behavior.
func (s *Server) SetDistributedBackends(
	db storage.Store,
	bus hotreload.Bus,
	xdsSrv *xds.Server,
	xdsListen string,
	xdsTLS *tls.Config,
	reader analytics.Reader,
	jails ratelimit.JailStore,
) {
	s.db = db
	s.reloadBus = bus
	s.xdsSrv = xdsSrv
	s.xdsListen = xdsListen
	s.xdsTLS = xdsTLS
	s.analyticsReader = reader
	s.jailStore = jails
}

// BootstrapDistributedState seeds PostgreSQL on first boot with configured
// bootstrap users and sites if empty, then publishes the initial policy snapshot
// to Redis hot-reload and Envoy xDS so Data Plane replicas hydrate immediately.
func (s *Server) BootstrapDistributedState(ctx context.Context) error {
	if s.db == nil {
		return nil
	}
	cfg := s.readConfig()

	// Seed admin user(s) from bootstrap config if not yet in PostgreSQL.
	for _, u := range cfg.API.Auth.Users {
		if u.Username == "" || u.PasswordHash == "" {
			continue
		}
		if _, err := s.db.GetUser(ctx, u.Username); err != nil {
			_ = s.db.UpsertUser(ctx, storage.User{
				Username:     u.Username,
				PasswordHash: u.PasswordHash,
				Role:         "admin",
				Scopes:       []string{"read", "write", "admin"},
				Enabled:      true,
			})
		}
	}

	// Seed initial sites if PostgreSQL sites table is empty.
	existingSites, err := s.db.ListSites(ctx)
	if err == nil && len(existingSites) == 0 {
		for _, st := range cfg.Sites {
			_ = s.db.UpsertSite(ctx, st, true)
		}
	}

	return s.syncControlPlane(ctx, "bootstrap", "system")
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

	if s.xdsSrv != nil && s.xdsListen != "" {
		go func() {
			if err := s.xdsSrv.Serve(ctx, s.xdsListen, s.xdsTLS); err != nil {
				logging.Error().Err(err).Msg("Envoy xDS server error")
			}
		}()
	}

	// The dashboard history comes from the sidecar stream in single-container mode.
	// In distributed Envoy xDS mode telemetry flows asynchronously via NATS -> ClickHouse.
	if s.xdsSrv == nil {
		go s.bridgeSidecarEvents(ctx)
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
				// Build the OIDC manager first and keep the running configuration if
				// it cannot be initialised: swapping in a manager whose providers
				// failed to load would silently disable OIDC (fail-closed).
				newOIDC := auth.NewOIDCManager()
				if len(newCfg.API.Auth.OIDC) > 0 {
					if cfgErr := newOIDC.Configure(newCfg.API.Auth.OIDC); cfgErr != nil {
						logging.Error().Err(cfgErr).Msg("reload rejected: invalid OIDC configuration")
						continue
					}
				}
				s.configMu.Lock()
				s.cfg = newCfg
				s.authMgr = auth.NewManager(newCfg.API.Auth.JWTSecret, newCfg.API.Auth.TokenTTL)
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
