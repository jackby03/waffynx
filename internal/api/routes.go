package api

import (
	"net/http"
	"net/http/pprof"

	"github.com/jackby03/waffynx/internal/metrics"
)

func (s *Server) registerRoutes(mux *http.ServeMux) {
	withAuth := s.authMiddleware(mux)
	requireAdmin := s.requireRole("admin")

	mux.HandleFunc("GET /health", s.handleHealth)

	// Auth routes
	mux.HandleFunc("POST /api/v1/auth/login", s.handleLogin)

	// Status and Configuration
	mux.HandleFunc("GET /api/v1/status", withAuth(s.handleStatus))
	mux.HandleFunc("GET /api/v1/config", withAuth(s.handleGetConfig))
	mux.HandleFunc("PUT /api/v1/config", withAuth(requireAdmin(s.handleUpdateConfig)))
	mux.HandleFunc("GET /api/v1/metrics", withAuth(s.handleMetrics))

	// Plugins
	mux.HandleFunc("GET /api/v1/plugins", withAuth(s.handleListPlugins))
	mux.HandleFunc("GET /api/v1/plugins/{name}", withAuth(s.handleGetPlugin))

	// Audit & Real-time Events
	mux.HandleFunc("GET /api/v1/audit", withAuth(s.handleAuditQuery))
	mux.HandleFunc("POST /api/v1/events", withAuth(s.requireScope("events:write")(s.handleIngestEvent)))
	mux.HandleFunc("GET /api/v1/events", withAuth(s.handleSSE))

	// Marketplace
	mux.HandleFunc("GET /api/v1/marketplace", withAuth(s.handleMarketplaceList))
	mux.HandleFunc("GET /api/v1/marketplace/categories", withAuth(s.handleMarketplaceCategories))
	mux.HandleFunc("GET /api/v1/marketplace/{name}", withAuth(s.handleMarketplaceGet))
	mux.HandleFunc("POST /api/v1/marketplace/install/{name}", withAuth(requireAdmin(s.handleMarketplaceInstall)))
	mux.HandleFunc("DELETE /api/v1/marketplace/uninstall/{name}", withAuth(requireAdmin(s.handleMarketplaceUninstall)))

	// Host Firewall
	mux.HandleFunc("GET /api/v1/firewall/rules", withAuth(s.handleFirewallRules))
	mux.HandleFunc("POST /api/v1/firewall/block", withAuth(requireAdmin(s.handleFirewallBlock)))
	mux.HandleFunc("DELETE /api/v1/firewall/unblock/{ip}", withAuth(requireAdmin(s.handleFirewallUnblock)))

	// Prometheus Metrics & Profiling
	mux.HandleFunc("GET /metrics", metrics.Handler().ServeHTTP)
	mux.HandleFunc("GET /debug/pprof/", withAuth(requireAdmin(pprof.Index)))
	mux.HandleFunc("GET /debug/pprof/cmdline", withAuth(requireAdmin(pprof.Cmdline)))
	mux.HandleFunc("GET /debug/pprof/profile", withAuth(requireAdmin(pprof.Profile)))
	mux.HandleFunc("GET /debug/pprof/symbol", withAuth(requireAdmin(pprof.Symbol)))
	mux.HandleFunc("GET /debug/pprof/trace", withAuth(requireAdmin(pprof.Trace)))

	// UI SPA assets
	mux.HandleFunc("GET /", s.handleRoot)
	mux.HandleFunc("GET /assets/", s.handleUIAsset)
}
