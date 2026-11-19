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
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("GET /readyz", s.handleReadyz)

	// Auth routes. Preflight for this (and every other /api/v1/ route) is
	// answered by corsMiddleware, so no explicit OPTIONS mapping is needed — and
	// mapping one here would route preflight at the login handler.
	mux.HandleFunc("POST /api/v1/auth/login", s.handleLogin)
	mux.HandleFunc("GET /api/v1/auth/me", withAuth(s.handleMe))

	// Status and Configuration
	mux.HandleFunc("GET /api/v1/status", withAuth(s.handleStatus))
	mux.HandleFunc("GET /api/v1/config", withAuth(s.handleGetConfig))
	mux.HandleFunc("PUT /api/v1/config", withAuth(requireAdmin(s.handleUpdateConfig)))
	mux.HandleFunc("GET /api/v1/metrics", withAuth(s.handleMetrics))

	// Sites (reverse-proxy topology). Reads need auth; writes need admin, because a
	// site change reconfigures what the proxy serves.
	mux.HandleFunc("GET /api/v1/sites", withAuth(s.handleSiteList))
	mux.HandleFunc("GET /api/v1/sites/{host}", withAuth(s.handleSiteGet))
	mux.HandleFunc("POST /api/v1/sites", withAuth(requireAdmin(s.handleSiteCreate)))
	mux.HandleFunc("PUT /api/v1/sites/{host}", withAuth(requireAdmin(s.handleSiteUpdate)))
	mux.HandleFunc("DELETE /api/v1/sites/{host}", withAuth(requireAdmin(s.handleSiteDelete)))

	// Plugins
	mux.HandleFunc("GET /api/v1/rules", withAuth(s.handleRuleList))
	mux.HandleFunc("GET /api/v1/plugins", withAuth(s.handleListPlugins))
	mux.HandleFunc("GET /api/v1/plugins/{name}", withAuth(s.handleGetPlugin))

	// Audit & Real-time Events
	mux.HandleFunc("GET /api/v1/audit", withAuth(s.handleAuditQuery))
	mux.HandleFunc("POST /api/v1/events", withAuth(s.requireScope("events:write")(s.handleIngestEvent)))
	mux.HandleFunc("GET /api/v1/events", withAuth(s.handleSSE))
	// History is the polling counterpart to the stream: it lets a reconnecting
	// dashboard backfill the gap instead of losing events.
	mux.HandleFunc("GET /api/v1/events/history", withAuth(s.handleEventHistory))

	// Custom rules live in the data plane (the sidecar evaluates them per
	// request), so these handlers proxy the socket and never keep a copy.
	mux.HandleFunc("GET /api/v1/custom-rules", withAuth(s.handleCustomRuleList))
	mux.HandleFunc("POST /api/v1/custom-rules", withAuth(requireAdmin(s.handleCustomRuleCreate)))
	mux.HandleFunc("DELETE /api/v1/custom-rules/{id}", withAuth(requireAdmin(s.handleCustomRuleDelete)))

	// Behavioural learning, also owned by the sidecar.
	mux.HandleFunc("GET /api/v1/learning/suggestions", withAuth(s.handleLearningSuggestions))
	mux.HandleFunc("GET /api/v1/learning/stats", withAuth(s.handleLearningStats))

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

	// False-Positive Exclusions (Phase 1 & Phase 4)
	mux.HandleFunc("GET /api/v1/exclusions", withAuth(s.handleExclusionList))
	mux.HandleFunc("POST /api/v1/exclusions", withAuth(requireAdmin(s.handleExclusionCreate)))
	mux.HandleFunc("DELETE /api/v1/exclusions/{id}", withAuth(requireAdmin(s.handleExclusionDelete)))

	// Zero-Trust Continuous Authorization Policies (Phase 3 ext_authz)
	mux.HandleFunc("GET /api/v1/zero-trust/policies", withAuth(s.handleZTPolicyList))
	mux.HandleFunc("POST /api/v1/zero-trust/policies", withAuth(requireAdmin(s.handleZTPolicyCreate)))
	mux.HandleFunc("PUT /api/v1/zero-trust/policies/{id}", withAuth(requireAdmin(s.handleZTPolicyUpdate)))
	mux.HandleFunc("DELETE /api/v1/zero-trust/policies/{id}", withAuth(requireAdmin(s.handleZTPolicyDelete)))

	// Observability & ClickHouse Analytics (Phase 4)
	mux.HandleFunc("GET /api/v1/analytics/events", withAuth(s.handleAnalyticsEvents))
	mux.HandleFunc("GET /api/v1/analytics/summary", withAuth(s.handleAnalyticsSummary))

	// Multi-Plane Cluster Topology & RBAC Users
	mux.HandleFunc("GET /api/v1/cluster/topology", withAuth(s.handleClusterTopology))
	mux.HandleFunc("GET /api/v1/users", withAuth(requireAdmin(s.handleUserList)))
	mux.HandleFunc("POST /api/v1/users", withAuth(requireAdmin(s.handleUserCreate)))
	mux.HandleFunc("DELETE /api/v1/users/{username}", withAuth(requireAdmin(s.handleUserDelete)))

	// Prometheus Metrics & Profiling
	mux.HandleFunc("GET /metrics", metrics.Handler().ServeHTTP)
	mux.HandleFunc("GET /debug/pprof/", withAuth(requireAdmin(pprof.Index)))
	mux.HandleFunc("GET /debug/pprof/cmdline", withAuth(requireAdmin(pprof.Cmdline)))
	mux.HandleFunc("GET /debug/pprof/profile", withAuth(requireAdmin(pprof.Profile)))
	mux.HandleFunc("GET /debug/pprof/symbol", withAuth(requireAdmin(pprof.Symbol)))
	mux.HandleFunc("GET /debug/pprof/trace", withAuth(requireAdmin(pprof.Trace)))

	// UI SPA assets
	// Unknown /api/v1 paths must not fall through to the SPA/JSON root handler:
	// it answers 200, so a typo in the dashboard looked like a successful call
	// that returned the wrong shape ("r.map is not a function").
	//
	// Registered per method because a method-less subtree conflicts with "GET /"
	// in the Go 1.22 mux, and the panic happens at startup, not at request time.
	for _, method := range []string{"GET", "POST", "PUT", "DELETE", "PATCH"} {
		mux.HandleFunc(method+" /api/v1/", s.handleAPINotFound)
	}

	mux.HandleFunc("GET /", s.handleRoot)
	mux.HandleFunc("GET /assets/", s.handleUIAsset)
}
