package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/jackby03/waffynx/internal/analytics"
	"github.com/jackby03/waffynx/internal/config"
	"github.com/jackby03/waffynx/internal/hotreload"
	"github.com/jackby03/waffynx/internal/ratelimit"
	"github.com/jackby03/waffynx/internal/sites"
	"github.com/jackby03/waffynx/internal/storage"
	"github.com/jackby03/waffynx/internal/telemetry"
	"github.com/jackby03/waffynx/internal/xds"
)

type stubAnalytics struct {
	events  []telemetry.SecurityEvent
	summary analytics.Summary
}

func (a *stubAnalytics) Ping(context.Context) error { return nil }
func (a *stubAnalytics) QueryEvents(context.Context, analytics.EventFilter) ([]telemetry.SecurityEvent, error) {
	return a.events, nil
}
func (a *stubAnalytics) QuerySummary(context.Context, int) (analytics.Summary, error) {
	return a.summary, nil
}

func newDistributedTestServer(t *testing.T) (*Server, *storage.MemoryStore, *hotreload.MemoryBus, *xds.Server, string) {
	t.Helper()
	hash, _ := bcrypt.GenerateFromPassword([]byte("AdminSecretPassword2026!"), bcrypt.MinCost)
	cfg := &config.Config{
		Listen: ":8443",
		API: config.APIConfig{
			Listen: ":9090",
			Auth: config.AuthConfig{
				JWTSecret: "0123456789abcdef0123456789abcdef",
				TokenTTL:  3600,
				Users:     []config.UserConfig{{Username: "admin", PasswordHash: string(hash)}},
			},
		},
		Sites: []sites.Site{{Host: "app.example.test", Upstream: "backend:80"}},
	}

	srv, err := NewServer(cfg, "", "")
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	db := storage.NewMemoryStore()
	bus := hotreload.NewMemoryBus()
	xdsSrv := xds.NewServer(xds.DefaultTopologyConfig())
	jails := ratelimit.NewMemoryLimiter()
	t.Cleanup(func() { _ = jails.Close() })
	ar := &stubAnalytics{
		events:  []telemetry.SecurityEvent{{EventID: "ev-1", Action: telemetry.ActionBlock, RuleID: "sqli-001"}},
		summary: analytics.Summary{WindowHours: 24, TotalEvents: 1, Blocked: 1},
	}

	srv.SetDistributedBackends(db, bus, xdsSrv, "", nil, ar, jails)
	if err := srv.BootstrapDistributedState(context.Background()); err != nil {
		t.Fatalf("BootstrapDistributedState: %v", err)
	}

	tok, err := srv.authMgr.GenerateToken("admin", "admin", []string{"read", "write", "admin"})
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	return srv, db, bus, xdsSrv, tok
}

func doAuthReq(h http.Handler, method, path, token string, body any) *httptest.ResponseRecorder {
	var rdr *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	} else {
		rdr = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, rdr)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestDistributedAPI_FullControlPlaneWorkflow(t *testing.T) {
	srv, _, bus, xdsSrv, tok := newDistributedTestServer(t)
	h := srv.Handler()

	// 1. Probes + DB-backed login.
	if rec := doAuthReq(h, http.MethodGet, "/healthz", "", nil); rec.Code != http.StatusOK {
		t.Fatalf("GET /healthz: %d", rec.Code)
	}
	if rec := doAuthReq(h, http.MethodGet, "/readyz", "", nil); rec.Code != http.StatusOK {
		t.Fatalf("GET /readyz: %d", rec.Code)
	}
	if rec := doAuthReq(h, http.MethodPost, "/api/v1/auth/login", "", map[string]string{
		"username": "admin", "password": "AdminSecretPassword2026!",
	}); rec.Code != http.StatusOK {
		t.Fatalf("DB login failed: %d %s", rec.Code, rec.Body.String())
	}

	// 2. Site CRUD persists in store and bumps Envoy xDS snapshot version.
	rec := doAuthReq(h, http.MethodPost, "/api/v1/sites", tok, sites.Site{Host: "api.example.test", Upstream: "api:8080"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create site: %d %s", rec.Code, rec.Body.String())
	}
	if xdsSrv.CurrentVersion() < 2 {
		t.Fatalf("expected xDS version >= 2 after site create, got %d", xdsSrv.CurrentVersion())
	}
	if rec := doAuthReq(h, http.MethodGet, "/api/v1/sites/api.example.test", tok, nil); rec.Code != http.StatusOK {
		t.Fatalf("get site: %d", rec.Code)
	}
	if rec := doAuthReq(h, http.MethodPut, "/api/v1/sites/api.example.test", tok, sites.Site{Host: "api.example.test", Upstream: "api:9090"}); rec.Code != http.StatusOK {
		t.Fatalf("update site: %d %s", rec.Code, rec.Body.String())
	}
	if rec := doAuthReq(h, http.MethodDelete, "/api/v1/sites/api.example.test", tok, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("delete site: %d", rec.Code)
	}

	// 3. Custom rules CRUD + hot-reload snapshot.
	rec = doAuthReq(h, http.MethodPost, "/api/v1/custom-rules", tok, map[string]any{
		"id": "r-db-1", "name": "Block secret", "enabled": true, "action": "block", "path_exact": "/secret",
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create custom rule: %d %s", rec.Code, rec.Body.String())
	}
	if rec := doAuthReq(h, http.MethodGet, "/api/v1/custom-rules", tok, nil); rec.Code != http.StatusOK {
		t.Fatalf("list custom rules: %d", rec.Code)
	}
	if rec := doAuthReq(h, http.MethodDelete, "/api/v1/custom-rules/r-db-1", tok, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("delete custom rule: %d", rec.Code)
	}

	// 4. Exclusions CRUD -> published to hot-reload bus.
	rec = doAuthReq(h, http.MethodPost, "/api/v1/exclusions", tok, map[string]any{
		"rule_id": "sqli-001", "host": "app.example.test", "path_prefix": "/search", "reason": "FP tuning",
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create exclusion: %d %s", rec.Code, rec.Body.String())
	}
	var exResp struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &exResp)
	if rec := doAuthReq(h, http.MethodGet, "/api/v1/exclusions", tok, nil); rec.Code != http.StatusOK {
		t.Fatalf("list exclusions: %d", rec.Code)
	}
	snap, _ := bus.LatestSnapshot(context.Background())
	if snap == nil || len(snap.Exclusions) != 1 {
		t.Fatalf("expected hot-reload snapshot to contain 1 exclusion, got %+v", snap)
	}
	if rec := doAuthReq(h, http.MethodDelete, "/api/v1/exclusions/"+exResp.ID, tok, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("delete exclusion: %d", rec.Code)
	}

	// 5. Zero-Trust Policies CRUD.
	rec = doAuthReq(h, http.MethodPost, "/api/v1/zero-trust/policies", tok, map[string]any{
		"name": "Admin JWT", "path_prefix": "/admin", "enabled": true, "require_jwt": true, "required_scopes": []string{"admin"},
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create ZT policy: %d %s", rec.Code, rec.Body.String())
	}
	var ztResp struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &ztResp)
	if rec := doAuthReq(h, http.MethodPut, "/api/v1/zero-trust/policies/"+ztResp.ID, tok, map[string]any{
		"name": "Admin JWT v2", "path_prefix": "/admin", "enabled": true, "require_jwt": true,
	}); rec.Code != http.StatusOK {
		t.Fatalf("update ZT policy: %d %s", rec.Code, rec.Body.String())
	}
	if rec := doAuthReq(h, http.MethodGet, "/api/v1/zero-trust/policies", tok, nil); rec.Code != http.StatusOK {
		t.Fatalf("list ZT policies: %d", rec.Code)
	}
	if rec := doAuthReq(h, http.MethodDelete, "/api/v1/zero-trust/policies/"+ztResp.ID, tok, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("delete ZT policy: %d", rec.Code)
	}

	// 6. Firewall IP ban persisted to DB + Redis jail.
	if rec := doAuthReq(h, http.MethodPost, "/api/v1/firewall/block", tok, map[string]any{
		"ip": "203.0.113.88", "reason": "brute force", "ttl": 600,
	}); rec.Code != http.StatusCreated {
		t.Fatalf("firewall block: %d %s", rec.Code, rec.Body.String())
	}
	if rec := doAuthReq(h, http.MethodGet, "/api/v1/firewall/rules", tok, nil); rec.Code != http.StatusOK {
		t.Fatalf("firewall list: %d", rec.Code)
	}
	if rec := doAuthReq(h, http.MethodDelete, "/api/v1/firewall/unblock/203.0.113.88", tok, nil); rec.Code != http.StatusOK {
		t.Fatalf("firewall unblock: %d", rec.Code)
	}

	// 7. ClickHouse analytics & cluster topology.
	if rec := doAuthReq(h, http.MethodGet, "/api/v1/analytics/events?limit=10", tok, nil); rec.Code != http.StatusOK {
		t.Fatalf("analytics events: %d", rec.Code)
	}
	if rec := doAuthReq(h, http.MethodGet, "/api/v1/analytics/summary?window_hours=24", tok, nil); rec.Code != http.StatusOK {
		t.Fatalf("analytics summary: %d", rec.Code)
	}
	if rec := doAuthReq(h, http.MethodGet, "/api/v1/cluster/topology", tok, nil); rec.Code != http.StatusOK {
		t.Fatalf("cluster topology: %d", rec.Code)
	}

	// 8. RBAC users CRUD.
	if rec := doAuthReq(h, http.MethodPost, "/api/v1/users", tok, map[string]any{
		"username": "analyst", "password": "AnalystPassword2026!", "role": "viewer",
	}); rec.Code != http.StatusCreated {
		t.Fatalf("create user: %d %s", rec.Code, rec.Body.String())
	}
	if rec := doAuthReq(h, http.MethodGet, "/api/v1/users", tok, nil); rec.Code != http.StatusOK {
		t.Fatalf("list users: %d", rec.Code)
	}
	if rec := doAuthReq(h, http.MethodDelete, "/api/v1/users/analyst", tok, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("delete user: %d", rec.Code)
	}
}
