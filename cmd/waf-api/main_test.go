package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/jackby03/waffynx/internal/audit"
	"github.com/jackby03/waffynx/internal/auth"
	"github.com/jackby03/waffynx/internal/config"
	"github.com/jackby03/waffynx/internal/events"
	"github.com/jackby03/waffynx/internal/marketplace"
)

func newTestAPIServer(t *testing.T, cfg *config.Config) (*apiServer, http.Handler) {
	t.Helper()
	if cfg == nil {
		cfg = &config.Config{
			Name: "waffynx-test",
			API: config.APIConfig{
				Listen: ":9090",
				Auth: config.AuthConfig{
					JWTSecret: "test-secret-key-1234567890-must-be-32-chars",
					TokenTTL:  3600,
				},
			},
		}
	}

	auditStore, _ := audit.NewStore(100, "")
	srv := &apiServer{
		cfg:        cfg,
		configPath: "test.yaml",
		authMgr:    auth.NewManager(cfg.API.Auth.JWTSecret, cfg.API.Auth.TokenTTL),
		oidcMgr:    auth.NewOIDCManager(),
		store:      marketplace.NewInMemoryStore(),
		audit:      auditStore,
		broker:     events.NewBroker(),
		bannedIPs:  make(map[string]BannedIP),
	}

	srv.seedMarketplace()

	mux := http.NewServeMux()

	withCORS := srv.corsMiddleware

	mux.HandleFunc("GET /health", srv.handleHealth)

	mux.HandleFunc("POST /api/v1/auth/login", withCORS(srv.handleLogin))
	mux.HandleFunc("OPTIONS /api/v1/auth/login", withCORS(srv.handleLogin))

	withAuth := srv.authMiddleware(mux)
	requireAdmin := srv.requireRole("admin")

	mux.HandleFunc("GET /api/v1/status", withCORS(withAuth(srv.handleStatus)))
	mux.HandleFunc("GET /api/v1/config", withCORS(withAuth(srv.handleGetConfig)))
	mux.HandleFunc("PUT /api/v1/config", withCORS(withAuth(requireAdmin(srv.handleUpdateConfig))))
	mux.HandleFunc("GET /api/v1/metrics", withCORS(withAuth(srv.handleMetrics)))
	mux.HandleFunc("GET /api/v1/plugins", withCORS(withAuth(srv.handleListPlugins)))
	mux.HandleFunc("GET /api/v1/events", withCORS(withAuth(srv.handleSSE)))
	mux.HandleFunc("POST /api/v1/events", withCORS(withAuth(srv.requireScope("events:write")(srv.handleIngestEvent))))
	mux.HandleFunc("GET /api/v1/marketplace", withCORS(withAuth(srv.handleMarketplaceList)))
	mux.HandleFunc("GET /api/v1/firewall/rules", withCORS(withAuth(srv.handleFirewallRules)))
	mux.HandleFunc("POST /api/v1/firewall/block", withCORS(withAuth(requireAdmin(srv.handleFirewallBlock))))
	mux.HandleFunc("DELETE /api/v1/firewall/unblock/{ip}", withCORS(withAuth(requireAdmin(srv.handleFirewallUnblock))))
	mux.HandleFunc("GET /", srv.handleRoot)

	return srv, mux
}

func TestAPI_Health(t *testing.T) {
	_, handler := newTestAPIServer(t, nil)

	req := httptest.NewRequest("GET", "/health", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}

	var resp map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal JSON: %v", err)
	}
	if resp["status"] != "ok" {
		t.Errorf("expected status 'ok', got %q", resp["status"])
	}
}

func TestAPI_Root(t *testing.T) {
	_, handler := newTestAPIServer(t, nil)

	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal JSON: %v", err)
	}
	if resp["service"] != "waf-api" {
		t.Errorf("expected service 'waf-api', got %v", resp["service"])
	}
}

func TestAPI_RootServesDashboardForHTMLClients(t *testing.T) {
	_, handler := newTestAPIServer(t, nil)

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Accept", "text/html")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", recorder.Code)
	}
	if got := recorder.Header().Get("Content-Type"); got != "text/html; charset=utf-8" {
		t.Fatalf("expected HTML content type, got %q", got)
	}
	if !bytes.Contains(recorder.Body.Bytes(), []byte(`id="root"`)) {
		t.Fatal("dashboard shell missing root element")
	}
}

func TestAPI_UIDirServesFromDisk(t *testing.T) {
	srv, handler := newTestAPIServer(t, nil)
	tmpDir := t.TempDir()
	srv.uiDir = tmpDir

	customHTML := []byte(`<!doctype html><html><body><div id="disk-test">Waffynx Disk UI</div></body></html>`)
	if err := os.WriteFile(path.Join(tmpDir, "index.html"), customHTML, 0o600); err != nil {
		t.Fatalf("failed to write test index.html: %v", err)
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Accept", "text/html")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", recorder.Code)
	}
	if !bytes.Contains(recorder.Body.Bytes(), []byte(`id="disk-test"`)) {
		t.Fatalf("expected response from disk, got: %s", recorder.Body.String())
	}
	if cc := recorder.Header().Get("Cache-Control"); !strings.Contains(cc, "no-cache") {
		t.Fatalf("expected Cache-Control to contain no-cache, got %q", cc)
	}
}

func TestAPI_AuthMiddleware_Unauthorized(t *testing.T) {
	_, handler := newTestAPIServer(t, nil)

	// Missing authorization header
	req := httptest.NewRequest("GET", "/api/v1/status", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401 for missing auth header, got %d", rec.Code)
	}

	// Invalid token
	req = httptest.NewRequest("GET", "/api/v1/status", nil)
	req.Header.Set("Authorization", "Bearer invalid-jwt-token")
	rec = httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401 for invalid token, got %d", rec.Code)
	}
}

func TestAPI_Login_NoUsersConfigured(t *testing.T) {
	_, handler := newTestAPIServer(t, nil)

	body := []byte(`{"username":"admin","password":"password123"}`)
	req := httptest.NewRequest("POST", "/api/v1/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotImplemented {
		t.Errorf("expected status 501 Not Implemented when no users configured, got %d", rec.Code)
	}
}

func TestAPI_Login_And_ProtectedEndpoints(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("secret123"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}

	cfg := &config.Config{
		Name: "waffynx-test",
		API: config.APIConfig{
			Listen: ":9090",
			Auth: config.AuthConfig{
				JWTSecret: "test-secret-key-1234567890-must-be-32-chars",
				TokenTTL:  3600,
				Users: []config.UserConfig{
					{
						Username:     "admin",
						PasswordHash: string(hash),
					},
				},
			},
		},
	}

	srv, handler := newTestAPIServer(t, cfg)

	// 1. Invalid Password -> 401
	badBody := []byte(`{"username":"admin","password":"wrongpassword"}`)
	req := httptest.NewRequest("POST", "/api/v1/auth/login", bytes.NewReader(badBody))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401 for wrong password, got %d", rec.Code)
	}

	// 2. Valid Login -> 200 + Token
	goodBody := []byte(`{"username":"admin","password":"secret123"}`)
	req = httptest.NewRequest("POST", "/api/v1/auth/login", bytes.NewReader(goodBody))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200 for valid login, got %d", rec.Code)
	}

	var loginResp map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &loginResp); err != nil {
		t.Fatalf("failed to parse login response: %v", err)
	}

	token, ok := loginResp["token"].(string)
	if !ok || token == "" {
		t.Fatal("login response missing token string")
	}

	// 3. Access GET /api/v1/status with JWT
	req = httptest.NewRequest("GET", "/api/v1/status", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200 for authenticated /api/v1/status, got %d", rec.Code)
	}

	// 4. Access GET /api/v1/config with JWT (Check JWTSecret redacted)
	req = httptest.NewRequest("GET", "/api/v1/config", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200 for authenticated /api/v1/config, got %d", rec.Code)
	}

	var configResp map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &configResp); err != nil {
		t.Fatalf("failed to parse config response: %v", err)
	}
	apiMap, _ := configResp["api"].(map[string]interface{})
	authMap, _ := apiMap["auth"].(map[string]interface{})
	jwtSecret, _ := authMap["jwt_secret"].(string)

	if jwtSecret != "***" {
		t.Errorf("expected jwt_secret to be '***', got %q", jwtSecret)
	}

	// 5. Access GET /api/v1/marketplace with JWT
	req = httptest.NewRequest("GET", "/api/v1/marketplace", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200 for authenticated /api/v1/marketplace, got %d", rec.Code)
	}
	if srv == nil {
		t.Error("server nil check")
	}
}

func TestAPI_RBAC_RoleEnforcement(t *testing.T) {
	cfg := &config.Config{
		Name: "waffynx-test",
		API: config.APIConfig{
			Listen: ":9090",
			Auth: config.AuthConfig{
				JWTSecret: "test-secret-key-1234567890-must-be-32-chars",
				TokenTTL:  3600,
			},
		},
	}

	srv, handler := newTestAPIServer(t, cfg)

	// Generate viewer token (non-admin)
	viewerToken, err := srv.authMgr.GenerateToken("viewer-user", "viewer", []string{"read"})
	if err != nil {
		t.Fatalf("failed to generate viewer token: %v", err)
	}

	// Attempt to PUT /api/v1/config with viewer token -> should be 403 Forbidden
	req := httptest.NewRequest("PUT", "/api/v1/config", bytes.NewReader([]byte(`{}`)))
	req.Header.Set("Authorization", "Bearer "+viewerToken)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected status 403 Forbidden for non-admin PUT /api/v1/config, got %d", rec.Code)
	}
}

func TestAPI_EventIngestRequiresScopeAndValidatesEvent(t *testing.T) {
	srv, handler := newTestAPIServer(t, nil)

	viewerToken, err := srv.authMgr.GenerateToken("viewer", "viewer", []string{"read"})
	if err != nil {
		t.Fatalf("generate viewer token: %v", err)
	}
	serviceToken, err := srv.authMgr.GenerateToken("event-bridge", "service", []string{"events:write"})
	if err != nil {
		t.Fatalf("generate service token: %v", err)
	}

	request := httptest.NewRequest("POST", "/api/v1/events", bytes.NewBufferString(`{"type":"blocked","path":"/attack","rule_id":"sql-001"}`))
	request.Header.Set("Authorization", "Bearer "+viewerToken)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("viewer status = %d, want 403", recorder.Code)
	}

	request = httptest.NewRequest("POST", "/api/v1/events", bytes.NewBufferString(`{"type":"blocked","path":"/attack","rule_id":"sql-001"}`))
	request.Header.Set("Authorization", "Bearer "+serviceToken)
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusAccepted {
		t.Fatalf("service status = %d, want 202", recorder.Code)
	}

	request = httptest.NewRequest("POST", "/api/v1/events", bytes.NewBufferString(`{"type":"allowed","path":"/","rule_id":"rule"}`))
	request.Header.Set("Authorization", "Bearer "+serviceToken)
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("invalid event status = %d, want 400", recorder.Code)
	}

	request = httptest.NewRequest("POST", "/api/v1/events", strings.NewReader(strings.Repeat("x", events.MaxEventBodyBytes+1)))
	request.Header.Set("Authorization", "Bearer "+serviceToken)
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("oversized event status = %d, want 400", recorder.Code)
	}
}

func TestAPI_CORS(t *testing.T) {
	cfg := &config.Config{
		Name: "waffynx-test",
		API: config.APIConfig{
			Listen:         ":9090",
			AllowedOrigins: []string{"https://app.example.com", "*"},
			Auth: config.AuthConfig{
				JWTSecret: "test-secret-key-1234567890-must-be-32-chars",
				TokenTTL:  3600,
			},
		},
	}

	_, handler := newTestAPIServer(t, cfg)

	// 1. Allowed origin request
	req := httptest.NewRequest("OPTIONS", "/api/v1/auth/login", nil)
	req.Header.Set("Origin", "https://app.example.com")
	req.Header.Set("Access-Control-Request-Method", "POST")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Errorf("expected preflight status 204 for allowed origin, got %d", rec.Code)
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "https://app.example.com" {
		t.Errorf("expected Access-Control-Allow-Origin 'https://app.example.com', got %q", got)
	}
	if got := rec.Header().Get("Access-Control-Allow-Credentials"); got != "true" {
		t.Errorf("expected Access-Control-Allow-Credentials 'true', got %q", got)
	}
	if got := rec.Header().Get("Vary"); got != "Origin" {
		t.Errorf("expected Vary 'Origin', got %q", got)
	}

	// 2. Unauthorized origin request
	req = httptest.NewRequest("OPTIONS", "/api/v1/auth/login", nil)
	req.Header.Set("Origin", "https://malicious.com")
	req.Header.Set("Access-Control-Request-Method", "POST")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected preflight status 403 for unauthorized origin, got %d", rec.Code)
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("expected empty Access-Control-Allow-Origin for unauthorized origin, got %q", got)
	}
	if got := rec.Header().Get("Vary"); got != "Origin" {
		t.Errorf("expected Vary 'Origin', got %q", got)
	}

	// 3. Wildcard origin request (should be rejected as invalid/disallowed origin configuration)
	req = httptest.NewRequest("OPTIONS", "/api/v1/auth/login", nil)
	req.Header.Set("Origin", "*")
	req.Header.Set("Access-Control-Request-Method", "POST")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected preflight status 403 for wildcard origin, got %d", rec.Code)
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("expected empty Access-Control-Allow-Origin for wildcard origin, got %q", got)
	}
	if got := rec.Header().Get("Vary"); got != "Origin" {
		t.Errorf("expected Vary 'Origin', got %q", got)
	}
}

func TestAPI_SSE_Auth(t *testing.T) {
	srv, handler := newTestAPIServer(t, nil)

	// 1. Missing auth header -> 401
	req := httptest.NewRequest("GET", "/api/v1/events", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401 for unauthenticated SSE request, got %d", rec.Code)
	}

	// 2. Valid auth header -> 200 (SSE stream started)
	token, err := srv.authMgr.GenerateToken("admin", "admin", []string{"read", "write"})
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel context immediately so handleSSE returns after connecting

	req = httptest.NewRequest("GET", "/api/v1/events", nil).WithContext(ctx)
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent && rec.Code != http.StatusOK {
		t.Errorf("expected status 200 or 204 for authenticated SSE request, got %d", rec.Code)
	}
}

func TestAPI_FirewallRules(t *testing.T) {
	srv, handler := newTestAPIServer(t, nil)

	adminToken, err := srv.authMgr.GenerateToken("admin", "admin", []string{"read", "write"})
	if err != nil {
		t.Fatalf("failed to generate admin token: %v", err)
	}
	operatorToken, err := srv.authMgr.GenerateToken("operator", "operator", []string{"read"})
	if err != nil {
		t.Fatalf("failed to generate operator token: %v", err)
	}

	// 1. GET /api/v1/firewall/rules initially empty
	req := httptest.NewRequest("GET", "/api/v1/firewall/rules", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	// 2. POST /api/v1/firewall/block with operator role -> 403 Forbidden
	blockPayload := `{"ip":"198.51.100.42","reason":"SQLi automated scan","ttl":3600}`
	req = httptest.NewRequest("POST", "/api/v1/firewall/block", strings.NewReader(blockPayload))
	req.Header.Set("Authorization", "Bearer "+operatorToken)
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403 for operator on firewall block, got %d", rec.Code)
	}

	// 3. POST /api/v1/firewall/block with admin role -> 201 Created
	req = httptest.NewRequest("POST", "/api/v1/firewall/block", strings.NewReader(blockPayload))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created for admin on firewall block, got %d (%s)", rec.Code, rec.Body.String())
	}

	// 4. GET /api/v1/firewall/rules contains the blocked IP
	req = httptest.NewRequest("GET", "/api/v1/firewall/rules", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if !strings.Contains(rec.Body.String(), "198.51.100.42") {
		t.Errorf("expected rules to contain blocked IP, got %s", rec.Body.String())
	}

	// 5. DELETE /api/v1/firewall/unblock/{ip}
	req = httptest.NewRequest("DELETE", "/api/v1/firewall/unblock/198.51.100.42", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 on unblock, got %d", rec.Code)
	}

	// 6. GET /api/v1/firewall/rules should no longer contain the IP
	req = httptest.NewRequest("GET", "/api/v1/firewall/rules", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if strings.Contains(rec.Body.String(), "198.51.100.42") {
		t.Errorf("expected IP to be removed after unblock, got %s", rec.Body.String())
	}
}
