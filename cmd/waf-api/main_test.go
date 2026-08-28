package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
	}

	srv.seedMarketplace()

	mux := http.NewServeMux()

	withCORS := srv.corsMiddleware

	mux.HandleFunc("GET /health", srv.handleHealth)

	mux.HandleFunc("POST /api/v1/auth/login", withCORS(srv.handleLogin))
	mux.HandleFunc("OPTIONS /api/v1/auth/login", withCORS(srv.handleLogin))

	withAuth := srv.authMiddleware(mux)

	mux.HandleFunc("GET /api/v1/status", withCORS(withAuth(srv.handleStatus)))
	mux.HandleFunc("GET /api/v1/config", withCORS(withAuth(srv.handleGetConfig)))
	mux.HandleFunc("PUT /api/v1/config", withCORS(withAuth(srv.handleUpdateConfig)))
	mux.HandleFunc("GET /api/v1/metrics", withCORS(withAuth(srv.handleMetrics)))
	mux.HandleFunc("GET /api/v1/plugins", withCORS(withAuth(srv.handleListPlugins)))
	mux.HandleFunc("GET /api/v1/events", withCORS(withAuth(srv.handleSSE)))
	mux.HandleFunc("GET /api/v1/marketplace", withCORS(withAuth(srv.handleMarketplaceList)))
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
