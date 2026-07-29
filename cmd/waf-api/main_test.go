package main

import (
	"bytes"
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
					JWTSecret: "test-secret-key-1234567890",
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
	mux.HandleFunc("GET /health", srv.handleHealth)
	mux.HandleFunc("POST /api/v1/auth/login", srv.handleLogin)

	withAuth := srv.authMiddleware(mux)
	withCORS := srv.corsMiddleware

	mux.HandleFunc("GET /api/v1/status", withCORS(withAuth(srv.handleStatus)))
	mux.HandleFunc("GET /api/v1/config", withCORS(withAuth(srv.handleGetConfig)))
	mux.HandleFunc("PUT /api/v1/config", withCORS(withAuth(srv.handleUpdateConfig)))
	mux.HandleFunc("GET /api/v1/metrics", withCORS(withAuth(srv.handleMetrics)))
	mux.HandleFunc("GET /api/v1/plugins", withCORS(withAuth(srv.handleListPlugins)))
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
				JWTSecret: "test-secret-key-1234567890",
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

