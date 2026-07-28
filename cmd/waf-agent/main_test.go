package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackby03/waffynx/internal/config"
	"github.com/jackby03/waffynx/internal/firewall"
)

func init() {
	firewall.SetRunCmd(func(name string, args ...string) (string, error) {
		return "", nil
	})
}

func newTestServer(t *testing.T) *agentServer {
	t.Helper()
	mgr, err := firewall.NewManager(config.FirewallConfig{
		Enabled: true,
		Backend: "nftables",
	})
	if err != nil {
		t.Fatalf("creating firewall manager: %v", err)
	}
	if err := mgr.Start(); err != nil {
		t.Fatalf("starting firewall manager: %v", err)
	}
	return &agentServer{
		cfg: &config.AgentConfig{
			Listen: ":9099",
			APIKey: "test-key",
		},
		mgr: mgr,
	}
}

func TestHandleHealth(t *testing.T) {
	srv := newTestServer(t)
	req := httptest.NewRequest("GET", "/health", nil)
	rec := httptest.NewRecorder()
	srv.handleHealth(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	var body map[string]string
	json.NewDecoder(rec.Body).Decode(&body)
	if body["status"] != "ok" {
		t.Errorf("expected status ok, got %v", body["status"])
	}
}

func TestHandleListRules(t *testing.T) {
	srv := newTestServer(t)
	req := httptest.NewRequest("GET", "/api/v1/firewall/rules", nil)
	rec := httptest.NewRecorder()
	srv.handleListRules(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestHandleBlockIP_Unauthorized(t *testing.T) {
	srv := newTestServer(t)
	body := map[string]string{"ip": "10.0.0.1"}
	data, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/api/v1/firewall/block", bytes.NewReader(data))
	rec := httptest.NewRecorder()
	srv.authMiddleware(srv.handleBlockIP)(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}
}

func TestHandleBlockIP_MissingIP(t *testing.T) {
	srv := newTestServer(t)
	body := map[string]string{}
	data, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/api/v1/firewall/block", bytes.NewReader(data))
	req.Header.Set("X-API-Key", "test-key")
	rec := httptest.NewRecorder()
	srv.authMiddleware(srv.handleBlockIP)(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

func TestHandleBlockIP_Authorized(t *testing.T) {
	srv := newTestServer(t)
	body := map[string]string{"ip": "10.0.0.1"}
	data, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/api/v1/firewall/block", bytes.NewReader(data))
	req.Header.Set("X-API-Key", "test-key")
	rec := httptest.NewRecorder()
	srv.authMiddleware(srv.handleBlockIP)(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	var resp map[string]string
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp["status"] != "blocked" {
		t.Errorf("expected blocked, got %v", resp["status"])
	}
}

func TestHandleUnblockIP_Authorized(t *testing.T) {
	srv := newTestServer(t)
	srv.mgr.BlockIP("10.0.0.1")

	req := httptest.NewRequest("DELETE", "/api/v1/firewall/block/10.0.0.1", nil)
	req.SetPathValue("ip", "10.0.0.1")
	req.Header.Set("X-API-Key", "test-key")
	rec := httptest.NewRecorder()
	srv.authMiddleware(srv.handleUnblockIP)(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestHandleUnblockIP_MissingIP(t *testing.T) {
	srv := newTestServer(t)
	req := httptest.NewRequest("DELETE", "/api/v1/firewall/block/", nil)
	req.SetPathValue("ip", "")
	req.Header.Set("X-API-Key", "test-key")
	rec := httptest.NewRecorder()
	srv.authMiddleware(srv.handleUnblockIP)(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

func TestAuthMiddleware_BearerToken(t *testing.T) {
	srv := newTestServer(t)
	req := httptest.NewRequest("GET", "/api/v1/firewall/rules", nil)
	req.Header.Set("Authorization", "Bearer test-key")
	rec := httptest.NewRecorder()
	srv.authMiddleware(srv.handleListRules)(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 with bearer token, got %d", rec.Code)
	}
}

func TestAuthMiddleware_NoAuthRequired(t *testing.T) {
	srv := newTestServer(t)
	srv.cfg.APIKey = ""

	req := httptest.NewRequest("GET", "/api/v1/firewall/rules", nil)
	rec := httptest.NewRecorder()
	srv.authMiddleware(srv.handleListRules)(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 when no auth required, got %d", rec.Code)
	}
}

func TestAuthMiddleware_WrongKey(t *testing.T) {
	srv := newTestServer(t)
	req := httptest.NewRequest("GET", "/api/v1/firewall/rules", nil)
	req.Header.Set("X-API-Key", "wrong-key")
	rec := httptest.NewRecorder()
	srv.authMiddleware(srv.handleListRules)(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}
}
