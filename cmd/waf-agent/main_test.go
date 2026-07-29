package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackby03/waffynx/internal/config"
	"github.com/jackby03/waffynx/internal/firewall"
)

func mockFirewallCmd() {
	firewall.SetRunCmd(func(name string, args ...string) (string, error) {
		key := name + " " + strings.Join(args, " ")
		if strings.Contains(key, "list") || strings.Contains(key, "status") {
			return `Status: active
[ 1] 80/tcp ALLOW IN Anywhere
`, nil
		}
		return "", nil
	})
}

func newTestAgentServer(t *testing.T, apiKey string) (*agentServer, http.Handler) {
	t.Helper()
	mockFirewallCmd()

	cfg := &config.AgentConfig{
		Listen: ":9095",
		APIKey: apiKey,
		Firewall: config.FirewallConfig{
			Enabled:   false,
			Backend:   "ufw",
			BlockList: []string{},
		},
		EventBroker: config.EventBrokerConfig{
			Enabled:        false,
			BlockThreshold: 3,
			WindowSeconds:  60,
		},
	}

	mgr, err := firewall.NewManager(cfg.Firewall)
	if err != nil {
		t.Fatalf("failed to create firewall manager: %v", err)
	}

	tracker := newEventTracker(3, 60)
	srv := &agentServer{
		cfg:     cfg,
		mgr:     mgr,
		tracker: tracker,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", srv.handleHealth)
	mux.HandleFunc("GET /api/v1/firewall/rules", srv.authMiddleware(srv.handleListRules))
	mux.HandleFunc("POST /api/v1/firewall/block", srv.authMiddleware(srv.handleBlockIP))
	mux.HandleFunc("DELETE /api/v1/firewall/block/{ip}", srv.authMiddleware(srv.handleUnblockIP))

	return srv, mux
}

func TestEventTracker(t *testing.T) {
	tracker := newEventTracker(3, 1) // 3 threshold, 1 sec window

	if tracker.record("1.2.3.4") {
		t.Error("event 1 should not trigger auto-block")
	}
	if tracker.record("1.2.3.4") {
		t.Error("event 2 should not trigger auto-block")
	}
	if !tracker.record("1.2.3.4") {
		t.Error("event 3 should trigger auto-block threshold")
	}

	// Sleep for window to expire and test cleanup
	time.Sleep(1100 * time.Millisecond)
	tracker.cleanup()

	tracker.mu.Lock()
	_, exists := tracker.counts["1.2.3.4"]
	tracker.mu.Unlock()

	if exists {
		t.Error("expected expired events for IP to be cleaned up")
	}
}

func TestAgent_Health(t *testing.T) {
	_, handler := newTestAgentServer(t, "")

	req := httptest.NewRequest("GET", "/health", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}

	var resp map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse JSON: %v", err)
	}
	if resp["status"] != "ok" {
		t.Errorf("expected status 'ok', got %q", resp["status"])
	}
}

func TestAgent_AuthMiddleware(t *testing.T) {
	apiKey := "secret-agent-key"
	_, handler := newTestAgentServer(t, apiKey)

	// 1. Missing API Key
	req := httptest.NewRequest("GET", "/api/v1/firewall/rules", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for missing API key, got %d", rec.Code)
	}

	// 2. Valid X-API-Key header
	req = httptest.NewRequest("GET", "/api/v1/firewall/rules", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 with X-API-Key, got %d", rec.Code)
	}

	// 3. Valid Authorization Bearer header
	req = httptest.NewRequest("GET", "/api/v1/firewall/rules", nil)
	req.Header.Set("Authorization", "Bearer "+apiKey)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 with Bearer token, got %d", rec.Code)
	}
}

func TestAgent_BlockAndUnblockIP(t *testing.T) {
	apiKey := "test-key"
	_, handler := newTestAgentServer(t, apiKey)

	// 1. Missing IP -> 400 Bad Request
	badBody := []byte(`{"port":80}`)
	req := httptest.NewRequest("POST", "/api/v1/firewall/block", bytes.NewReader(badBody))
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing IP, got %d", rec.Code)
	}

	// 2. Valid Block IP -> 200 OK
	goodBody := []byte(`{"ip":"10.0.0.55"}`)
	req = httptest.NewRequest("POST", "/api/v1/firewall/block", bytes.NewReader(goodBody))
	req.Header.Set("X-API-Key", apiKey)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 for BlockIP, got %d", rec.Code)
	}

	var blockResp map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &blockResp)
	if blockResp["status"] != "blocked" || blockResp["ip"] != "10.0.0.55" {
		t.Errorf("unexpected block response: %v", blockResp)
	}

	// 3. Valid Unblock IP -> 200 OK
	req = httptest.NewRequest("DELETE", "/api/v1/firewall/block/10.0.0.55", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 for UnblockIP, got %d", rec.Code)
	}

	var unblockResp map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &unblockResp)
	if unblockResp["status"] != "unblocked" || unblockResp["ip"] != "10.0.0.55" {
		t.Errorf("unexpected unblock response: %v", unblockResp)
	}
}
