package engine

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/jackby03/waffynx/internal/events"
	"github.com/jackby03/waffynx/internal/learning"
	"github.com/jackby03/waffynx/internal/plugin"
	"github.com/jackby03/waffynx/internal/policy"
	wrules "github.com/jackby03/waffynx/internal/rules"
)

func TestSidecarSocketPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX socket permissions are only enforced on Linux; Windows does not support 0600 file modes")
	}
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "sidecar_test.sock")

	s := NewSidecar(socketPath, nil, nil, nil, nil, nil, nil, nil)
	if err := s.Start(); err != nil {
		t.Fatalf("failed to start sidecar: %v", err)
	}
	defer s.Stop()

	info, err := os.Stat(socketPath)
	if err != nil {
		t.Fatalf("failed to stat socket: %v", err)
	}

	perm := info.Mode().Perm()
	if perm != 0600 {
		t.Errorf("expected socket permissions 0600, got %o", perm)
	}
}

func TestSidecarPublishesBlockedEventWithoutChangingPipeline(t *testing.T) {
	received := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer service-token" {
			t.Errorf("missing event bridge authorization")
		}
		received <- struct{}{}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	s := NewSidecar("", nil, nil, nil, learning.NewEngine(10), nil, nil, events.NewBroker())
	s.SetEventPublisher(events.NewPublisher(server.URL, "service-token", time.Second))
	s.recordLearning(&policy.Request{Method: "GET", Path: "/attack", RemoteIP: "127.0.0.1"}, "block", "sql-001", "pattern", time.Now())

	select {
	case <-received:
	case <-time.After(time.Second):
		t.Fatal("blocked event was not published")
	}
}

// TestSidecarIPBanRuleDeniesRequest proves the WAF-layer ban actually blocks.
//
// This is the enforcement path the API relies on in container mode: POST
// /rules/add with a rule scoped to an IP, and the next /evaluate from that IP
// must be denied with 403. Without it, "block this IP" has no implementation
// that works without host privileges.
func TestSidecarIPBanRuleDeniesRequest(t *testing.T) {
	s := NewSidecar("", policy.NewRuleEngine(), plugin.NewChain(), nil, nil, nil, wrules.NewEngine(), nil)

	mux := http.NewServeMux()
	mux.HandleFunc("/evaluate", s.handleEvaluate)
	mux.HandleFunc("/rules/add", s.handleRulesAdd)

	// 1. Ban an IP through the same endpoint the API uses.
	body, err := json.Marshal(wrules.CustomRule{
		ID:      "ip-ban-203.0.113.7",
		Name:    "IP ban",
		Enabled: true,
		Action:  wrules.ActionBlock,
		IPs:     []string{"203.0.113.7"},
	})
	if err != nil {
		t.Fatalf("failed to marshal rule: %v", err)
	}

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/rules/add", bytes.NewReader(body)))
	if rec.Code != http.StatusCreated {
		t.Fatalf("expected rule to be accepted, got %d: %s", rec.Code, rec.Body.String())
	}

	// 2. A request from the banned IP must be denied. The nginx module forwards
	// the real client address in X-WN-IP over the 0600 Unix socket.
	evaluate := func(ip string) int {
		req := httptest.NewRequest(http.MethodGet, "/evaluate", nil)
		req.Header.Set("X-WN-M", http.MethodGet)
		req.Header.Set("X-WN-H", "example.com")
		req.Header.Set("X-WN-U", "/anything")
		req.Header.Set("X-WN-IP", ip)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec.Code
	}

	if got := evaluate("203.0.113.7"); got != http.StatusForbidden {
		t.Errorf("expected 403 for banned IP, got %d", got)
	}

	// 3. Any other IP must be unaffected, so the ban is scoped, not global.
	if got := evaluate("203.0.113.8"); got == http.StatusForbidden {
		t.Errorf("expected a non-banned IP not to be blocked, got %d", got)
	}
}
