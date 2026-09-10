package engine

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/jackby03/waffynx/internal/events"
	"github.com/jackby03/waffynx/internal/learning"
	"github.com/jackby03/waffynx/internal/policy"
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
