package api

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackby03/waffynx/internal/config"
	"github.com/jackby03/waffynx/internal/events"
)

// TestEventBridgeFeedsBroker is the regression guard for a history endpoint that
// always answered [] while the WAF was blocking traffic.
//
// The sidecar publishes into its own broker (engine process); the API has another.
// Without the bridge, /api/v1/events/history is permanently empty even though the
// data plane is producing events.
func TestEventBridgeFeedsBroker(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "sidecar.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Skipf("unix sockets unavailable on this host: %v", err)
	}
	defer func() { _ = ln.Close() }()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()

		if _, err := fmt.Fprint(conn, "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n"); err != nil {
			return
		}
		// One real frame, exactly as the sidecar writes it.
		if _, err := fmt.Fprint(conn,
			`data: {"type":"blocked","method":"GET","path":"/?q=UNION+SELECT+1","remote_ip":"203.0.113.9","rule_id":"WAF-SQLI-001","reason":"SQL UNION SELECT (matched in query)","timestamp":"2026-01-01T00:00:00Z"}`+"\n\n"); err != nil {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}()

	srv := &Server{
		cfg:    &config.Config{Sidecar: config.SidecarConfig{SocketPath: sock}},
		broker: events.NewBroker(),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	go srv.consumeSidecarEvents(ctx, sock)

	deadline := time.Now().Add(1500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if history := srv.broker.History(1); len(history) == 1 {
			got := history[0]
			if got.RuleID != "WAF-SQLI-001" {
				t.Fatalf("rule id = %q, want WAF-SQLI-001", got.RuleID)
			}
			if got.RemoteIP != "203.0.113.9" {
				t.Fatalf("remote ip = %q", got.RemoteIP)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}

	t.Fatal("the sidecar event never reached the API broker")
}
