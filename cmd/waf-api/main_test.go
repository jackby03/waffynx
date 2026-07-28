package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackby03/waffynx/internal/events"
)

func TestHandleSSE_Heartbeat(t *testing.T) {
	srv := &apiServer{broker: events.NewBroker()}
	req := httptest.NewRequest("GET", "/api/v1/events", nil)
	rec := httptest.NewRecorder()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	req = req.WithContext(ctx)

	srv.handleSSE(rec, req)

	body := rec.Body.String()
	if !strings.Contains(body, ": connected") {
		t.Error("expected connected message")
	}
	if !strings.Contains(body, "stats") {
		t.Error("expected stats heartbeat")
	}
}

func TestHandleSSE_ForwardsBrokerEvents(t *testing.T) {
	srv := &apiServer{broker: events.NewBroker()}
	req := httptest.NewRequest("GET", "/api/v1/events", nil)
	rec := httptest.NewRecorder()

	go func() {
		time.Sleep(20 * time.Millisecond)
		srv.broker.Publish(events.WafEvent{
			Type:     events.TypeBlocked,
			Method:   "POST",
			Path:     "/api/login",
			RemoteIP: "10.0.0.1",
		})
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	req = req.WithContext(ctx)

	srv.handleSSE(rec, req)

	body := rec.Body.String()
	if !strings.Contains(body, "blocked") {
		t.Error("expected blocked event from broker")
	}
	if !strings.Contains(body, "10.0.0.1") {
		t.Error("expected remote IP in event")
	}
}

func TestHandleSSE_NoBroker(t *testing.T) {
	srv := &apiServer{}
	req := httptest.NewRequest("GET", "/api/v1/events", nil)
	rec := httptest.NewRecorder()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	req = req.WithContext(ctx)

	srv.handleSSE(rec, req)

	body := rec.Body.String()
	if !strings.Contains(body, "stats") {
		t.Error("expected heartbeat fallback when no broker")
	}
}

func TestHandleIngestEvent_Success(t *testing.T) {
	srv := &apiServer{broker: events.NewBroker()}

	ch := srv.broker.Subscribe()
	defer srv.broker.Unsubscribe(ch)

	body := map[string]string{
		"type":      "blocked",
		"method":    "POST",
		"path":      "/login",
		"remote_ip": "192.168.0.1",
	}
	data, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/api/v1/events", bytes.NewReader(data))
	rec := httptest.NewRecorder()

	srv.handleIngestEvent(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Errorf("expected 202, got %d", rec.Code)
	}

	select {
	case evt := <-ch:
		if !strings.Contains(string(evt), "blocked") {
			t.Error("expected blocked event in broker")
		}
	case <-time.After(time.Second):
		t.Error("event not published to broker")
	}
}

func TestHandleIngestEvent_NoType(t *testing.T) {
	srv := &apiServer{broker: events.NewBroker()}

	body := map[string]string{"method": "GET"}
	data, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/api/v1/events", bytes.NewReader(data))
	rec := httptest.NewRecorder()

	srv.handleIngestEvent(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

func TestHandleIngestEvent_NoBroker(t *testing.T) {
	srv := &apiServer{}

	body := map[string]string{"type": "blocked"}
	data, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/api/v1/events", bytes.NewReader(data))
	rec := httptest.NewRecorder()

	srv.handleIngestEvent(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", rec.Code)
	}
}
