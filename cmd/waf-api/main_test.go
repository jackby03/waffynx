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
	"github.com/jackby03/waffynx/internal/marketplace"
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

func TestHandleMarketplaceList(t *testing.T) {
	srv := &apiServer{store: marketplace.NewInMemoryStore()}
	srv.seedMarketplace()

	req := httptest.NewRequest("GET", "/api/v1/marketplace", nil)
	rec := httptest.NewRecorder()
	srv.handleMarketplaceList(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var pkgs []map[string]interface{}
	json.NewDecoder(rec.Body).Decode(&pkgs)
	if len(pkgs) < 3 {
		t.Errorf("expected at least 3 packages, got %d", len(pkgs))
	}
}

func TestHandleMarketplaceList_Empty(t *testing.T) {
	srv := &apiServer{store: marketplace.NewInMemoryStore()}

	req := httptest.NewRequest("GET", "/api/v1/marketplace", nil)
	rec := httptest.NewRecorder()
	srv.handleMarketplaceList(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

func TestHandleMarketplaceGet(t *testing.T) {
	srv := &apiServer{store: marketplace.NewInMemoryStore()}
	srv.seedMarketplace()

	req := httptest.NewRequest("GET", "/api/v1/marketplace/rate-limit?version=1.0.0", nil)
	req.SetPathValue("name", "rate-limit")
	rec := httptest.NewRecorder()
	srv.handleMarketplaceGet(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var pkg map[string]interface{}
	json.NewDecoder(rec.Body).Decode(&pkg)
	if pkg["name"] != "rate-limit" {
		t.Errorf("expected rate-limit, got %v", pkg["name"])
	}
}

func TestHandleMarketplaceGet_NotFound(t *testing.T) {
	srv := &apiServer{store: marketplace.NewInMemoryStore()}

	req := httptest.NewRequest("GET", "/api/v1/marketplace/nonexistent", nil)
	req.SetPathValue("name", "nonexistent")
	rec := httptest.NewRecorder()
	srv.handleMarketplaceGet(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rec.Code)
	}
}

func TestHandleMarketplaceInstall(t *testing.T) {
	srv := &apiServer{store: marketplace.NewInMemoryStore()}
	srv.seedMarketplace()

	req := httptest.NewRequest("POST", "/api/v1/marketplace/install/rate-limit?version=1.0.0", nil)
	req.SetPathValue("name", "rate-limit")
	rec := httptest.NewRecorder()
	srv.handleMarketplaceInstall(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

func TestHandleMarketplaceInstall_NotFound(t *testing.T) {
	srv := &apiServer{store: marketplace.NewInMemoryStore()}

	req := httptest.NewRequest("POST", "/api/v1/marketplace/install/nonexistent", nil)
	req.SetPathValue("name", "nonexistent")
	rec := httptest.NewRecorder()
	srv.handleMarketplaceInstall(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rec.Code)
	}
}

func TestHandleMarketplaceUninstall(t *testing.T) {
	srv := &apiServer{store: marketplace.NewInMemoryStore()}
	srv.seedMarketplace()
	srv.store.Install("rate-limit", "1.0.0")

	req := httptest.NewRequest("DELETE", "/api/v1/marketplace/uninstall/rate-limit", nil)
	req.SetPathValue("name", "rate-limit")
	rec := httptest.NewRecorder()
	srv.handleMarketplaceUninstall(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

func TestHandleMarketplaceUninstall_NotFound(t *testing.T) {
	srv := &apiServer{store: marketplace.NewInMemoryStore()}

	req := httptest.NewRequest("DELETE", "/api/v1/marketplace/uninstall/nonexistent", nil)
	req.SetPathValue("name", "nonexistent")
	rec := httptest.NewRecorder()
	srv.handleMarketplaceUninstall(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rec.Code)
	}
}

func TestHandleMarketplaceCategories(t *testing.T) {
	srv := &apiServer{store: marketplace.NewInMemoryStore()}
	srv.seedMarketplace()

	req := httptest.NewRequest("GET", "/api/v1/marketplace/categories", nil)
	rec := httptest.NewRecorder()
	srv.handleMarketplaceCategories(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var body map[string]interface{}
	json.NewDecoder(rec.Body).Decode(&body)
	cats, ok := body["categories"].([]interface{})
	if !ok || len(cats) == 0 {
		t.Error("expected non-empty categories")
	}
}
