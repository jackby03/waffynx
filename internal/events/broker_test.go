package events

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestWafEventValidate(t *testing.T) {
	tests := []struct {
		name    string
		event   WafEvent
		wantErr bool
	}{
		{name: "valid", event: WafEvent{Type: TypeBlocked, Path: "/login", RuleID: "sql-001"}},
		{name: "missing path", event: WafEvent{Type: TypeBlocked, RuleID: "sql-001"}, wantErr: true},
		{name: "wrong type", event: WafEvent{Type: TypeAllowed, Path: "/", RuleID: "rule"}, wantErr: true},
		{name: "oversized reason", event: WafEvent{Type: TypeBlocked, Path: "/", RuleID: "rule", Reason: string(make([]byte, 4097))}, wantErr: true},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			err := testCase.event.Validate()
			if (err != nil) != testCase.wantErr {
				t.Fatalf("Validate() error = %v, wantErr %v", err, testCase.wantErr)
			}
		})
	}
}

func TestPublisherSendsAuthenticatedEvent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer service-token" {
			t.Errorf("authorization = %q", got)
		}
		if got := r.Header.Get("Content-Type"); got != "application/json" {
			t.Errorf("content type = %q", got)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil || len(body) == 0 {
			t.Errorf("event body = %q, err = %v", body, err)
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	publisher := NewPublisher(server.URL, "service-token", time.Second)
	err := publisher.Publish(WafEvent{Type: TypeBlocked, Path: "/attack", RuleID: "sql-001"})
	if err != nil {
		t.Fatalf("Publish() error = %v", err)
	}
}

func TestPublisherReportsUnavailableAPI(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	url := server.URL
	server.Close()

	err := NewPublisher(url, "service-token", 100*time.Millisecond).Publish(WafEvent{
		Type: TypeBlocked, Path: "/attack", RuleID: "sql-001",
	})
	if err == nil {
		t.Fatal("Publish() error = nil, want unavailable API error")
	}
}

func TestNewBroker(t *testing.T) {
	b := NewBroker()
	if b == nil {
		t.Fatal("expected non-nil Broker instance")
	}
	if b.subscribers == nil {
		t.Fatal("expected subscribers map to be initialized")
	}
}

func TestBroker_SubscribeAndPublish(t *testing.T) {
	b := NewBroker()
	ch := b.Subscribe()

	if len(b.subscribers) != 1 {
		t.Fatalf("expected 1 subscriber, got %d", len(b.subscribers))
	}

	event := WafEvent{
		Type:     TypeBlocked,
		Method:   "GET",
		Path:     "/api/test",
		RemoteIP: "127.0.0.1",
		RuleID:   "rule-100",
		Reason:   "test block",
	}

	start := time.Now()
	b.Publish(event)

	select {
	case data, ok := <-ch:
		if !ok {
			t.Fatal("expected open channel")
		}
		var received WafEvent
		if err := json.Unmarshal(data, &received); err != nil {
			t.Fatalf("failed to unmarshal event: %v", err)
		}
		if received.Type != event.Type {
			t.Errorf("expected type %s, got %s", event.Type, received.Type)
		}
		if received.Method != event.Method {
			t.Errorf("expected method %s, got %s", event.Method, received.Method)
		}
		if received.Timestamp.Before(start) {
			t.Errorf("expected timestamp to be set to current time, got %v", received.Timestamp)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("timed out waiting for event")
	}
}

func TestBroker_Unsubscribe(t *testing.T) {
	b := NewBroker()
	ch := b.Subscribe()

	b.Unsubscribe(ch)

	b.mu.RLock()
	_, exists := b.subscribers[ch]
	b.mu.RUnlock()

	if exists {
		t.Error("expected channel to be removed from subscribers map")
	}

	select {
	case _, ok := <-ch:
		if ok {
			t.Error("expected channel to be closed")
		}
	default:
		// channel might not report closed immediately without read, but <-ch returned ok=false
	}

	// Publish after unsubscribe should not deliver to unsubscribed channel
	b.Publish(WafEvent{Type: TypeAllowed})

	select {
	case _, ok := <-ch:
		if ok {
			t.Error("expected channel to remain closed without receiving new events")
		}
	default:
	}
}

func TestBroker_PublishMultipleSubscribers(t *testing.T) {
	b := NewBroker()
	ch1 := b.Subscribe()
	ch2 := b.Subscribe()

	event := WafEvent{Type: TypeStats, Method: "POST"}
	b.Publish(event)

	for i, ch := range []subscriber{ch1, ch2} {
		select {
		case data := <-ch:
			var rec WafEvent
			if err := json.Unmarshal(data, &rec); err != nil {
				t.Fatalf("sub %d unmarshal err: %v", i, err)
			}
			if rec.Type != event.Type {
				t.Errorf("sub %d expected type %s, got %s", i, event.Type, rec.Type)
			}
		case <-time.After(1 * time.Second):
			t.Fatalf("sub %d timed out", i)
		}
	}
}

func TestBroker_PublishNonBlockingFullBuffer(t *testing.T) {
	b := NewBroker()
	_ = b.Subscribe() // channel capacity is 64

	// Fill channel buffer
	for i := 0; i < 64; i++ {
		b.Publish(WafEvent{Type: TypeAllowed, Reason: "fill"})
	}

	// 65th publish should not block or panic even if channel buffer is full
	done := make(chan struct{})
	go func() {
		b.Publish(WafEvent{Type: TypeBlocked, Reason: "overflow"})
		close(done)
	}()

	select {
	case <-done:
		// Publish completed without blocking
	case <-time.After(1 * time.Second):
		t.Fatal("Publish blocked when subscriber buffer was full")
	}
}

func TestBroker_ConcurrentPublishSubscribe(t *testing.T) {
	b := NewBroker()
	var wg sync.WaitGroup

	numGoroutines := 20
	numEventsPerGoroutine := 50

	// Concurrent subscribers & unsubscribers
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ch := b.Subscribe()
			time.Sleep(1 * time.Millisecond)
			// Read anything delivered while active
			select {
			case <-ch:
			default:
			}
			b.Unsubscribe(ch)
		}()
	}

	// Concurrent publishers
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < numEventsPerGoroutine; j++ {
				b.Publish(WafEvent{
					Type:   TypeSuggestion,
					Method: "GET",
					Path:   "/test",
				})
			}
		}()
	}

	wg.Wait()
}

// TestBroker_HistoryKeepsBoundedWindow guards GET /api/v1/events/history. The
// control plane must be able to show recent events while the ring stays fixed:
// history driven by traffic must not become a leak.
func TestBroker_HistoryKeepsBoundedWindow(t *testing.T) {
	b := NewBroker()

	if got := b.History(10); len(got) != 0 {
		t.Fatalf("empty broker history = %d events, want 0", len(got))
	}

	for i := 0; i < maxHistory+200; i++ {
		b.Publish(WafEvent{
			Type:   TypeBlocked,
			Path:   fmt.Sprintf("/attack/%d", i),
			RuleID: "rule-1",
		})
	}

	recent := b.History(10)
	if len(recent) != 10 {
		t.Fatalf("History(10) = %d events, want 10", len(recent))
	}
	for i, evt := range recent {
		want := fmt.Sprintf("/attack/%d", maxHistory+199-i)
		if evt.Path != want {
			t.Fatalf("History(10)[%d].Path = %q, want %q (newest first)", i, evt.Path, want)
		}
		if evt.Timestamp.IsZero() {
			t.Fatalf("History(10)[%d] has no timestamp", i)
		}
	}

	all := b.History(maxHistory + 1)
	if len(all) != maxHistory {
		t.Fatalf("History(maxHistory+1) = %d events, want clamp to %d", len(all), maxHistory)
	}
	if all[0].Path != fmt.Sprintf("/attack/%d", maxHistory+199) {
		t.Fatalf("clamped history newest = %q, want the last published event", all[0].Path)
	}

	b.mu.RLock()
	count, capacity := b.count, len(b.history)
	b.mu.RUnlock()
	if count != maxHistory || capacity != maxHistory {
		t.Fatalf("history holds %d/%d events, want %d (bounded)", count, capacity, maxHistory)
	}

	if got := b.History(0); len(got) != 1 {
		t.Fatalf("History(0) = %d events, want clamp to 1", len(got))
	}
}

// History runs on the request path while the sidecar publishes blocks, so the
// two must be safe concurrently (the race detector is the real assertion here).
func TestBroker_HistoryConcurrentWithPublish(t *testing.T) {
	b := NewBroker()
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			b.Publish(WafEvent{Type: TypeBlocked, Path: "/attack", RuleID: "rule-1"})
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			if got := b.History(50); len(got) > 50 {
				t.Errorf("History(50) = %d events", len(got))
				return
			}
		}
	}()

	wg.Wait()
}
