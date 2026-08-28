package events

import (
	"encoding/json"
	"sync"
	"testing"
	"time"
)

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
	case <-time.After(100 * time.Millisecond):
		t.Fatal("timed out waiting for channel to close")
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
	ch := b.Subscribe()
	capacity := cap(ch)

	// Fill channel buffer
	for i := 0; i < capacity; i++ {
		b.Publish(WafEvent{Type: TypeAllowed, Reason: "fill"})
	}

	if got, want := len(ch), capacity; got != want {
		t.Fatalf("expected subscriber channel buffer to be full (%d), got %d", want, got)
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

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for concurrent publish/subscribe workload to complete")
	}
