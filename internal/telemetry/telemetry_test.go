package telemetry

import (
	"strings"
	"testing"
	"time"
)

// TestRedactEvent_NoCredentialLeakage is a permanent security regression test
// enforcing Constitution §2.2 (PII & credential redaction before persistence).
func TestRedactEvent_NoCredentialLeakage(t *testing.T) {
	sampleJWT := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
	ev := SecurityEvent{
		EventID:   "evt-1",
		Timestamp: time.Now().UTC(),
		Action:    ActionBlock,
		Path:      "/api/login?user=alice&password=SuperSecret99&token=" + sampleJWT,
		Headers: map[string]string{
			":path":          "/api/login?user=alice&password=SuperSecret99&token=" + sampleJWT,
			"Referer":        "https://app.example.test/reset?password=SuperSecret99",
			"Authorization":  "Bearer " + sampleJWT,
			"Cookie":         "session=secret-cookie-value",
			"X-Api-Key":      "sk-live-123456",
			"X-Custom-Token": "tok-abc",
			"User-Agent":     "curl/8.0",
		},
		BodySnippet: `{"username":"alice","password":"MyPassword!23","card_number":"4532-1234-5678-9010"}`,
		Reason:      "blocked bearer " + sampleJWT,
	}

	got := RedactEvent(ev)

	for _, forbidden := range []string{
		"SuperSecret99",
		sampleJWT,
		"secret-cookie-value",
		"sk-live-123456",
		"tok-abc",
		"MyPassword!23",
		"4532-1234-5678-9010",
	} {
		if strings.Contains(got.Path, forbidden) ||
			strings.Contains(got.BodySnippet, forbidden) ||
			strings.Contains(got.Reason, forbidden) {
			t.Errorf("redacted event leaked sensitive value %q: %+v", forbidden, got)
		}
		for hk, hv := range got.Headers {
			if strings.Contains(hv, forbidden) {
				t.Errorf("header %s leaked sensitive value %q: %q", hk, forbidden, hv)
			}
		}
	}

	if got.Headers["User-Agent"] != "curl/8.0" {
		t.Errorf("non-sensitive header altered: %q", got.Headers["User-Agent"])
	}
	if got.Headers["Authorization"] != redactedMarker {
		t.Errorf("expected Authorization redacted, got %q", got.Headers["Authorization"])
	}
	if !strings.Contains(got.Path, "user=alice") {
		t.Errorf("non-sensitive query param stripped unexpectedly: %q", got.Path)
	}
}

func TestMemoryEmitter_NonBlockingDrop(t *testing.T) {
	em := NewMemoryEmitter(2)
	for i := 0; i < 5; i++ {
		em.Emit(SecurityEvent{EventID: "e", Action: ActionBlock})
	}
	if em.Dropped() != 3 {
		t.Fatalf("expected 3 dropped events when buffer full, got %d", em.Dropped())
	}
	evs := em.Events()
	if len(evs) != 2 {
		t.Fatalf("expected 2 buffered events, got %d", len(evs))
	}
	if err := em.Close(); err != nil {
		t.Fatalf("close failed: %v", err)
	}
}

func TestNATSEmitter_DisabledReturnsNil(t *testing.T) {
	em, err := NewNATSEmitter(NATSConfig{Enabled: false})
	if err != nil || em != nil {
		t.Fatalf("expected nil emitter when disabled, got em=%v err=%v", em, err)
	}
	// Nil receiver must be safe on hot path.
	em.Emit(SecurityEvent{Action: ActionAllow})
	if em.Dropped() != 0 {
		t.Fatal("nil emitter dropped count must be 0")
	}
	if err := em.Close(); err != nil {
		t.Fatalf("nil emitter close failed: %v", err)
	}
}
