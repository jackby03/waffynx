package ingestor

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackby03/waffynx/internal/telemetry"
)

type fakeWriter struct {
	mu      sync.Mutex
	batches [][]telemetry.SecurityEvent
	fail    bool
}

func (f *fakeWriter) InitSchema(context.Context) error { return nil }
func (f *fakeWriter) Ping(context.Context) error       { return nil }
func (f *fakeWriter) BulkInsert(_ context.Context, evs []telemetry.SecurityEvent) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail {
		return errors.New("clickhouse unavailable")
	}
	cp := append([]telemetry.SecurityEvent(nil), evs...)
	f.batches = append(f.batches, cp)
	return nil
}

func TestWorker_BatchEnrichRedactAndRetry(t *testing.T) {
	ctx := context.Background()
	fw := &fakeWriter{}
	geo, err := NewGeoResolver("")
	if err != nil {
		t.Fatalf("NewGeoResolver: %v", err)
	}
	defer geo.Close()

	w := NewWorker(Config{BatchSize: 2, FlushInterval: time.Second}, fw, geo)

	ev1, _ := json.Marshal(telemetry.SecurityEvent{
		EventID:  "1",
		Action:   telemetry.ActionBlock,
		RemoteIP: "10.0.0.5",
		Path:     "/login?password=leaked",
		Headers:  map[string]string{"Authorization": "Bearer secret"},
	})
	ev2, _ := json.Marshal(telemetry.SecurityEvent{
		EventID:  "2",
		Action:   telemetry.ActionBlock,
		RemoteIP: "8.8.8.8",
		Path:     "/?q=UNION+SELECT",
	})

	// First event stays buffered until BatchSize=2.
	if err := w.EnrichAndAppend(ctx, ev1); err != nil {
		t.Fatalf("EnrichAndAppend 1: %v", err)
	}
	if w.WrittenCount() != 0 {
		t.Fatalf("expected 0 written before batch threshold, got %d", w.WrittenCount())
	}

	// Second event triggers automatic batch flush.
	if err := w.EnrichAndAppend(ctx, ev2); err != nil {
		t.Fatalf("EnrichAndAppend 2: %v", err)
	}
	if w.WrittenCount() != 2 || len(fw.batches) != 1 || len(fw.batches[0]) != 2 {
		t.Fatalf("expected 1 batch of 2 events, got written=%d batches=%d", w.WrittenCount(), len(fw.batches))
	}

	got1 := fw.batches[0][0]
	if got1.CountryCode != "LOCAL" {
		t.Errorf("expected private IP enriched as LOCAL, got %q", got1.CountryCode)
	}
	if strings.Contains(got1.Path, "leaked") || got1.Headers["Authorization"] != "[REDACTED]" {
		t.Errorf("ingestor failed to redact sensitive data: %+v", got1)
	}
	got2 := fw.batches[0][1]
	if got2.CountryCode != "XX" {
		t.Errorf("expected public IP without MMDB enriched as XX, got %q", got2.CountryCode)
	}

	// Verify transient ClickHouse failure re-queues batch for next flush.
	fw.fail = true
	_ = w.EnrichAndAppend(ctx, ev1)
	if err := w.Flush(ctx); err == nil {
		t.Fatal("expected error when writer fails")
	}
	fw.fail = false
	if err := w.Flush(ctx); err != nil {
		t.Fatalf("retry flush failed: %v", err)
	}
	if w.WrittenCount() != 3 {
		t.Fatalf("expected re-queued event persisted on retry, got written=%d", w.WrittenCount())
	}
}
