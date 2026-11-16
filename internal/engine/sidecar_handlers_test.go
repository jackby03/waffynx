package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackby03/waffynx/internal/events"
	"github.com/jackby03/waffynx/internal/learning"
	"github.com/jackby03/waffynx/internal/policy"
	wrules "github.com/jackby03/waffynx/internal/rules"
)

// syncRecorder is a thread-safe http.ResponseWriter that also implements
// http.Flusher. httptest.ResponseRecorder is not safe to read while a handler is
// still writing, which the SSE test needs to do (and -race would catch).
type syncRecorder struct {
	mu      sync.Mutex
	buf     bytes.Buffer
	header  http.Header
	status  int
	flushes int
}

func (r *syncRecorder) Header() http.Header {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.header == nil {
		r.header = make(http.Header)
	}
	return r.header
}

func (r *syncRecorder) Write(b []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.buf.Write(b)
}

func (r *syncRecorder) WriteHeader(status int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.status == 0 {
		r.status = status
	}
}

func (r *syncRecorder) Flush() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.flushes++
}

func (r *syncRecorder) body() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.buf.String()
}

func (r *syncRecorder) code() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.status == 0 {
		return http.StatusOK
	}
	return r.status
}

// serve runs one request through a mux wired exactly like Sidecar.Start does.
func serveSidecar(s *Sidecar, method, target, body string) *syncRecorder {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/rules", s.handleRulesList)
	mux.HandleFunc("/rules/add", s.handleRulesAdd)
	mux.HandleFunc("/rules/delete", s.handleRulesDelete)
	mux.HandleFunc("/learning/suggestions", s.handleLearningSuggestions)
	mux.HandleFunc("/learning/stats", s.handleLearningStats)
	mux.HandleFunc("/learning/dataset", s.handleLearningDataset)

	rec := &syncRecorder{}
	mux.ServeHTTP(rec, httptest.NewRequest(method, target, strings.NewReader(body)))
	return rec
}

func TestSidecarHealth(t *testing.T) {
	s := NewSidecar("", nil, nil, nil, nil, nil, nil, nil)
	rec := serveSidecar(s, http.MethodGet, "/health", "")

	if rec.code() != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.code())
	}
	var payload map[string]string
	if err := json.Unmarshal([]byte(rec.body()), &payload); err != nil {
		t.Fatalf("health body is not JSON: %v (%q)", err, rec.body())
	}
	if payload["status"] != "ok" {
		t.Errorf("expected status ok, got %q", payload["status"])
	}
}

// TestSidecarRulesDegradedMode covers every handler's behaviour when the rules
// engine is absent: the sidecar must stay up and answer honestly, never panic.
func TestSidecarRulesDegradedMode(t *testing.T) {
	s := NewSidecar("", nil, nil, nil, nil, nil, nil, nil) // rules == nil

	if rec := serveSidecar(s, http.MethodGet, "/rules", ""); rec.code() != http.StatusOK || strings.TrimSpace(rec.body()) != "[]" {
		t.Errorf("list: expected 200 [] with no rules engine, got %d %q", rec.code(), rec.body())
	}
	if rec := serveSidecar(s, http.MethodPost, "/rules/add", `{}`); rec.code() != http.StatusServiceUnavailable {
		t.Errorf("add: expected 503 with no rules engine, got %d", rec.code())
	}
	if rec := serveSidecar(s, http.MethodDelete, "/rules/delete?id=x", ""); rec.code() != http.StatusServiceUnavailable {
		t.Errorf("delete: expected 503 with no rules engine, got %d", rec.code())
	}
}

func TestSidecarRulesAddRejectsMalformedJSON(t *testing.T) {
	s := NewSidecar("", nil, nil, nil, nil, nil, wrules.NewEngine(), nil)
	rec := serveSidecar(s, http.MethodPost, "/rules/add", `{"id": `)

	if rec.code() != http.StatusBadRequest {
		t.Fatalf("expected 400 for malformed JSON, got %d", rec.code())
	}
	if !strings.Contains(rec.body(), "invalid rule JSON") {
		t.Errorf("expected an actionable error message, got %q", rec.body())
	}
}

func TestSidecarRulesAddGeneratesIDWhenAbsent(t *testing.T) {
	s := NewSidecar("", nil, nil, nil, nil, nil, wrules.NewEngine(), nil)
	rec := serveSidecar(s, http.MethodPost, "/rules/add", `{"name":"no id","enabled":true}`)

	if rec.code() != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.code(), rec.body())
	}
	var created wrules.CustomRule
	if err := json.Unmarshal([]byte(rec.body()), &created); err != nil {
		t.Fatalf("response is not a rule: %v", err)
	}
	if !strings.HasPrefix(created.ID, "custom-") {
		t.Errorf("expected a generated custom-* id, got %q", created.ID)
	}
}

func TestSidecarRulesListAndDelete(t *testing.T) {
	s := NewSidecar("", nil, nil, nil, nil, nil, wrules.NewEngine(), nil)
	s.rules.AddRule(wrules.CustomRule{ID: "keep", Enabled: true, Action: wrules.ActionBlock, IPs: []string{"10.0.0.1"}})
	s.rules.AddRule(wrules.CustomRule{ID: "drop", Enabled: true, Action: wrules.ActionBlock, IPs: []string{"10.0.0.2"}})

	rec := serveSidecar(s, http.MethodGet, "/rules", "")
	if rec.code() != http.StatusOK {
		t.Fatalf("list: expected 200, got %d", rec.code())
	}
	var listed []wrules.CustomRule
	if err := json.Unmarshal([]byte(rec.body()), &listed); err != nil {
		t.Fatalf("list body is not a rule array: %v", err)
	}
	if len(listed) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(listed))
	}

	if rec := serveSidecar(s, http.MethodDelete, "/rules/delete", ""); rec.code() != http.StatusBadRequest {
		t.Errorf("delete without id: expected 400, got %d", rec.code())
	}
	if rec := serveSidecar(s, http.MethodDelete, "/rules/delete?id=drop", ""); rec.code() != http.StatusNoContent {
		t.Errorf("delete: expected 204, got %d", rec.code())
	}

	remaining := s.rules.List()
	if len(remaining) != 1 || remaining[0].ID != "keep" {
		t.Errorf("expected only 'keep' to remain, got %v", remaining)
	}
}

// TestSidecarLearningEndpoints covers both the populated and the degraded
// branches, since the control room polls these continuously.
func TestSidecarLearningEndpoints(t *testing.T) {
	t.Run("without a learning engine", func(t *testing.T) {
		s := NewSidecar("", nil, nil, nil, nil, nil, nil, nil)
		for _, tc := range []struct{ path, want string }{
			{"/learning/suggestions", "[]"},
			{"/learning/stats", "{}"},
			{"/learning/dataset", "[]"},
		} {
			rec := serveSidecar(s, http.MethodGet, tc.path, "")
			if rec.code() != http.StatusOK {
				t.Errorf("%s: expected 200, got %d", tc.path, rec.code())
			}
			if strings.TrimSpace(rec.body()) != tc.want {
				t.Errorf("%s: expected %q, got %q", tc.path, tc.want, rec.body())
			}
		}
	})

	t.Run("with a learning engine", func(t *testing.T) {
		s := NewSidecar("", nil, nil, nil, learning.NewEngine(10), nil, nil, nil)
		for _, path := range []string{"/learning/suggestions", "/learning/stats", "/learning/dataset"} {
			rec := serveSidecar(s, http.MethodGet, path, "")
			if rec.code() != http.StatusOK {
				t.Errorf("%s: expected 200, got %d", path, rec.code())
			}
			if !json.Valid([]byte(rec.body())) {
				t.Errorf("%s: body is not valid JSON: %q", path, rec.body())
			}
		}
	})
}

func TestSidecarSSEStreamsPublishedEvents(t *testing.T) {
	broker := events.NewBroker()
	s := NewSidecar("", nil, nil, nil, nil, nil, nil, broker)

	mux := http.NewServeMux()
	mux.HandleFunc("/events", s.handleSSE)

	ctx, cancel := context.WithCancel(context.Background())
	rec := &syncRecorder{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/events", nil).WithContext(ctx))
	}()

	waitFor(t, done, func() bool { return strings.Contains(rec.body(), ": connected") },
		"SSE never sent the connection preamble")
	if rec.flushes == 0 {
		t.Error("expected the preamble to be flushed so the client sees it immediately")
	}

	broker.Publish(events.WafEvent{Type: events.TypeBlocked, Path: "/blocked-path"})
	waitFor(t, done, func() bool { return strings.Contains(rec.body(), "/blocked-path") },
		"published event was not streamed to the subscriber")

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("SSE handler did not return after the client disconnected")
	}
}

func TestSidecarSSEWithoutBroker(t *testing.T) {
	s := NewSidecar("", nil, nil, nil, nil, nil, nil, nil)
	mux := http.NewServeMux()
	mux.HandleFunc("/events", s.handleSSE)

	rec := &syncRecorder{}
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/events", nil))
	if rec.code() != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 with no broker, got %d", rec.code())
	}
}

// TestSidecarSSERequiresFlusher covers the guard for a ResponseWriter that cannot
// stream, which would otherwise hang the client forever.
func TestSidecarSSERequiresFlusher(t *testing.T) {
	s := NewSidecar("", nil, nil, nil, nil, nil, nil, events.NewBroker())
	mux := http.NewServeMux()
	mux.HandleFunc("/events", s.handleSSE)

	mux.ServeHTTP(&nonFlushingWriter{}, httptest.NewRequest(http.MethodGet, "/events", nil))
}

type nonFlushingWriter struct{ header http.Header }

func (w *nonFlushingWriter) Header() http.Header {
	if w.header == nil {
		w.header = make(http.Header)
	}
	return w.header
}
func (w *nonFlushingWriter) Write(b []byte) (int, error) { return len(b), nil }
func (w *nonFlushingWriter) WriteHeader(int)             {}

// waitFor polls cond until it holds, the handler finishes, or the deadline hits.
func waitFor(t *testing.T, done chan struct{}, cond func() bool, msg string) {
	t.Helper()
	deadline := time.After(2 * time.Second)
	for {
		if cond() {
			return
		}
		select {
		case <-done:
			t.Fatalf("%s (handler exited)", msg)
		case <-deadline:
			t.Fatalf("%s (timed out)", msg)
		default:
			time.Sleep(2 * time.Millisecond)
		}
	}
}

// TestSidecarRecordLearningTruncatesBody guards the body-snippet limit, which
// keeps attacker-controlled payloads from bloating the learning dataset.
func TestSidecarRecordLearningTruncatesBody(t *testing.T) {
	learn := learning.NewEngine(10)
	s := NewSidecar("", policy.NewRuleEngine(), nil, nil, learn, nil, nil, nil)

	long := strings.Repeat("A", 500)
	s.recordLearning(&policy.Request{Method: "POST", Path: "/x", Body: []byte(long)}, "block", "r1", "reason", time.Now())

	records := learn.Records()
	if len(records) != 1 {
		t.Fatalf("expected 1 learning record, got %d", len(records))
	}
	if len(records[0].BodySnippet) > 100 {
		t.Errorf("body snippet was not truncated: %d bytes", len(records[0].BodySnippet))
	}
	if records[0].Verdict != learning.Verdict("block") {
		t.Errorf("expected verdict block, got %q", records[0].Verdict)
	}
}

// TestSidecarRecordLearningDefaultsRuleID covers the empty-ruleID branch: an
// unattributed block must still be traceable in the dataset.
func TestSidecarRecordLearningDefaultsRuleID(t *testing.T) {
	learn := learning.NewEngine(10)
	s := NewSidecar("", policy.NewRuleEngine(), nil, nil, learn, nil, nil, nil)

	s.recordLearning(&policy.Request{Method: "GET", Path: "/x"}, "block", "", "no rule", time.Now())

	dataset := learn.ExportDataset()
	if len(dataset) != 1 {
		t.Fatalf("expected 1 dataset record, got %d", len(dataset))
	}
	if dataset[0].RuleID != "unknown" {
		t.Errorf("expected an empty rule id to be stored as 'unknown', got %q", dataset[0].RuleID)
	}
}

func TestSidecarRecordLearningWithoutEngineIsNoop(t *testing.T) {
	s := NewSidecar("", nil, nil, nil, nil, nil, nil, nil)
	s.recordLearning(&policy.Request{Path: "/x"}, "block", "r1", "reason", time.Now())
}
