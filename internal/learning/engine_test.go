package learning

import (
	"testing"
)

func TestNewEngine(t *testing.T) {
	e := NewEngine(100)
	if e == nil {
		t.Fatal("expected engine")
	}
	if e.maxSize != 100 {
		t.Errorf("expected maxSize 100, got %d", e.maxSize)
	}
	if !e.enabled {
		t.Error("expected enabled by default")
	}
}

func TestRecord(t *testing.T) {
	e := NewEngine(10)
	e.Record(Record{Method: "GET", Path: "/api/users", Verdict: VerdictAllow})
	e.Record(Record{Method: "POST", Path: "/api/login", Verdict: VerdictBlock, RuleID: "sql-001"})
	e.Record(Record{Method: "GET", Path: "/health", Verdict: VerdictAllow})

	records := e.Records()
	if len(records) != 3 {
		t.Errorf("expected 3 records, got %d", len(records))
	}
	if records[1].Verdict != VerdictBlock {
		t.Error("expected block verdict")
	}
}

func TestRecordCircularBuffer(t *testing.T) {
	e := NewEngine(3)
	for i := 0; i < 5; i++ {
		e.Record(Record{Path: "/test", Verdict: VerdictAllow})
	}
	records := e.Records()
	if len(records) != 3 {
		t.Errorf("expected 3 records after overflow, got %d", len(records))
	}
}

func TestStats(t *testing.T) {
	e := NewEngine(100)
	e.Record(Record{Verdict: VerdictAllow})
	e.Record(Record{Verdict: VerdictAllow})
	e.Record(Record{Verdict: VerdictBlock})

	stats := e.Stats()
	if stats["total"].(int) != 3 {
		t.Errorf("expected 3 total, got %v", stats["total"])
	}
	if stats["allowed"].(int) != 2 {
		t.Errorf("expected 2 allowed, got %v", stats["allowed"])
	}
	if stats["blocked"].(int) != 1 {
		t.Errorf("expected 1 blocked, got %v", stats["blocked"])
	}
}

func TestSuggestions_Empty(t *testing.T) {
	e := NewEngine(100)
	suggestions := e.Suggestions()
	if suggestions != nil {
		t.Error("expected nil suggestions for empty engine")
	}
}

func TestSuggestions_Whitelist(t *testing.T) {
	e := NewEngine(1000)
	for i := 0; i < 50; i++ {
		e.Record(Record{Path: "/api/health", Method: "GET", Verdict: VerdictAllow})
	}
	e.Record(Record{Path: "/api/users/123", Method: "GET", Verdict: VerdictAllow})
	e.Record(Record{Path: "/api/users/456", Method: "GET", Verdict: VerdictAllow})

	suggestions := e.Suggestions()
	if len(suggestions) == 0 {
		t.Error("expected whitelist suggestion for high-traffic path")
	}
}

func TestSuggestions_Blocklist(t *testing.T) {
	e := NewEngine(1000)
	for i := 0; i < 10; i++ {
		e.Record(Record{RemoteIP: "10.0.0.1", Verdict: VerdictBlock, RuleID: "sql-001"})
	}
	e.Record(Record{RemoteIP: "10.0.0.1", Verdict: VerdictAllow})
	e.Record(Record{RemoteIP: "10.0.0.1", Verdict: VerdictAllow})

	suggestions := e.Suggestions()
	hasBlocklist := false
	for _, s := range suggestions {
		if s.Type == "blocklist" && s.Pattern == "10.0.0.1" {
			hasBlocklist = true
		}
	}
	if !hasBlocklist {
		t.Error("expected blocklist suggestion for high-block IP")
	}
}

func TestSuggestions_RateLimit(t *testing.T) {
	e := NewEngine(100)
	for i := 0; i < 50; i++ {
		e.Record(Record{RemoteIP: "1.2.3.4", Verdict: VerdictAllow})
	}
	for i := 0; i < 10; i++ {
		e.Record(Record{RemoteIP: "5.6.7.8", Verdict: VerdictAllow})
	}

	suggestions := e.Suggestions()
	hasRate := false
	for _, s := range suggestions {
		if s.Type == "rate_limit" && s.Pattern == "1.2.3.4" {
			hasRate = true
		}
	}
	if !hasRate {
		t.Error("expected rate limit suggestion for high-volume IP")
	}
}

func TestNormalizePath(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"/api/users/123", "/api/users/{id}"},
		{"/files/42/download", "/files/{id}/download"},
		{"/static/css/main.css", "/static/css/main.css"},
		{"/api/v1/products?page=1", "/api/v1/products"},
		{"", "/"},
	}

	for _, tt := range tests {
		got := normalizePath(tt.input)
		if got != tt.expected {
			t.Errorf("normalizePath(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestExportDataset(t *testing.T) {
	e := NewEngine(100)
	e.Record(Record{
		Method:   "GET",
		Path:     "/api/users?page=1&limit=10",
		Host:     "example.com",
		RemoteIP: "1.2.3.4",
		Verdict:  VerdictAllow,
	})
	e.Record(Record{
		Method:   "POST",
		Path:     "/api/login",
		Host:     "example.com",
		RemoteIP: "5.6.7.8",
		Verdict:  VerdictBlock,
		RuleID:   "sql-001",
		Reason:   "SQL injection detected",
	})

	dataset := e.ExportDataset()
	if len(dataset) != 2 {
		t.Errorf("expected 2 records, got %d", len(dataset))
	}
	if dataset[0].Label != "allow" {
		t.Error("expected first record to be allow")
	}
	if dataset[1].Label != "block" {
		t.Error("expected second record to be block")
	}
	if dataset[0].HasQuery != true {
		t.Error("expected HasQuery=true for /api/users?page=1")
	}
	if dataset[0].QueryParams != 2 {
		t.Errorf("expected 2 query params, got %d", dataset[0].QueryParams)
	}
}

func TestDisable(t *testing.T) {
	e := NewEngine(100)
	e.Disable()
	e.Record(Record{Path: "/test", Verdict: VerdictAllow})
	if len(e.Records()) != 0 {
		t.Error("expected no records when disabled")
	}
	e.Enable()
	e.Record(Record{Path: "/test", Verdict: VerdictAllow})
	if len(e.Records()) != 1 {
		t.Error("expected 1 record after re-enabling")
	}
}
