package audit

import (
	"os"
	"testing"
)

func TestNewStore(t *testing.T) {
	s, err := NewStore(100, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer s.Close()
	if s == nil {
		t.Fatal("expected store")
	}
}

func TestRecord(t *testing.T) {
	s, _ := NewStore(100, "")
	defer s.Close()

	s.Record(Event{Actor: "admin", Action: "GET /api/status", Result: "allowed", ActorIP: "127.0.0.1"})
	s.Record(Event{Actor: "hacker", Action: "POST /api/login", Result: "blocked", ActorIP: "10.0.0.1"})

	events := s.Query(QueryFilter{Limit: 10})
	if len(events) != 2 {
		t.Errorf("expected 2 events, got %d", len(events))
	}
}

func TestQuery_FilterByActor(t *testing.T) {
	s, _ := NewStore(100, "")
	defer s.Close()

	s.Record(Event{Actor: "admin", Action: "GET /api", Result: "allowed"})
	s.Record(Event{Actor: "user1", Action: "POST /api/login", Result: "blocked"})
	s.Record(Event{Actor: "admin", Action: "DELETE /api/config", Result: "allowed"})

	events := s.Query(QueryFilter{Limit: 10, Actor: "admin"})
	if len(events) != 2 {
		t.Errorf("expected 2 admin events, got %d", len(events))
	}
}

func TestQuery_FilterByResult(t *testing.T) {
	s, _ := NewStore(100, "")
	defer s.Close()

	s.Record(Event{Actor: "a", Action: "GET /api", Result: "allowed"})
	s.Record(Event{Actor: "b", Action: "POST /api", Result: "blocked"})
	s.Record(Event{Actor: "c", Action: "GET /api", Result: "blocked"})

	events := s.Query(QueryFilter{Limit: 10, Result: "blocked"})
	if len(events) != 2 {
		t.Errorf("expected 2 blocked events, got %d", len(events))
	}
}

func TestStats(t *testing.T) {
	s, _ := NewStore(100, "")
	defer s.Close()

	s.Record(Event{Result: "allowed"})
	s.Record(Event{Result: "allowed"})
	s.Record(Event{Result: "blocked"})

	stats := s.Stats()
	if stats["total"].(int) != 3 {
		t.Errorf("expected 3 total, got %v", stats["total"])
	}
	if stats["allowed"].(int) != 2 {
		t.Errorf("expected 2 allowed, got %v", stats["allowed"])
	}
}

func TestFileStore(t *testing.T) {
	tmpFile := "/tmp/waffynx-audit-test.jsonl"
	os.Remove(tmpFile)

	s, err := NewStore(100, tmpFile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	s.Record(Event{Actor: "test", Action: "GET /", Result: "allowed"})
	s.Close()

	data, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatalf("reading audit file: %v", err)
	}
	if len(data) == 0 {
		t.Error("expected data in audit file")
	}
	os.Remove(tmpFile)
}

func TestRecordCircularBuffer(t *testing.T) {
	s, _ := NewStore(3, "")
	defer s.Close()

	for i := 0; i < 5; i++ {
		s.Record(Event{Actor: "test", Action: "GET /", Result: "allowed"})
	}

	events := s.Query(QueryFilter{Limit: 10})
	if len(events) != 3 {
		t.Errorf("expected 3 events after overflow, got %d", len(events))
	}
}

func TestQuery_Limit(t *testing.T) {
	s, _ := NewStore(100, "")
	defer s.Close()

	for i := 0; i < 10; i++ {
		s.Record(Event{Actor: "test", Action: "GET /", Result: "allowed"})
	}

	events := s.Query(QueryFilter{Limit: 3})
	if len(events) != 3 {
		t.Errorf("expected 3 events with limit, got %d", len(events))
	}
}
