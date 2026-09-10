package events

import (
	"io"
	"net/http"
	"net/http/httptest"
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
