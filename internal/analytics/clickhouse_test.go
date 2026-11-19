package analytics

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackby03/waffynx/internal/telemetry"
)

func TestClickHouseClient_SchemaInsertQueryAndSummary(t *testing.T) {
	var seenQueries []string
	var insertedBody string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ping" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("Ok.\n"))
			return
		}
		q := r.URL.Query().Get("query")
		seenQueries = append(seenQueries, q)

		switch {
		case strings.HasPrefix(q, "INSERT INTO"):
			b, _ := io.ReadAll(r.Body)
			insertedBody = string(b)
			w.WriteHeader(http.StatusOK)
		case strings.Contains(q, "SELECT event_id"):
			// Ensure user filter arrived as bound HTTP parameter, not spliced into SQL.
			if r.URL.Query().Get("param_q") != "UNION'; DROP TABLE" {
				t.Errorf("expected bound param_q, got %q", r.URL.Query().Get("param_q"))
			}
			_, _ = w.Write([]byte(`{"event_id":"e1","ts":"2026-11-19T05:00:00.000Z","node_id":"waf-1","plane":"data-plane","action":"block","stage":"catalog","method":"GET","host":"app.example.test","path":"/?q=1","remote_ip":"203.0.113.1","country_code":"US","rule_id":"sqli-001","severity":"critical","reason":"SQLi","status_code":403,"latency_us":"420","ml_score":0.9,"shadow_mode":0,"headers_json":"{\"Authorization\":\"[REDACTED]\"}","body_snippet":""}` + "\n"))
		case strings.Contains(q, "uniqExact"):
			_, _ = w.Write([]byte(`{"total":"12","blocked":"5","rate_limited":"2","auth_denied":"1","shadow_blocked":"1","unique_ips":"4"}` + "\n"))
		case strings.Contains(q, "SELECT rule_id AS k"):
			_, _ = w.Write([]byte(`{"k":"sqli-001","cnt":"5"}` + "\n"))
		case strings.Contains(q, "SELECT remote_ip AS k"):
			_, _ = w.Write([]byte(`{"k":"203.0.113.1","cnt":"3"}` + "\n"))
		case strings.Contains(q, "SELECT country_code AS k"):
			_, _ = w.Write([]byte(`{"k":"US","cnt":"4"}` + "\n"))
		case strings.Contains(q, "toStartOfHour"):
			_, _ = w.Write([]byte(`{"bucket":"2026-11-19T05:00:00Z","total":"12","blocked":"8"}` + "\n"))
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()

	cli, err := NewClickHouseClient(Config{Enabled: true, URL: srv.URL, Database: "waffynx", Username: "default"})
	if err != nil {
		t.Fatalf("NewClickHouseClient: %v", err)
	}
	ctx := context.Background()

	if err := cli.Ping(ctx); err != nil {
		t.Fatalf("Ping: %v", err)
	}
	if err := cli.InitSchema(ctx); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	if err := cli.BulkInsert(ctx, []telemetry.SecurityEvent{
		{
			EventID:   "e1",
			Timestamp: time.Now().UTC(),
			Action:    telemetry.ActionBlock,
			Host:      "app.example.test",
			Path:      "/login?password=secret123",
			Headers:   map[string]string{"Authorization": "Bearer secret-jwt"},
		},
	}); err != nil {
		t.Fatalf("BulkInsert: %v", err)
	}
	if strings.Contains(insertedBody, "secret123") || strings.Contains(insertedBody, "secret-jwt") {
		t.Fatalf("BulkInsert leaked unredacted credentials: %s", insertedBody)
	}

	events, err := cli.QueryEvents(ctx, EventFilter{
		Query:       "UNION'; DROP TABLE",
		Action:      "block",
		Host:        "app.example.test",
		RemoteIP:    "203.0.113.1",
		RuleID:      "sqli-001",
		CountryCode: "us",
		Limit:       50,
	})
	if err != nil || len(events) != 1 || events[0].RuleID != "sqli-001" {
		t.Fatalf("QueryEvents: %+v err=%v", events, err)
	}

	sum, err := cli.QuerySummary(ctx, 24)
	if err != nil {
		t.Fatalf("QuerySummary: %v", err)
	}
	if sum.TotalEvents != 12 || sum.Blocked != 5 || len(sum.TopRules) != 1 || len(sum.Timeline) != 1 {
		t.Fatalf("unexpected summary: %+v", sum)
	}
}

func TestNewClickHouseClient_Validation(t *testing.T) {
	cli, err := NewClickHouseClient(Config{Enabled: false})
	if err != nil || cli != nil {
		t.Fatalf("expected nil client when disabled")
	}
	if _, err := NewClickHouseClient(Config{Enabled: true, URL: "http://ch:8123", Database: "bad;db"}); err == nil {
		t.Fatal("expected error for unsafe database identifier")
	}
}
