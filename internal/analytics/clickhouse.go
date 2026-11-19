// Package analytics provides a pure standard-library HTTP client for
// ClickHouse bulk ingestion (JSONEachRow) and parameterized security analytics
// queries used by the Observability and Control Planes (Constitution §2.3).
package analytics

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/jackby03/waffynx/internal/telemetry"
)

// Config holds ClickHouse HTTP connection parameters.
type Config struct {
	Enabled  bool   `yaml:"enabled"`
	URL      string `yaml:"url"` // e.g. http://clickhouse:8123
	Database string `yaml:"database"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

// EventFilter narrows ClickHouse analytical event queries.
type EventFilter struct {
	Query       string
	Action      string
	Host        string
	RemoteIP    string
	RuleID      string
	CountryCode string
	SinceHours  int
	Limit       int
	Offset      int
}

// TopCount represents a grouped metric bucket (top rule, IP, country, etc.).
type TopCount struct {
	Key   string `json:"key"`
	Count uint64 `json:"count"`
}

// TimelinePoint represents one time-series bucket.
type TimelinePoint struct {
	Bucket  string `json:"bucket"`
	Total   uint64 `json:"total"`
	Blocked uint64 `json:"blocked"`
}

// Summary aggregates SOC security metrics across the requested time window.
type Summary struct {
	WindowHours   int             `json:"window_hours"`
	TotalEvents   uint64          `json:"total_events"`
	Blocked       uint64          `json:"blocked"`
	RateLimited   uint64          `json:"rate_limited"`
	AuthDenied    uint64          `json:"auth_denied"`
	ShadowBlocked uint64          `json:"shadow_blocked"`
	UniqueIPs     uint64          `json:"unique_ips"`
	TopRules      []TopCount      `json:"top_rules"`
	TopIPs        []TopCount      `json:"top_ips"`
	TopCountries  []TopCount      `json:"top_countries"`
	Timeline      []TimelinePoint `json:"timeline"`
}

// Reader is the read-only analytics interface consumed by the Control Plane API.
type Reader interface {
	Ping(ctx context.Context) error
	QueryEvents(ctx context.Context, filter EventFilter) ([]telemetry.SecurityEvent, error)
	QuerySummary(ctx context.Context, windowHours int) (Summary, error)
}

// Writer is the bulk-ingestion interface consumed by cmd/log-ingestor.
type Writer interface {
	InitSchema(ctx context.Context) error
	BulkInsert(ctx context.Context, events []telemetry.SecurityEvent) error
	Ping(ctx context.Context) error
}

// ClickHouseClient implements both Reader and Writer over ClickHouse's native HTTP API.
type ClickHouseClient struct {
	baseURL  string
	database string
	username string
	password string
	http     *http.Client
}

// NewClickHouseClient validates config and constructs a ClickHouse HTTP client.
func NewClickHouseClient(cfg Config) (*ClickHouseClient, error) {
	if !cfg.Enabled || strings.TrimSpace(cfg.URL) == "" {
		return nil, nil
	}
	if cfg.Database == "" {
		cfg.Database = "waffynx"
	}
	if !isSafeIdent(cfg.Database) {
		return nil, fmt.Errorf("invalid clickhouse database name %q", cfg.Database)
	}
	return &ClickHouseClient{
		baseURL:  strings.TrimRight(cfg.URL, "/"),
		database: cfg.Database,
		username: cfg.Username,
		password: cfg.Password,
		http:     &http.Client{Timeout: 10 * time.Second},
	}, nil
}

func isSafeIdent(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, r := range s {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '_' {
			return false
		}
	}
	return true
}

func (c *ClickHouseClient) Ping(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/ping", nil)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("clickhouse ping returned %s", resp.Status)
	}
	return nil
}

// InitSchema idempotently creates the database and partitioned security_events table.
func (c *ClickHouseClient) InitSchema(ctx context.Context) error {
	createDB := fmt.Sprintf("CREATE DATABASE IF NOT EXISTS %s", c.database)
	if _, err := c.exec(ctx, createDB, nil, nil); err != nil {
		return fmt.Errorf("creating clickhouse database: %w", err)
	}

	createTable := fmt.Sprintf(`
CREATE TABLE IF NOT EXISTS %s.security_events (
	event_id String,
	timestamp DateTime64(3, 'UTC'),
	node_id LowCardinality(String),
	plane LowCardinality(String),
	action LowCardinality(String),
	stage LowCardinality(String),
	method LowCardinality(String),
	host String,
	path String,
	remote_ip String,
	country_code LowCardinality(String),
	user_agent String,
	rule_id String,
	severity LowCardinality(String),
	reason String,
	status_code UInt16,
	latency_us Int64,
	ml_score Float64,
	zt_subject String,
	shadow_mode UInt8,
	headers_json String,
	body_snippet String
) ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(timestamp)
ORDER BY (timestamp, action, host, remote_ip, rule_id)
TTL toDateTime(timestamp) + INTERVAL 30 DAY
`, c.database)

	if _, err := c.exec(ctx, createTable, nil, nil); err != nil {
		return fmt.Errorf("creating security_events table: %w", err)
	}
	return nil
}

// flexInt64 unmarshals ClickHouse Int64 values which ClickHouse encodes as
// quoted JSON strings in JSONEachRow to avoid IEEE-754 53-bit truncation.
type flexInt64 int64

func (f *flexInt64) UnmarshalJSON(b []byte) error {
	s := strings.TrimSpace(string(b))
	s = strings.Trim(s, `"`)
	if s == "" || s == "null" {
		*f = 0
		return nil
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return err
	}
	*f = flexInt64(n)
	return nil
}

type chQueryRow struct {
	EventID     string    `json:"event_id"`
	TS          string    `json:"ts"`
	Timestamp   string    `json:"timestamp"`
	NodeID      string    `json:"node_id"`
	Plane       string    `json:"plane"`
	Action      string    `json:"action"`
	Stage       string    `json:"stage"`
	Method      string    `json:"method"`
	Host        string    `json:"host"`
	Path        string    `json:"path"`
	RemoteIP    string    `json:"remote_ip"`
	CountryCode string    `json:"country_code"`
	UserAgent   string    `json:"user_agent"`
	RuleID      string    `json:"rule_id"`
	Severity    string    `json:"severity"`
	Reason      string    `json:"reason"`
	StatusCode  int       `json:"status_code"`
	LatencyUs   flexInt64 `json:"latency_us"`
	MLScore     float64   `json:"ml_score"`
	ZTSubject   string    `json:"zt_subject"`
	ShadowMode  uint8     `json:"shadow_mode"`
	HeadersJSON string    `json:"headers_json"`
	BodySnippet string    `json:"body_snippet"`
}

type chRow struct {
	EventID     string  `json:"event_id"`
	Timestamp   string  `json:"timestamp"`
	NodeID      string  `json:"node_id"`
	Plane       string  `json:"plane"`
	Action      string  `json:"action"`
	Stage       string  `json:"stage"`
	Method      string  `json:"method"`
	Host        string  `json:"host"`
	Path        string  `json:"path"`
	RemoteIP    string  `json:"remote_ip"`
	CountryCode string  `json:"country_code"`
	UserAgent   string  `json:"user_agent"`
	RuleID      string  `json:"rule_id"`
	Severity    string  `json:"severity"`
	Reason      string  `json:"reason"`
	StatusCode  int     `json:"status_code"`
	LatencyUs   int64   `json:"latency_us"`
	MLScore     float64 `json:"ml_score"`
	ZTSubject   string  `json:"zt_subject"`
	ShadowMode  uint8   `json:"shadow_mode"`
	HeadersJSON string  `json:"headers_json"`
	BodySnippet string  `json:"body_snippet"`
}

// BulkInsert writes a batch of redacted SecurityEvents via JSONEachRow.
func (c *ClickHouseClient) BulkInsert(ctx context.Context, events []telemetry.SecurityEvent) error {
	if len(events) == 0 {
		return nil
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, raw := range events {
		ev := telemetry.RedactEvent(raw)
		ts := ev.Timestamp
		if ts.IsZero() {
			ts = time.Now().UTC()
		}
		hdrJSON := "{}"
		if len(ev.Headers) > 0 {
			if b, err := json.Marshal(ev.Headers); err == nil {
				hdrJSON = string(b)
			}
		}
		var shadow uint8
		if ev.ShadowMode {
			shadow = 1
		}
		row := chRow{
			EventID:     ev.EventID,
			Timestamp:   ts.UTC().Format("2006-01-02 15:04:05.000"),
			NodeID:      ev.NodeID,
			Plane:       ev.Plane,
			Action:      string(ev.Action),
			Stage:       ev.Stage,
			Method:      ev.Method,
			Host:        ev.Host,
			Path:        ev.Path,
			RemoteIP:    ev.RemoteIP,
			CountryCode: ev.CountryCode,
			UserAgent:   ev.UserAgent,
			RuleID:      ev.RuleID,
			Severity:    ev.Severity,
			Reason:      ev.Reason,
			StatusCode:  ev.StatusCode,
			LatencyUs:   ev.LatencyUs,
			MLScore:     ev.MLScore,
			ZTSubject:   ev.ZTSubject,
			ShadowMode:  shadow,
			HeadersJSON: hdrJSON,
			BodySnippet: ev.BodySnippet,
		}
		if err := enc.Encode(row); err != nil {
			return fmt.Errorf("encoding clickhouse row: %w", err)
		}
	}

	query := fmt.Sprintf("INSERT INTO %s.security_events FORMAT JSONEachRow", c.database)
	_, err := c.exec(ctx, query, nil, &buf)
	return err
}

// QueryEvents retrieves security events using ClickHouse parameterized bindings
// to eliminate any possibility of SQL injection (Constitution §1.4).
func (c *ClickHouseClient) QueryEvents(ctx context.Context, filter EventFilter) ([]telemetry.SecurityEvent, error) {
	limit := filter.Limit
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	offset := filter.Offset
	if offset < 0 {
		offset = 0
	}
	sinceHours := filter.SinceHours
	if sinceHours <= 0 || sinceHours > 720 {
		sinceHours = 24
	}

	conds := []string{fmt.Sprintf("timestamp >= now() - INTERVAL %d HOUR", sinceHours)}
	params := make(map[string]string)

	if filter.Action != "" {
		conds = append(conds, "action = {action:String}")
		params["action"] = filter.Action
	}
	if filter.Host != "" {
		conds = append(conds, "host = {host:String}")
		params["host"] = filter.Host
	}
	if filter.RemoteIP != "" {
		conds = append(conds, "remote_ip = {remote_ip:String}")
		params["remote_ip"] = filter.RemoteIP
	}
	if filter.RuleID != "" {
		conds = append(conds, "rule_id = {rule_id:String}")
		params["rule_id"] = filter.RuleID
	}
	if filter.CountryCode != "" {
		conds = append(conds, "country_code = {cc:String}")
		params["cc"] = strings.ToUpper(filter.CountryCode)
	}
	if filter.Query != "" {
		conds = append(conds, "(positionCaseInsensitive(path, {q:String}) > 0 OR positionCaseInsensitive(rule_id, {q:String}) > 0 OR positionCaseInsensitive(remote_ip, {q:String}) > 0 OR positionCaseInsensitive(reason, {q:String}) > 0)")
		params["q"] = filter.Query
	}

	sql := fmt.Sprintf(`
SELECT event_id, formatDateTime(timestamp, '%%Y-%%m-%%dT%%H:%%i:%%S.000Z', 'UTC') AS ts,
       node_id, plane, action, stage, method, host, path, remote_ip, country_code,
       user_agent, rule_id, severity, reason, status_code, latency_us, ml_score,
       zt_subject, shadow_mode, headers_json, body_snippet
FROM %s.security_events
WHERE %s
ORDER BY timestamp DESC
LIMIT %d OFFSET %d
FORMAT JSONEachRow`, c.database, strings.Join(conds, " AND "), limit, offset)

	raw, err := c.exec(ctx, sql, params, nil)
	if err != nil {
		return nil, err
	}

	out := make([]telemetry.SecurityEvent, 0)
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var r chQueryRow
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			continue
		}
		tsRaw := r.TS
		if tsRaw == "" {
			tsRaw = r.Timestamp
		}
		ts, _ := time.Parse(time.RFC3339, tsRaw)
		var hdrs map[string]string
		if r.HeadersJSON != "" {
			_ = json.Unmarshal([]byte(r.HeadersJSON), &hdrs)
		}
		out = append(out, telemetry.SecurityEvent{
			EventID:     r.EventID,
			Timestamp:   ts,
			NodeID:      r.NodeID,
			Plane:       r.Plane,
			Action:      telemetry.EventAction(r.Action),
			Stage:       r.Stage,
			Method:      r.Method,
			Host:        r.Host,
			Path:        r.Path,
			RemoteIP:    r.RemoteIP,
			CountryCode: r.CountryCode,
			UserAgent:   r.UserAgent,
			RuleID:      r.RuleID,
			Severity:    r.Severity,
			Reason:      r.Reason,
			StatusCode:  r.StatusCode,
			LatencyUs:   int64(r.LatencyUs),
			MLScore:     r.MLScore,
			ZTSubject:   r.ZTSubject,
			ShadowMode:  r.ShadowMode != 0,
			Headers:     hdrs,
			BodySnippet: r.BodySnippet,
		})
	}
	return out, nil
}

// QuerySummary computes overview KPIs, top attack vectors/IPs/countries, and timeline buckets.
func (c *ClickHouseClient) QuerySummary(ctx context.Context, windowHours int) (Summary, error) {
	if windowHours <= 0 || windowHours > 720 {
		windowHours = 24
	}
	summary := Summary{
		WindowHours:  windowHours,
		TopRules:     []TopCount{},
		TopIPs:       []TopCount{},
		TopCountries: []TopCount{},
		Timeline:     []TimelinePoint{},
	}

	// 1. Totals
	totalsSQL := fmt.Sprintf(`
SELECT count() AS total,
       countIf(action = 'block') AS blocked,
       countIf(action = 'rate_limited') AS rate_limited,
       countIf(action = 'auth_denied') AS auth_denied,
       countIf(action = 'shadow_block') AS shadow_blocked,
       uniqExact(remote_ip) AS unique_ips
FROM %s.security_events
WHERE timestamp >= now() - INTERVAL %d HOUR
FORMAT JSONEachRow`, c.database, windowHours)

	if raw, err := c.exec(ctx, totalsSQL, nil, nil); err == nil && len(bytes.TrimSpace(raw)) > 0 {
		var row struct {
			Total         string `json:"total"`
			Blocked       string `json:"blocked"`
			RateLimited   string `json:"rate_limited"`
			AuthDenied    string `json:"auth_denied"`
			ShadowBlocked string `json:"shadow_blocked"`
			UniqueIPs     string `json:"unique_ips"`
		}
		if json.Unmarshal(bytes.TrimSpace(raw), &row) == nil {
			summary.TotalEvents = parseUint(row.Total)
			summary.Blocked = parseUint(row.Blocked)
			summary.RateLimited = parseUint(row.RateLimited)
			summary.AuthDenied = parseUint(row.AuthDenied)
			summary.ShadowBlocked = parseUint(row.ShadowBlocked)
			summary.UniqueIPs = parseUint(row.UniqueIPs)
		}
	} else if err != nil {
		return summary, err
	}

	// 2. Top rules / IPs / countries
	summary.TopRules = c.queryTop(ctx, "rule_id", windowHours, "action != 'allow' AND rule_id != ''")
	summary.TopIPs = c.queryTop(ctx, "remote_ip", windowHours, "action != 'allow' AND remote_ip != ''")
	summary.TopCountries = c.queryTop(ctx, "country_code", windowHours, "country_code != ''")

	// 3. Hourly timeline
	tlSQL := fmt.Sprintf(`
SELECT formatDateTime(toStartOfHour(timestamp), '%%Y-%%m-%%dT%%H:00:00Z', 'UTC') AS bucket,
       count() AS total,
       countIf(action IN ('block','rate_limited','auth_denied')) AS blocked
FROM %s.security_events
WHERE timestamp >= now() - INTERVAL %d HOUR
GROUP BY bucket
ORDER BY bucket ASC
FORMAT JSONEachRow`, c.database, windowHours)
	if raw, err := c.exec(ctx, tlSQL, nil, nil); err == nil {
		for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
			if strings.TrimSpace(line) == "" {
				continue
			}
			var pt struct {
				Bucket  string `json:"bucket"`
				Total   string `json:"total"`
				Blocked string `json:"blocked"`
			}
			if json.Unmarshal([]byte(line), &pt) == nil {
				summary.Timeline = append(summary.Timeline, TimelinePoint{
					Bucket:  pt.Bucket,
					Total:   parseUint(pt.Total),
					Blocked: parseUint(pt.Blocked),
				})
			}
		}
	}

	return summary, nil
}

func (c *ClickHouseClient) queryTop(ctx context.Context, column string, windowHours int, extraWhere string) []TopCount {
	sql := fmt.Sprintf(`
SELECT %s AS k, count() AS cnt
FROM %s.security_events
WHERE timestamp >= now() - INTERVAL %d HOUR AND %s
GROUP BY k
ORDER BY cnt DESC
LIMIT 10
FORMAT JSONEachRow`, column, c.database, windowHours, extraWhere)

	raw, err := c.exec(ctx, sql, nil, nil)
	if err != nil {
		return []TopCount{}
	}
	out := make([]TopCount, 0)
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var row struct {
			K   string `json:"k"`
			Cnt string `json:"cnt"`
		}
		if json.Unmarshal([]byte(line), &row) == nil {
			out = append(out, TopCount{Key: row.K, Count: parseUint(row.Cnt)})
		}
	}
	return out
}

func parseUint(s string) uint64 {
	n, _ := strconv.ParseUint(strings.TrimSpace(s), 10, 64)
	return n
}

func (c *ClickHouseClient) exec(ctx context.Context, query string, params map[string]string, body io.Reader) ([]byte, error) {
	q := url.Values{}
	q.Set("query", query)
	for k, v := range params {
		q.Set("param_"+k, v)
	}
	endpoint := c.baseURL + "/?" + q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, body)
	if err != nil {
		return nil, err
	}
	if c.username != "" {
		req.SetBasicAuth(c.username, c.password)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("clickhouse request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	data, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("clickhouse returned %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	return data, nil
}
