// Package telemetry defines the structured security event schema, mandatory
// PII/credential redaction (Constitution §2.2), and asynchronous non-blocking
// NATS JetStream emission from the Data Plane (Constitution §1.3).
package telemetry

import "time"

// EventAction classifies the Data Plane enforcement outcome.
type EventAction string

const (
	ActionAllow       EventAction = "allow"
	ActionBlock       EventAction = "block"
	ActionShadowBlock EventAction = "shadow_block"
	ActionRateLimited EventAction = "rate_limited"
	ActionChallenge   EventAction = "challenge"
	ActionAuthDenied  EventAction = "auth_denied"
)

// SecurityEvent is the canonical observability record emitted asynchronously
// by the Data Plane and ingested into ClickHouse.
type SecurityEvent struct {
	EventID     string            `json:"event_id"`
	Timestamp   time.Time         `json:"timestamp"`
	NodeID      string            `json:"node_id"`
	Plane       string            `json:"plane"`
	Action      EventAction       `json:"action"`
	Stage       string            `json:"stage,omitempty"`
	Method      string            `json:"method"`
	Host        string            `json:"host"`
	Path        string            `json:"path"`
	RemoteIP    string            `json:"remote_ip"`
	CountryCode string            `json:"country_code,omitempty"`
	UserAgent   string            `json:"user_agent,omitempty"`
	RuleID      string            `json:"rule_id,omitempty"`
	Severity    string            `json:"severity,omitempty"`
	Reason      string            `json:"reason,omitempty"`
	StatusCode  int               `json:"status_code"`
	LatencyUs   int64             `json:"latency_us"`
	MLScore     float64           `json:"ml_score,omitempty"`
	ZTSubject   string            `json:"zt_subject,omitempty"`
	ShadowMode  bool              `json:"shadow_mode,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
	BodySnippet string            `json:"body_snippet,omitempty"`
}

// Emitter receives security events from the Data Plane hot path.
// Implementations MUST be non-blocking (Constitution §1.3).
type Emitter interface {
	Emit(ev SecurityEvent)
	Dropped() uint64
	Close() error
}
