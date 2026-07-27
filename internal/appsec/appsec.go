// Package appsec provides ML-based anomaly detection for HTTP requests.
//
// It defines an interface that can be backed by either:
//   - A pure Go anomaly scorer (for development/testing)
//   - The open-appsec C++ engine via a Unix socket bridge (for production)
//
// The scorer receives decoded request features and returns a score
// between 0.0 (safe) and 1.0 (malicious), plus a verdict.
package appsec

import "context"

// Verdict is the ML model's decision about a request.
type Verdict string

const (
	VerdictAllow    Verdict = "allow"
	VerdictBlock    Verdict = "block"
	VerdictSuspicious Verdict = "suspicious"
)

// Result holds the ML evaluation output for a single HTTP request.
type Result struct {
	Verdict     Verdict   `json:"verdict"`
	Score       float64   `json:"score"`        // 0.0 = safe, 1.0 = malicious
	Confidence  float64   `json:"confidence"`   // model confidence in its verdict
	Reasons     []string  `json:"reasons"`      // human-readable reasons
	Anomalies   []string  `json:"anomalies"`    // detected anomalies (SQLi, XSS-like, etc.)
	ModelName   string    `json:"model_name"`   // which model produced the verdict
}

// Features contains decoded, normalized request data for ML input.
type Features struct {
	Method       string
	URI          string
	Host         string
	ClientIP     string
	UserAgent    string
	ContentType  string
	Referer      string
	Body         []byte
	HeadersCount int
	URILength    int
	QueryParams  map[string]string
	HasPayload   bool
	PayloadSize  int64
}

// Scorer evaluates HTTP request features and returns a risk assessment.
type Scorer interface {
	// Evaluate runs the ML model on the given features and returns a verdict.
	Evaluate(ctx context.Context, features *Features) (*Result, error)

	// Name returns the scorer implementation name (e.g. "open-appsec", "basic-go").
	Name() string

	// Health checks if the scorer is operational.
	Health(ctx context.Context) error

	// Close releases any resources held by the scorer.
	Close() error
}

// ScoreThreshold returns true if the score exceeds the block threshold.
func ScoreThreshold(score float64) Verdict {
	switch {
	case score >= 0.70:
		return VerdictBlock
	case score >= 0.40:
		return VerdictSuspicious
	default:
		return VerdictAllow
	}
}
