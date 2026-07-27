package appsec

import (
	"context"
	"testing"
)

func TestBasicScorer_SQLiURL(t *testing.T) {
	s := NewBasicScorer()
	ctx := context.Background()

	tests := []struct {
		name     string
		uri      string
		expected Verdict
	}{
		{"union select", "/users?id=1 UNION SELECT 1,2,3--", VerdictBlock},
		{"or 1=1", "/login?user=admin' OR 1=1--", VerdictBlock},
		{"or 1=1 variant", "/login?user=' OR '1'='1", VerdictBlock},
		{"information_schema", "/db?table=information_schema.tables", VerdictBlock},
		{"normal query", "/users?id=42", VerdictAllow},
		{"normal path", "/api/health", VerdictAllow},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := s.Evaluate(ctx, &Features{
				URI:     tt.uri,
				Host:    "example.com",
				Method:  "GET",
			})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.Verdict != tt.expected {
				t.Errorf("expected %s, got %s (score=%.2f, reasons=%v)",
					tt.expected, result.Verdict, result.Score, result.Reasons)
			}
		})
	}
}

func TestBasicScorer_XSS(t *testing.T) {
	s := NewBasicScorer()
	ctx := context.Background()

	tests := []struct {
		name     string
		uri      string
		expected Verdict
	}{
		{"script tag", "/page?x=<script>alert(1)</script>", VerdictBlock},
		{"onerror handler", "/img?src=x onerror=alert(1)", VerdictBlock},
		{"javascript protocol", "/redirect?url=javascript:alert(1)", VerdictBlock},
		{"document.cookie", "/eval?code=document.cookie", VerdictBlock},
		{"normal text", "/page?text=hello world", VerdictAllow},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := s.Evaluate(ctx, &Features{
				URI:    tt.uri,
				Host:   "example.com",
				Method: "GET",
			})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.Verdict != tt.expected {
				t.Errorf("expected %s, got %s (score=%.2f, reasons=%v)",
					tt.expected, result.Verdict, result.Score, result.Reasons)
			}
		})
	}
}

func TestBasicScorer_PathTraversal(t *testing.T) {
	s := NewBasicScorer()
	ctx := context.Background()

	result, err := s.Evaluate(ctx, &Features{
		URI:    "/download?file=../../../etc/passwd",
		Host:   "example.com",
		Method: "GET",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Verdict != VerdictBlock {
		t.Errorf("expected block, got %s (score=%.2f)", result.Verdict, result.Score)
	}
}

func TestBasicScorer_CmdInjection(t *testing.T) {
	s := NewBasicScorer()
	ctx := context.Background()

	result, err := s.Evaluate(ctx, &Features{
		URI:    "/ping?host=8.8.8.8;cat /etc/passwd",
		Host:   "example.com",
		Method: "GET",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Verdict != VerdictBlock {
		t.Errorf("expected block, got %s (score=%.2f)", result.Verdict, result.Score)
	}
}

func TestBasicScorer_NormalRequests(t *testing.T) {
	s := NewBasicScorer()
	ctx := context.Background()

	tests := []string{
		"/api/users",
		"/health",
		"/products?category=electronics&page=1",
		"/blog/hello-world",
		"/images/logo.png",
	}

	for _, uri := range tests {
		t.Run(uri, func(t *testing.T) {
			result, err := s.Evaluate(ctx, &Features{
				URI:    uri,
				Host:   "example.com",
				Method: "GET",
			})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.Verdict == VerdictBlock {
				t.Errorf("expected allow, got block for %s (score=%.2f, reasons=%v)",
					uri, result.Score, result.Reasons)
			}
		})
	}
}

func TestBasicScorer_BodyInspection(t *testing.T) {
	s := NewBasicScorer()
	ctx := context.Background()

	tests := []struct {
		name     string
		uri      string
		body     []byte
		expected Verdict
	}{
		{"sqli in body", "/api/login", []byte(`{"user":"admin","pass":"' OR 1=1--"}`), VerdictBlock},
		{"xss in body", "/api/review", []byte(`{"comment":"<script>alert(1)</script>"}`), VerdictBlock},
		{"normal json", "/api/login", []byte(`{"user":"admin","pass":"secret123"}`), VerdictAllow},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := s.Evaluate(ctx, &Features{
				URI:      tt.uri,
				Body:     tt.body,
				Host:     "example.com",
				Method:   "POST",
				HasPayload: true,
			})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.Verdict != tt.expected {
				t.Errorf("expected %s, got %s (score=%.2f, reasons=%v)",
					tt.expected, result.Verdict, result.Score, result.Reasons)
			}
		})
	}
}

func TestCalculateEntropy(t *testing.T) {
	tests := []struct {
		input    string
		expected float64
	}{
		{"", 0},
		{"aaaa", 0},              // all same = 0 entropy
		{"ab", 1.0},              // 50/50 = 1 bit
		{"abcd", 2.0},             // 4 unique = 2 bits
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := calculateEntropy(tt.input)
			if got < tt.expected-0.01 || got > tt.expected+0.01 {
				t.Errorf("calculateEntropy(%q) = %f, want ~%f", tt.input, got, tt.expected)
			}
		})
	}
}

func TestAnalyzeCharDistribution(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected float64
	}{
		{"empty", "", 0},
		{"normal text", "hello world", 0},
		{"URL encoded", "%27%20OR%201%3D1%27%20--", 0.35}, // ~16% encoded chars
		{"high special", "!@#$%^&*()_+{}|:\"<>?", 0.45},   // 100% special
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := analyzeCharDistribution(tt.input)
			if tt.expected == 0 && got > 0 {
				t.Errorf("analyzeCharDistribution(%q) = %f, want 0", tt.input, got)
			} else if tt.expected > 0 && got == 0 {
				t.Errorf("analyzeCharDistribution(%q) = 0, want >0", tt.input)
			}
		})
	}
}

func TestBasicScorer_BadUserAgent(t *testing.T) {
	s := NewBasicScorer()
	ctx := context.Background()

	result, err := s.Evaluate(ctx, &Features{
		URI:       "/api/users",
		Host:      "example.com",
		Method:    "GET",
		UserAgent: "sqlmap/1.0",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Score == 0 {
		t.Errorf("bad UA should produce some score, got 0")
	}
}

func TestBasicScorer_MissingUserAgent(t *testing.T) {
	s := NewBasicScorer()
	ctx := context.Background()

	result, err := s.Evaluate(ctx, &Features{
		URI:       "/api/users",
		Host:      "example.com",
		Method:    "GET",
		UserAgent: "",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Verdict == VerdictBlock {
		t.Errorf("missing UA alone should not block, got %s", result.Verdict)
	}
	if result.Score == 0 {
		t.Error("missing UA should add some score")
	}
}

func TestBasicScorer_LongURI(t *testing.T) {
	s := NewBasicScorer()
	ctx := context.Background()

	longURI := make([]byte, 3000)
	for i := range longURI {
		longURI[i] = 'a'
	}

	result, err := s.Evaluate(ctx, &Features{
		URI:       "/search?q=" + string(longURI),
		Host:      "example.com",
		Method:    "GET",
		URILength: 3008,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Score == 0 {
		t.Error("very long URI should produce some score")
	}
}

func TestScoreThreshold(t *testing.T) {
	tests := []struct {
		score    float64
		expected Verdict
	}{
		{0.0, VerdictAllow},
		{0.35, VerdictAllow},
		{0.45, VerdictSuspicious},
		{0.69, VerdictSuspicious},
		{0.70, VerdictBlock},
		{0.95, VerdictBlock},
		{1.0, VerdictBlock},
	}

	for _, tt := range tests {
		got := ScoreThreshold(tt.score)
		if got != tt.expected {
			t.Errorf("ScoreThreshold(%.2f) = %s, want %s", tt.score, got, tt.expected)
		}
	}
}
