package appsec

import (
	"context"
	"fmt"
	"math"
	"strings"
	"sync"
	"time"
	"unicode"
)

const (
	// Entropy threshold constants for normalizing Shannon entropy scores (4.5-8.0 -> 0.0-1.0).
	minEntropyThreshold = 4.5
	maxEntropyThreshold = 8.0
	entropyRange        = maxEntropyThreshold - minEntropyThreshold
)

// BasicScorer provides ML-like anomaly detection in pure Go.
//
// It uses heuristics similar to what an ML model would learn:
//   - Entropy scoring (random-looking strings = suspicious)
//   - Character distribution analysis
//   - Known attack pattern density
//   - Request frequency per client IP
//
// This is a development/staging scorer. In production, replace with
// the open-appsec bridge that uses real ML models.
type BasicScorer struct {
	mu      sync.RWMutex
	enabled bool

	// Attack patterns (same ones we'd feed to an ML feature extractor)
	sqliPatterns    []string
	xssPatterns     []string
	pathTraversal   []string
	cmdInjection    []string

	// Rate tracking per IP (simple frequency anomaly)
	ipFrequency     map[string]*ipCounter
	maxReqPerMinute int
}

type ipCounter struct {
	count     int
	windowStart time.Time
}

func toLowerSlice(slice []string) []string {
	res := make([]string, len(slice))
	for i, s := range slice {
		res[i] = strings.ToLower(s)
	}
	return res
}

func NewBasicScorer() *BasicScorer {
	return &BasicScorer{
		enabled: true,
		sqliPatterns: toLowerSlice([]string{
			"union select", "union/**/select",
			"or 1=1", "' or '1'='1",
			"or 1=1--", "' or 1=1#",
			"information_schema", "load_file(",
			"outfile", "char(",
		}),
		xssPatterns: toLowerSlice([]string{
			"<script", "</script>",
			"javascript:",
			"onerror=", "onload=", "onclick=", "onfocus=",
			"alert(", "prompt(", "confirm(",
			"document.cookie", "document.write",
			"eval(", "fromcharcode",
		}),
		pathTraversal: toLowerSlice([]string{
			"../", "..\\",
			"/etc/passwd", "/etc/shadow",
			"boot.ini", "win.ini",
			"proc/self/environ",
		}),
		cmdInjection: toLowerSlice([]string{
			";cat ", ";ls ", ";id ", ";wget ",
			"|cat ", "|ls ", "|id ",
			"&&cat ", "&&ls ", "&&id ",
			"$(cat ", "$(id)", "$(ls)",
			"`cat ", "`id`", "`ls`",
		}),
		ipFrequency:     make(map[string]*ipCounter),
		maxReqPerMinute: 300,
	}
}

func (s *BasicScorer) Name() string { return "basic-go" }

func (s *BasicScorer) Health(ctx context.Context) error {
	return nil
}

func (s *BasicScorer) Close() error {
	return nil
}

func (s *BasicScorer) Evaluate(ctx context.Context, features *Features) (*Result, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.enabled {
		return &Result{Verdict: VerdictAllow, Score: 0.0, ModelName: s.Name()}, nil
	}

	var (
		reasons   []string
		anomalies []string
		totalScore float64
	)

	// === 1. Pattern-based detection (supervised ML simulation) ===
	// High-risk patterns: immediate block regardless of other scores.

	// SQLi
	if sqliScore, matched := s.checkPatterns(features.URI, features.QueryParams, features.Body, s.sqliPatterns); sqliScore > 0 {
		totalScore += sqliScore * 0.80
		anomalies = append(anomalies, "sqli")
		reasons = append(reasons, fmt.Sprintf("SQLi pattern detected: %s", matched))
	}

	// XSS
	if xssScore, matched := s.checkPatterns(features.URI, features.QueryParams, features.Body, s.xssPatterns); xssScore > 0 {
		totalScore += xssScore * 0.80
		anomalies = append(anomalies, "xss")
		reasons = append(reasons, fmt.Sprintf("XSS pattern detected: %s", matched))
	}

	// Path traversal
	if ptScore, matched := s.checkPatterns(features.URI, features.QueryParams, features.Body, s.pathTraversal); ptScore > 0 {
		totalScore += ptScore * 0.75
		anomalies = append(anomalies, "path-traversal")
		reasons = append(reasons, fmt.Sprintf("Path traversal detected: %s", matched))
	}

	// Command injection
	if cmdScore, matched := s.checkPatterns(features.URI, features.QueryParams, features.Body, s.cmdInjection); cmdScore > 0 {
		totalScore += cmdScore * 0.80
		anomalies = append(anomalies, "cmd-injection")
		reasons = append(reasons, fmt.Sprintf("Command injection detected: %s", matched))
	}

	// Any high-risk pattern match → immediate block, skip other analysis
	if len(anomalies) > 0 && totalScore >= 0.70 {
		return &Result{
			Verdict:    VerdictBlock,
			Score:      totalScore,
			Confidence: 0.90,
			Reasons:    reasons,
			Anomalies:  anomalies,
			ModelName:  s.Name(),
		}, nil
	}

	// === 2. Entropy analysis (unsupervised ML simulation) ===

	// High entropy in URI or body = possible encoded payload
	entropy := calculateEntropy(features.URI)
	if len(features.Body) > 0 {
		bodyEntropy := calculateEntropy(string(features.Body))
		if bodyEntropy > entropy {
			entropy = bodyEntropy
		}
	}
	if entropy > minEntropyThreshold {
		entropyScore := (entropy - minEntropyThreshold) / entropyRange // normalize 4.5-8.0 -> 0.0-1.0
		if entropyScore > 1.0 {
			entropyScore = 1.0
		}
		totalScore += entropyScore * 0.15
		if entropyScore > 0.5 {
			anomalies = append(anomalies, "high-entropy")
			reasons = append(reasons, fmt.Sprintf("High URI entropy: %.2f", entropy))
		}
	}

	// === 3. Character distribution anomalies ===

	charScore := analyzeCharDistribution(features.URI)
	if len(features.Body) > 0 {
		bodyCharScore := analyzeCharDistribution(string(features.Body))
		if bodyCharScore > charScore {
			charScore = bodyCharScore
		}
	}
	totalScore += charScore * 0.10
	if charScore > 0.5 {
		anomalies = append(anomalies, "char-distribution")
		reasons = append(reasons, "Suspicious character distribution")
	}

	// === 4. Header anomalies ===

	headerScore := s.analyzeHeaders(features)
	totalScore += headerScore * 0.10
	if headerScore > 0.5 {
		anomalies = append(anomalies, "header-anomaly")
	}

	// === 5. Rate/frequency anomaly ===

	rateScore := s.checkRate(features.ClientIP)
	totalScore += rateScore * 0.10
	if rateScore > 0.5 {
		anomalies = append(anomalies, "rate-anomaly")
		reasons = append(reasons, fmt.Sprintf("High request rate from %s", features.ClientIP))
	}

	// === 6. URI length outlier ===

	if features.URILength > 2048 {
		lengthScore := math.Min(float64(features.URILength)/8192.0, 1.0)
		totalScore += lengthScore * 0.05
		anomalies = append(anomalies, "uri-length")
		reasons = append(reasons, fmt.Sprintf("Unusually long URI: %d chars", features.URILength))
	}

	// === Final scoring ===

	// Cap total score at 1.0
	if totalScore > 1.0 {
		totalScore = 1.0
	}

	verdict := ScoreThreshold(totalScore)

	confidence := 0.7 // base confidence
	if len(anomalies) >= 2 {
		confidence = 0.85
	}
	if len(anomalies) >= 3 {
		confidence = 0.95
	}

	return &Result{
		Verdict:    verdict,
		Score:      totalScore,
		Confidence: confidence,
		Reasons:    reasons,
		Anomalies:  anomalies,
		ModelName:  s.Name(),
	}, nil
}

// checkPatterns scans URI, query parameters, and body for known attack patterns.
// Returns a score (0-1) and the first matched pattern.
func (s *BasicScorer) checkPatterns(uri string, params map[string]string, body []byte, patterns []string) (float64, string) {
	lowerURI := strings.ToLower(uri)
	bodyStr := strings.ToLower(string(body))

	var lowerParams []string
	if len(params) > 0 {
		lowerParams = make([]string, 0, len(params))
		for _, val := range params {
			lowerParams = append(lowerParams, strings.ToLower(val))
		}
	}

	for _, pattern := range patterns {
		if strings.Contains(lowerURI, pattern) {
			return 0.9, pattern
		}

		for _, val := range lowerParams {
			if strings.Contains(val, pattern) {
				return 0.9, pattern
			}
		}

		if len(body) > 0 && strings.Contains(bodyStr, pattern) {
			return 0.9, pattern
		}
	}
	return 0.0, ""
}

// calculateEntropy computes Shannon entropy of a string.
// Higher values mean more random/disordered content.
func calculateEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}

	freq := make(map[rune]int)
	for _, c := range s {
		freq[c]++
	}

	var entropy float64
	n := float64(len(s))
	for _, count := range freq {
		p := float64(count) / n
		entropy -= p * math.Log2(p)
	}
	return entropy
}

// analyzeCharDistribution checks for unusual character mixes.
func analyzeCharDistribution(s string) float64 {
	if len(s) == 0 {
		return 0
	}

	var (
		upper, lower, digits, special, encoded int
		total                                   = len(s)
	)

	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case unicode.IsUpper(rune(c)):
			upper++
		case unicode.IsLower(rune(c)):
			lower++
		case unicode.IsDigit(rune(c)):
			digits++
		case c == '%':
			// Check for URL encoding pattern %XX
			if i+2 < len(s) && isHex(s[i+1]) && isHex(s[i+2]) {
				encoded++
			}
			special++
		default:
			special++
		}
	}

	// Heuristic: lots of %XX = URL-encoded payload
	encodedRatio := float64(encoded) / float64(total)
	if encodedRatio > 0.05 {
		return math.Min(encodedRatio*10.0, 1.0)
	}

	// Heuristic: high ratio of special chars
	specialRatio := float64(special) / float64(total)
	if specialRatio > 0.15 {
		return math.Min(specialRatio*3.0, 1.0)
	}

	return 0
}

func isHex(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

// analyzeHeaders checks for suspicious header patterns.
func (s *BasicScorer) analyzeHeaders(f *Features) float64 {
	var score float64
	var reasons int

	// Missing User-Agent is suspicious
	if f.UserAgent == "" {
		score += 0.3
		reasons++
	}

	// Known bad User-Agents
	lowerUA := strings.ToLower(f.UserAgent)
	badUAs := []string{"nikto", "sqlmap", "acunetix", "nessus", "burpsuite", "nmap", "masscan"}
	for _, bad := range badUAs {
		if strings.Contains(lowerUA, bad) {
			score += 0.8
			reasons++
			break
		}
	}

	// Very short or very long User-Agent
	if len(f.UserAgent) > 0 && len(f.UserAgent) < 10 {
		score += 0.2
		reasons++
	}
	if len(f.UserAgent) > 500 {
		score += 0.3
		reasons++
	}

	if reasons == 0 {
		return 0
	}
	return math.Min(score, 1.0)
}

// checkRate flags IPs making too many requests.
func (s *BasicScorer) checkRate(ip string) float64 {
	if ip == "" {
		return 0
	}

	now := time.Now()
	counter, exists := s.ipFrequency[ip]

	if !exists || now.Sub(counter.windowStart) > time.Minute {
		s.ipFrequency[ip] = &ipCounter{count: 1, windowStart: now}
		return 0
	}

	counter.count++
	rate := float64(counter.count) / float64(s.maxReqPerMinute)

	if rate > 1.0 {
		return math.Min(rate-1.0, 1.0)
	}
	return 0
}
