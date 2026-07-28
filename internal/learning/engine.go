package learning

import (
	"sort"
	"strings"
	"sync"
	"time"
)

type Verdict string

const (
	VerdictAllow Verdict = "allow"
	VerdictBlock Verdict = "block"
)

type Record struct {
	Timestamp   time.Time         `json:"timestamp"`
	Method      string            `json:"method"`
	Path        string            `json:"path"`
	Host        string            `json:"host"`
	RemoteIP    string            `json:"remote_ip"`
	ContentType string            `json:"content_type,omitempty"`
	BodySnippet string            `json:"body_snippet,omitempty"`
	Verdict     Verdict           `json:"verdict"`
	RuleID      string            `json:"rule_id,omitempty"`
	Reason      string            `json:"reason,omitempty"`
	Duration    time.Duration     `json:"duration_ms,omitempty"`
	Tags        map[string]string `json:"tags,omitempty"`
}

type Suggestion struct {
	Type        string  `json:"type"`        // "whitelist", "blocklist", "rate_limit"
	Pattern     string  `json:"pattern"`     // URI pattern or IP
	Description string  `json:"description"` // Human readable
	Confidence  float64 `json:"confidence"`  // 0.0 - 1.0
	Matches     int     `json:"matches"`     // How many requests matched
	Sample      string  `json:"sample"`      // Example matching request
}

type pathGroup struct {
	prefix    string
	count     int
	blocked   int
	lastSeen  time.Time
}

type Engine struct {
	mu       sync.RWMutex
	records  []Record
	maxSize  int
	position int
	enabled  bool
}

func NewEngine(maxSize int) *Engine {
	if maxSize <= 0 {
		maxSize = 1000
	}
	return &Engine{
		records: make([]Record, 0, maxSize),
		maxSize: maxSize,
		enabled: true,
	}
}

func (e *Engine) Enable()  { e.mu.Lock(); e.enabled = true; e.mu.Unlock() }
func (e *Engine) Disable() { e.mu.Lock(); e.enabled = false; e.mu.Unlock() }

func (e *Engine) Record(r Record) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if !e.enabled {
		return
	}

	r.Timestamp = time.Now()

	if len(e.records) < e.maxSize {
		e.records = append(e.records, r)
	} else {
		e.records[e.position] = r
		e.position = (e.position + 1) % e.maxSize
	}
}

func (e *Engine) Records() []Record {
	e.mu.RLock()
	defer e.mu.RUnlock()

	result := make([]Record, len(e.records))
	copy(result, e.records)
	return result
}

func (e *Engine) Stats() map[string]interface{} {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var allowed, blocked int
	for _, r := range e.records {
		if r.Verdict == VerdictAllow {
			allowed++
		} else {
			blocked++
		}
	}

	total := len(e.records)
	return map[string]interface{}{
		"total":   total,
		"allowed": allowed,
		"blocked": blocked,
		"max":     e.maxSize,
	}
}

func (e *Engine) Suggestions() []Suggestion {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if len(e.records) == 0 {
		return nil
	}

	var suggestions []Suggestion

	whitelistSuggestions := e.analyzeWhitelist()
	suggestions = append(suggestions, whitelistSuggestions...)

	blocklistSuggestions := e.analyzeBlocklist()
	suggestions = append(suggestions, blocklistSuggestions...)

	rateSuggestions := e.analyzeRate()
	suggestions = append(suggestions, rateSuggestions...)

	sort.Slice(suggestions, func(i, j int) bool {
		return suggestions[i].Confidence > suggestions[j].Confidence
	})

	return suggestions
}

func (e *Engine) analyzeWhitelist() []Suggestion {
	paths := make(map[string]*pathGroup)

	for _, r := range e.records {
		prefix := normalizePath(r.Path)
		g, ok := paths[prefix]
		if !ok {
			g = &pathGroup{prefix: prefix}
			paths[prefix] = g
		}
		g.count++
		if r.Verdict == VerdictBlock {
			g.blocked++
		}
		if r.Timestamp.After(g.lastSeen) {
			g.lastSeen = r.Timestamp
		}
	}

	var suggestions []Suggestion
	for _, g := range paths {
		if g.count < 10 {
			continue
		}

		blockRate := float64(g.blocked) / float64(g.count)

		if blockRate > 0.1 {
			suggestions = append(suggestions, Suggestion{
				Type:        "whitelist",
				Pattern:     g.prefix,
				Description: "High false positive rate — consider whitelisting this path pattern",
				Confidence:  blockRate,
				Matches:     g.blocked,
				Sample:      g.prefix,
			})
		}

		if blockRate == 0 && g.count >= 50 {
			suggestions = append(suggestions, Suggestion{
				Type:        "whitelist",
				Pattern:     g.prefix,
				Description: "Frequently accessed with zero false positives — safe to add to bypass list",
				Confidence:  0.95,
				Matches:     g.count,
				Sample:      g.prefix,
			})
		}
	}

	return suggestions
}

func (e *Engine) analyzeBlocklist() []Suggestion {
	ipCounts := make(map[string]int)
	ipBlocked := make(map[string]int)

	for _, r := range e.records {
		if r.RemoteIP == "" {
			continue
		}
		ipCounts[r.RemoteIP]++
		if r.Verdict == VerdictBlock {
			ipBlocked[r.RemoteIP]++
		}
	}

	var suggestions []Suggestion
	for ip, total := range ipCounts {
		blocked := ipBlocked[ip]
		if total >= 5 && blocked > 0 {
			ratio := float64(blocked) / float64(total)
			if ratio >= 0.8 {
				suggestions = append(suggestions, Suggestion{
					Type:        "blocklist",
					Pattern:     ip,
					Description: "IP with high block ratio — consider adding to permanent blocklist",
					Confidence:  ratio,
					Matches:     blocked,
					Sample:      ip,
				})
			}
		}
	}

	return suggestions
}

func (e *Engine) analyzeRate() []Suggestion {
	ipCounts := make(map[string]int)

	for _, r := range e.records {
		if r.RemoteIP == "" {
			continue
		}
		ipCounts[r.RemoteIP]++
	}

	var suggestions []Suggestion
	for ip, count := range ipCounts {
		if count >= 50 {
			rate := float64(count) / float64(len(e.records))
			if rate > 0.1 {
				suggestions = append(suggestions, Suggestion{
					Type:        "rate_limit",
					Pattern:     ip,
					Description: "IP generating high traffic volume — consider stricter rate limits",
					Confidence:  rate * 5,
					Matches:     count,
					Sample:      ip,
				})
			}
		}
	}

	return suggestions
}

type DatasetRecord struct {
	URI          string  `json:"uri"`
	Method       string  `json:"method"`
	Host         string  `json:"host"`
	RemoteIP     string  `json:"remote_ip"`
	ContentType  string  `json:"content_type"`
	URILength    int     `json:"uri_length"`
	BodyLength   int     `json:"body_length"`
	HasQuery     bool    `json:"has_query"`
	QueryParams  int     `json:"query_params"`
	Label        string  `json:"label"`
	RuleID       string  `json:"rule_id,omitempty"`
	Reason       string  `json:"reason,omitempty"`
	Timestamp    string  `json:"timestamp"`
}

func (e *Engine) ExportDataset() []DatasetRecord {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var dataset []DatasetRecord
	for _, r := range e.records {
		entry := DatasetRecord{
			URI:        r.Path,
			Method:     r.Method,
			Host:       r.Host,
			RemoteIP:   r.RemoteIP,
			ContentType: r.ContentType,
			URILength:  len(r.Path),
			BodyLength: len(r.BodySnippet),
			HasQuery:   strings.Contains(r.Path, "?"),
			QueryParams: strings.Count(r.Path, "&") + 1,
			Label:      string(r.Verdict),
			RuleID:     r.RuleID,
			Reason:     r.Reason,
			Timestamp:  r.Timestamp.Format(time.RFC3339),
		}
		if entry.HasQuery && !strings.Contains(r.Path, "=") {
			entry.QueryParams = 0
		}
		dataset = append(dataset, entry)
	}

	return dataset
}

func normalizePath(path string) string {
	idx := strings.Index(path, "?")
	if idx >= 0 {
		path = path[:idx]
	}

	parts := strings.Split(strings.Trim(path, "/"), "/")

	for i, p := range parts {
		if isNumeric(p) {
			parts[i] = "{id}"
		} else if isUUID(p) {
			parts[i] = "{uuid}"
		} else if isHex(p) && len(p) > 16 {
			parts[i] = "{hash}"
		}
	}

	return "/" + strings.Join(parts, "/")
}

func isNumeric(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return len(s) > 0
}

func isUUID(s string) bool {
	return len(s) == 36 && strings.Count(s, "-") == 4
}

func isHex(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return len(s) > 0
}
