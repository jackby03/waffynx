package rules

import (
	"net"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackby03/waffynx/internal/logging"
	"github.com/jackby03/waffynx/internal/policy"
)

type Action = policy.Action

const (
	ActionAllow Action = policy.ActionAllow
	ActionDeny  Action = policy.ActionDeny
	ActionBlock Action = policy.ActionBlock
	ActionLog   Action = policy.ActionLog
)

type CustomRule struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Enabled     bool   `json:"enabled"`
	Priority    int    `json:"priority"`
	Action      Action `json:"action"`

	Methods      []string `json:"methods,omitempty"`
	PathPattern  string   `json:"path_pattern,omitempty"`
	PathExact    string   `json:"path_exact,omitempty"`
	Hosts        []string `json:"hosts,omitempty"`
	IPs          []string `json:"ips,omitempty"`
	IPCIDRs      []string `json:"ip_cidrs,omitempty"`
	HeaderName   string   `json:"header_name,omitempty"`
	HeaderValue  string   `json:"header_value,omitempty"`
	BodyContains string   `json:"body_contains,omitempty"`
	QueryParam   string   `json:"query_param,omitempty"`
	QueryValue   string   `json:"query_value,omitempty"`
}

// Exclusion waives a specific rule (or "*" for all rules) on a matching host,
// path, or query parameter to tune false positives without restarting the engine.
type Exclusion struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	RuleID     string    `json:"rule_id"`
	Host       string    `json:"host,omitempty"`
	PathExact  string    `json:"path_exact,omitempty"`
	PathPrefix string    `json:"path_prefix,omitempty"`
	Param      string    `json:"param,omitempty"`
	Reason     string    `json:"reason,omitempty"`
	Enabled    bool      `json:"enabled"`
	CreatedAt  time.Time `json:"created_at,omitempty"`
}

type compiledRule struct {
	raw   CustomRule
	cidrs []*net.IPNet
}

type compiledSnapshot struct {
	rules      []compiledRule
	exclusions []Exclusion
}

// Engine evaluates custom rules and false-positive exclusions on the hot path
// without acquiring locks (Constitution §1.2). Mutations compile a fresh
// snapshot off the hot path and swap it atomically via atomic.Pointer.
type Engine struct {
	// writeMu serialises mutations; hot-path readers only touch snap.
	writeMu    sync.Mutex
	rules      []CustomRule
	exclusions []Exclusion
	snap       atomic.Pointer[compiledSnapshot]
}

func NewEngine() *Engine {
	e := &Engine{}
	e.snap.Store(&compiledSnapshot{})
	return e
}

func compileSnapshot(rawRules []CustomRule, rawExclusions []Exclusion) *compiledSnapshot {
	sorted := make([]CustomRule, len(rawRules))
	copy(sorted, rawRules)
	sort.SliceStable(sorted, func(i, j int) bool {
		return sorted[i].Priority < sorted[j].Priority
	})

	compiled := make([]compiledRule, len(sorted))
	for i, r := range sorted {
		cr := compiledRule{raw: r}
		if len(r.IPCIDRs) > 0 {
			cr.cidrs = make([]*net.IPNet, 0, len(r.IPCIDRs))
			for _, cidr := range r.IPCIDRs {
				if _, ipNet, err := net.ParseCIDR(cidr); err == nil {
					cr.cidrs = append(cr.cidrs, ipNet)
				}
			}
		}
		compiled[i] = cr
	}

	ex := make([]Exclusion, len(rawExclusions))
	copy(ex, rawExclusions)

	return &compiledSnapshot{
		rules:      compiled,
		exclusions: ex,
	}
}

func (e *Engine) publishLocked() {
	e.snap.Store(compileSnapshot(e.rules, e.exclusions))
}

// ReplaceSnapshot atomically replaces the entire rules and exclusions set.
// Used by the Control Plane hot-reload subscriber (Constitution §1.2).
func (e *Engine) ReplaceSnapshot(newRules []CustomRule, newExclusions []Exclusion) {
	compiled := compileSnapshot(newRules, newExclusions)
	e.writeMu.Lock()
	e.rules = append([]CustomRule(nil), newRules...)
	e.exclusions = append([]Exclusion(nil), newExclusions...)
	e.snap.Store(compiled)
	e.writeMu.Unlock()
}

func (e *Engine) AddRule(r CustomRule) {
	e.writeMu.Lock()
	defer e.writeMu.Unlock()
	for i, existing := range e.rules {
		if existing.ID == r.ID && r.ID != "" {
			e.rules[i] = r
			e.publishLocked()
			return
		}
	}
	e.rules = append(e.rules, r)
	e.publishLocked()
}

func (e *Engine) RemoveRule(id string) {
	e.writeMu.Lock()
	defer e.writeMu.Unlock()
	for i, r := range e.rules {
		if r.ID == id {
			e.rules = append(e.rules[:i], e.rules[i+1:]...)
			e.publishLocked()
			return
		}
	}
}

func (e *Engine) List() []CustomRule {
	e.writeMu.Lock()
	defer e.writeMu.Unlock()
	result := make([]CustomRule, len(e.rules))
	copy(result, e.rules)
	return result
}

func (e *Engine) AddExclusion(ex Exclusion) {
	e.writeMu.Lock()
	defer e.writeMu.Unlock()
	for i, existing := range e.exclusions {
		if existing.ID == ex.ID && ex.ID != "" {
			e.exclusions[i] = ex
			e.publishLocked()
			return
		}
	}
	e.exclusions = append(e.exclusions, ex)
	e.publishLocked()
}

func (e *Engine) RemoveExclusion(id string) {
	e.writeMu.Lock()
	defer e.writeMu.Unlock()
	for i, ex := range e.exclusions {
		if ex.ID == id {
			e.exclusions = append(e.exclusions[:i], e.exclusions[i+1:]...)
			e.publishLocked()
			return
		}
	}
}

func (e *Engine) ListExclusions() []Exclusion {
	e.writeMu.Lock()
	defer e.writeMu.Unlock()
	result := make([]Exclusion, len(e.exclusions))
	copy(result, e.exclusions)
	return result
}

// IsExcluded reports whether ruleID is waived for req by an active exclusion.
// Runs completely lock-free on the hot path.
func (e *Engine) IsExcluded(req *policy.Request, ruleID string) bool {
	if req == nil {
		return false
	}
	snap := e.snap.Load()
	if snap == nil || len(snap.exclusions) == 0 {
		return false
	}
	rawPath := req.Path
	cleanPath := rawPath
	if idx := strings.IndexByte(rawPath, '?'); idx >= 0 {
		cleanPath = rawPath[:idx]
	}
	for i := range snap.exclusions {
		ex := &snap.exclusions[i]
		if !ex.Enabled {
			continue
		}
		if ex.RuleID != "" && ex.RuleID != "*" && ex.RuleID != ruleID {
			continue
		}
		if ex.Host != "" && !strings.EqualFold(ex.Host, req.Host) {
			continue
		}
		if ex.PathExact != "" && cleanPath != ex.PathExact && rawPath != ex.PathExact {
			continue
		}
		if ex.PathPrefix != "" && !strings.HasPrefix(cleanPath, ex.PathPrefix) {
			continue
		}
		if ex.Param != "" && !hasQueryParam(rawPath, ex.Param, "") {
			continue
		}
		return true
	}
	return false
}

// Evaluate checks compiled custom rules against req lock-free.
func (e *Engine) Evaluate(req *policy.Request) *policy.Result {
	snap := e.snap.Load()
	if snap == nil {
		return &policy.Result{Action: ActionAllow}
	}

	for i := range snap.rules {
		cr := &snap.rules[i]
		if !cr.raw.Enabled {
			continue
		}
		if matchRule(cr, req) {
			if e.IsExcluded(req, cr.raw.ID) {
				continue
			}
			logging.Debug().Str("rule_id", cr.raw.ID).Str("action", string(cr.raw.Action)).Msg("custom rule matched")
			return &policy.Result{
				Action: cr.raw.Action,
				RuleID: cr.raw.ID,
				Reason: cr.raw.Description,
			}
		}
	}

	return &policy.Result{Action: ActionAllow}
}

func matchRule(cr *compiledRule, req *policy.Request) bool {
	rule := &cr.raw
	if len(rule.Methods) > 0 && !slices.Contains(rule.Methods, req.Method) {
		return false
	}

	if rule.PathExact != "" && req.Path != rule.PathExact {
		return false
	}

	if rule.PathPattern != "" {
		matched, _ := filepath.Match(rule.PathPattern, req.Path)
		if !matched {
			return false
		}
	}

	if len(rule.Hosts) > 0 && !slices.Contains(rule.Hosts, req.Host) {
		return false
	}

	if len(rule.IPs) > 0 && !slices.Contains(rule.IPs, req.RemoteIP) {
		return false
	}

	if len(cr.cidrs) > 0 {
		ip := net.ParseIP(req.RemoteIP)
		if ip == nil {
			return false
		}
		for _, ipNet := range cr.cidrs {
			if !ipNet.Contains(ip) {
				return false
			}
		}
	}

	if rule.HeaderName != "" {
		values, ok := req.Headers[rule.HeaderName]
		if !ok {
			if rule.HeaderValue != "" {
				return false
			}
		} else if rule.HeaderValue != "" && !slices.Contains(values, rule.HeaderValue) {
			return false
		}
	}

	if rule.BodyContains != "" && !strings.Contains(string(req.Body), rule.BodyContains) {
		return false
	}

	if rule.QueryParam != "" {
		if !hasQueryParam(req.Path, rule.QueryParam, rule.QueryValue) {
			return false
		}
	}

	return true
}

func hasQueryParam(rawPath, wantKey, wantVal string) bool {
	queryIdx := strings.IndexByte(rawPath, '?')
	if queryIdx < 0 {
		return false
	}
	query := rawPath[queryIdx+1:]
	for len(query) > 0 {
		var pair string
		if idx := strings.IndexByte(query, '&'); idx >= 0 {
			pair = query[:idx]
			query = query[idx+1:]
		} else {
			pair = query
			query = ""
		}
		key, val, found := strings.Cut(pair, "=")
		if found && key == wantKey {
			if wantVal != "" && val != wantVal {
				return false
			}
			return true
		}
	}
	return false
}
