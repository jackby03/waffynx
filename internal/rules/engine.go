package rules

import (
	"net"
	"path/filepath"
	"slices"
	"strings"
	"sync"

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

	Methods     []string `json:"methods,omitempty"`
	PathPattern string   `json:"path_pattern,omitempty"`
	PathExact   string   `json:"path_exact,omitempty"`
	Hosts       []string `json:"hosts,omitempty"`
	IPs         []string `json:"ips,omitempty"`
	IPCIDRs     []string `json:"ip_cidrs,omitempty"`
	HeaderName  string   `json:"header_name,omitempty"`
	HeaderValue string   `json:"header_value,omitempty"`
	BodyContains string  `json:"body_contains,omitempty"`
	QueryParam  string   `json:"query_param,omitempty"`
	QueryValue  string   `json:"query_value,omitempty"`
}

type Engine struct {
	mu    sync.RWMutex
	rules []CustomRule
}

func NewEngine() *Engine {
	return &Engine{}
}

func (e *Engine) AddRule(r CustomRule) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rules = append(e.rules, r)
}

func (e *Engine) RemoveRule(id string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for i, r := range e.rules {
		if r.ID == id {
			e.rules = append(e.rules[:i], e.rules[i+1:]...)
			return
		}
	}
}

func (e *Engine) List() []CustomRule {
	e.mu.RLock()
	defer e.mu.RUnlock()
	result := make([]CustomRule, len(e.rules))
	copy(result, e.rules)
	return result
}

func (e *Engine) Evaluate(req *policy.Request) *policy.Result {
	e.mu.RLock()
	defer e.mu.RUnlock()

	for _, rule := range e.rules {
		if !rule.Enabled {
			continue
		}
		if e.matchRule(&rule, req) {
			logging.Debug().Str("rule_id", rule.ID).Str("action", string(rule.Action)).Msg("custom rule matched")
			return &policy.Result{
				Action: rule.Action,
				RuleID: rule.ID,
				Reason: rule.Description,
			}
		}
	}

	return &policy.Result{Action: ActionAllow}
}

func (e *Engine) matchRule(rule *CustomRule, req *policy.Request) bool {
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

	for _, cidr := range rule.IPCIDRs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		ip := net.ParseIP(req.RemoteIP)
		if ip == nil || !ipNet.Contains(ip) {
			return false
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
		queryIdx := strings.IndexByte(req.Path, '?')
		if queryIdx < 0 {
			return false
		}
		query := req.Path[queryIdx+1:]
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
			if found && key == rule.QueryParam {
				if rule.QueryValue != "" && val != rule.QueryValue {
					return false
				}
				return true
			}
		}
		return false
	}

	return true
}
