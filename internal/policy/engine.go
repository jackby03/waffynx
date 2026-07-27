package policy

import (
	"context"
	"sync"

	"github.com/jackby03/waffynx/internal/logging"
)

type RuleEngine struct {
	mu    sync.RWMutex
	rules []Rule
}

type Rule struct {
	ID          string
	Name        string
	Phase       Phase
	Priority    int
	Description string
	Enabled     bool
	Match       func(ctx context.Context, req *Request) bool
	Action      Action
	Reason      string
}

func NewRuleEngine() *RuleEngine {
	return &RuleEngine{}
}

func (re *RuleEngine) AddRule(rule Rule) {
	re.mu.Lock()
	defer re.mu.Unlock()
	re.rules = append(re.rules, rule)
}

func (re *RuleEngine) RemoveRule(id string) {
	re.mu.Lock()
	defer re.mu.Unlock()
	for i, rule := range re.rules {
		if rule.ID == id {
			re.rules = append(re.rules[:i], re.rules[i+1:]...)
			return
		}
	}
}

func (re *RuleEngine) Evaluate(ctx context.Context, phase Phase, req *Request) *Result {
	re.mu.RLock()
	defer re.mu.RUnlock()

	for _, rule := range re.rules {
		if !rule.Enabled || rule.Phase != phase {
			continue
		}
		if rule.Match != nil && rule.Match(ctx, req) {
			logging.Debug().
				Str("rule_id", rule.ID).
				Str("rule_name", rule.Name).
				Str("action", string(rule.Action)).
				Msg("policy rule matched")
			return &Result{
				Action: rule.Action,
				RuleID: rule.ID,
				Reason: rule.Reason,
			}
		}
	}

	return &Result{Action: ActionAllow}
}
