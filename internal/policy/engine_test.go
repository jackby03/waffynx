package policy

import (
	"context"
	"testing"
)

func TestRuleEngine_AddAndEvaluate(t *testing.T) {
	engine := NewRuleEngine()
	ctx := context.Background()

	engine.AddRule(Rule{
		ID:      "block-sqli",
		Name:    "Block SQL Injection",
		Phase:   PhaseRequest,
		Enabled: true,
		Match: func(ctx context.Context, req *Request) bool {
			return req.Path == "/users?id=1' OR 1=1--"
		},
		Action: ActionBlock,
		Reason: "SQLi detected",
	})

	blocked := &Request{
		Method: "GET",
		Path:   "/users?id=1' OR 1=1--",
		Host:   "example.com",
	}

	allowed := &Request{
		Method: "GET",
		Path:   "/users?id=42",
		Host:   "example.com",
	}

	result := engine.Evaluate(ctx, PhaseRequest, blocked)
	if result.Action != ActionBlock {
		t.Errorf("expected block, got %s", result.Action)
	}
	if result.RuleID != "block-sqli" {
		t.Errorf("expected rule ID 'block-sqli', got %s", result.RuleID)
	}

	result = engine.Evaluate(ctx, PhaseRequest, allowed)
	if result.Action != ActionAllow {
		t.Errorf("expected allow, got %s", result.Action)
	}
}

func TestRuleEngine_DisabledRule(t *testing.T) {
	engine := NewRuleEngine()
	ctx := context.Background()

	engine.AddRule(Rule{
		ID:      "disabled-rule",
		Name:    "Disabled",
		Phase:   PhaseRequest,
		Enabled: false,
		Match: func(ctx context.Context, req *Request) bool {
			return true
		},
		Action: ActionBlock,
	})

	req := &Request{Method: "GET", Path: "/"}
	result := engine.Evaluate(ctx, PhaseRequest, req)

	if result.Action != ActionAllow {
		t.Errorf("disabled rule should not match, got %s", result.Action)
	}
}

func TestRuleEngine_WrongPhase(t *testing.T) {
	engine := NewRuleEngine()
	ctx := context.Background()

	engine.AddRule(Rule{
		ID:      "response-rule",
		Name:    "Response Only",
		Phase:   PhaseResponse,
		Enabled: true,
		Match: func(ctx context.Context, req *Request) bool {
			return true
		},
		Action: ActionDeny,
	})

	req := &Request{Method: "GET", Path: "/"}
	result := engine.Evaluate(ctx, PhaseRequest, req)

	if result.Action != ActionAllow {
		t.Errorf("response-phase rule should not fire in request phase, got %s", result.Action)
	}
}

func TestRuleEngine_RemoveRule(t *testing.T) {
	engine := NewRuleEngine()
	ctx := context.Background()

	engine.AddRule(Rule{
		ID:      "temp-rule",
		Name:    "Temp",
		Phase:   PhaseRequest,
		Enabled: true,
		Match: func(ctx context.Context, req *Request) bool {
			return true
		},
		Action: ActionBlock,
	})

	engine.RemoveRule("temp-rule")

	req := &Request{Method: "GET", Path: "/"}
	result := engine.Evaluate(ctx, PhaseRequest, req)

	if result.Action != ActionAllow {
		t.Errorf("removed rule should not match, got %s", result.Action)
	}
}

func TestRuleEngine_FirstMatchWins(t *testing.T) {
	engine := NewRuleEngine()
	ctx := context.Background()

	engine.AddRule(Rule{
		ID:      "rule-a",
		Name:    "A - allow",
		Phase:   PhaseRequest,
		Enabled: true,
		Match: func(ctx context.Context, req *Request) bool {
			return true
		},
		Action: ActionLog,
		Reason: "should match first",
	})

	engine.AddRule(Rule{
		ID:      "rule-b",
		Name:    "B - should not fire",
		Phase:   PhaseRequest,
		Enabled: true,
		Match: func(ctx context.Context, req *Request) bool {
			return true
		},
		Action: ActionBlock,
		Reason: "should not fire",
	})

	req := &Request{Method: "GET", Path: "/"}
	result := engine.Evaluate(ctx, PhaseRequest, req)

	if result.Action != ActionLog {
		t.Errorf("first matching rule should win, expected log got %s", result.Action)
	}
	if result.RuleID != "rule-a" {
		t.Errorf("expected rule-a to match, got %s", result.RuleID)
	}
}

func TestRuleEngine_EmptyEngine(t *testing.T) {
	engine := NewRuleEngine()
	ctx := context.Background()

	req := &Request{Method: "GET", Path: "/"}
	result := engine.Evaluate(ctx, PhaseRequest, req)

	if result.Action != ActionAllow {
		t.Errorf("empty engine should allow, got %s", result.Action)
	}
}

func TestRuleEngine_MatchWithBody(t *testing.T) {
	engine := NewRuleEngine()
	ctx := context.Background()

	engine.AddRule(Rule{
		ID:      "block-body-sqli",
		Name:    "Block SQLi in body",
		Phase:   PhaseRequest,
		Enabled: true,
		Match: func(ctx context.Context, req *Request) bool {
			return string(req.Body) == `{"user":"admin' OR 1=1--"}`
		},
		Action: ActionBlock,
		Reason: "SQLi in body",
	})

	badReq := &Request{
		Method: "POST",
		Path:   "/login",
		Body:   []byte(`{"user":"admin' OR 1=1--"}`),
	}

	goodReq := &Request{
		Method: "POST",
		Path:   "/login",
		Body:   []byte(`{"user":"admin"}`),
	}

	result := engine.Evaluate(ctx, PhaseRequest, badReq)
	if result.Action != ActionBlock {
		t.Errorf("expected block for body SQLi, got %s", result.Action)
	}

	result = engine.Evaluate(ctx, PhaseRequest, goodReq)
	if result.Action != ActionAllow {
		t.Errorf("expected allow for clean body, got %s", result.Action)
	}
}

func TestRuleEngine_NilMatch(t *testing.T) {
	engine := NewRuleEngine()
	ctx := context.Background()

	engine.AddRule(Rule{
		ID:      "nil-match",
		Name:    "No match function",
		Phase:   PhaseRequest,
		Enabled: true,
		Match:   nil,
		Action:  ActionBlock,
	})

	req := &Request{Method: "GET", Path: "/"}
	result := engine.Evaluate(ctx, PhaseRequest, req)

	if result.Action != ActionAllow {
		t.Errorf("rule with nil match should not fire, got %s", result.Action)
	}
}
