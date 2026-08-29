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

func TestRuleEngine_Evaluate_Table(t *testing.T) {
	type testCtxKey string

	tests := []struct {
		name           string
		rules          []Rule
		beforeEval     func(*RuleEngine)
		phase          Phase
		ctx            context.Context
		req            *Request
		expectedAction Action
		expectedRuleID string
		expectedReason string
	}{
		{
			name: "Context values passed to Match function",
			rules: []Rule{
				{
					ID:      "ctx-rule",
					Name:    "Context Check",
					Phase:   PhaseRequest,
					Enabled: true,
					Match: func(ctx context.Context, req *Request) bool {
						val, ok := ctx.Value(testCtxKey("tenant")).(string)
						return ok && val == "tenant-123"
					},
					Action: ActionDeny,
					Reason: "Tenant denied",
				},
			},
			phase:          PhaseRequest,
			ctx:            context.WithValue(context.Background(), testCtxKey("tenant"), "tenant-123"),
			req:            &Request{Method: "GET", Path: "/api"},
			expectedAction: ActionDeny,
			expectedRuleID: "ctx-rule",
			expectedReason: "Tenant denied",
		},
		{
			name: "Match IP, Query and Headers",
			rules: []Rule{
				{
					ID:      "header-ip-rule",
					Name:    "IP and Header match",
					Phase:   PhaseRequest,
					Enabled: true,
					Match: func(ctx context.Context, req *Request) bool {
						return req.RemoteIP == "192.168.1.100" &&
							req.Query == "debug=true" &&
							len(req.Headers["X-Admin-Token"]) > 0 &&
							req.Headers["X-Admin-Token"][0] == "secret"
					},
					Action: ActionBlock,
					Reason: "Unauthorized admin debug attempt",
				},
			},
			phase: PhaseRequest,
			ctx:   context.Background(),
			req: &Request{
				Method:   "GET",
				Path:     "/admin",
				Query:    "debug=true",
				RemoteIP: "192.168.1.100",
				Headers: map[string][]string{
					"X-Admin-Token": {"secret"},
				},
			},
			expectedAction: ActionBlock,
			expectedRuleID: "header-ip-rule",
			expectedReason: "Unauthorized admin debug attempt",
		},
		{
			name: "Remove non-existent rule does not affect evaluation",
			rules: []Rule{
				{
					ID:      "keep-rule",
					Name:    "Keep Rule",
					Phase:   PhaseResponse,
					Enabled: true,
					Match: func(ctx context.Context, req *Request) bool {
						return true
					},
					Action: ActionLog,
					Reason: "Log response",
				},
			},
			beforeEval: func(engine *RuleEngine) {
				engine.RemoveRule("non-existent-id")
			},
			phase:          PhaseResponse,
			ctx:            context.Background(),
			req:            &Request{Method: "GET", Path: "/"},
			expectedAction: ActionLog,
			expectedRuleID: "keep-rule",
			expectedReason: "Log response",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			engine := NewRuleEngine()
			for _, r := range tt.rules {
				engine.AddRule(r)
			}

			if tt.beforeEval != nil {
				tt.beforeEval(engine)
			}

			res := engine.Evaluate(tt.ctx, tt.phase, tt.req)
			if res.Action != tt.expectedAction {
				t.Errorf("expected action %s, got %s", tt.expectedAction, res.Action)
			}
			if res.RuleID != tt.expectedRuleID {
				t.Errorf("expected rule ID %q, got %q", tt.expectedRuleID, res.RuleID)
			}
			if res.Reason != tt.expectedReason {
				t.Errorf("expected reason %q, got %q", tt.expectedReason, res.Reason)
			}
		})
	}
}

func TestRuleEngine_ConcurrentAccess(t *testing.T) {
	engine := NewRuleEngine()
	ctx := context.Background()

	engine.AddRule(Rule{
		ID:      "rule-base",
		Phase:   PhaseRequest,
		Enabled: true,
		Match:   func(ctx context.Context, req *Request) bool { return false },
		Action:  ActionAllow,
	})

	const goroutines = 10
	const iterations = 100
	done := make(chan struct{}, goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			req := &Request{Method: "GET", Path: "/test"}
			ruleID := "rule-concurrent"

			for j := 0; j < iterations; j++ {
				engine.Evaluate(ctx, PhaseRequest, req)
				if j%3 == 0 {
					engine.AddRule(Rule{
						ID:      ruleID,
						Phase:   PhaseRequest,
						Enabled: true,
						Match:   func(ctx context.Context, req *Request) bool { return req.Path == "/test" },
						Action:  ActionBlock,
					})
				} else if j%3 == 1 {
					engine.RemoveRule(ruleID)
				}
			}
		}()
	}

	for i := 0; i < goroutines; i++ {
		<-done
	}
}
