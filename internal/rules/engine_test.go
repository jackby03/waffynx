package rules

import (
	"testing"

	"github.com/jackby03/waffynx/internal/policy"
)

func TestNewEngine(t *testing.T) {
	e := NewEngine()
	if e == nil {
		t.Fatal("expected engine")
	}
}

func TestAddAndList(t *testing.T) {
	e := NewEngine()
	e.AddRule(CustomRule{ID: "rule-1", Name: "Test", Enabled: true, Action: ActionBlock})
	e.AddRule(CustomRule{ID: "rule-2", Name: "Test 2", Enabled: true, Action: ActionLog})

	rules := e.List()
	if len(rules) != 2 {
		t.Errorf("expected 2 rules, got %d", len(rules))
	}
}

func TestRemove(t *testing.T) {
	e := NewEngine()
	e.AddRule(CustomRule{ID: "rule-1", Action: ActionBlock})
	e.AddRule(CustomRule{ID: "rule-2", Action: ActionAllow})
	e.RemoveRule("rule-1")

	if len(e.List()) != 1 {
		t.Errorf("expected 1 rule after removal, got %d", len(e.List()))
	}
	if e.List()[0].ID != "rule-2" {
		t.Error("expected rule-2 to remain")
	}
}

func TestEvaluate_MethodMatch(t *testing.T) {
	e := NewEngine()
	e.AddRule(CustomRule{
		ID:      "block-post",
		Enabled: true,
		Action:  ActionBlock,
		Methods: []string{"POST"},
	})

	req := &policy.Request{Method: "POST", Path: "/api/data"}
	result := e.Evaluate(req)
	if result.Action != ActionBlock {
		t.Errorf("expected block, got %s", result.Action)
	}

	req.Method = "GET"
	result = e.Evaluate(req)
	if result.Action != ActionAllow {
		t.Errorf("expected allow for GET, got %s", result.Action)
	}
}

func TestEvaluate_PathExact(t *testing.T) {
	e := NewEngine()
	e.AddRule(CustomRule{
		ID:        "block-login",
		Enabled:   true,
		Action:    ActionDeny,
		PathExact: "/api/login",
	})

	result := e.Evaluate(&policy.Request{Path: "/api/login"})
	if result.Action != ActionDeny {
		t.Errorf("expected deny, got %s", result.Action)
	}

	result = e.Evaluate(&policy.Request{Path: "/api/logout"})
	if result.Action != ActionAllow {
		t.Errorf("expected allow for /api/logout, got %s", result.Action)
	}
}

func TestEvaluate_PathPattern(t *testing.T) {
	e := NewEngine()
	e.AddRule(CustomRule{
		ID:          "block-admin",
		Enabled:     true,
		Action:      ActionBlock,
		PathPattern: "/admin/*",
	})

	result := e.Evaluate(&policy.Request{Path: "/admin/users"})
	if result.Action != ActionBlock {
		t.Errorf("expected block, got %s", result.Action)
	}

	result = e.Evaluate(&policy.Request{Path: "/api/users"})
	if result.Action != ActionAllow {
		t.Errorf("expected allow, got %s", result.Action)
	}
}

func TestEvaluate_HostMatch(t *testing.T) {
	e := NewEngine()
	e.AddRule(CustomRule{
		ID:      "block-bad-host",
		Enabled: true,
		Action:  ActionBlock,
		Hosts:   []string{"evil.com"},
	})

	result := e.Evaluate(&policy.Request{Host: "evil.com", Path: "/"})
	if result.Action != ActionBlock {
		t.Errorf("expected block, got %s", result.Action)
	}

	result = e.Evaluate(&policy.Request{Host: "good.com", Path: "/"})
	if result.Action != ActionAllow {
		t.Errorf("expected allow, got %s", result.Action)
	}
}

func TestEvaluate_IPMatch(t *testing.T) {
	e := NewEngine()
	e.AddRule(CustomRule{
		ID:      "block-ip",
		Enabled: true,
		Action:  ActionBlock,
		IPs:     []string{"10.0.0.1"},
	})

	result := e.Evaluate(&policy.Request{RemoteIP: "10.0.0.1", Path: "/"})
	if result.Action != ActionBlock {
		t.Errorf("expected block, got %s", result.Action)
	}
}

func TestEvaluate_IPCIDR(t *testing.T) {
	e := NewEngine()
	e.AddRule(CustomRule{
		ID:       "block-range",
		Enabled:  true,
		Action:   ActionBlock,
		IPCIDRs:  []string{"10.0.0.0/8"},
	})

	result := e.Evaluate(&policy.Request{RemoteIP: "10.1.2.3", Path: "/"})
	if result.Action != ActionBlock {
		t.Errorf("expected block for 10.1.2.3, got %s", result.Action)
	}

	result = e.Evaluate(&policy.Request{RemoteIP: "192.168.1.1", Path: "/"})
	if result.Action != ActionAllow {
		t.Errorf("expected allow for 192.168.1.1, got %s", result.Action)
	}
}

func TestEvaluate_HeaderMatch(t *testing.T) {
	e := NewEngine()
	e.AddRule(CustomRule{
		ID:          "block-bot",
		Enabled:     true,
		Action:      ActionBlock,
		HeaderName:  "User-Agent",
		HeaderValue: "Googlebot/2.1",
	})

	req := &policy.Request{
		Path:    "/",
		Headers: map[string][]string{"User-Agent": {"Googlebot/2.1"}},
	}
	result := e.Evaluate(req)
	if result.Action != ActionBlock {
		t.Errorf("expected block, got %s", result.Action)
	}

	req2 := &policy.Request{
		Path:    "/",
		Headers: map[string][]string{"User-Agent": {"Mozilla/5.0"}},
	}
	result2 := e.Evaluate(req2)
	if result2.Action != ActionAllow {
		t.Errorf("expected allow, got %s", result2.Action)
	}
}

func TestEvaluate_BodyContains(t *testing.T) {
	e := NewEngine()
	e.AddRule(CustomRule{
		ID:           "block-sqli",
		Enabled:      true,
		Action:       ActionBlock,
		BodyContains: "DROP TABLE",
	})

	result := e.Evaluate(&policy.Request{Body: []byte("SELECT * FROM users; DROP TABLE users;")})
	if result.Action != ActionBlock {
		t.Errorf("expected block, got %s", result.Action)
	}

	result = e.Evaluate(&policy.Request{Body: []byte("SELECT * FROM users")})
	if result.Action != ActionAllow {
		t.Errorf("expected allow, got %s", result.Action)
	}
}

func TestEvaluate_QueryParam(t *testing.T) {
	e := NewEngine()
	e.AddRule(CustomRule{
		ID:         "block-sqli-param",
		Enabled:    true,
		Action:     ActionBlock,
		QueryParam: "id",
	})

	result := e.Evaluate(&policy.Request{Path: "/api/users?id=123"})
	if result.Action != ActionBlock {
		t.Errorf("expected block for matching query param, got %s", result.Action)
	}

	result = e.Evaluate(&policy.Request{Path: "/api/products?page=1"})
	if result.Action != ActionAllow {
		t.Errorf("expected allow for non-matching param, got %s", result.Action)
	}

	result = e.Evaluate(&policy.Request{Path: "/no-params"})
	if result.Action != ActionAllow {
		t.Errorf("expected allow for no params, got %s", result.Action)
	}
}

func TestEvaluate_Disabled(t *testing.T) {
	e := NewEngine()
	e.AddRule(CustomRule{
		ID:      "disabled",
		Enabled: false,
		Action:  ActionBlock,
		Methods: []string{"GET"},
	})

	result := e.Evaluate(&policy.Request{Method: "GET", Path: "/"})
	if result.Action != ActionAllow {
		t.Errorf("expected allow for disabled rule, got %s", result.Action)
	}
}

func TestEvaluate_Combined(t *testing.T) {
	e := NewEngine()
	e.AddRule(CustomRule{
		ID:          "combined",
		Enabled:     true,
		Action:      ActionBlock,
		Methods:     []string{"POST"},
		PathPattern: "/api/*",
		Hosts:       []string{"example.com"},
	})

	result := e.Evaluate(&policy.Request{Method: "POST", Path: "/api/data", Host: "example.com"})
	if result.Action != ActionBlock {
		t.Errorf("expected block, got %s", result.Action)
	}

	result = e.Evaluate(&policy.Request{Method: "GET", Path: "/api/data", Host: "example.com"})
	if result.Action != ActionAllow {
		t.Errorf("expected allow (wrong method), got %s", result.Action)
	}
}
