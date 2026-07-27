package policy

import "context"

type Action string

const (
	ActionAllow Action = "allow"
	ActionDeny  Action = "deny"
	ActionBlock Action = "block"
	ActionLog   Action = "log"
)

type Phase string

const (
	PhaseRequest  Phase = "request"
	PhaseResponse Phase = "response"
)

type Request struct {
	Method   string
	Host     string
	Path     string
	Query    string
	Headers  map[string][]string
	Body     []byte
	RemoteIP string
}

type Result struct {
	Action   Action
	RuleID   string
	Reason   string
	Score    float64
	Metadata map[string]string
}

type Evaluator interface {
	Evaluate(ctx context.Context, phase Phase, req *Request) *Result
}
