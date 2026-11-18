package engine

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackby03/waffynx/internal/appsec"
	"github.com/jackby03/waffynx/internal/plugin"
	"github.com/jackby03/waffynx/internal/policy"
)

// allowEvaluator keeps the policy stage out of the way so these tests observe the
// scorer's failure policy and nothing else.
type allowEvaluator struct{}

func (allowEvaluator) Evaluate(context.Context, policy.Phase, *policy.Request) *policy.Result {
	return &policy.Result{Action: policy.ActionAllow}
}

// failingScorer models an unreachable scoring engine: a dead socket, a timeout.
type failingScorer struct{}

func (failingScorer) Name() string                 { return "failing" }
func (failingScorer) Health(context.Context) error { return errors.New("scorer down") }
func (failingScorer) Close() error                 { return nil }
func (failingScorer) Evaluate(context.Context, *appsec.Features) (*appsec.Result, error) {
	return nil, errors.New("scorer down")
}

func decideWithFailingScorer(t *testing.T, failOpen bool) Decision {
	t.Helper()
	s := NewSidecar("", allowEvaluator{}, plugin.NewChain(), failingScorer{}, nil, nil, nil, nil)
	s.SetAppSecFailOpen(failOpen)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	return s.Decide(w, r, &policy.Request{Method: "GET", Host: "app.example.com", Path: "/"}, nil)
}

// TestScorerFailureBlocksByDefault is the regression guard for §7.3: an
// unreachable scorer used to be reported as "allow" by the client itself, so an
// engine outage stopped inspection silently and the site looked healthy.
//
// Constitution §1.1: never silently bypass uninspected traffic.
func TestScorerFailureBlocksByDefault(t *testing.T) {
	d := decideWithFailingScorer(t, false)

	if d.Allow {
		t.Fatal("an unreachable scorer must not allow the request by default")
	}
	if d.Stage != "appsec-error" {
		t.Errorf("Stage = %q, want appsec-error", d.Stage)
	}
	if d.RuleID != "appsec-unavailable" {
		t.Errorf("RuleID = %q, want appsec-unavailable", d.RuleID)
	}
}

// Choosing to keep serving is allowed, but it must be an explicit setting.
func TestScorerFailureAllowsWhenFailOpen(t *testing.T) {
	d := decideWithFailingScorer(t, true)

	if !d.Allow {
		t.Fatalf("appsec.fail_open=true must allow, got stage %q", d.Stage)
	}
}
