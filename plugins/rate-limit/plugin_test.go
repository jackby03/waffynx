package ratelimit

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackby03/waffynx/internal/plugin"
	"github.com/jackby03/waffynx/internal/ratelimit"
)

// failingLimiter is a backend that cannot answer, which is the whole point: a
// Redis outage, a closed pool, a timeout.
type failingLimiter struct{}

func (failingLimiter) Allow(context.Context, string, int, time.Duration) (bool, error) {
	return false, errors.New("backend down")
}

func (failingLimiter) Close() error { return nil }

func testContext() *plugin.Context {
	ctx := plugin.NewContext(context.Background(),
		httptest.NewRecorder(),
		httptest.NewRequest(http.MethodGet, "/", nil))
	ctx.Values["wn_ip"] = "203.0.113.7"
	return ctx
}

func newPluginWith(t *testing.T, limiter ratelimit.Limiter, failOpen bool) *RateLimitPlugin {
	t.Helper()
	p := &RateLimitPlugin{}
	if err := p.Init(map[string]interface{}{}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	p.limiter = limiter
	p.failOpen = failOpen
	return p
}

// TestRateLimitBackendFailureIsRefusedByDefault is the regression guard for a
// fail-open path: "rate limit check failed, allowing" meant that a limiter
// outage silently disabled rate limiting, with nothing but a warn log.
//
// Constitution §1.1: never silently bypass inspection.
func TestRateLimitBackendFailureIsRefusedByDefault(t *testing.T) {
	p := newPluginWith(t, failingLimiter{}, false)
	ctx := testContext()

	_, err := p.Execute(ctx)
	if err == nil {
		t.Fatal("a limiter backend failure must not allow the request by default")
	}
	if ctx.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want %d", ctx.StatusCode, http.StatusServiceUnavailable)
	}
}

// Choosing to keep serving is legitimate, but it has to be explicit.
func TestRateLimitBackendFailureAllowedWhenFailOpen(t *testing.T) {
	p := newPluginWith(t, failingLimiter{}, true)

	if _, err := p.Execute(testContext()); err != nil {
		t.Fatalf("fail_open must allow the request, got %v", err)
	}
}

// The normal path still works: a backend that decides is obeyed.
func TestRateLimitExceededIsRejected(t *testing.T) {
	p := newPluginWith(t, failingLimiter{}, false)
	p.limiter = &stubLimiter{allow: false}

	ctx := testContext()
	if _, err := p.Execute(ctx); err == nil {
		t.Fatal("expected the request to be limited")
	}
	if ctx.StatusCode != http.StatusTooManyRequests {
		t.Errorf("status = %d, want %d", ctx.StatusCode, http.StatusTooManyRequests)
	}
}

type stubLimiter struct{ allow bool }

func (s *stubLimiter) Allow(context.Context, string, int, time.Duration) (bool, error) {
	return s.allow, nil
}

func (s *stubLimiter) Close() error { return nil }
