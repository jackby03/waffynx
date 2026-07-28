package ratelimit

import (
	"context"
	"testing"
	"time"
)

func TestMemoryLimiter_Allow(t *testing.T) {
	limiter := NewMemoryLimiter()
	ctx := context.Background()
	defer limiter.Close()

	key := "test-ip"
	limit := 10
	window := time.Second

	for i := 0; i < limit; i++ {
		allowed, err := limiter.Allow(ctx, key, limit, window)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !allowed {
			t.Errorf("request %d should be allowed", i+1)
		}
	}

	allowed, err := limiter.Allow(ctx, key, limit, window)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if allowed {
		t.Error("request should be rate limited after exceeding limit")
	}
}

func TestMemoryLimiter_TokenRefill(t *testing.T) {
	limiter := NewMemoryLimiter()
	ctx := context.Background()
	defer limiter.Close()

	key := "refill-test"
	limit := 2
	window := 100 * time.Millisecond

	allowed, _ := limiter.Allow(ctx, key, limit, window)
	if !allowed {
		t.Fatal("first request should be allowed")
	}
	allowed, _ = limiter.Allow(ctx, key, limit, window)
	if !allowed {
		t.Fatal("second request should be allowed")
	}
	allowed, _ = limiter.Allow(ctx, key, limit, window)
	if allowed {
		t.Fatal("third request should be denied")
	}

	time.Sleep(150 * time.Millisecond)

	allowed, _ = limiter.Allow(ctx, key, limit, window)
	if !allowed {
		t.Error("request should be allowed after window refill")
	}
}

func TestMemoryLimiter_DifferentKeys(t *testing.T) {
	limiter := NewMemoryLimiter()
	ctx := context.Background()
	defer limiter.Close()

	allowed, _ := limiter.Allow(ctx, "ip-a", 1, time.Second)
	if !allowed {
		t.Error("ip-a should be allowed")
	}

	allowed, _ = limiter.Allow(ctx, "ip-b", 1, time.Second)
	if !allowed {
		t.Error("ip-b should be allowed (different key)")
	}

	allowed, _ = limiter.Allow(ctx, "ip-a", 1, time.Second)
	if allowed {
		t.Error("ip-a should be rate limited")
	}
}

func TestRedisLimiter_NoConnection(t *testing.T) {
	cfg := Config{Enabled: true, Addr: "localhost:9999"}
	_, err := NewRedisLimiter(cfg)
	if err == nil {
		t.Error("expected error for unreachable Redis")
	}
}

func TestRedisLimiter_Disabled(t *testing.T) {
	limiter, err := NewRedisLimiter(Config{Enabled: false})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if limiter != nil {
		t.Error("expected nil limiter when disabled")
	}
}

func TestConfig_Defaults(t *testing.T) {
	cfg := Config{Enabled: true}
	if cfg.Addr != "" {
		return
	}
	limiter, err := NewRedisLimiter(cfg)
	if err == nil {
		defer limiter.Close()
	}
}
