package ratelimit

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestMemoryLimiter_Allow(t *testing.T) {
	limiter := NewMemoryLimiter()
	defer limiter.Close()
	ctx := context.Background()

	// Limit 5 requests per second
	for i := 0; i < 5; i++ {
		allowed, err := limiter.Allow(ctx, "user1", 5, time.Second)
		if err != nil {
			t.Fatalf("unexpected error on request %d: %v", i, err)
		}
		if !allowed {
			t.Errorf("expected request %d to be allowed", i)
		}
	}
}

func TestMemoryLimiter_Deny(t *testing.T) {
	limiter := NewMemoryLimiter()
	defer limiter.Close()
	ctx := context.Background()

	// Exhaust limit of 3
	for i := 0; i < 3; i++ {
		allowed, _ := limiter.Allow(ctx, "user_deny", 3, time.Second)
		if !allowed {
			t.Fatalf("expected request %d to be allowed", i)
		}
	}

	// 4th request should be denied
	allowed, err := limiter.Allow(ctx, "user_deny", 3, time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if allowed {
		t.Error("expected 4th request to be denied, but was allowed")
	}
}

func TestMemoryLimiter_Refill(t *testing.T) {
	limiter := NewMemoryLimiter()
	defer limiter.Close()
	ctx := context.Background()

	// Exhaust limit of 2 in 100ms
	window := 100 * time.Millisecond
	limiter.Allow(ctx, "user_refill", 2, window)
	limiter.Allow(ctx, "user_refill", 2, window)

	allowed, _ := limiter.Allow(ctx, "user_refill", 2, window)
	if allowed {
		t.Fatal("expected request to be denied before refill")
	}

	// Wait for bucket token refill (sleep 120ms)
	time.Sleep(120 * time.Millisecond)

	allowed, err := limiter.Allow(ctx, "user_refill", 2, window)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !allowed {
		t.Error("expected request to be allowed after token refill")
	}
}

func TestMemoryLimiter_MultipleIPs(t *testing.T) {
	limiter := NewMemoryLimiter()
	defer limiter.Close()
	ctx := context.Background()

	// Exhaust IP 1 (limit 1)
	limiter.Allow(ctx, "192.168.1.1", 1, time.Second)
	allowed1, _ := limiter.Allow(ctx, "192.168.1.1", 1, time.Second)
	if allowed1 {
		t.Error("expected IP1 second request to be denied")
	}

	// IP 2 should still be allowed
	allowed2, err := limiter.Allow(ctx, "192.168.1.2", 1, time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !allowed2 {
		t.Error("expected IP2 first request to be allowed")
	}
}

func TestMemoryLimiter_Concurrent(t *testing.T) {
	limiter := NewMemoryLimiter()
	defer limiter.Close()
	ctx := context.Background()

	var wg sync.WaitGroup
	goroutines := 50
	requestsPerRoutine := 20

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		key := fmt.Sprintf("key_%d", i%5) // 5 distinct keys
		go func(k string) {
			defer wg.Done()
			for j := 0; j < requestsPerRoutine; j++ {
				_, _ = limiter.Allow(ctx, k, 10, time.Second)
			}
		}(key)
	}

	wg.Wait()
}

func TestMemoryLimiter_Cleanup(t *testing.T) {
	limiter := NewMemoryLimiter()
	defer limiter.Close()
	ctx := context.Background()

	// Add bucket
	limiter.Allow(ctx, "stale_ip", 10, time.Second)

	// Artificially make bucket old
	limiter.mu.Lock()
	if b, ok := limiter.buckets["stale_ip"]; ok {
		b.lastAccess = time.Now().Add(-1 * time.Hour)
	}
	limiter.mu.Unlock()

	// Trigger manual cleanup
	limiter.cleanup()

	limiter.mu.Lock()
	_, exists := limiter.buckets["stale_ip"]
	limiter.mu.Unlock()

	if exists {
		t.Error("expected stale bucket to be deleted by cleanup()")
	}
}

func TestRedisLimiter_Disabled(t *testing.T) {
	cfg := Config{Enabled: false}
	rl, err := NewRedisLimiter(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rl != nil {
		t.Error("expected nil RedisLimiter when disabled")
	}
}
