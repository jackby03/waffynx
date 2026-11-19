package ratelimit

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
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

func TestConfig_EffectiveTimeout(t *testing.T) {
	if got := (Config{}).EffectiveTimeout(); got != DefaultTimeout {
		t.Fatalf("expected default %v, got %v", DefaultTimeout, got)
	}
	if got := (Config{TimeoutMs: 7}).EffectiveTimeout(); got != 7*time.Millisecond {
		t.Fatalf("expected 7ms, got %v", got)
	}
}

func TestMemoryLimiter_Jails(t *testing.T) {
	limiter := NewMemoryLimiter()
	defer limiter.Close()
	ctx := context.Background()

	jailed, _, err := limiter.IsJailed(ctx, "203.0.113.5")
	if err != nil || jailed {
		t.Fatalf("expected unjailed IP, got jailed=%v err=%v", jailed, err)
	}

	if err := limiter.JailIP(ctx, "203.0.113.5", "credential stuffing", 200*time.Millisecond); err != nil {
		t.Fatalf("JailIP failed: %v", err)
	}
	jailed, reason, err := limiter.IsJailed(ctx, "203.0.113.5")
	if err != nil || !jailed || reason != "credential stuffing" {
		t.Fatalf("expected jailed with reason, got jailed=%v reason=%q err=%v", jailed, reason, err)
	}

	list, err := limiter.ListJails(ctx)
	if err != nil || len(list) != 1 || list[0].IP != "203.0.113.5" {
		t.Fatalf("unexpected jail list: %+v err=%v", list, err)
	}

	if err := limiter.UnjailIP(ctx, "203.0.113.5"); err != nil {
		t.Fatalf("UnjailIP failed: %v", err)
	}
	jailed, _, _ = limiter.IsJailed(ctx, "203.0.113.5")
	if jailed {
		t.Fatal("expected IP to be unjailed")
	}

	// Expiry check.
	_ = limiter.JailIP(ctx, "203.0.113.9", "short", 30*time.Millisecond)
	time.Sleep(50 * time.Millisecond)
	jailed, _, _ = limiter.IsJailed(ctx, "203.0.113.9")
	if jailed {
		t.Fatal("expected expired jail to clear")
	}

	// Default TTL and cleanup of expired jails.
	_ = limiter.JailIP(ctx, "203.0.113.10", "default ttl", 0)
	_ = limiter.JailIP(ctx, "203.0.113.11", "expired", 10*time.Millisecond)
	time.Sleep(25 * time.Millisecond)
	limiter.cleanup()
	list, _ = limiter.ListJails(ctx)
	if len(list) != 1 || list[0].IP != "203.0.113.10" {
		t.Fatalf("expected only active jail after cleanup, got %+v", list)
	}
}

// startFakeRedis serves minimal RESP2 responses (PING, EVALSHA/EVAL, SET, GET, DEL, SCAN)
// so RedisLimiter methods are exercised deterministically without external Redis.
func startFakeRedis(t *testing.T) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen fake redis: %v", err)
	}
	var mu sync.Mutex
	kv := make(map[string]string)
	done := make(chan struct{})

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				r := bufio.NewReader(c)
				for {
					line, err := r.ReadString('\n')
					if err != nil {
						return
					}
					if !strings.HasPrefix(line, "*") {
						continue
					}
					var nargs int
					_, _ = fmt.Sscanf(strings.TrimSpace(line), "*%d", &nargs)
					args := make([]string, 0, nargs)
					for i := 0; i < nargs; i++ {
						_, _ = r.ReadString('\n')
						val, err := r.ReadString('\n')
						if err != nil {
							return
						}
						args = append(args, strings.TrimRight(val, "\r\n"))
					}
					if len(args) == 0 {
						continue
					}
					cmd := strings.ToUpper(args[0])
					switch cmd {
					case "HELLO":
						_, _ = c.Write([]byte("-ERR unknown command HELLO\r\n"))
					case "CLIENT":
						_, _ = c.Write([]byte("+OK\r\n"))
					case "PING":
						_, _ = c.Write([]byte("+PONG\r\n"))
					case "EVALSHA", "EVAL":
						_, _ = c.Write([]byte(":1\r\n"))
					case "SET":
						if len(args) >= 3 {
							mu.Lock()
							kv[args[1]] = args[2]
							mu.Unlock()
						}
						_, _ = c.Write([]byte("+OK\r\n"))
					case "GET":
						mu.Lock()
						v, ok := kv[args[1]]
						mu.Unlock()
						if !ok {
							_, _ = c.Write([]byte("$-1\r\n"))
						} else {
							_, _ = fmt.Fprintf(c, "$%d\r\n%s\r\n", len(v), v)
						}
					case "DEL":
						mu.Lock()
						delete(kv, args[1])
						mu.Unlock()
						_, _ = c.Write([]byte(":1\r\n"))
					case "SCAN":
						mu.Lock()
						keys := make([]string, 0, len(kv))
						for k := range kv {
							keys = append(keys, k)
						}
						mu.Unlock()
						var b strings.Builder
						fmt.Fprintf(&b, "*2\r\n$1\r\n0\r\n*%d\r\n", len(keys))
						for _, k := range keys {
							fmt.Fprintf(&b, "$%d\r\n%s\r\n", len(k), k)
						}
						_, _ = c.Write([]byte(b.String()))
					default:
						_, _ = c.Write([]byte("+OK\r\n"))
					}
				}
			}(conn)
		}
	}()

	return ln.Addr().String(), func() {
		close(done)
		_ = ln.Close()
	}
}

func TestRedisLimiter_SlidingWindowAndJails(t *testing.T) {
	addr, stop := startFakeRedis(t)
	defer stop()

	rl, err := NewRedisLimiter(Config{Enabled: true, Addr: addr, TimeoutMs: 100})
	if err != nil {
		t.Fatalf("NewRedisLimiter failed: %v", err)
	}
	defer rl.Close()

	ctx := context.Background()
	allowed, err := rl.Allow(ctx, "198.51.100.1", 10, time.Second)
	if err != nil || !allowed {
		t.Fatalf("expected Allow=true, got allowed=%v err=%v", allowed, err)
	}
	allowedZero, err := rl.Allow(ctx, "198.51.100.1", 0, time.Second)
	if err != nil || allowedZero {
		t.Fatalf("expected Allow=false for limit=0, got allowed=%v err=%v", allowedZero, err)
	}

	if err := rl.JailIP(ctx, "198.51.100.2", "bot abuse", time.Minute); err != nil {
		t.Fatalf("JailIP failed: %v", err)
	}
	jailed, reason, err := rl.IsJailed(ctx, "198.51.100.2")
	if err != nil || !jailed || reason != "bot abuse" {
		t.Fatalf("expected jailed with reason, got jailed=%v reason=%q err=%v", jailed, reason, err)
	}
	notJailed, _, err := rl.IsJailed(ctx, "198.51.100.99")
	if err != nil || notJailed {
		t.Fatalf("expected unjailed, got %v err=%v", notJailed, err)
	}
	jails, err := rl.ListJails(ctx)
	if err != nil || len(jails) != 1 || jails[0].IP != "198.51.100.2" {
		t.Fatalf("unexpected ListJails: %+v err=%v", jails, err)
	}
	if err := rl.UnjailIP(ctx, "198.51.100.2"); err != nil {
		t.Fatalf("UnjailIP failed: %v", err)
	}

	// Verify NewRedisLimiterWithClient wrapper.
	wrapped := NewRedisLimiterWithClient(redis.NewClient(&redis.Options{Addr: "127.0.0.1:1"}), 0)
	defer wrapped.Close()
	if _, err := wrapped.Allow(ctx, "k", 5, time.Second); err == nil {
		t.Fatal("expected error against closed port")
	}
}
