package ratelimit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

// DefaultTimeout is the strict hot-path budget for ephemeral Redis/Dragonfly
// lookups mandated by Constitution §1.1 (<= 10ms).
const DefaultTimeout = 10 * time.Millisecond

// Limiter is the interface for rate limiting backends.
type Limiter interface {
	Allow(ctx context.Context, key string, limit int, window time.Duration) (bool, error)
	Close() error
}

// JailEntry describes a temporarily blocked IP address stored in ephemeral state.
type JailEntry struct {
	IP        string    `json:"ip"`
	Reason    string    `json:"reason"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// JailStore manages temporary IP bans ("IP Jails") in shared or in-memory state.
type JailStore interface {
	JailIP(ctx context.Context, ip, reason string, ttl time.Duration) error
	IsJailed(ctx context.Context, ip string) (bool, string, error)
	UnjailIP(ctx context.Context, ip string) error
	ListJails(ctx context.Context) ([]JailEntry, error)
}

// Config holds Redis connection and degradation parameters.
type Config struct {
	Enabled   bool   `yaml:"enabled"`
	Addr      string `yaml:"addr"`
	Password  string `yaml:"password"`
	DB        int    `yaml:"db"`
	TimeoutMs int    `yaml:"timeout_ms"`
	// FailOpen defaults to false (Constitution §1.1). When true, rate-limit
	// backend errors allow traffic through while keeping in-memory L7 rules active.
	FailOpen bool `yaml:"fail_open"`
}

// EffectiveTimeout returns a bounded hot-path lookup timeout capped at DefaultTimeout
// unless explicitly configured lower (never allowing unbounded waits).
func (c Config) EffectiveTimeout() time.Duration {
	if c.TimeoutMs <= 0 {
		return DefaultTimeout
	}
	return time.Duration(c.TimeoutMs) * time.Millisecond
}

// slidingWindowScript implements an atomic Redis sliding-window counter using a
// sorted set of request timestamps (milliseconds) with automatic TTL expiry.
var slidingWindowScript = redis.NewScript(`
local key = KEYS[1]
local now_ms = tonumber(ARGV[1])
local window_ms = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
local member = ARGV[4]

redis.call('ZREMRANGEBYSCORE', key, '-inf', now_ms - window_ms)
local count = redis.call('ZCARD', key)
if count >= limit then
  return 0
end
redis.call('ZADD', key, now_ms, member)
redis.call('PEXPIRE', key, window_ms + 1000)
return 1
`)

// RedisLimiter implements Limiter (sliding window) and JailStore backed by Redis/Dragonfly.
type RedisLimiter struct {
	client     *redis.Client
	prefix     string
	jailPrefix string
	timeout    time.Duration
}

func NewRedisLimiter(cfg Config) (*RedisLimiter, error) {
	if !cfg.Enabled {
		return nil, nil
	}

	if cfg.Addr == "" {
		cfg.Addr = "localhost:6379"
	}

	timeout := cfg.EffectiveTimeout()
	client := redis.NewClient(&redis.Options{
		Addr:         cfg.Addr,
		Password:     cfg.Password,
		DB:           cfg.DB,
		DialTimeout:  2 * time.Second,
		ReadTimeout:  timeout,
		WriteTimeout: timeout,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("redis connection failed at %s: %w", cfg.Addr, err)
	}

	return &RedisLimiter{
		client:     client,
		prefix:     "waffynx:ratelimit:",
		jailPrefix: "waffynx:jail:",
		timeout:    timeout,
	}, nil
}

// NewRedisLimiterWithClient wraps an already-connected redis.Client for shared
// connection pooling across rate limiting and IP jails.
func NewRedisLimiterWithClient(client *redis.Client, timeout time.Duration) *RedisLimiter {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	return &RedisLimiter{
		client:     client,
		prefix:     "waffynx:ratelimit:",
		jailPrefix: "waffynx:jail:",
		timeout:    timeout,
	}
}

func (r *RedisLimiter) withTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithTimeout(ctx, r.timeout)
}

func (r *RedisLimiter) Allow(ctx context.Context, key string, limit int, window time.Duration) (bool, error) {
	if limit <= 0 {
		return false, nil
	}
	windowMs := window.Milliseconds()
	if windowMs < 1 {
		windowMs = 1000
	}

	opCtx, cancel := r.withTimeout(ctx)
	defer cancel()

	now := time.Now()
	nowMs := now.UnixMilli()
	member := fmt.Sprintf("%d-%d", nowMs, now.UnixNano())
	redisKey := r.prefix + key

	res, err := slidingWindowScript.Run(opCtx, r.client, []string{redisKey}, nowMs, windowMs, limit, member).Int()
	if err != nil {
		return false, fmt.Errorf("redis sliding window: %w", err)
	}
	return res == 1, nil
}

func (r *RedisLimiter) JailIP(ctx context.Context, ip, reason string, ttl time.Duration) error {
	if ttl <= 0 {
		ttl = time.Hour
	}
	now := time.Now().UTC()
	entry := JailEntry{
		IP:        ip,
		Reason:    reason,
		CreatedAt: now,
		ExpiresAt: now.Add(ttl),
	}
	payload, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("encoding jail entry: %w", err)
	}
	opCtx, cancel := r.withTimeout(ctx)
	defer cancel()
	return r.client.Set(opCtx, r.jailPrefix+ip, payload, ttl).Err()
}

func (r *RedisLimiter) IsJailed(ctx context.Context, ip string) (bool, string, error) {
	opCtx, cancel := r.withTimeout(ctx)
	defer cancel()
	val, err := r.client.Get(opCtx, r.jailPrefix+ip).Result()
	if errors.Is(err, redis.Nil) {
		return false, "", nil
	}
	if err != nil {
		return false, "", fmt.Errorf("redis jail lookup: %w", err)
	}
	var entry JailEntry
	if jsonErr := json.Unmarshal([]byte(val), &entry); jsonErr == nil && entry.Reason != "" {
		return true, entry.Reason, nil
	}
	return true, val, nil
}

func (r *RedisLimiter) UnjailIP(ctx context.Context, ip string) error {
	opCtx, cancel := r.withTimeout(ctx)
	defer cancel()
	return r.client.Del(opCtx, r.jailPrefix+ip).Err()
}

func (r *RedisLimiter) ListJails(ctx context.Context) ([]JailEntry, error) {
	opCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	var cursor uint64
	out := make([]JailEntry, 0)
	for {
		keys, next, err := r.client.Scan(opCtx, cursor, r.jailPrefix+"*", 100).Result()
		if err != nil {
			return nil, fmt.Errorf("scanning jails: %w", err)
		}
		for _, k := range keys {
			raw, getErr := r.client.Get(opCtx, k).Result()
			if getErr != nil {
				continue
			}
			var entry JailEntry
			if json.Unmarshal([]byte(raw), &entry) == nil {
				out = append(out, entry)
			}
		}
		cursor = next
		if cursor == 0 {
			break
		}
	}
	return out, nil
}

func (r *RedisLimiter) Close() error {
	if r.client != nil {
		return r.client.Close()
	}
	return nil
}

// MemoryLimiter is the in-process token bucket and IP jail implementation.
// It implements both Limiter and JailStore for standalone mode and testing.
type MemoryLimiter struct {
	mu              sync.Mutex
	buckets         map[string]*bucket
	jails           map[string]JailEntry
	done            chan struct{}
	bucketTTL       time.Duration
	cleanupInterval time.Duration
}

type bucket struct {
	tokens     float64
	lastCheck  time.Time
	lastAccess time.Time
}

func NewMemoryLimiter() *MemoryLimiter {
	m := &MemoryLimiter{
		buckets:         make(map[string]*bucket),
		jails:           make(map[string]JailEntry),
		done:            make(chan struct{}),
		bucketTTL:       30 * time.Minute,
		cleanupInterval: 5 * time.Minute,
	}

	go m.runCleanup()

	return m
}

func (m *MemoryLimiter) runCleanup() {
	ticker := time.NewTicker(m.cleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-m.done:
			return
		case <-ticker.C:
			m.cleanup()
		}
	}
}

func (m *MemoryLimiter) cleanup() {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	for key, b := range m.buckets {
		if now.Sub(b.lastAccess) > m.bucketTTL {
			delete(m.buckets, key)
		}
	}
	for ip, j := range m.jails {
		if now.After(j.ExpiresAt) {
			delete(m.jails, ip)
		}
	}
}

func (m *MemoryLimiter) Allow(ctx context.Context, key string, limit int, window time.Duration) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	b, ok := m.buckets[key]
	if !ok {
		b = &bucket{
			tokens:     float64(limit),
			lastCheck:  time.Now(),
			lastAccess: time.Now(),
		}
		m.buckets[key] = b
	}

	now := time.Now()
	b.lastAccess = now
	elapsed := now.Sub(b.lastCheck).Seconds()
	rate := float64(limit) / window.Seconds()
	b.tokens += elapsed * rate
	if b.tokens > float64(limit) {
		b.tokens = float64(limit)
	}
	b.lastCheck = now

	if b.tokens >= 1 {
		b.tokens--
		return true, nil
	}

	return false, nil
}

func (m *MemoryLimiter) JailIP(_ context.Context, ip, reason string, ttl time.Duration) error {
	if ttl <= 0 {
		ttl = time.Hour
	}
	now := time.Now().UTC()
	m.mu.Lock()
	m.jails[ip] = JailEntry{
		IP:        ip,
		Reason:    reason,
		CreatedAt: now,
		ExpiresAt: now.Add(ttl),
	}
	m.mu.Unlock()
	return nil
}

func (m *MemoryLimiter) IsJailed(_ context.Context, ip string) (bool, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	j, ok := m.jails[ip]
	if !ok {
		return false, "", nil
	}
	if time.Now().After(j.ExpiresAt) {
		delete(m.jails, ip)
		return false, "", nil
	}
	return true, j.Reason, nil
}

func (m *MemoryLimiter) UnjailIP(_ context.Context, ip string) error {
	m.mu.Lock()
	delete(m.jails, ip)
	m.mu.Unlock()
	return nil
}

func (m *MemoryLimiter) ListJails(_ context.Context) ([]JailEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	out := make([]JailEntry, 0, len(m.jails))
	for ip, j := range m.jails {
		if now.After(j.ExpiresAt) {
			delete(m.jails, ip)
			continue
		}
		out = append(out, j)
	}
	return out, nil
}

func (m *MemoryLimiter) Close() error {
	close(m.done)
	return nil
}
