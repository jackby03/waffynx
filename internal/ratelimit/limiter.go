package ratelimit

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

// Limiter is the interface for rate limiting backends.
type Limiter interface {
	Allow(ctx context.Context, key string, limit int, window time.Duration) (bool, error)
	Close() error
}

// Config holds Redis connection parameters.
type Config struct {
	Enabled  bool   `yaml:"enabled"`
	Addr     string `yaml:"addr"`
	Password string `yaml:"password"`
	DB       int    `yaml:"db"`
}

// RedisLimiter implements Limiter using Redis fixed-window counters.
type RedisLimiter struct {
	client *redis.Client
	prefix string
}

func NewRedisLimiter(cfg Config) (*RedisLimiter, error) {
	if !cfg.Enabled {
		return nil, nil
	}

	if cfg.Addr == "" {
		cfg.Addr = "localhost:6379"
	}

	client := redis.NewClient(&redis.Options{
		Addr:     cfg.Addr,
		Password: cfg.Password,
		DB:       cfg.DB,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		client.Close()
		return nil, fmt.Errorf("redis connection failed at %s: %w", cfg.Addr, err)
	}

	return &RedisLimiter{
		client: client,
		prefix: "waffynx:ratelimit:",
	}, nil
}

func (r *RedisLimiter) Allow(ctx context.Context, key string, limit int, window time.Duration) (bool, error) {
	windowSec := int64(window.Seconds())
	if windowSec < 1 {
		windowSec = 1
	}

	now := time.Now().Unix()
	bucket := now / windowSec
	redisKey := fmt.Sprintf("%s%s:%d", r.prefix, key, bucket)

	count, err := r.client.Incr(ctx, redisKey).Result()
	if err != nil {
		return false, fmt.Errorf("redis incr: %w", err)
	}

	if count == 1 {
		r.client.Expire(ctx, redisKey, window+time.Second)
	}

	return int(count) <= limit, nil
}

func (r *RedisLimiter) Close() error {
	if r.client != nil {
		return r.client.Close()
	}
	return nil
}

// MemoryLimiter is the in-process token bucket implementation.
// It implements the same Limiter interface for swapping backends.
type MemoryLimiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
}

type bucket struct {
	tokens    float64
	lastCheck time.Time
}

func NewMemoryLimiter() *MemoryLimiter {
	return &MemoryLimiter{
		buckets: make(map[string]*bucket),
	}
}

func (m *MemoryLimiter) Allow(ctx context.Context, key string, limit int, window time.Duration) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	b, ok := m.buckets[key]
	if !ok {
		b = &bucket{
			tokens:    float64(limit),
			lastCheck: time.Now(),
		}
		m.buckets[key] = b
	}

	now := time.Now()
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

func (m *MemoryLimiter) Close() error {
	return nil
}
