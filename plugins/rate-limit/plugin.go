package ratelimit

import (
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/jackby03/waffynx/internal/plugin"
)

var (
	PluginName = "rate-limit"
	Version    = "1.0.0"
)

func init() {
	plugin.Register(PluginName, func() plugin.Plugin {
		return &RateLimitPlugin{}
	}, &plugin.Metadata{
		Name:        PluginName,
		Version:     Version,
		Description: "Rate limiting based on client IP and configurable thresholds",
		Author:      "Waffynx",
		License:     "MIT",
		Phase:       plugin.PhasePreRequest,
		Priority:    100,
		Tags:        []string{"security", "rate-limiting", "ddos"},
	})
}

type RateLimitPlugin struct {
	enabled           bool
	requestsPerSecond int
	burst             int

	mu      sync.Mutex
	clients map[string]*clientBucket
}

type clientBucket struct {
	tokens    float64
	lastCheck time.Time
}

func (p *RateLimitPlugin) Name() string        { return PluginName }
func (p *RateLimitPlugin) Version() string     { return Version }
func (p *RateLimitPlugin) Description() string { return "Rate limiting plugin" }
func (p *RateLimitPlugin) Phase() plugin.Phase { return plugin.PhasePreRequest }
func (p *RateLimitPlugin) Priority() int       { return 100 }

func (p *RateLimitPlugin) Init(config map[string]interface{}) error {
	p.enabled = true
	if v, ok := config["requests_per_second"].(int); ok {
		p.requestsPerSecond = v
	}
	if v, ok := config["burst"].(int); ok {
		p.burst = v
	}
	if p.requestsPerSecond == 0 {
		p.requestsPerSecond = 100
	}
	if p.burst == 0 {
		p.burst = 200
	}

	p.clients = make(map[string]*clientBucket)

	go p.cleanup()
	return nil
}

func (p *RateLimitPlugin) Execute(ctx *plugin.Context) (*plugin.Context, error) {
	if !p.enabled {
		return ctx, nil
	}

	clientIP := p.extractIP(ctx)
	if clientIP == "" {
		return ctx, nil
	}

	if !p.allow(clientIP) {
		ctx.StatusCode = http.StatusTooManyRequests
		ctx.ResponseWriter.Header().Set("Retry-After", "1")
		ctx.ResponseWriter.Header().Set("Content-Type", "application/json")
		ctx.ResponseWriter.WriteHeader(http.StatusTooManyRequests)
		ctx.ResponseWriter.Write([]byte(`{"error":"rate limit exceeded"}`))
		return ctx, fmt.Errorf("rate limit exceeded for %s", clientIP)
	}

	return ctx, nil
}

func (p *RateLimitPlugin) Close() error {
	return nil
}

func (p *RateLimitPlugin) extractIP(ctx *plugin.Context) string {
	if v, ok := ctx.Values["wn_ip"].(string); ok && v != "" {
		return v
	}
	if ctx.Request != nil {
		ip := ctx.Request.RemoteAddr
		if forwarded := ctx.Request.Header.Get("X-Forwarded-For"); forwarded != "" {
			ip = forwarded
		}
		return ip
	}
	return ""
}

func (p *RateLimitPlugin) allow(ip string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()

	bucket, ok := p.clients[ip]
	if !ok {
		bucket = &clientBucket{
			tokens:    float64(p.burst),
			lastCheck: time.Now(),
		}
		p.clients[ip] = bucket
	}

	now := time.Now()
	elapsed := now.Sub(bucket.lastCheck).Seconds()
	bucket.tokens += elapsed * float64(p.requestsPerSecond)
	if bucket.tokens > float64(p.burst) {
		bucket.tokens = float64(p.burst)
	}
	bucket.lastCheck = now

	if bucket.tokens >= 1 {
		bucket.tokens--
		return true
	}

	return false
}

func (p *RateLimitPlugin) cleanup() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		p.mu.Lock()
		cutoff := time.Now().Add(-60 * time.Second)
		for ip, bucket := range p.clients {
			if bucket.lastCheck.Before(cutoff) {
				delete(p.clients, ip)
			}
		}
		p.mu.Unlock()
	}
}
