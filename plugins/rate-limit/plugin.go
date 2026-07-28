package ratelimit

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/jackby03/waffynx/internal/logging"
	"github.com/jackby03/waffynx/internal/plugin"
	wratelimit "github.com/jackby03/waffynx/internal/ratelimit"
)

var (
	PluginName = "rate-limit"
	Version    = "1.1.0"
)

func init() {
	plugin.Register(PluginName, func() plugin.Plugin {
		return &RateLimitPlugin{}
	}, &plugin.Metadata{
		Name:        PluginName,
		Version:     Version,
		Description: "Rate limiting (in-memory token bucket or Redis shared state)",
		Author:      "Waffynx",
		License:     "MIT",
		Phase:       plugin.PhasePreRequest,
		Priority:    100,
		Tags:        []string{"security", "rate-limiting", "ddos", "redis"},
	})
}

type RateLimitPlugin struct {
	enabled           bool
	requestsPerSecond int
	burst             int

	limiter wratelimit.Limiter
	redis   *wratelimit.RedisLimiter
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

	redisCfg := parseRedisConfig(config)
	if redisCfg.Enabled {
		limiter, err := wratelimit.NewRedisLimiter(redisCfg)
		if err != nil {
			logging.Warn().Err(err).Msg("redis rate limiter unavailable, falling back to in-memory")
			p.limiter = wratelimit.NewMemoryLimiter()
		} else {
			p.limiter = limiter
			p.redis = limiter
			logging.Info().Str("addr", redisCfg.Addr).Msg("redis rate limiter enabled")
		}
	} else {
		p.limiter = wratelimit.NewMemoryLimiter()
	}

	return nil
}

func parseRedisConfig(config map[string]interface{}) wratelimit.Config {
	cfg := wratelimit.Config{}
	if redisRaw, ok := config["redis"]; ok {
		if redisMap, ok := redisRaw.(map[string]interface{}); ok {
			if v, ok := redisMap["enabled"].(bool); ok {
				cfg.Enabled = v
			}
			if v, ok := redisMap["addr"].(string); ok {
				cfg.Addr = v
			}
			if v, ok := redisMap["password"].(string); ok {
				cfg.Password = v
			}
			if v, ok := redisMap["db"].(int); ok {
				cfg.DB = v
			}
		}
	}
	return cfg
}

func (p *RateLimitPlugin) Execute(ctx *plugin.Context) (*plugin.Context, error) {
	if !p.enabled {
		return ctx, nil
	}

	clientIP := p.extractIP(ctx)
	if clientIP == "" {
		return ctx, nil
	}

	allowed, err := p.limiter.Allow(context.Background(), clientIP, p.requestsPerSecond, time.Second)
	if err != nil {
		logging.Warn().Err(err).Str("ip", clientIP).Msg("rate limit check failed, allowing")
		return ctx, nil
	}

	if !allowed {
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
	if p.limiter != nil {
		return p.limiter.Close()
	}
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
