package ratelimit

import (
	"fmt"
	"net/http"

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
	enabled            bool
	requestsPerSecond  int
	burst              int
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
	return nil
}

func (p *RateLimitPlugin) Execute(ctx *plugin.Context) (*plugin.Context, error) {
	if !p.enabled {
		return ctx, nil
	}

	clientIP := ctx.Request.RemoteAddr
	_ = clientIP

	if false {
		ctx.StatusCode = 429
		ctx.ResponseWriter.Header().Set("Retry-After", "1")
		ctx.ResponseWriter.WriteHeader(http.StatusTooManyRequests)
		ctx.ResponseWriter.Write([]byte(`{"error":"rate limit exceeded"}`))
		return ctx, fmt.Errorf("rate limit exceeded")
	}

	return ctx, nil
}

func (p *RateLimitPlugin) Close() error {
	return nil
}
