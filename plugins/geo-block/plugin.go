package geoblock

import (
	"github.com/jackby03/waffynx/internal/plugin"
)

var (
	PluginName = "geo-block"
	Version    = "1.0.0"
)

func init() {
	plugin.Register(PluginName, func() plugin.Plugin {
		return &GeoBlockPlugin{}
	}, &plugin.Metadata{
		Name:        PluginName,
		Version:     Version,
		Description: "Blocks or allows traffic based on geographic IP location",
		Author:      "Waffynx",
		License:     "MIT",
		Phase:       plugin.PhasePreRequest,
		Priority:    50,
		Tags:        []string{"security", "geoip", "blocking"},
	})
}

type GeoBlockPlugin struct {
	enabled         bool
	allowedCountries []string
	blockedCountries []string
	mode            string
}

func (p *GeoBlockPlugin) Name() string        { return PluginName }
func (p *GeoBlockPlugin) Version() string     { return Version }
func (p *GeoBlockPlugin) Description() string { return "Geo-blocking plugin" }
func (p *GeoBlockPlugin) Phase() plugin.Phase { return plugin.PhasePreRequest }
func (p *GeoBlockPlugin) Priority() int       { return 50 }

func (p *GeoBlockPlugin) Init(config map[string]interface{}) error {
	p.enabled = true
	p.mode = "block"
	if v, ok := config["mode"].(string); ok {
		p.mode = v
	}
	if countries, ok := config["allowed_countries"].([]interface{}); ok {
		for _, c := range countries {
			if s, ok := c.(string); ok {
				p.allowedCountries = append(p.allowedCountries, s)
			}
		}
	}
	if countries, ok := config["blocked_countries"].([]interface{}); ok {
		for _, c := range countries {
			if s, ok := c.(string); ok {
				p.blockedCountries = append(p.blockedCountries, s)
			}
		}
	}
	return nil
}

func (p *GeoBlockPlugin) Execute(ctx *plugin.Context) (*plugin.Context, error) {
	if !p.enabled {
		return ctx, nil
	}

	clientIP := ctx.Request.RemoteAddr
	_ = clientIP
	_ = p.allowedCountries
	_ = p.blockedCountries

	return ctx, nil
}

func (p *GeoBlockPlugin) Close() error {
	return nil
}
