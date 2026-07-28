package botprotection

import (
	"net/http"
	"strings"

	"github.com/jackby03/waffynx/internal/plugin"
)

var (
	PluginName = "bot-protection"
	Version    = "1.0.0"
)

func init() {
	plugin.Register(PluginName, func() plugin.Plugin {
		return &BotProtectionPlugin{}
	}, &plugin.Metadata{
		Name:        PluginName,
		Version:     Version,
		Description: "Detects and blocks malicious bots using multiple detection methods",
		Author:      "Waffynx",
		License:     "MIT",
		Phase:       plugin.PhasePreRequest,
		Priority:    75,
		Tags:        []string{"security", "bot", "anti-scraping"},
	})
}

type BotProtectionPlugin struct {
	enabled       bool
	challengeType string
	mode          string
	knownBots     []string
}

func (p *BotProtectionPlugin) Name() string        { return PluginName }
func (p *BotProtectionPlugin) Version() string     { return Version }
func (p *BotProtectionPlugin) Description() string { return "Bot protection plugin" }
func (p *BotProtectionPlugin) Phase() plugin.Phase { return plugin.PhasePreRequest }
func (p *BotProtectionPlugin) Priority() int       { return 75 }

func (p *BotProtectionPlugin) Init(config map[string]interface{}) error {
	p.enabled = true
	p.challengeType = "js"
	p.mode = "log"

	if v, ok := config["challenge_type"].(string); ok {
		p.challengeType = v
	}
	if v, ok := config["mode"].(string); ok {
		p.mode = v
	}

	p.knownBots = []string{
		"curl",
		"wget",
		"python-requests",
		"Go-http-client",
		"libwww-perl",
	}

	return nil
}

func (p *BotProtectionPlugin) Execute(ctx *plugin.Context) (*plugin.Context, error) {
	if !p.enabled {
		return ctx, nil
	}

	ua := ""
	if v, ok := ctx.Values["wn_ua"].(string); ok {
		ua = v
	}
	if ua == "" {
		ua = ctx.Request.Header.Get("User-Agent")
	}
	for _, bot := range p.knownBots {
		if strings.Contains(strings.ToLower(ua), strings.ToLower(bot)) {
			if p.mode == "block" {
				ctx.StatusCode = 403
				ctx.ResponseWriter.Header().Set("Content-Type", "application/json")
				ctx.ResponseWriter.WriteHeader(http.StatusForbidden)
				ctx.ResponseWriter.Write([]byte(`{"error":"bot access denied"}`))
			}
			ctx.Tags["bot_detected"] = "true"
			ctx.Tags["bot_user_agent"] = ua
			break
		}
	}

	return ctx, nil
}

func (p *BotProtectionPlugin) Close() error {
	return nil
}
