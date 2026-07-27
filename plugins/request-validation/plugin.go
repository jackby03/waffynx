package requestvalidation

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/jackby03/waffynx/internal/plugin"
)

var (
	PluginName = "request-validation"
	Version    = "1.0.0"
)

func init() {
	plugin.Register(PluginName, func() plugin.Plugin {
		return &RequestValidationPlugin{}
	}, &plugin.Metadata{
		Name:        PluginName,
		Version:     Version,
		Description: "Validates incoming requests: body size, content type, SQLi/XSS patterns",
		Author:      "Waffynx",
		License:     "MIT",
		Phase:       plugin.PhasePreRequest,
		Priority:    25,
		Tags:        []string{"security", "validation", "waf"},
	})
}

type RequestValidationPlugin struct {
	enabled             bool
	maxBodySize         int64
	allowedContentTypes []string
	blockPatterns       []string
}

func (p *RequestValidationPlugin) Name() string        { return PluginName }
func (p *RequestValidationPlugin) Version() string     { return Version }
func (p *RequestValidationPlugin) Description() string { return "Request validation plugin" }
func (p *RequestValidationPlugin) Phase() plugin.Phase { return plugin.PhasePreRequest }
func (p *RequestValidationPlugin) Priority() int       { return 25 }

func (p *RequestValidationPlugin) Init(config map[string]interface{}) error {
	p.enabled = true
	p.maxBodySize = 10 * 1024 * 1024 // 10MB default

	if v, ok := config["max_body_size"].(int); ok {
		p.maxBodySize = int64(v)
	}

	if types, ok := config["allowed_content_types"].([]interface{}); ok {
		for _, t := range types {
			if s, ok := t.(string); ok {
				p.allowedContentTypes = append(p.allowedContentTypes, s)
			}
		}
	}

	p.blockPatterns = []string{
		"../", "..\\",
		"<script", "</script>",
		"javascript:",
		"onerror=", "onload=",
		"union select", "union/**/select",
		"or 1=1", "' or '1'='1",
		"exec(", "system(",
		"${", "{{",
	}

	return nil
}

func (p *RequestValidationPlugin) Execute(ctx *plugin.Context) (*plugin.Context, error) {
	if !p.enabled {
		return ctx, nil
	}

	// Get original Content-Type from the nginx-sidecar bridge context
	contentType := ""
	if ct, ok := ctx.Values["wn_ct"]; ok {
		if s, ok := ct.(string); ok {
			contentType = s
		}
	}
	if len(p.allowedContentTypes) > 0 {
		allowed := false
		for _, ct := range p.allowedContentTypes {
			if strings.HasPrefix(contentType, ct) {
				allowed = true
				break
			}
		}
		if !allowed && ctx.Request.ContentLength > 0 {
			ctx.StatusCode = 415
			ctx.ResponseWriter.Header().Set("Content-Type", "application/json")
			ctx.ResponseWriter.WriteHeader(http.StatusUnsupportedMediaType)
			ctx.ResponseWriter.Write([]byte(`{"error":"unsupported content type"}`))
			return ctx, fmt.Errorf("unsupported content type: %s", contentType)
		}
	}

	// SQLi/XSS pattern check in the ORIGINAL URL (from nginx, via ctx.Values)
	// URL-decode to catch encoded payloads (%20, %27, etc.)
	urlPath := ""
	if uri, ok := ctx.Values["wn_uri"]; ok {
		if s, ok := uri.(string); ok {
			decoded, err := url.QueryUnescape(s)
			if err == nil {
				urlPath = decoded
			} else {
				urlPath = s
			}
		}
	}
	// Also normalize + to space (nginx sends + for space in query strings)
	urlPath = strings.ReplaceAll(urlPath, "+", " ")
	for _, pattern := range p.blockPatterns {
		if strings.Contains(strings.ToLower(urlPath), strings.ToLower(pattern)) {
			ctx.StatusCode = 403
			ctx.ResponseWriter.Header().Set("Content-Type", "application/json")
			ctx.ResponseWriter.WriteHeader(http.StatusForbidden)
			ctx.ResponseWriter.Write([]byte(`{"error":"malicious request detected"}`))
			ctx.Tags["waf_blocked"] = "true"
			ctx.Tags["waf_pattern"] = pattern
			return ctx, fmt.Errorf("waf pattern matched: %s", pattern)
		}
	}

	return ctx, nil
}

func (p *RequestValidationPlugin) Close() error {
	return nil
}
