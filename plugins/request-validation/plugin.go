package requestvalidation

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/jackby03/waffynx/internal/parsers"
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
		// SQL comment terminators: the classic way to truncate the remainder of a
		// query ("admin'--"). Found missing by `waffynx verify`.
		"'--", "\"--",
		// Time-based blind SQLi and schema/file access primitives.
		"sleep(", "pg_sleep(", "benchmark(",
		"information_schema",
		"into outfile", "into dumpfile",
		"load_file(",
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
			return p.block(ctx, pattern, "URL")
		}
	}

	if body, ok := ctx.Values["wn_body"].(string); ok && body != "" {
		// The body is encoded by whatever produced it, so matching the raw bytes
		// misses every documented encoding. A form-encoded POST carries
		// "union+select", and JSON carries "\u003cscript\u003e": both reach the
		// application as the attack the patterns describe. Verified against a
		// running container before this was fixed.
		for _, variant := range bodyMatchVariants(contentType, body) {
			lowerBody := strings.ToLower(variant)
			for _, pattern := range p.blockPatterns {
				if strings.Contains(lowerBody, strings.ToLower(pattern)) {
					return p.block(ctx, pattern, "body")
				}
			}
		}

		// GraphQL query inspection
		gqlResult := parsers.InspectGraphQL(contentType, []byte(body))
		if gqlResult.IsGraphQL && len(gqlResult.Issues) > 0 {
			ctx.StatusCode = 403
			ctx.ResponseWriter.Header().Set("Content-Type", "application/json")
			ctx.ResponseWriter.WriteHeader(http.StatusForbidden)
			errPayload, _ := json.Marshal(map[string]string{
				"error": "graphql validation failed: " + strings.Join(gqlResult.Issues, "; "),
			})
			ctx.ResponseWriter.Write(errPayload)
			ctx.Tags["waf_blocked"] = "true"
			ctx.Tags["waf_graphql_depth"] = fmt.Sprintf("%d", gqlResult.QueryDepth)
			return ctx, fmt.Errorf("graphql validation: %s", strings.Join(gqlResult.Issues, "; "))
		}

		// File upload inspection
		uploadResult := parsers.InspectFileUpload(ctx.Request, []byte(body))
		if uploadResult.IsUpload && len(uploadResult.Issues) > 0 {
			ctx.StatusCode = 403
			ctx.ResponseWriter.Header().Set("Content-Type", "application/json")
			ctx.ResponseWriter.WriteHeader(http.StatusForbidden)
			errPayload, _ := json.Marshal(map[string]string{
				"error": "file upload validation failed: " + strings.Join(uploadResult.Issues, "; "),
			})
			ctx.ResponseWriter.Write(errPayload)
			ctx.Tags["waf_blocked"] = "true"
			return ctx, fmt.Errorf("file upload validation: %s", strings.Join(uploadResult.Issues, "; "))
		}
	}

	return ctx, nil
}

func (p *RequestValidationPlugin) Close() error {
	return nil
}

// block writes the denial and returns the error that stops the plugin chain.
// Extracted so the URL, body and encoded forms report identically.
func (p *RequestValidationPlugin) block(ctx *plugin.Context, pattern, where string) (*plugin.Context, error) {
	ctx.StatusCode = http.StatusForbidden
	ctx.ResponseWriter.Header().Set("Content-Type", "application/json")
	ctx.ResponseWriter.WriteHeader(http.StatusForbidden)
	_, _ = ctx.ResponseWriter.Write([]byte(`{"error":"malicious request detected"}`))
	ctx.Tags["waf_blocked"] = "true"
	ctx.Tags["waf_pattern"] = pattern
	return ctx, fmt.Errorf("waf pattern matched in %s: %s", where, pattern)
}

// bodyMatchVariants returns the forms of the body a pattern is checked against.
// The raw bytes are always first.
//
// Decoding is content-type aware on purpose. A "+" means a space in
// application/x-www-form-urlencoded and means a plus everywhere else; rewriting
// it unconditionally would block arithmetic and phone numbers in JSON. Decoding
// is skipped unless the body actually contains the marker, so the common path
// stays a single pass.
func bodyMatchVariants(contentType, body string) []string {
	variants := []string{body}
	ct := strings.ToLower(contentType)

	switch {
	case strings.Contains(ct, "application/x-www-form-urlencoded"):
		if !strings.ContainsAny(body, "%+") {
			return variants
		}
		// QueryUnescape turns "+" into a space and decodes %XX, which is exactly
		// the transformation the application applies before it reads the value.
		if decoded, err := url.QueryUnescape(body); err == nil && decoded != body {
			variants = append(variants, decoded)
		}

	case strings.Contains(ct, "application/json"):
		if !strings.Contains(body, `\u`) {
			return variants
		}
		if decoded := decodeJSONUnicodeEscapes(body); decoded != body {
			variants = append(variants, decoded)
		}
	}

	return variants
}

// decodeJSONUnicodeEscapes rewrites \uXXXX sequences into the characters they
// represent, so `{"q":"\u003cscript\u003e"}` matches the same pattern as
// `<script>`. Surrogate pairs are decoded as two runes; that is enough for
// pattern matching, which only ever looks for ASCII markers.
func decodeJSONUnicodeEscapes(s string) string {
	var b strings.Builder
	b.Grow(len(s))

	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+5 < len(s) && s[i+1] == 'u' {
			if r, ok := hex4(s[i+2 : i+6]); ok {
				b.WriteRune(r)
				i += 5
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// hex4 parses exactly four hexadecimal digits into a rune.
func hex4(s string) (rune, bool) {
	if len(s) != 4 {
		return 0, false
	}
	var v rune
	for i := 0; i < 4; i++ {
		var d rune
		switch c := s[i]; {
		case c >= '0' && c <= '9':
			d = rune(c - '0')
		case c >= 'a' && c <= 'f':
			d = rune(c-'a') + 10
		case c >= 'A' && c <= 'F':
			d = rune(c-'A') + 10
		default:
			return 0, false
		}
		v = v*16 + d
	}
	return v, true
}
