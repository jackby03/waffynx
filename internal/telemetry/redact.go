package telemetry

import (
	"regexp"
	"strings"
)

const redactedMarker = "[REDACTED]"

var sensitiveHeaders = map[string]struct{}{
	"authorization":        {},
	"proxy-authorization":  {},
	"cookie":               {},
	"set-cookie":           {},
	"x-api-key":            {},
	"x-auth-token":         {},
	"x-csrf-token":         {},
	"x-xsrf-token":         {},
	"x-session-token":      {},
	"x-amz-security-token": {},
}

var (
	// Matches Bearer tokens and compact JWTs (header.payload.signature).
	jwtPattern = regexp.MustCompile(`(?i)(bearer\s+[a-z0-9\-._~+/]+=*|eyJ[a-zA-Z0-9_-]{8,}\.eyJ[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,})`)
	// Matches sensitive query parameters: password=, token=, secret=, api_key=, access_token=, auth=.
	querySecretRe = regexp.MustCompile(`(?i)((?:^|[?&])(?:password|passwd|pwd|secret|token|access_token|refresh_token|api_key|apikey|auth|session_id|jwt)=)([^&#\s]+)`)
	// Matches JSON key-value pairs carrying credentials or secrets.
	jsonSecretRe = regexp.MustCompile(`(?i)("(?:password|passwd|secret|token|access_token|refresh_token|api_key|apikey|private_key|authorization|credit_card|card_number|cvv|ssn)"\s*:\s*")([^"]*)(")`)
	// Matches common 13-19 digit PANs with optional spaces/dashes.
	panRe = regexp.MustCompile(`\b(?:\d[ -]*?){13,19}\b`)
)

// RedactHeaders returns a copy of headers with sensitive credential/session
// headers replaced by [REDACTED] (Constitution §2.2).
func RedactHeaders(headers map[string]string) map[string]string {
	if len(headers) == 0 {
		return nil
	}
	out := make(map[string]string, len(headers))
	for k, v := range headers {
		lower := strings.ToLower(strings.TrimSpace(k))
		if _, sensitive := sensitiveHeaders[lower]; sensitive {
			out[k] = redactedMarker
			continue
		}
		if strings.Contains(lower, "token") || strings.Contains(lower, "secret") || strings.Contains(lower, "password") || strings.Contains(lower, "apikey") || strings.Contains(lower, "api-key") {
			out[k] = redactedMarker
			continue
		}
		// Scrub both secret query parameters (e.g. HTTP/2 :path, Referer) and bearer/JWT tokens.
		cleaned := querySecretRe.ReplaceAllString(v, "${1}"+redactedMarker)
		out[k] = jwtPattern.ReplaceAllString(cleaned, redactedMarker)
	}
	return out
}

// RedactURI masks secret query parameter values and inline JWTs in a request path.
func RedactURI(uri string) string {
	if uri == "" {
		return ""
	}
	s := querySecretRe.ReplaceAllString(uri, "${1}"+redactedMarker)
	return jwtPattern.ReplaceAllString(s, redactedMarker)
}

// RedactBodySnippet trims to maxLen bytes and scrubs secrets, tokens, and PANs.
func RedactBodySnippet(body string, maxLen int) string {
	if body == "" {
		return ""
	}
	if maxLen <= 0 {
		maxLen = 512
	}
	s := body
	if len(s) > maxLen*2 {
		s = s[:maxLen*2]
	}
	s = jsonSecretRe.ReplaceAllString(s, `${1}`+redactedMarker+`${3}`)
	s = querySecretRe.ReplaceAllString(s, "${1}"+redactedMarker)
	s = jwtPattern.ReplaceAllString(s, redactedMarker)
	s = panRe.ReplaceAllString(s, redactedMarker)
	if len(s) > maxLen {
		s = s[:maxLen]
	}
	return s
}

// RedactEvent applies mandatory PII & credential redaction across all sensitive
// fields of a SecurityEvent before persistence or transmission.
func RedactEvent(ev SecurityEvent) SecurityEvent {
	ev.Path = RedactURI(ev.Path)
	ev.Headers = RedactHeaders(ev.Headers)
	ev.BodySnippet = RedactBodySnippet(ev.BodySnippet, 512)
	ev.Reason = jwtPattern.ReplaceAllString(ev.Reason, redactedMarker)
	return ev
}
