Date: 2024-05-24
Title: Overly Permissive CORS Policy Fixed
Vulnerability: `cmd/waf-api/main.go` contained a hardcoded wildcard (`*`) in its `Access-Control-Allow-Origin` HTTP header on the management API (e.g. `corsMiddleware`, `handleRoot`, `handleSSE`).
Learning: Global wildcard CORS headers blindly trust any origin, risking unauthorized cross-origin access and exposure of administration APIs to malicious websites. Unintended CORS exposure can happen in secondary endpoints like SSE or root status handlers.
Prevention: Default CORS setups to restrict origins using a configured allowlist (`cfg.API.AllowedOrigins`). Validate the request `Origin` against the config, and only return wildcard headers or credential-allowing headers when strictly configured or validated.
