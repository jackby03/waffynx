Date: 2024-05-24
Title: Overly Permissive CORS Policy Fixed
Vulnerability: `cmd/waf-api/main.go` contained a hardcoded wildcard (`*`) in its `Access-Control-Allow-Origin` HTTP header on the management API (e.g. `corsMiddleware`, `handleRoot`, `handleSSE`).
Learning: Global wildcard CORS headers blindly trust any origin, risking unauthorized cross-origin access and exposure of administration APIs to malicious websites. Unintended CORS exposure can happen in secondary endpoints like SSE or root status handlers.
Prevention: Default CORS setups to restrict origins using a configured allowlist (`cfg.API.AllowedOrigins`). Validate the request `Origin` against the config, and only return wildcard headers or credential-allowing headers when strictly configured or validated.

Date: 2024-05-24
Title: Strict CORS Policy Implementation
Vulnerability: `cmd/waf-api/main.go` returned CORS headers (`Access-Control-Allow-Methods`, `Access-Control-Allow-Headers`) and a `204 No Content` response to preflight `OPTIONS` requests even for unauthorized origins.
Learning: Emitting any CORS-related headers for unauthorized origins can leak information about the API's capabilities and intended usage patterns. A preflight request from an unauthorized origin should be explicitly rejected.
Prevention: Ensure that *all* CORS response headers are conditionally applied only after validating the request's origin against the allowlist. Reject unauthorized preflight `OPTIONS` requests with a `403 Forbidden` status code to signal explicit denial.
