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

## 2024-05-XX - Weak Default JWT Secret Allowed
* **Title:** Weak Default JWT Secret Allowed
* **Vulnerability:** The API server only logged a warning if the JWT secret was empty or set to a specific default literal ("change-me-in-production"), allowing it to start with weak/default credentials.
* **Learning:** Always enforce strong security defaults. Fail-safe design means applications should refuse to start if critical security configurations (like signing keys) are missing or known to be insecure, rather than just warning the user.
* **Prevention:** Implement strict length and complexity checks for sensitive configuration values during application startup and exit with an error if they are not met (e.g., require at least 32 bytes for HS256 JWT keys).

## 2024-05-XX - Weak Default API Key Allowed
**Vulnerability:** The agent server only logged a warning if the API key was set to a specific default literal ("change-me-in-production") or empty, allowing it to start with weak/default credentials.
**Learning:** Failing to strictly validate API keys at startup can lead to unauthorized access to critical endpoints (like firewall control).
**Prevention:** Always abort server startup if required security credentials (like API keys or JWT secrets) are empty or match known unsafe default values.

## 2024-05-XX - Timing Attack Vulnerability in API Key Validation
**Vulnerability:** The `authMiddleware` in `cmd/waf-agent/main.go` was using a standard string comparison (`==` or `!=`) to validate the provided API key against the configured one. This allowed for timing side-channel attacks.
**Learning:** Standard string comparisons fail early, meaning the time taken to evaluate the comparison depends on the number of matching characters at the beginning. Attackers can exploit this by measuring the response time to guess the secret key character by character.
**Prevention:** Always use constant-time comparison functions like `crypto/subtle.ConstantTimeCompare` when comparing sensitive data like passwords, API keys, HMACs, or tokens to prevent timing attacks.

## 2026-08-01 - DOM XSS via innerHTML in UI Dashboard
**Vulnerability:** The management dashboard (`cmd/waf-api/ui/index.html`) was concatenating dynamic variables (like HTTP method, path, attack type, and IP address) directly into `innerHTML` strings when rendering the live attack log and settings. This allowed for Cross-Site Scripting (XSS) if an attacker sent malicious input that was subsequently logged and rendered in the UI.
**Learning:** Using `innerHTML` for displaying dynamically generated content from untrusted sources is a common vector for XSS. The source of the content, even if it comes from internal API logs, should still be treated as potentially untrusted if it originated from user input.
**Prevention:** Always sanitize or escape data when inserting it into the DOM. Prefer using `textContent` for raw strings, or use a helper function to HTML-escape variables before inserting them into string templates assigned to `innerHTML`.
## 2026-08-01 - Unreachable Error Returns in API Configuration
**Vulnerability:** The application was using `logging.Fatal()` when a weak JWT secret was configured, which causes an immediate `os.Exit(1)` and makes the subsequent `return fmt.Errorf(...)` unreachable.
**Learning:** In Go functions designed to return an error, using `Fatal()` bypasses graceful degradation and caller error handling, causing abrupt process termination.
**Prevention:** Always use `logging.Error()` in functions returning errors to allow the application to fail gracefully.
## 2024-10-25 - [Fix authorization bypass backdoor in OIDC manager]
**Vulnerability:** A hardcoded check blindly granted the `admin` role if an OIDC token claim email matched `idToken.Issuer + "admin"`.
**Learning:** Hardcoded, undocumented logic based on predictable string concatenation (like `issuer+"admin"`) creates dangerous authorization bypasses/backdoors, even if relying on external identity providers.
**Prevention:** Avoid magic strings for authorization rules and rely solely on established claims parsing (e.g. groups claims) configured by administrators.

## 2024-05-24

**Title:** Missing CORS Middleware on Unauthenticated Login Endpoint
**Vulnerability:** A cross-origin resource sharing (CORS) misconfiguration resulting from omitted middleware on sensitive endpoints, specifically the `/api/v1/auth/login` endpoint.
**Learning:** In Go 1.22's `http.ServeMux`, method-specific route registration (e.g., `"POST /path"`) means preflight `OPTIONS` requests won't match automatically. If CORS middleware requires handling preflight requests, the `OPTIONS` method must be explicitly registered alongside the target endpoint, wrapping it in the CORS middleware.
**Prevention:** Ensure all endpoints intended to be accessed cross-origin have proper CORS middleware applied. For Go 1.22+ `http.ServeMux` where method specificity is used, explicitly register the `OPTIONS` method with CORS middleware.
