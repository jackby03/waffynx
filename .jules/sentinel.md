## 2024-05-18 - Unauthenticated pprof endpoints in management API
**Vulnerability:** The management API (`waf-api`) exposed `net/http/pprof` debugging endpoints without authentication.
**Learning:** Development tools and debugging handlers must be explicitly wrapped in the same authentication middleware as the rest of the application when mounted on a public mux.
**Prevention:** Always apply default-deny or universal authentication middleware to the root router before attaching specific handlers, including standard library debugging endpoints.
