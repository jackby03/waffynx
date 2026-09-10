# Functional Specification: Dashboard UI

**Status:** Approved
**Feature ID:** `SPEC-001`
**Target Milestone:** v0.2.0
**Related Components:** `cmd/waf-api/ui/`, `cmd/waf-api/`, `internal/engine/`

---

## 1. Objective & Context

Waffynx needs an authenticated operator dashboard for health, metrics, plugins, and blocked-request events. The dashboard is a control-plane client only; it must never inspect or proxy production traffic directly.

## 2. Scope Boundaries

### 2.1 In-Scope
- [ ] Serve a production-built SPA from `cmd/waf-api/ui/` through `waf-api`.
- [ ] Authenticate with `POST /api/v1/auth/login`; keep the JWT in memory by default and clear it on `401` or logout.
- [ ] Display authenticated status, metrics, and registered plugins.
- [ ] Consume authenticated blocked-event SSE using a streaming `fetch` client with an `Authorization` header.
- [ ] Reconnect SSE with bounded exponential backoff and show disconnected state.
- [ ] Render event fields as text, never as HTML.
- [ ] Provide responsive desktop and mobile layouts.

### 2.2 Out-of-Scope
- Multi-tenant administration, user creation, and role management.
- Editing YAML or arbitrary configuration from the browser.
- Direct access to the sidecar Unix socket.
- Plugin installation or uninstallation in the first release.
- Storing JWTs in `localStorage`.

---

## 3. Functional Requirements

### Requirement 1: Authentication
- **Type:** Event-Driven
- **Rule:** WHEN valid credentials are submitted, the UI SHALL store the JWT in memory and navigate to the protected dashboard.
- **Rule:** IF an API request returns `401`, THEN the UI SHALL discard the token and navigate to `/login`.

### Requirement 2: Authenticated Event Stream
- **Type:** State-Driven
- **Rule:** WHILE the dashboard is open, the UI SHALL connect to `GET /api/v1/events` using an authenticated streaming request.
- **Rule:** IF the stream disconnects, THEN the UI SHALL retry with exponential backoff capped at 30 seconds and expose the connection state.
- **Rule:** WHEN a blocked event arrives, the UI SHALL display timestamp, IP, method, path, rule ID, and reason within one second under normal local-network conditions.

### Requirement 3: Event Bridge
- **Type:** Ubiquitous
- **Rule:** The sidecar SHALL publish blocked events to the API event-ingest endpoint using a dedicated service credential; the API SHALL validate the credential and broadcast the event to authenticated dashboard clients.
- **Rule:** IF event delivery to the API fails, THEN the sidecar SHALL log the failure and SHALL NOT weaken request inspection or allow traffic because of that failure.

### Requirement 4: Dashboard Data
- **Type:** Event-Driven
- **Rule:** WHEN an authenticated view loads, the UI SHALL fetch status, metrics, and plugins and show explicit loading, empty, and error states.

### Requirement 5: Safe Rendering
- **Type:** Unwanted Behavior
- **Rule:** IF event data contains markup or control characters, THEN the UI SHALL render it as escaped text and SHALL not use `innerHTML` or `dangerouslySetInnerHTML` for untrusted values.

## 4. Error Handling & Edge Cases

| Scenario | Expected behavior |
|---|---|
| Invalid login | Show generic authentication error; do not reveal whether the user exists |
| Expired or revoked JWT | Clear in-memory session and redirect to login |
| SSE `401`/`403` | Stop retries and require login |
| SSE network failure | Retry with bounded exponential backoff and visible status |
| Malformed event | Ignore the event, log a client-safe diagnostic, keep the stream alive |
| API timeout/5xx | Show retry action and preserve the rest of the dashboard |
| Empty metrics/plugins/events | Show an explicit empty state, not a blank panel |

## 5. Acceptance Scenarios

### Scenario A: Successful Login
- **Given:** A valid configured operator credential.
- **When:** The user submits the login form.
- **Then:** The UI receives a JWT, keeps it in memory, and opens the protected dashboard.

### Scenario B: Authenticated Live Event
- **Given:** The sidecar has emitted an event through the authenticated API ingest boundary.
- **When:** An authenticated dashboard is connected to the event stream.
- **Then:** The event appears with the required fields within one second.

### Scenario C: Authentication Failure
- **Given:** An authenticated dashboard session.
- **When:** The API returns `401`.
- **Then:** The token is cleared and the user is redirected to `/login`.

### Scenario D: XSS Payload
- **Given:** An event path contains `<script>alert(1)</script>`.
- **When:** The event is rendered.
- **Then:** The literal text is shown and no script executes or DOM node is created from the value.

### Scenario E: Event Delivery Failure
- **Given:** The API ingest endpoint is unavailable.
- **When:** The sidecar tries to publish a blocked event.
- **Then:** The request remains governed by the normal fail-closed inspection path and the delivery error is observable in logs/metrics.
