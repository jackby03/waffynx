# Functional Specification: Dashboard UI

**Status:** Draft / In Progress  
**Feature ID:** `SPEC-001`  
**Target Milestone:** v0.2.0  
**Related Component:** `ui/` & `cmd/waf-api/`  

---

## 1. Objective & Context

### 1.1 Problem Statement
Waffynx currently operates as a headless WAF engine. Operators and security engineers can only monitor security events, rule violations, and system metrics via raw API curl commands or Prometheus endpoints. There is no graphical management interface to visualize threats in real time or manage configuration.

### 1.2 Value Proposition & Goals
Provide a single-page web dashboard (SPA) that allows administrators to:
- Monitor live traffic and attack blocks via Server-Sent Events (SSE).
- Authenticate securely via JWT with the `waf-api` service.
- View system health, metrics, and active plugins.
- Manage rules and view audit history.

---

## 2. Scope Boundaries

### 2.1 In-Scope (Strict Requirements)
<!-- 
[TODO: Fill in what MUST be built in this initial phase]
Examples:
- [ ] Authentication: Login screen with JWT storage and session handling.
- [ ] Overview Dashboard: Real-time traffic KPIs (Total requests, Blocked requests, RPS, Latency).
- [ ] Live Attack Stream: Real-time table consuming SSE from `/api/v1/events`.
- [ ] Plugins & Rules View: List active plugins and their status.
-->
- [ ] **Authentication:** Login interface authenticating against `/api/v1/auth/login`, storing JWT in `sessionStorage`, with automatic redirect on 401.
- [ ] **Overview Dashboard:** Core KPI cards with periodic polling against `/api/v1/status` and `/api/v1/metrics` (Engine status, total requests, total blocked attacks, average latency).
- [ ] **Live Attack Stream:** Real-time table consuming SSE from `/api/v1/events` featuring pause/resume controls and a bounded in-memory circular buffer (maximum 250 events).
- [ ] **Plugins & Marketplace View:** Registered plugin inspection and catalog listings consuming `/api/v1/plugins` and `/api/v1/marketplace`.

### 2.2 Out-of-Scope (Deliberately Excluded for v1)
<!-- 
[TODO: Fill in what is explicitly NOT part of this release to prevent scope creep]
Examples:
- ⛔ Multi-tenant user management / RBAC creation.
- ⛔ Live in-browser YAML file editing of waffynx.yaml.
- ⛔ Direct database connection outside of waf-api REST endpoints.
-->
- ⛔ Multi-tenant user management, role creation, or RBAC controls.
- ⛔ In-browser direct file or rule editing of `waffynx.yaml`.
- ⛔ Direct database connections or Unix domain socket streaming outside the `waf-api` REST/SSE endpoints.
- ⛔ Complex historical time-series analytics (delegated to Prometheus/Grafana).

---

## 3. User Personas & Core Workflows

### Persona: Security Administrator
- **Workflow 1 (Login):** Opens dashboard -> enters credentials -> receives JWT -> redirects to Overview.
- **Workflow 2 (Live Monitoring):** Watches live attacks streaming in real time as requests are blocked by Nginx/Sidecar.
- **Workflow 3 (Plugin Inspection):** Inspects active security plugins (SQLi, XSS, RateLimit, BotDetection) and their configurations.

---

## 4. Structured Functional Requirements (EARS)

<!--
EARS Patterns:
- Ubiquitous: "The UI SHALL <behavior>."
- Event-driven: "WHEN <trigger>, the UI SHALL <behavior>."
- State-driven: "WHILE <state>, the UI SHALL <behavior>."
- Unwanted: "IF <error/invalid>, THEN the UI SHALL <behavior>."
-->

### Requirement 1: Authentication & Token Lifecycle
- **Rule:** WHEN an unauthenticated user navigates to any dashboard view, the UI SHALL redirect to `/login`.
- **Rule:** IF an API request returns `401 Unauthorized`, THEN the UI SHALL clear the stored JWT and redirect to `/login`.

### Requirement 2: Real-time Event Ingestion
- **Rule:** WHILE connected to `/api/v1/events` via EventSource (SSE), the UI SHALL append incoming security events to the live attack feed without requiring page reloads.
- **Rule:** IF the SSE connection drops, THEN the UI SHALL attempt automatic reconnection with exponential backoff.

### Requirement 3: Metrics & Overview Display
- **Rule:** WHILE the operator is viewing the Overview page, the UI SHALL poll `/api/v1/status` and `/api/v1/metrics` every 5 seconds.
- **Rule:** WHEN `/health` returns any HTTP status other than `200 OK`, the UI SHALL display a persistent "Engine Disconnected" banner across the top header.
- **Rule:** WHEN total requests or blocked count changes, the UI SHALL animate counter transitions without page reloads or layout shifts.

---

## 5. Security Invariants (Constitution Compliance)

1. **XSS Prevention:** Under no circumstances should untrusted event data (URIs, User-Agents, IPs, attack payloads) be injected into the DOM using `innerHTML`. Use framework data-binding (`textContent` equivalents). *(See `.jules/sentinel.md`)*.
2. **CORS & Credentials:** Requests to `waf-api` must include Bearer tokens in headers, respecting the server's strict origin validation.

---

## 6. Acceptance Criteria (Given-When-Then)

### Scenario A: Successful Login & Token Persistence
- **Given:** A valid operator credential (`username` / `password`).
- **When:** The user submits the login form.
- **Then:** The UI receives a JWT, stores it securely, and navigates to the dashboard home.

### Scenario B: Live Event Streaming
- **Given:** An authenticated operator viewing the live stream table.
- **When:** The sidecar blocks an attack and `waf-api` emits a SSE event.
- **Then:** A new row appears at the top of the table within 1 second showing IP, timestamp, rule ID, and URI.

<!-- [TODO: Add any additional acceptance scenarios below] -->
