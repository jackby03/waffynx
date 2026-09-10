# Clarifications & Q/A: Dashboard UI

**Related Spec:** [`spec.md`](./spec.md)  
**Related Plan:** [`plan.md`](./plan.md)

---

## Log of Clarifications

### Q-001: Frontend framework and styling
- **Raised by:** Agent
- **Date:** 2026-09-09
- **Question:** Which frontend framework and styling solution is approved for `cmd/waf-api/ui/`?
- **Proposed decision:** React + TypeScript + Vite + project-owned CSS tokens. Avoid adding a UI framework unless approved separately.
- **Status:** Resolved by user approval

### Q-002: Authenticated SSE transport
- **Raised by:** Agent
- **Date:** 2026-09-09
- **Question:** How should the browser authenticate the SSE stream?
- **Proposed decision:** Use `fetch` with `ReadableStream` and an `Authorization: Bearer` header. Native `EventSource` is rejected because it cannot set that header.
- **Status:** Resolved by user approval

### Q-003: Sidecar-to-API event delivery
- **Raised by:** Agent
- **Date:** 2026-09-09
- **Question:** How do sidecar events reach the API broker used by the dashboard?
- **Proposed decision:** Add a local authenticated HTTP ingest boundary, `POST /api/v1/events`, with a dedicated service JWT/scope. Event-delivery failure must not change the WAF verdict.
- **Status:** Resolved by user approval

### Q-004: UI delivery
- **Raised by:** Agent
- **Date:** 2026-09-09
- **Question:** Where should the production SPA be served from?
- **Proposed decision:** Build under `cmd/waf-api/ui/`, embed `dist` into `waf-api`, and serve the SPA without shadowing `/api/v1/*` routes.
- **Status:** Resolved by user approval

### Approval rule

Q-001 through Q-004 were approved by the user on 2026-09-09. The approved decisions are binding for this implementation.
