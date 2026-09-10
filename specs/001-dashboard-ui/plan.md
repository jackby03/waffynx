# Technical Architecture Plan: Dashboard UI

**Status:** Approved
**Related Spec:** [`spec.md`](./spec.md)
**Target Directory:** `cmd/waf-api/ui/`

---

## 1. Architecture & Boundaries

- Build the SPA as a separate frontend package under `cmd/waf-api/ui/`.
- Embed the production assets into `waf-api` with `embed.FS` and serve them from the control-plane HTTP server.
- Keep the existing JSON API routes under `/api/v1/`; serve the SPA shell for browser routes without replacing API responses.
- Do not expose the sidecar Unix socket to the browser.
- Add an explicit sidecar-to-API event bridge. The sidecar sends blocked events to `POST /api/v1/events` over a configured local HTTP endpoint using a dedicated service JWT. The API validates that credential, publishes to its broker, and exposes the stream only to authenticated operators.
- Event bridge failure is telemetry-only and must not alter the request verdict.

## 2. Technology and Client Strategy

- React with TypeScript and Vite, unless the approved clarification selects another framework.
- Native `fetch` for REST calls.
- Use `fetch` plus `ReadableStream` for SSE so the client can set `Authorization: Bearer <JWT>`. Do not use native `EventSource`, because it cannot set a Bearer header.
- Keep the JWT in memory. Do not use `localStorage`; use `sessionStorage` only if a later approved requirement explicitly accepts the XSS trade-off.
- Use framework text binding for all event values. Do not use `innerHTML` or `dangerouslySetInnerHTML`.

## 3. API Contracts

| Endpoint | Method | Auth | Purpose |
|---|---|---|---|
| `/api/v1/auth/login` | `POST` | None | Return short-lived operator JWT |
| `/api/v1/status` | `GET` | Operator JWT | Health and runtime status |
| `/api/v1/metrics` | `GET` | Operator JWT | Dashboard metrics |
| `/api/v1/plugins` | `GET` | Operator JWT | Registered plugins |
| `/api/v1/events` | `GET` | Operator JWT | Streaming SSE response |
| `/api/v1/events` | `POST` | Dedicated service JWT/admin service scope | Sidecar event ingestion |

The event schema is `events.WafEvent`: `type`, `timestamp`, `method`, `path`, `remote_ip`, `rule_id`, and `reason`. The API must validate body size, event type, and required field lengths before publishing.

## 4. Component Layout

```text
cmd/waf-api/ui/
├── package.json
├── package-lock.json
├── vite.config.ts
├── src/
│   ├── features/auth/
│   ├── features/overview/
│   ├── features/live-events/
│   ├── features/plugins/
│   ├── services/api.ts
│   ├── services/event-stream.ts
│   └── App.tsx
└── dist/                         # generated, embedded at build time

Sidecar -> authenticated POST /api/v1/events -> API broker -> authenticated fetch stream -> Dashboard
```

## 5. Security and Failure Analysis

| Control | Design | Verification |
|---|---|---|
| Browser auth | In-memory JWT; clear on `401` | Auth/session tests |
| SSE auth | Bearer header on streaming fetch | Unauthorized stream test |
| Service auth | Dedicated credential and scope, never browser token | Ingest auth test |
| XSS prevention | Escaped framework text rendering | DOM/XSS test |
| CORS | Exact configured origin; reject unauthorized preflight | API regression tests |
| Event failure | Does not affect WAF verdict | Fault-injection integration test |
| API input | Size/type/field validation | Negative and fuzz tests |
| Delivery | Bounded timeout and no unbounded retry storm | Unit test with failing API |

## 6. Verification Strategy

### Go
```bash
go test -race ./...
gofmt -s -l .
golangci-lint run ./...
make build
```

### Frontend

From `cmd/waf-api/ui/`:
```bash
npm ci
npm run lint
npm test -- --run
npm run build
```

The exact scripts must exist in `package.json`; missing scripts are a failed gate, not an optional check.

### Integration

Run the API, sidecar, and dashboard in the Linux VM and verify:

1. A blocked request creates an event.
2. The event crosses the authenticated ingest boundary.
3. An authenticated dashboard receives it.
4. An unauthenticated client receives `401` and cannot subscribe.
5. Event bridge failure does not allow an otherwise blocked request.

Use `make vagrant-test` for the Linux verification cycle.
