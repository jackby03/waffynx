# Technical Architecture Plan: Dashboard UI

**Status:** Awaiting Spec Finalization  
**Related Spec:** [`spec.md`](./spec.md)  
**Target Directory:** `ui/`  

---

## 1. Technology Stack & Framework Selection

<!-- 
[To be finalized once spec.md is completed]
Proposed stack:
- Core: React 18 / TypeScript
- Build Tool: Vite
- Styling: Vanilla CSS / Tailwind CSS / Modern CSS Modules with Dark Mode
- Routing: React Router or lightweight SPA router
- State / Query: TanStack Query (or native fetch + hooks)
- Streaming: Native EventSource for SSE (/api/v1/events)
-->

---

## 2. API Contracts & Consumed Endpoints

| Endpoint | Method | Auth | Purpose |
| :--- | :--- | :--- | :--- |
| `/api/v1/auth/login` | `POST` | None | Authenticate operator, return JWT |
| `/health` | `GET` | None | Health check & engine status ping |
| `/api/v1/status` | `GET` | Bearer JWT | Engine uptime, connection counters |
| `/api/v1/metrics` | `GET` | Bearer JWT | Aggregated traffic & block statistics |
| `/api/v1/events` | `GET (SSE)` | Bearer JWT | Live streaming security events feed |
| `/api/v1/plugins` | `GET` | Bearer JWT | List registered security plugins |
| `/api/v1/marketplace` | `GET` | Bearer JWT | List available plugin packages |

---

## 3. Component Architecture & Routes

```text
ui/src/
├── assets/             # Static logos, icons
├── components/         # Reusable UI primitives (Card, Badge, Button, Table, Modal)
├── features/
│   ├── auth/           # Login form, token storage, auth guard
│   ├── overview/       # KPI widgets, traffic gauges, status bar
│   ├── live-events/    # Real-time SSE table with pause/filter controls
│   ├── plugins/        # Plugin grid & status cards
│   └── marketplace/    # Catalog listing
├── services/           # api.ts (fetch wrapper with Bearer token & auto-logout on 401)
├── App.tsx             # Route definitions & layout shell (Sidebar + Header)
└── main.tsx            # Entry point
```

---

## 4. Invariants & Security Analysis

- **XSS Sanitization:** React JSX automatically escapes dynamic strings before DOM insertion. Direct usage of `dangerouslySetInnerHTML` is strictly prohibited.
- **Token Storage:** Store JWT in memory or `sessionStorage`/`localStorage` with automatic cleanup on expiration.
- **CORS Handling:** During development, Vite dev server proxies `/api` to `http://localhost:9090` to eliminate CORS preflight overhead.

---

## 5. Verification & Testing Strategy

- **Build verification:** `npm run build` (zero TypeScript errors).
- **Linter check:** `npm run lint` (zero warnings).
- **End-to-End verification:** Run alongside local `waf-api` with test event injection via `curl -X POST /api/v1/events`.
