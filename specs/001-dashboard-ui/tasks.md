# Atomic Tasks: Dashboard UI

**Related Spec:** [`spec.md`](./spec.md)  
**Related Plan:** [`plan.md`](./plan.md)  
**Status:** Pending Spec Approval  

---

<!-- 
[Will be fully populated once spec.md is filled and approved]
-->

## Phase 1: Project Scaffolding & Setup
- [ ] **Task 1.1: Initialize Vite React/TypeScript template**  
  *Done when:* `ui/package.json` builds cleanly with `pnpm run build` and `tsc --noEmit`.
- [ ] **Task 1.2: Configure Tailwind CSS and SOC Dark Theme tokens**  
  *Done when:* Tailwind imports compile without warnings and custom colors (`slate-950`, `emerald-500`, `rose-500`) are usable in classes.
- [ ] **Task 1.3: Setup API client and 401 interceptor**  
  *Done when:* `services/api.ts` automatically attaches the Bearer token from `sessionStorage` and clears storage on `401`.

## Phase 2: Authentication & Routing Shell
- [ ] **Task 2.1: Implement AuthContext and session handling**  
  *Done when:* User login state is verified and stored in `sessionStorage`.
- [ ] **Task 2.2: Implement LoginPage and AuthGuard router wrapper**  
  *Done when:* Unauthenticated access to `/` redirects to `/login`, and valid credentials redirect to `/overview`.
- [ ] **Task 2.3: Build base layout shell**  
  *Done when:* Sidebar navigation and Header (with engine health pill) render correctly across views.

## Phase 3: Feature Implementations
- [ ] **Task 3.1: Overview Dashboard KPI cards**  
  *Done when:* Total requests, blocked requests, and uptime poll every 5s from `/api/v1/metrics` and `/api/v1/status`.
- [ ] **Task 3.2: SSE client service with exponential backoff**  
  *Done when:* `sse.service.ts` connects to `/api/v1/events` and reconnects on socket drop.
- [ ] **Task 3.3: Live Events table with bounded buffer**  
  *Done when:* New attacks prepend to the table in real time, capping at 250 items with pause/resume functionality.
- [ ] **Task 3.4: Plugins & Marketplace view**  
  *Done when:* Registered plugins and catalog cards render data from `/api/v1/plugins` and `/api/v1/marketplace`.

## Phase 4: Security Verification & Final Build
- [ ] **Task 4.1: XSS sanitization test**  
  *Done when:* Injected script tags in mock events render strictly as plain text in the DOM.
- [ ] **Task 4.2: Production build validation**  
  *Done when:* `pnpm run lint` and `pnpm run build` produce a deployable static bundle under `ui/dist/` with 0 warnings.
