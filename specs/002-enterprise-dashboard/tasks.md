# Atomic Tasks: Enterprise Security Center Dashboard

**Related Spec:** [`spec.md`](./spec.md)
**Related Plan:** [`plan.md`](./plan.md)
**Status:** Complete
**Progress:** 10 / 10 tasks completed

Only one task may be `in_progress` at a time.

## Phase 1: Backend API Extensions

- [x] **Task 1.1: Implement Firewall Endpoints in Management API**
  - **Files:** `cmd/waf-api/main.go`, `cmd/waf-api/main_test.go`
  - **Scope:** Expose `/api/v1/firewall/rules`, `/api/v1/firewall/block`, and `/api/v1/firewall/unblock/{ip}` with admin RBAC.
  - **DoD:** Unit tests verify authorization, valid input handling, and 403 on non-admin.

## Phase 2: Frontend Data Layer & Cyber-Ops Styles

- [x] **Task 2.1: Extend Frontend API Services**
  - **Files:** `cmd/waf-api/ui/src/services/api.ts`
  - **Scope:** Add TypeScript types and methods for firewall operations, config update, and enriched events.
  - **DoD:** `tsc --noEmit` passes with zero type errors.

- [x] **Task 2.2: Implement Cyber-Ops Design System & Layout Styles**
  - **Files:** `cmd/waf-api/ui/src/styles.css`
  - **Scope:** Dark cyber-ops palette, persistent sidebar layout, responsive drawer modal, badges and SVG styling.
  - **DoD:** Styles validate cleanly with no syntax errors.

## Phase 3: Core Views & Incident Forensics

- [x] **Task 3.1: Implement Sidebar & Navigation Shell**
  - **Files:** `cmd/waf-api/ui/src/components/Sidebar.tsx`, `components/Topbar.tsx`
  - **Scope:** Collapsible navigation, view switching, enforcement status pill, sign-out.
  - **DoD:** Component renders all 5 views and maintains active tab state.

- [x] **Task 3.2: Implement Threat Radar & SVG Analytics**
  - **Files:** `cmd/waf-api/ui/src/components/ThreatRadar.tsx`
  - **Scope:** Traffic throughput/block curve, OWASP threat donut, top attacked URIs and top attacker IPs.
  - **DoD:** Renders dynamic data and handles empty/loading states safely.

- [x] **Task 3.3: Implement Attack Forensics Table & Inspector Drawer**
  - **Files:** `cmd/waf-api/ui/src/components/AttackForensics.tsx`, `components/ForensicDrawer.tsx`
  - **Scope:** Filterable incident table; clicking any row opens slide-over drawer with HTTP dump, payload highlight, ML reasons, and "Ban IP in Kernel" button.
  - **DoD:** DOM safely renders text-only payloads, clicking row triggers drawer, and ban action invokes API.

## Phase 4: Security Policies, Firewall & Plugins

- [x] **Task 4.1: Implement Policies, Host Firewall & Marketplace Views**
  - **Files:** `cmd/waf-api/ui/src/components/SecurityPolicies.tsx`, `components/HostFirewall.tsx`, `components/MarketplaceView.tsx`
  - **Scope:** Enforcement mode switch (Blocking/Transparent), kernel IP ban table, and plugin configuration cards.
  - **DoD:** All views functional, inputs validate properly, type check passes.

## Phase 5: Assembly & Full System Verification

- [x] **Task 5.1: Assemble Root App, Build Production Bundle & Verify in VM**
  - **Files:** `cmd/waf-api/ui/src/main.tsx`, `cmd/waf-api/ui/dist/`
  - **Scope:** Assemble views, run `npm run build`, copy to Vagrant VM, run test suite and verify visually via browser.
  - **DoD:** All unit tests pass, `test.sh` passes 19/19, browser shows new Cyber-Ops SOC UI.

## Phase 6: Decoupled Architecture & Local Mock Development Environment

- [x] **Task 6.1: Add Live Disk-Serving Support to Backend (`waf-api`)**
  - **Files:** `cmd/waf-api/main.go`, `cmd/waf-api/main_test.go`
  - **Scope:** Introduce `--ui-dir` flag and `WAFFYNX_UI_DIR` environment variable to serve SPA assets directly from filesystem during dev/testing, eliminating full Go binary recompilation on UI edits.
  - **DoD:** Unit tests (`TestAPI_UIDirServesFromDisk`) verify disk serving and cache headers; all tests pass.

- [x] **Task 6.2: Implement Local Mock Backend & Real-Time Threat Simulator**
  - **Files:** `cmd/waf-api/ui/src/api/mock/`, `cmd/waf-api/ui/src/api/wafApi.ts`
  - **Scope:** Seamless dev mode with mock auth (`admin`/`admin`), 20+ signature rules, 6 marketplace plugins, and 2.2s simulated SSE stream.
  - **DoD:** `npm run dev` boots in <500ms on `http://localhost:5173/` with full live telemetry without requiring Vagrant VM.

- [x] **Task 6.3: Modular Frontend Refactoring (Clean Architecture)**
  - **Files:** `ui/src/` (`api/`, `components/`, `views/`, `context/`, `styles/`)
  - **Scope:** Decouple flat components into reusable atomic components (`common/`, `layout/`, `charts/`), dedicated views, centralized React contexts (`AuthContext`, `WafContext`), and modular CSS tokens.
  - **DoD:** `npx tsc --noEmit` passes with 0 errors; production build builds in <500ms.

## Phase 7: UI Decoupling & Control Plane Modularization (`internal/api`)

- [x] **Task 7.1: Relocate Frontend to Repository Root (`/ui`) & Go Embed Bridge**
  - **Files:** `ui/`, `ui/embed.go`, `ui/dist/placeholder.html`, `.gitignore`, `Makefile`
  - **Scope:** Move frontend from `cmd/waf-api/ui` to `/ui`, create clean `ui/embed.go` with `//go:embed all:dist`, add fallback placeholder so Go always builds out of the box on clean clones.
  - **DoD:** `go build ./ui` passes with zero errors; `/ui` is independent top-level package.

- [x] **Task 7.2: Refactor Management API into Modular `internal/api` Package**
  - **Files:** `internal/api/` (`types.go`, `server.go`, `routes.go`, `middleware.go`, `handlers_*.go`, `server_test.go`), `cmd/waf-api/main.go`, `cmd/waf-api/main_test.go`
  - **Scope:** Decompose 1,104-line `cmd/waf-api/main.go` into domain-specific modules in `internal/api`, slim `cmd/waf-api/main.go` down to 48 lines of CLI bootstrap, port all 12 tests to `server_test.go`.
  - **DoD:** `go test -v ./internal/api/...` passes 12/12; `go build ./cmd/waf-api` passes; zero breaking changes to HTTP contracts.


