# Atomic Tasks: Dashboard UI

**Related Spec:** [`spec.md`](./spec.md)
**Related Plan:** [`plan.md`](./plan.md)
**Status:** Under Review
**Progress:** 0 / 12 tasks completed

Only one task may be `in_progress`. Each task must be completed and verified before the next task starts.

## Phase 0: Approval and Contracts

- [ ] **Task 0.1: Approve feature documents**
  - **Files:** `spec.md`, `plan.md`, `clarifications.md`
  - **Scope:** Resolve all blocking questions and change spec/plan status to `Approved`.
  - **DoD:** No blocking clarification remains and user explicitly approves the documents.

- [ ] **Task 0.2: Define event bridge contract**
  - **Files:** `internal/events/`, `internal/config/`, API/sidecar contract tests
  - **Scope:** Define service authentication, event limits, timeout, response codes, and failure behavior.
  - **DoD:** Contract tests cover valid, unauthorized, oversized, malformed, and unavailable-ingest cases.

## Phase 1: Backend Event Boundary

- [ ] **Task 1.1: Implement authenticated event ingestion**
  - **Files:** `cmd/waf-api/main.go`, `internal/auth/`, tests
  - **Scope:** Validate service credentials and event fields before publishing.
  - **DoD:** Service token succeeds; operator-only or missing token fails; malformed events return `400`; tests pass with `go test -race ./cmd/waf-api`.

- [ ] **Task 1.2: Publish sidecar events to the API**
  - **Files:** `internal/engine/sidecar.go`, `internal/config/`, tests
  - **Scope:** Add bounded, authenticated delivery for blocked events only; delivery errors must not change verdicts.
  - **DoD:** Integration test proves a blocked event reaches the API broker and a failed API does not change the block response.

## Phase 2: Frontend Setup and Authentication

- [ ] **Task 2.1: Initialize the UI package**
  - **Files:** `cmd/waf-api/ui/package.json`, lockfile, Vite/TypeScript configuration
  - **Scope:** Add only approved frontend dependencies and scripts for lint, test, and build.
  - **DoD:** `npm ci`, `npm run lint`, `npm test -- --run`, and `npm run build` pass.

- [ ] **Task 2.2: Implement login and session guard**
  - **Files:** `cmd/waf-api/ui/src/features/auth/`, `services/api.ts`
  - **Scope:** In-memory JWT, logout, redirect on `401`, generic login errors.
  - **DoD:** Unit tests cover valid login, invalid login, expiry/401, logout, and absence of persistent token storage.

## Phase 3: Dashboard Features

- [ ] **Task 3.1: Implement overview data views**
  - **Files:** `cmd/waf-api/ui/src/features/overview/`
  - **Scope:** Status, metrics, plugins, loading/error/empty states.
  - **DoD:** Component tests cover successful, empty, timeout, and `401` responses.

- [ ] **Task 3.2: Implement authenticated streaming event client**
  - **Files:** `cmd/waf-api/ui/src/services/event-stream.ts`, live-events feature
  - **Scope:** `fetch` streaming with Bearer header, parser, bounded exponential backoff, visible connection state.
  - **DoD:** Tests cover event parsing, malformed event, `401` stop, reconnect cap, cancellation, and duplicate prevention.

- [ ] **Task 3.3: Implement safe event rendering and responsive shell**
  - **Files:** `cmd/waf-api/ui/src/`
  - **Scope:** Text-only event fields, responsive desktop/mobile layout, accessible states.
  - **DoD:** DOM test proves a script payload is rendered as text; keyboard and mobile layout checks pass.

## Phase 4: Serving and Integration

- [ ] **Task 4.1: Embed and serve production assets**
  - **Files:** `cmd/waf-api/`, `cmd/waf-api/ui/`, tests
  - **Scope:** Embed `dist`, preserve API routes, serve SPA fallback only for UI routes.
  - **DoD:** Go tests verify API routes are not shadowed and a production UI asset is served.

- [ ] **Task 4.2: Add Linux end-to-end coverage**
  - **Files:** `test/`, `vagrant/` if needed
  - **Scope:** Exercise sidecar event, API ingest, authenticated stream, and failure behavior.
  - **DoD:** `make vagrant-test` passes and unauthorized SSE access is rejected.

## Phase 5: Final Verification

- [ ] **Task 5.1: Run repository quality gates**
  - **Files:** none beyond approved changes
  - **Scope:** Run Go, frontend, security regression, and Linux checks from `plan.md`.
  - **DoD:** `go test -race ./...`, `gofmt -s -l .`, `golangci-lint run ./...`, frontend checks, and `make vagrant-test` pass; no out-of-scope files changed.
