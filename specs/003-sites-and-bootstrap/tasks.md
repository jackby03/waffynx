# Atomic Tasks: Site Management & Zero-File Bootstrap

**Related Spec:** [`spec.md`](./spec.md)
**Related Plan:** [`plan.md`](./plan.md)
**Progress:** 0 / 22 Tasks Completed

---

## Guidelines for Execution

1. Work through tasks sequentially. Do not jump ahead.
2. Follow TDD: write the failing test first, then the implementation.
3. Check a task off (`[x]`) only when its **Definition of Done (DoD)** is fully satisfied.
4. One task per commit. No task may leave `golangci-lint run ./...` non-clean.

---

## Phase 1: Validation & Renderer (pure, no I/O)

- [ ] **Task 1.1: `internal/sites` types and validation**
  - **Files:** `internal/sites/site.go`, `internal/sites/site_test.go`
  - **Action:** `Site`, `TLSPair`, `PathRule` types plus `Validate()`. Table tests cover every rule in `plan.md` §3, including injection attempts (`host` containing `;`, `{`, newline, `..`).
  - **DoD:** injection attempts rejected with a typed error; `go test ./internal/sites` green.

- [ ] **Task 1.2: nginx renderer**
  - **Files:** `internal/sites/render.go`, `internal/sites/render_test.go`, `internal/sites/testdata/*.golden`
  - **Action:** `Render(sites []Site, opts) (map[string]string, error)` producing one `server` block per site.
  - **DoD:** golden-file tests for HTTP-only, TLS, multiple path rules, wildcard host. No `fmt.Sprintf` of unvalidated input.

- [ ] **Task 1.3: base `nginx.conf` template with `include sites/*.conf`**
  - **Files:** `deploy/docker/nginx.conf.tmpl`, `internal/sites/conf.go`
  - **Action:** move the current `http {}` block into a template that includes the generated directory, preserving the `/health` location.
  - **DoD:** rendering zero sites yields a config that still serves `/health` and passes `nginx -t`.

## Phase 2: Transactional Apply

- [ ] **Task 2.1: apply protocol with rollback**
  - **Files:** `internal/sites/apply.go`, `internal/sites/apply_test.go`
  - **Action:** validate → render to temp → `nginx -t` → rename → reload → persist, with restore on failure (`plan.md` §4).
  - **DoD:** tests prove that a failing `nginx -t` leaves the previous files byte-identical and nginx untouched.

- [ ] **Task 2.2: serialise applies**
  - **Files:** `internal/sites/apply.go`
  - **Action:** single `applyMu`; coalesce rapid applies.
  - **DoD:** concurrent-apply test shows no interleaved render and no lost update.

- [ ] **Task 2.3: expose apply + reload from the engine**
  - **Files:** `internal/engine/engine.go`, `internal/engine/engine_unix.go`
  - **Action:** `ApplyConfig(files map[string]string) error` that writes, reloads and surfaces the last error. Windows stub returns the existing "requires Linux" error.
  - **DoD:** `engine.Reload` behaviour unchanged; new method covered on Linux paths.

## Phase 3: Config & Persistence

- [ ] **Task 3.1: `sites:` in the config schema**
  - **Files:** `internal/config/config.go`, `internal/config/config_test.go`, `configs/waffynx.yaml`
  - **Action:** add `Sites []sites.Site` (or an equivalent local type to avoid an import cycle), validation wired into `Parse`.
  - **DoD:** invalid site in YAML fails `config.Parse`; `waffynx check` reports it.

- [ ] **Task 3.2: atomic config persistence**
  - **Files:** `internal/api/handlers_sites.go`, `internal/api/handlers_sites_test.go`
  - **Action:** temp file + rename, `0600`, validate before write. Reuse the same writer as `handleUpdateConfig` so there is one implementation.
  - **DoD:** test asserts `0600` mode and that a validation failure leaves the file untouched.

## Phase 4: API

- [ ] **Task 4.1: `GET /api/v1/sites` and `GET /api/v1/sites/{host}`**
  - **Files:** `internal/api/handlers_sites.go`, `internal/api/routes.go`
  - **DoD:** authenticated, returns the list; unknown host → `404`.

- [ ] **Task 4.2: `POST /api/v1/sites`**
  - **DoD:** `201` on success; `400` invalid; `409` duplicate; **the site is served** (asserted by an integration test, not just a status code).

- [ ] **Task 4.3: `PUT` and `DELETE /api/v1/sites/{host}`**
  - **DoD:** `200`/`204`; deletion stops proxying that host; both emit audit records.

- [ ] **Task 4.4: RBAC and audit coverage**
  - **DoD:** non-admin gets `403` on every mutating verb; each write records an audit event with actor and result.

## Phase 5: Environment Bootstrap

- [ ] **Task 5.1: env overlay before validation**
  - **Files:** `internal/config/env.go`, `internal/config/env_test.go`
  - **DoD:** `WAFFYNX_SITE_HOST` + `WAFFYNX_SITE_UPSTREAM` alone produce a valid config with one site; malformed values fail closed with a clear error.

- [ ] **Task 5.2: JWT secret generation and persistence**
  - **Files:** `internal/config/secret.go`, tests
  - **DoD:** secret generated once, persisted `0600`, reused across restarts; existing `NewServer` placeholder rejection still fires when the file is unreadable.

- [ ] **Task 5.3: entrypoint applies bootstrap then starts nginx**
  - **Files:** `deploy/docker/entrypoint.sh`
  - **DoD:** fresh `docker run` with only env vars serves a protected site; no config file mounted.

## Phase 6: CLI

- [ ] **Task 6.1: `waffynx site list|show`**
  - **DoD:** talks to the API with a token; exits non-zero on auth failure with an actionable message.

- [ ] **Task 6.2: `waffynx site add|remove`**
  - **DoD:** round-trips against a running instance; `--tls-cert/--tls-key` supported; errors surface the API status and body.

- [ ] **Task 6.3: `waffynx verify --target <url>`**
  - **DoD:** benign probe expects 2xx, SQLi probe expects 403; reports each result; exit code reflects mismatches.

## Phase 7: Verification & Documentation

- [ ] **Task 7.1: CI end-to-end job**
  - **Files:** `.github/workflows/ci.yml`
  - **Action:** build the image, run it with env bootstrap against a throwaway upstream (`nginx:alpine`), assert 200 benign / 403 SQLi.
  - **DoD:** job fails if either assertion fails; runtime under 4 minutes.

- [ ] **Task 7.2: docs**
  - **Files:** `README.md`, `docs/ROADMAP.md`, `AGENTS.md`
  - **DoD:** README quick start becomes the single env-var command; roadmap §7 gaps 2, 3 and 6 marked fixed; AGENTS.md §5 gains the `site` commands.

- [ ] **Task 7.3: coverage gate**
  - **DoD:** `internal/sites` ≥ 80% and the renderer ≥ 90%, verified in the CI coverage report.
