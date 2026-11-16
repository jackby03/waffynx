# Functional Specification: Site Management & Zero-File Bootstrap

**Status:** Draft — awaiting review
**Feature ID:** `SPEC-003`
**Author(s):** Waffynx Core Team
**Created:** 2026-11-16
**Target Milestone:** v0.2.0 (Phase 0 of [`docs/ROADMAP.md`](../../docs/ROADMAP.md))

---

## 1. Objective & Context

### 1.1 Problem Statement

Waffynx cannot currently protect a site without hand-editing files on the host:

- **Topology is static nginx configuration.** `deploy/docker/nginx.conf` hardcodes
  `proxy_pass http://backend:80` and a `server_name localhost`. Adding a domain
  means editing that file and restarting the container.
- **`cfg.Routes` does not do this.** The `routes:` key is only consumed by
  `internal/gateway` — the forward proxy that ADR-0003 put out of scope — and by
  the config API for display. It does not generate nginx configuration and does
  not affect the reverse-proxy data plane at all.
- **First boot requires editing a 136-line YAML.** The image ships a config whose
  `api.auth.jwt_secret` is the literal `change-me-in-production`, and `NewServer`
  correctly refuses to start with it. So `docker run` with no volume fails.

The result: the only working deployment path is "clone, compile nginx, compile the
module, edit YAML, run". That is the opposite of the product thesis.

> **This is not a CRUD task.** A CRUD that writes a `sites:` list nobody reads
> would return `201 Created` while protecting nothing — the same fail-open defect
> as the IP-ban handler (see `docs/ROADMAP.md` §7, gap 1). The real deliverable is
> a **renderer that turns the site list into a valid nginx configuration and
> reloads nginx**.

### 1.2 Value Proposition & Goals

- **Goal 1:** protect a site with a single `docker run` and no file editing.
- **Goal 2:** `waffynx site add` creates a working reverse proxy in one command,
  and the change survives a restart.
- **Goal 3:** the management API is the single write path, so the CLI and any
  future GUI cannot diverge.
- **Goal 4:** an invalid change is rejected before it can take the proxy down.

---

## 2. Scope

### 2.1 In-Scope (Strict Requirements)

- [ ] `sites:` section in `configs/waffynx.yaml`: host, upstream, TLS (cert/key
      paths), path-prefix rules, per-site plugin selection.
- [ ] **nginx configuration renderer**: produce `server` blocks from sites, with
      the `waffynx*` directives and `proxy_pass` pointing at the site's upstream.
- [ ] **Atomic apply**: validate → render → write → `nginx -s reload`. On any
      failure, keep the previous configuration live and report the error.
- [ ] Management API: `GET/POST/PUT/DELETE /api/v1/sites[/{host}]`, authenticated,
      mutating operations `requireAdmin`.
- [ ] CLI: `waffynx site add|list|show|remove`, talking to the API.
- [ ] Environment bootstrap: `WAFFYNX_SITE_HOST` + `WAFFYNX_SITE_UPSTREAM`
      (+ optional TLS paths) create the first site at boot, no file editing.
- [ ] `WAFFYNX_JWT_SECRET`: if unset, generate once and persist to the data
      directory with `0600`; never fall back to a placeholder.
- [ ] Every write is validated by `config.Parse` before touching disk, and files
      are written `0600` (secrets) with a temp-file + rename.
- [ ] `waffynx verify` gains a `--target` mode that checks a running instance
      (benign 200, SQLi 403) so the deployed path can be proven, not assumed.

### 2.2 Out-of-Scope (Deliberately Excluded)

- ⛔ **GUI screens** for sites. Phase 0 is CLI/API-first; the control room comes
  after the behaviour settles.
- ⛔ **Automatic certificate issuance (ACME)**. This spec accepts cert/key file
  paths and plain HTTP only. Issuance is a separate spec.
- ⛔ Per-site policy authoring UI, managed rule catalog, WAF analytics.
- ⛔ Multi-tenancy, teams, RBAC beyond the existing `admin` role.
- ⛔ Rewriting `internal/gateway` (forward proxy). It stays frozen; `routes:`
  keeps serving it.
- ⛔ Hot-reloading the C module itself. Only nginx configuration reload is in
  scope.
- ⛔ Backwards compatibility with the placeholder-secret startup path: it is
  removed, not tolerated.

---

## 3. Structured Requirements (Given-When-Then)

**R1 — Create a site via the API.**
Given an authenticated admin and a valid body `{host, upstream, tls?}`,
when `POST /api/v1/sites` is called,
then a `server` block for that host is rendered, nginx reloads, a request to that
host is proxied to the upstream, the config file is updated atomically, and the
response is `201`.

**R2 — Reject an invalid upstream.**
Given a body whose `upstream` is not `host:port` or a `http(s)://` URL,
when the site is created,
then the response is `400`, the config file is unchanged, and nginx is not
reloaded.

**R3 — Never break a running proxy.**
Given a rendered configuration that `nginx -t` rejects,
when the site is applied,
then the previous configuration stays live, the response is `500` with the nginx
error, and the on-disk config is rolled back.

**R4 — Persistence.**
Given a site created through the API,
when the process restarts,
then the site is still protected and listed by `waffynx site list`.

**R5 — Zero-file bootstrap.**
Given a fresh container with `WAFFYNX_SITE_HOST` and `WAFFYNX_SITE_UPSTREAM` set
and no mounted config,
when it starts,
then that site is protected and the API is reachable, with no manual file edit.

**R6 — Secret handling.**
Given no `WAFFYNX_JWT_SECRET`,
when the container starts for the first time,
then a random secret is generated, persisted `0600`, and reused on restart, so
tokens remain valid across restarts.

**R7 — Duplicate hosts.**
Given a site for `example.com` already exists,
when another is created with the same host and path prefix,
then the response is `409` and nothing is written.

**R8 — Removal.**
Given an existing site,
when `DELETE /api/v1/sites/example.com` is called,
then its `server` block is removed, nginx reloads, and requests to that host stop
being proxied by Waffynx.

---

## 4. Acceptance Criteria

1. `docker run -e WAFFYNX_SITE_HOST=example.test -e WAFFYNX_SITE_UPSTREAM=<ip:port> waffynx`
   protects the site with **no** mounted files and **no** manual edit.
2. `curl http://example.test/` reaches the upstream; `curl "http://example.test/?q=UNION+SELECT+1"`
   returns `403`.
3. `waffynx site add`, `list`, `remove` work against a running instance and the
   result survives `docker restart`.
4. A bad upstream, a duplicate host and a broken nginx config each fail with the
   documented status code, leaving the previous configuration live.
5. `waffynx verify --target http://127.0.0.1:8080` reports the deployed instance
   blocking a SQLi probe and allowing benign traffic.
6. `golangci-lint run ./...` is clean and coverage of the new renderer is ≥ 80%
   (it is pure string generation, there is no excuse).

---

## 5. Constraints

- Constitution §1.1: fail closed. A renderer error must never leave the proxy
  with no rules — it keeps the last good configuration.
- Constitution §1.2: the renderer runs on the control plane, not the hot path.
- Constitution §1.4: `host` and `upstream` are untrusted input; validate the
  character set and length, and never interpolate them into nginx syntax
  unchecked (a `host` containing `;` or `{` would inject directives).
- Constitution §2.2: config files carry the JWT secret → `0600`, temp file +
  rename, no world-readable intermediate.
