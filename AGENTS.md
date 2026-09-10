# AGENTS.md — Operational Context & Agent Directives

## 1. Project Context
- **Description:** Waffynx — High-performance Web Application Firewall (WAF) combining a native Nginx C module, a low-latency Go sidecar inspection pipeline, and an ML-based scoring bridge (`open-appsec`).
- **Stack:** Go 1.22 (`CGO_ENABLED=0` for pure Go binaries) | C (Nginx 1.26 module) | C++ (open-appsec bridge) | POSIX / Linux.
- **Philosophy:** Spec-Driven Development (SDD). All implementations derive strictly from [`constitution.md`](constitution.md), [`specs/HARNESS.md`](specs/HARNESS.md), and feature-specific `spec.md` / `tasks.md`.

---

## 2. Essential Commands (Execution & Verification)
*Run only these verified commands to validate your work:*

- **Build Go binaries:** `make build` (outputs `waffynx`, `waf-agent`, `waf-api` to `bin/`)
- **Run all unit tests:** `go test -race ./...`
- **Run single test package:** `go test -v -race ./internal/<package>`
- **Run specific test:** `go test -v ./internal/policy -run TestPolicyEvaluate`
- **Run fuzz tests:** `go test -fuzz=FuzzEvaluator -fuzztime=10s ./internal/policy`
- **Lint / Static analysis:** `golangci-lint run ./...`
- **Format check:** `gofmt -s -l .`
- **Compile C++ bridge (Linux):** `make bridge-build` (outputs `dist/libwaffynx_bridge.so`)
- **Vagrant VM test cycle (Windows dev):** `make vagrant-test` (executes end-to-end integration test inside Linux VM)

---

## 3. Project Map
```text
waffynx/
├── constitution.md           # Supreme architectural law & non-negotiable security invariants
├── specs/                    # Spec-Driven Development (HARNESS.md, templates/, feature specs)
├── docs/adr/                 # Architecture Decision Records (ADR-XXXX)
├── cmd/                      # Binary entrypoints
│   ├── waffynx/              # Main engine CLI (starts sidecar socket server & proxy)
│   ├── waf-agent/            # Host firewall agent (nftables/UFW rule sync)
│   ├── waf-api/              # Management REST API (:9090)
│   └── appsec-bridge/        # Standalone ML daemon mock
├── internal/                 # Private application logic
│   ├── engine/               # Sidecar Unix socket server & 3-stage pipeline orchestrator
│   ├── policy/               # Rule-based policy evaluator (conditions, operators)
│   ├── plugin/               # Plugin interface, registry & priority chain
│   ├── appsec/               # ML scoring bridge (BasicScorer & BridgeScorer)
│   ├── ratelimit/            # Memory and Redis-backed rate limiting
│   ├── firewall/             # Host firewall drivers (nftables & UFW)
│   ├── auth/                 # JWT manager & OIDC integration
│   ├── marketplace/          # Plugin package catalog & in-memory store
│   └── upstream/             # Reverse proxy load balancer (round-robin, least-conn)
├── modules/ngx_waffynx/      # Nginx C module (intercepts HTTP, communicates via Unix socket)
├── plugins/                  # Built-in WAF plugins (SQLi, XSS, rate-limit, bot detection)
├── pkg/proto/                # Protobuf definitions & generated gRPC code
├── configs/                  # Production configurations (waffynx.yaml, nginx.conf)
├── deploy/                   # Deployment assets (helm/, docker/, systemd/)
├── third_party/              # Forked submodules (nginx, open-appsec)
├── test/                     # Integration tests & payload fixtures (eval_sqli.json, eval_normal.json)
└── vagrant/                  # Ubuntu 22.04 VM environment & provisioning
```

---

## 4. Critical Behavior Guardrails

1. **Linux-Only Runtime:** Production runtime is Linux only. `engine_windows.go` is an intentional stub. When developing on Windows, run builds and tests via WSL or the Vagrant VM (`make vagrant-test`).
2. **Zero Unauthorized Dependencies:** Do not add third-party dependencies to `go.mod` without explicit architectural approval. Prefer standard library (`net/http`, `crypto`, `sync`, `context`).
3. **Fail-Closed Security:** If an internal component, plugin, or scorer times out or crashes during request inspection, fail closed (`403 Forbidden` / deny). Never allow uninspected traffic on failure.
4. **Secrets & Timing Attacks:** Never use `==` for secrets, API keys, or JWT tokens. Always use `crypto/subtle.ConstantTimeCompare`.
5. **Unix Socket Permissions:** All Unix domain sockets must be created with `0600` or `0660` permissions. World-accessible modes (`0666`/`0777`) are strictly forbidden.
6. **Strict CORS & Input Validation:** Always reject unauthorized preflight `OPTIONS` requests with `403 Forbidden`. Wildcard `*` CORS with credentials is prohibited.
7. **Atomic Task Execution:** Work on **one task** in `tasks.md` at a time. Do not modify files outside the declared `In-Scope` boundary.
8. **Preserve Documentation & LF:** Never delete existing comments, docstrings, or architectural rationales. Always commit standard POSIX LF (`\n`) line endings (CRLF breaks Nginx builds).

---

## 5. Code Conventions & Standards

- **Go Idioms:** Standard library conventions. Explicit error handling: wrap errors with context (`fmt.Errorf("parsing rule %s: %w", id, err)`). Never discard errors silently.
- **Hot-Path Performance:** The inspection pipeline (`sidecar.go -> plugin chain -> policy evaluator`) runs on every request. Eliminate unnecessary heap allocations, avoid buffer copying, and minimize lock contention (`sync.RWMutex` read-locks).
- **Strict Typing:** Avoid `interface{}` or `any` where concrete structs or interfaces can be defined.
- **Logging:** Use `internal/logging` (zerolog wrapper). Never use `log.Fatal()` or `os.Exit()` inside library functions; return `error` instead.
- **Naming Conventions:**
  - Files: `snake_case.go`
  - Types/Interfaces: `PascalCase`
  - Functions/Methods: `PascalCase` (exported) / `camelCase` (unexported)
  - Config/JSON/YAML tags: `snake_case`

---

## 6. Definition of Done (DoD)

Before declaring any task or feature complete, verify that:

1. **Tests Pass:** All unit and integration tests pass with zero race conditions (`go test -race ./...`).
2. **No Linter Warnings:** `golangci-lint run ./...` returns exit code `0`.
3. **Security Invariants Intact:** Invariants in [`constitution.md`](constitution.md) and regression rules in [`.jules/sentinel.md`](.jules/sentinel.md) are not violated.
4. **Spec Compliance:** Acceptance criteria in `spec.md` and task criteria in `tasks.md` are 100% met.
