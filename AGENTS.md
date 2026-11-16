# AGENTS.md — Operational Directives & Agent Governance

> **Governance Notice:** This document is subordinate to [`constitution.md`](constitution.md). All AI agents, contributors, and automated tools operating in this repository must strictly comply with the laws, security invariants, and execution protocols defined herein.

---

## 1. Hierarchy of Authority (Constitution §4.1)

When resolving design, scope, or implementation ambiguities, artifacts strictly adhere to the following order of precedence:

1. **[`constitution.md`](constitution.md) — Absolute Authority:** Non-negotiable architectural laws, security invariants, hard technical constraints, and separation of planes.
2. **`specs/<feature>/spec.md` — Feature Contract & Boundaries:** Approved functional requirements, user stories, and strict `Out-of-Scope` declarations.
3. **`specs/<feature>/plan.md` — Technical Implementation Architecture:** Component mappings, data contracts, failure modes, and verification commands.
4. **`specs/<feature>/tasks.md` — Atomic Execution Checklist:** Sequential tasks with explicit Definitions of Done (DoD).

### Strategic Reference Documents (Non-Governing)
* **[`docs/ROADMAP.md`](docs/ROADMAP.md):** active roadmap. Self-hosted WAF + reverse proxy, container-first, targeting near-total parity with Cloudflare WAF (WAF only).
* **[`docs/FUTURE.md`](docs/FUTURE.md):** parked NGFW / SWG / ZTNA research. **Out of scope** — nothing here may be implemented under the current product direction (ADR-0003).
* **[`docs/adr/`](docs/adr/):** Architectural Decision Records documenting historical context and technology choices.
* **[`specs/HARNESS.md`](specs/HARNESS.md):** Detailed step-by-step operational loop for Spec-Driven Development.

---

## 2. Constitutional Invariants & Non-Negotiable Rules

Agents must never violate the following core principles established in `constitution.md`:

### Architectural Principles (Constitution §1)
* **Fail-Closed Security (Default-Deny) [§1.1]:** If an internal component, plugin, or ML scorer times out or crashes, the system must fail-safe **according to the configured policy** (default: block or drop; never silently bypass uninspected traffic). Insecure defaults are forbidden; startup must abort if credentials or keys are missing or placeholders.
* **Zero-Allocation in the Hot Path [§1.2]:** The inspection pipeline runs on every request. Eliminate heap allocations via `sync.Pool`, prohibit reflection (`reflect`) or dynamic schema unmarshaling in the hot path, and maintain sub-2ms P99 latency overhead.
* **Strict Separation of Planes [§1.3]:**
  * **Data Plane (`modules/ngx_waffynx`, `internal/engine`):** Pure inspection and enforcement. Zero external network dependencies, zero blocking file I/O, zero external DB queries during inspection.
  * **Control Plane (`cmd/waf-api`):** Management, telemetry, IaC, and SOC UI. Strictly forbidden from participating in per-request data plane inspection.
  * **Host Enforcement Agent (`cmd/waf-agent`):** Kernel packet filtering (nftables/eBPF) driven asynchronously via control-plane events.
* **Zero-Trust Boundary Validation [§1.4]:** Treat all inputs—including internal IPC payloads and headers—as untrusted. Enforce bounded buffer lengths and character set validation before parsing.

### Hard Technical Constraints (Constitution §2)
* **Target Runtime [§2.1]:** Linux is the sole production runtime. Standalone daemons (`waf-api`, `waf-agent`) must compile statically with `CGO_ENABLED=0 GOOS=linux`. All source files must use standard POSIX LF (`\n`) line endings.
* **Cryptographic Rigor & Sockets [§2.2]:** Zero secrets in source. All token, key, and signature comparisons must use `crypto/subtle.ConstantTimeCompare`. Unix domain sockets under `/var/run/waffynx/` must enforce `0600` or `0660` permissions (world-accessible permissions are forbidden).
* **Dependency Discipline [§2.3]:** Exhaust the Go standard library before proposing third-party packages. Adding dependencies to the data plane requires an approved ADR.

### Quality & Regression Invariants (Constitution §3)
* **Verification-First Delivery [§3.1]:** Automated tests are mandatory. Parsers, policy evaluators, and protocol decoders require both unit tests and fuzz tests (`go test -fuzz`).
* **Regression Immutability [§3.2]:** Security fixes addressing a known vulnerability must include a permanent regression test.
* **Static Analysis [§3.3]:** Code must pass `golangci-lint` **with strict security and performance linters enabled** (`errcheck`, `govet`, `ineffassign`, `staticcheck`, `unused`, plus `gosec`, `bodyclose`, `nilerr`, `errorlint`, `copyloopvar`, `unconvert`, `misspell`) and return exit code `0`. Configuration lives in [`.golangci.yml`](.golangci.yml).

---

## 3. Spec-Driven Execution Protocol (Constitution §4.2)

Every AI agent must execute tasks within the SDD framework:

1. **Spec Before Code:** Never generate production code or schema migrations without an approved `spec.md`, `plan.md`, and `tasks.md` in `specs/`.
2. **Strict Scope Boundaries:** Respect the `Out-of-Scope` section of each feature specification. Never synthesize unrequested utility libraries, premature abstractions, or unsolicited architectural refactors.
3. **Atomic Task Execution:** Work on **one task** in `tasks.md` at a time. Mark it `in_progress`, implement within the declared scope, verify its DoD, and mark it complete before moving to the next.
4. **Preservation of Context:** Never delete existing comments, docstrings, architectural rationales, or license headers.

---

## 4. Scope Mapping to Constitutional Planes

When implementing capabilities from [`docs/ROADMAP.md`](docs/ROADMAP.md), agents must align with the constitutional planes. The product is a **self-hosted WAF and reverse proxy, container-first**; anything in [`docs/FUTURE.md`](docs/FUTURE.md) is out of scope.

| Constitutional Plane | System Subsystem | Roadmap Capabilities | Implementation Boundary |
| :--- | :--- | :--- | :--- |
| **Data Plane** | `modules/ngx_waffynx`<br>`internal/engine` | Reverse-proxy WAF inspection, rule engine, parsers, bot defense, API schema validation, pluggable AI scoring | Native Nginx C module + zero-copy Go sidecar via `0600` Unix socket. Sub-2ms hot path. |
| **Host Enforcement Agent** | `cmd/waf-agent`<br>`internal/firewall` | Host `nftables`/`ufw` drop — **system mode only (P1)**. Never started in the container. | Asynchronous kernel driver. Must never be required for the core protection path. |
| **Control Plane** | `cmd/waf-api`<br>`internal/api` | Sites/proxy-host management, policy and rule authoring, optional external-AI provider config, SOC Control Room UI, audit and security events | Out-of-band management. Strictly prohibited from inline request data path. |

---

## 5. Essential Commands (Execution & Verification)

*Run only these commands to validate your work:*

> **Platform note:** the local dev box is `windows/386`, but Linux is the sole production runtime (Constitution §2.1). Lint and build with `GOOS=linux` so the data-plane files behind build tags (`internal/engine/engine_unix.go`, `internal/appsec/bridge_cpp_linux.go`) are actually analysed instead of their stubs. `-race` requires `GOARCH=amd64` plus a C toolchain and is not available on the 386 Windows dev box; it runs in CI and in the Vagrant VM.

* **Build Go binaries:** `make build` (outputs `waffynx`, `waf-agent`, `waf-api`, `appsec-bridge` to `bin/`)
* **Run all unit tests:** `go test -race ./...` (use `make test`, which covers `./...` including `cmd/`)
* **Run single test package:** `go test -v -race ./internal/<package>`
* **Run specific test:** `go test -v ./internal/policy -run TestPolicyEvaluate`
* **Run fuzz tests:** `go test -fuzz=FuzzPolicyEvaluate -fuzztime=10s ./internal/policy` (see also `FuzzParseRequest` in `internal/parsers`)
* **Functional self-test:** `waffynx verify -c configs/waffynx.yaml` (drives benign and malicious requests through the real inspection pipeline; exits non-zero on any mismatch, `--json` for CI)
* **Lint / Static analysis:** `GOOS=linux golangci-lint run ./...` (also runs the `gofmt -s` formatter)
* **Format check:** `gofmt -s -l .` (`.gitattributes` pins `eol=lf`, so the working tree stays LF regardless of a contributor's `core.autocrlf`)
* **Compile C++ bridge (Linux):** `make bridge-build` (outputs `bin/libwaffynx_bridge.so`)
* **Vagrant VM test cycle (Windows dev):** `make vagrant-test` (executes end-to-end integration test inside the Linux VM)

---

## 6. Repository Layout & Component Boundaries

| Path | Plane | Responsibility |
| :--- | :--- | :--- |
| `constitution.md` | Governance | Supreme architectural law and non-negotiable invariants. |
| `AGENTS.md` | Governance | Operational context, agent directives, and constitutional alignment. |
| `specs/` | Governance | Spec-Driven Development feature lifecycles (`spec.md`, `plan.md`, `tasks.md`). |
| `docs/` | Architecture | Master roadmap (`ROADMAP.md`) and Architecture Decision Records (`adr/`). |
| `.golangci.yml` | Governance | Linter configuration enforcing Constitution §3.3 (standard + security/performance linters, `gofmt -s` formatter). |
| `.gitattributes` | Governance | Pins `eol=lf` so the working tree satisfies Constitution §2.1 independently of `core.autocrlf`. |
| `cmd/waffynx/` | Data Plane | Main engine CLI entrypoint (sidecar socket listener & proxy bootstrap). |
| `cmd/waf-agent/` | Host Agent | Host firewall daemon (nftables/UFW synchronization). |
| `cmd/waf-api/` | Control Plane | Management REST API CLI bootstrap (<60 lines). |
| `cmd/appsec-bridge/` | Data Plane | Open-AppSec scoring daemon exposing a `0600` Unix socket; CGo build links `libwaffynx_bridge.so`. |
| `ui/` | Control Plane | Waffynx Control Room single-page application (React 19 + TypeScript + Vite). |
| `internal/api/` | Control Plane | Management REST API (:9090), SSE broker, middleware, and SPA file server. |
| `internal/engine/` | Data Plane | Low-latency 3-stage inspection pipeline (orchestrator & Unix socket server). |
| `internal/policy/` | Data Plane | Rule-based policy evaluation engine (conditions, operators, actions). |
| `internal/plugin/` | Data Plane | Plugin interface, registry, and priority chain execution. |
| `internal/appsec/` | Data Plane | Open-AppSec ML bridge and scoring client. |
| `internal/firewall/` | Host Agent | Host firewall drivers (nftables and UFW rule managers). |
| `internal/auth/` | Control Plane | JWT authentication manager and OIDC integrations. |
| `internal/marketplace/` | Control Plane | Plugin package catalog and in-memory distribution store. |
| `internal/upstream/` | Data Plane | Reverse proxy load balancing algorithms (round-robin, least-connections). |
| `internal/audit/` | Control Plane | Bounded in-memory audit ring buffer with optional append-only file sink and query filters. |
| `internal/config/` | Shared | YAML schema, load, and validation for API, agent, and engine configuration (fail-closed at startup). |
| `internal/events/` | Control Plane | In-process WAF event broker (pub/sub) and authenticated publisher to the API. |
| `internal/gateway/` | Data Plane | Host-level forward proxy gateway and route table. |
| `internal/learning/` | Data Plane | Behavioral learning engine: verdict history and rule-suggestion generation, driven from the sidecar. |
| `internal/logging/` | Shared | Structured (zerolog) logger used by every plane; hot-path callers must stay allocation-free. |
| `internal/metrics/` | Control Plane | Prometheus metric registration and the `/metrics` HTTP handler. |
| `internal/parsers/` | Data Plane | Request-body, upload, and GraphQL decoders; carries active fuzz targets (`internal/parsers/fuzz_test.go`). |
| `internal/ratelimit/` | Data Plane | Rate-limiter interface with a Redis fixed-window backend. |
| `internal/rules/` | Data Plane | Custom rule engine layered on top of the policy evaluator. |
| `internal/tls/` | Control Plane | Certificate manager with ACME/autocert integration. |
| `internal/version/` | Shared | Build version metadata injected via ldflags. |
| `modules/ngx_waffynx/` | Data Plane | Native Nginx C module for zero-copy HTTP interception (built against the `third_party/nginx` submodule, currently 1.31.4). |
| `plugins/` | Data Plane | Built-in inspection plugins (SQLi, XSS, rate-limiting, bot defense). |
| `configs/` | Configuration | Production runtime configurations (`waffynx.yaml`, `nginx.conf`). |
| `deploy/` | Infrastructure | Deployment assets (Helm charts, Dockerfiles, systemd unit files). |
| `vagrant/` | Development | Ubuntu 22.04 VM environment for Linux-native integration testing. |

---

## 7. Definition of Done (DoD)

Before declaring any task or feature complete, verify that:

1. **Tests Pass:** All unit and integration tests pass with zero race conditions (`go test -race ./...`).
2. **Zero Linter Warnings:** `GOOS=linux golangci-lint run ./...` returns exit code `0` with no baseline or merge-base filter. The tree is clean, so every finding is a regression.
3. **Constitutional Invariants Intact:** Invariants in [`constitution.md`](constitution.md) and the regression-test rule in its §3.2 are strictly upheld.
4. **Scope Boundaries Respected:** No modifications were made outside the declared task scope in `tasks.md`.
5. **Spec Compliance:** Acceptance criteria in `spec.md` and task criteria in `tasks.md` are 100% met.
