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
* **[`docs/ROADMAP.md`](docs/ROADMAP.md):** 14-pillar enterprise roadmap consolidating F5, Palo Alto Networks, Fortinet, Check Point, Cisco, and Cloudflare capabilities.
* **[`docs/adr/`](docs/adr/):** Architectural Decision Records documenting historical context and technology choices.
* **[`specs/HARNESS.md`](specs/HARNESS.md):** Detailed step-by-step operational loop for Spec-Driven Development.

---

## 2. Constitutional Invariants & Non-Negotiable Rules

Agents must never violate the following core principles established in `constitution.md`:

### Architectural Principles (Constitution §1)
* **Fail-Closed Security (Default-Deny) [§1.1]:** If an internal component, plugin, or ML scorer times out or crashes, fail closed (`403 Forbidden` / drop). Insecure defaults are forbidden; startup must abort if credentials or keys are missing or placeholders.
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
* **Regression Immutability [§3.2]:** Security fixes addressing logged vulnerabilities (e.g., in `.jules/sentinel.md`) must include a permanent regression test.
* **Static Analysis [§3.3]:** Code must pass `golangci-lint run ./...` with zero errors or unhandled warnings.

---

## 3. Spec-Driven Execution Protocol (Constitution §4.2)

Every AI agent must execute tasks within the SDD framework:

1. **Spec Before Code:** Never generate production code or schema migrations without an approved `spec.md`, `plan.md`, and `tasks.md` in `specs/`.
2. **Strict Scope Boundaries:** Respect the `Out-of-Scope` section of each feature specification. Never synthesize unrequested utility libraries, premature abstractions, or unsolicited architectural refactors.
3. **Atomic Task Execution:** Work on **one task** in `tasks.md` at a time. Mark it `in_progress`, implement within the declared scope, verify its DoD, and mark it complete before moving to the next.
4. **Preservation of Context:** Never delete existing comments, docstrings, architectural rationales, or license headers.

---

## 4. Tri-Architecture Mapping to Constitutional Planes

When implementing capabilities from [`docs/ROADMAP.md`](docs/ROADMAP.md), agents must align with the constitutional planes:

| Constitutional Plane | System Subsystem | Roadmap Capabilities | Implementation Boundary |
| :--- | :--- | :--- | :--- |
| **Data Plane** | `modules/ngx_waffynx`<br>`internal/engine` | Full-Proxy Inverso (WAF/ASM), Forward Proxy (SWG/CASB), Bot Defense, iRules, Open-AppSec ML | Native Nginx C module + zero-copy Go sidecar via `0600` Unix socket. Sub-2ms hot path. |
| **Host Enforcement Agent** | `cmd/waf-agent`<br>`internal/firewall` | Inline Packet Engine (NGFW), Stateful L2–L4 filtering, SYN cookies, Volumetric flood mitigation | Asynchronous nftables/eBPF kernel driver. No GC-heavy structures in packet loops. |
| **Control Plane** | `cmd/waf-api`<br>`internal/api` | Management REST/gRPC API, Declarative IaC, SOC Control Room UI, High-Speed Logging (HSL) | Out-of-band management. Strictly prohibited from inline request data path. |

---

## 5. Essential Commands (Execution & Verification)

*Run only these verified commands to validate your work:*

* **Build Go binaries:** `make build` (outputs `waffynx`, `waf-agent`, `waf-api` to `bin/`)
* **Run all unit tests:** `go test -race ./...`
* **Run single test package:** `go test -v -race ./internal/<package>`
* **Run specific test:** `go test -v ./internal/policy -run TestPolicyEvaluate`
* **Run fuzz tests:** `go test -fuzz=FuzzEvaluator -fuzztime=10s ./internal/policy`
* **Lint / Static analysis:** `golangci-lint run ./...`
* **Format check:** `gofmt -s -l .`
* **Compile C++ bridge (Linux):** `make bridge-build` (outputs `dist/libwaffynx_bridge.so`)
* **Vagrant VM test cycle (Windows dev):** `make vagrant-test` (executes end-to-end integration test inside Linux VM)

---

## 6. Repository Layout & Component Boundaries

| Path | Plane | Responsibility |
| :--- | :--- | :--- |
| `constitution.md` | Governance | Supreme architectural law and non-negotiable invariants. |
| `AGENTS.md` | Governance | Operational context, agent directives, and constitutional alignment. |
| `specs/` | Governance | Spec-Driven Development feature lifecycles (`spec.md`, `plan.md`, `tasks.md`). |
| `docs/` | Architecture | Master roadmap (`ROADMAP.md`) and Architecture Decision Records (`adr/`). |
| `cmd/waffynx/` | Data Plane | Main engine CLI entrypoint (sidecar socket listener & proxy bootstrap). |
| `cmd/waf-agent/` | Host Agent | Host firewall daemon (nftables/UFW synchronization). |
| `cmd/waf-api/` | Control Plane | Management REST API (:9090) and telemetry ingestion. |
| `internal/engine/` | Data Plane | Low-latency 3-stage inspection pipeline (orchestrator & Unix socket server). |
| `internal/policy/` | Data Plane | Rule-based policy evaluation engine (conditions, operators, actions). |
| `internal/plugin/` | Data Plane | Plugin interface, registry, and priority chain execution. |
| `internal/appsec/` | Data Plane | Open-AppSec ML bridge and scoring client. |
| `internal/firewall/` | Host Agent | Host firewall drivers (nftables and UFW rule managers). |
| `internal/auth/` | Control Plane | JWT authentication manager and OIDC integrations. |
| `internal/marketplace/` | Control Plane | Plugin package catalog and in-memory distribution store. |
| `internal/upstream/` | Data Plane | Reverse proxy load balancing algorithms (round-robin, least-connections). |
| `modules/ngx_waffynx/` | Data Plane | Native Nginx 1.26 C module for zero-copy HTTP interception. |
| `plugins/` | Data Plane | Built-in inspection plugins (SQLi, XSS, rate-limiting, bot defense). |
| `configs/` | Configuration | Production runtime configurations (`waffynx.yaml`, `nginx.conf`). |
| `deploy/` | Infrastructure | Deployment assets (Helm charts, Dockerfiles, systemd unit files). |
| `vagrant/` | Development | Ubuntu 22.04 VM environment for Linux-native integration testing. |

---

## 7. Definition of Done (DoD)

Before declaring any task or feature complete, verify that:

1. **Tests Pass:** All unit and integration tests pass with zero race conditions (`go test -race ./...`).
2. **Zero Linter Warnings:** `golangci-lint run ./...` returns exit code `0`.
3. **Constitutional Invariants Intact:** Invariants in [`constitution.md`](constitution.md) and regression rules in [`.jules/sentinel.md`](.jules/sentinel.md) are strictly upheld.
4. **Scope Boundaries Respected:** No modifications were made outside the declared task scope in `tasks.md`.
5. **Spec Compliance:** Acceptance criteria in `spec.md` and task criteria in `tasks.md` are 100% met.
