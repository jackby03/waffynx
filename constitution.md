# Constitution of Waffynx

> **The Supreme Law of the Repository**  
> Every contributor, engineer, and AI agent operating in this codebase MUST strictly adhere to this document. In case of conflict between any task description, feature request, or suggestion and this Constitution, this Constitution prevails.

---

## 1. Core Architectural & Design Principles

1. **Fail-Closed Security (Default-Deny)**
   - If an internal component, ML scorer, or plugin fails or times out during request evaluation, the system must fail-safe according to the configured policy (default: block or drop, never silently allow uninspected traffic).
   - Insecure defaults are strictly prohibited. The system must refuse to start if sensitive security credentials (JWT secrets, API keys) are missing, empty, or using default placeholder strings.

2. **KISS & Simplicity in the Hot Path**
   - The inspection pipeline (`nginx ACCESS phase -> Unix socket -> Go sidecar -> Scorer`) is executed on every HTTP request.
   - Minimize memory allocations, avoid unnecessary object copying, and eliminate lock contention in the evaluation path.

3. **Separation of Concerns & Modularity**
   - **C Module (`modules/ngx_waffynx`)**: Solely responsible for capturing HTTP metadata and delegating inspection over Unix socket.
   - **Sidecar (`internal/engine`)**: High-throughput orchestration pipeline (Plugins -> Policy Rules -> ML Scorer).
   - **Management API (`cmd/waf-api`)**: Control plane only. Must never participate in the data plane inspection hot path.
   - **Firewall Agent (`cmd/waf-agent`)**: Host-level packet filtering (nftables/UFW) driven by control-plane events.

4. **Zero-Trust Internal Boundaries**
   - Treat all inputs—even those received from internal components, socket streams, or headers—as untrusted. Validate lengths, formats, and encodings.

---

## 2. Hard Technical Constraints

1. **Target Runtime Environment**
   - **Linux is the only production target.**
   - All Go binaries (`waffynx`, `waf-api`, `waf-agent`) must compile cleanly with `CGO_ENABLED=0 GOOS=linux GOARCH=amd64` (and `arm64` for containerized environments).
   - C/C++ components (`modules/ngx_waffynx`, `dist/libwaffynx_bridge.so`) require GCC/Clang with standard Linux POSIX APIs.
   - Files created or edited must use standard POSIX LF (`\n`) line endings. Never commit CRLF line endings.

2. **Secrets & Cryptographic Rigor**
   - **Zero Secrets in Source**: No credentials, private keys, or API tokens may ever be hardcoded or checked into Git.
   - **Constant-Time Comparison**: Authentication tokens, API keys, and HMAC hashes must always be compared using constant-time comparison primitives (e.g., `crypto/subtle.ConstantTimeCompare`) to prevent timing side-channel attacks.
   - **Unix Socket Security**: All Unix domain sockets (`/var/run/waffynx/*.sock`) must be created with restrictive file permissions (`0600` or `0660`). World-accessible permissions (`0666` or `0777`) are strictly prohibited.

3. **Dependency Governance**
   - Do not introduce new external third-party libraries without explicit architectural review.
   - Prefer standard library packages wherever feasible (`net/http`, `crypto`, `sync`, `context`).

---

## 3. Quality & Testing Standards

1. **Test-First / Spec-Driven Requirement**
   - New features or bug fixes must include automated tests proving compliance before the feature is marked complete.
   - Core security evaluators, parsers, and policy engines must maintain unit tests and fuzzing targets (`go test -fuzz`).

2. **Regression & Security Invariants**
   - Any fix for a security vulnerability documented in `.jules/sentinel.md` or a regression test must permanently remain in the CI test suite.
   - Preflight `OPTIONS` requests from unauthorized origins must be rejected (`403 Forbidden`).
   - CORS origin validation must check exact matches or authorized regex allowlists; wildcard `*` with credentials is forbidden.

---

## 4. Spec-Driven Workflow Rules for AI Agents

1. **Spec First, Code Second**
   - Agents must never generate production code without an approved specification (`spec.md`), technical plan (`plan.md`), and task checklist (`tasks.md`) under `specs/`.
2. **Scope Boundaries**
   - Agents must respect the `Out-of-Scope` section of each feature spec. Do not invent unrequested helpers, abstractions, or features.
3. **Preservation of Context**
   - Do not remove existing documentation comments, licenses, or architectural explanations when refactoring.

---

## 5. [TODO: Custom Project Principles]
<!--
Add your team-specific or organization-specific rules below:
- Example: Code formatting / linter requirements (golangci-lint).
- Example: Branching and PR naming conventions.
- Example: Specific performance SLA (e.g. sub-millisecond sidecar evaluation latency).
-->
