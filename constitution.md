# Constitution of Waffynx

> **The Supreme Law of the Repository**  
> Every contributor, engineer, and AI agent operating in this codebase MUST strictly adhere to this document. In case of conflict between any task description, feature request, or suggestion and this Constitution, this Constitution prevails.

---

## 1. Core Architectural & Design Principles

### 1.1 Fail-Closed Security (Default-Deny)

- If an internal component, ML scorer, or plugin fails or times out during request evaluation, the system must fail-safe according to the configured policy (default: block or drop; never silently bypass uninspected traffic).
- Insecure defaults are strictly prohibited. The system must refuse to start if sensitive security credentials (JWT secrets, API keys, certificates) are missing, empty, or use default placeholder strings.

### 1.2 Zero-Allocation Mindset in the Hot Path

- The inspection pipeline (`nginx ACCESS phase -> Unix socket -> Go sidecar -> Policy Engine`) is executed on every HTTP request.
- Hot-path execution must avoid dynamic heap allocations: use reusable buffers (`sync.Pool`), eliminate unnecessary object copying, and prohibit reflection (`reflect`) or dynamic schema unmarshaling during request evaluation.
- P99 evaluation overhead added by the inspection sidecar must not exceed 2ms under baseline load.

### 1.3 Strict Separation of Planes

- **Data Plane (C Module & Engine Sidecar)**: Pure inspection and enforcement. Must maintain zero network dependencies outside local IPC and must never perform blocking file I/O or external database queries during inspection.
- **Control Plane (`cmd/waf-api`)**: Management, telemetry, and configuration ingestion. Strictly forbidden from participating directly in the per-request data plane.
- **Host Enforcement Agent (`cmd/waf-agent`)**: Packet filtering (e.g., nftables) driven asynchronously via control-plane events.

### 1.4 Zero-Trust Boundary Validation

- Treat all inputs—including payloads from internal Unix sockets, headers, and inter-process messages—as untrusted. Enforce strict bounded checks on buffer lengths, encoding schemas, and character sets before parsing.

---

## 2. Hard Technical Constraints

### 2.1 Target Runtime & Compilation

- **Target OS**: Linux (POSIX compliant) is the sole production runtime environment.
- **Go Toolchain**:
  - Standalone daemons (`waf-api`, `waf-agent`) must compile as purely static binaries (`CGO_ENABLED=0 GOOS=linux`).
  - Any hybrid modules or C-shared bridges (`bin/*.so`) must clearly declare their required toolchain (GCC/Clang) and build flags in the root `Makefile`.
- **Source Integrity**: Standard POSIX line endings (`\n`, LF) are mandatory. CRLF line endings are forbidden.

### 2.2 Cryptographic Rigor & Socket Security

- **Zero Secrets in Source**: No credentials, tokens, or private keys may ever be committed to VCS, mock fixtures excepted only if visibly randomized and non-functional.
- **Constant-Time Comparison**: Token, key, and signature verifications must strictly use constant-time primitives (e.g., `crypto/subtle.ConstantTimeCompare`) to prevent timing attacks.
- **Unix Socket Permissions**: Sockets created under `/var/run/waffynx/` must enforce restrictive permissions (`0600` or `0660`). World-writable permissions (`0666`, `0777`) will trigger immediate static check failure.

### 2.3 Dependency Discipline

- Standard library packages (`net/http`, `crypto`, `sync`, `context`) must be exhausted before proposing external dependencies.
- Introducing third-party packages into the data plane requires an explicit Architecture Decision Record (ADR).

---

## 3. Quality, Testing & Regression Invariants

### 3.1 Verification-First Delivery

- No code may be merged without automated verification demonstrating compliance with acceptance criteria.
- Low-level parsers, policy evaluators, and protocol decoders must maintain both standard unit suites and active fuzzing targets (`go test -fuzz`).

### 3.2 Regression Immutability

- Any bug fix or security patch addressing a known vulnerability must include a permanently retained regression test replicating the attack vector.

### 3.3 Static Analysis Compliance

- Code must pass `golangci-lint` (with strict security and performance linters enabled) and static C analyzers with zero errors or unhandled warnings before merging.

---

## 4. Governance for AI Agents

### 4.1 Hierarchy of Authority

When resolving design, scope, or implementation ambiguities, artifacts strictly adhere to the following order of precedence:

1. `constitution.md` (Absolute authority)
2. `AGENTS.md` (Operational directives)

### 4.2 Execution Protocol

- **Strict Scope Boundaries**: Implement what was asked. Never synthesize unrequested utility libraries, premature abstractions, or unsolicited architectural refactors.
- **Evidence, not prose**: A change is described by the PR that makes it and by the command output that proves it works. There are no separate design documents to drift from the code.
- **Preservation of Context**: Existing documentation comments, licenses, and architecture decision headers must be preserved during automated modifications.
