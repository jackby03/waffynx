# Constitution of Waffynx

> **The Supreme Law of the Repository**  
> Every contributor, engineer, and AI agent operating in this codebase MUST strictly adhere to this document. In case of conflict between any task description, feature request, or suggestion and this Constitution, this Constitution prevails.

---

## 1. Core Architectural & Design Principles

### 1.1 Fail-Closed Security (Default-Deny)

- If an internal inspection component, ML scorer, external authorization/processing hook (`ext_authz` / `ext_proc`), or plugin fails or times out during request evaluation, the system must fail-safe according to the configured policy (default: block or drop; never silently bypass uninspected traffic).
- Auxiliary ephemeral state stores (e.g., distributed Redis/Dragonfly rate-limiters or IP jails) must enforce strict bounded timeouts (e.g., `<= 10ms`) and default to fail-closed. Controlled fail-open degradation is permitted *only* when explicitly configured by the operator for rate-limit/state lookups, and must never disable compiled in-memory L7 inspection rules, signatures, or Zero-Trust authorization checks.
- Insecure defaults are strictly prohibited. Every daemon and container must refuse to start if sensitive security credentials (JWT secrets, API keys, database/broker passwords, TLS/mTLS keys) are missing, empty, or use default placeholder strings.

### 1.2 Zero-Allocation Mindset & Lock-Free Hot Path

- The inspection pipeline (`Edge PEP [Nginx C module or Envoy Proxy] -> local Unix socket or internal mTLS gRPC [ext_proc / ext_authz] -> Go WAF Engine -> Policy/Catalog Engine`) is executed on every HTTP request.
- Hot-path execution must avoid dynamic heap allocations: use reusable buffers (`sync.Pool`), eliminate unnecessary object copying, and prohibit reflection (`reflect`) or dynamic schema unmarshaling during request evaluation.
- Dynamic configuration, rule, and policy updates pushed from the Control Plane must be compiled off the hot path and swapped atomically via lock-free pointers (`atomic.Pointer`), with zero request stalls and zero dropped connections.
- P99 evaluation overhead under baseline load must not exceed:
  - **2ms** for co-located / local Unix Domain Socket (UDS) IPC.
  - **5ms** for cross-container internal RPC (mTLS gRPC between Edge PEP and WAF Engine containers/pods).

### 1.3 Strict Separation of Planes (Multi-Container & Zero-Trust Aligned)

The platform is organized into four isolated planes designed to run as independent containers or Deployments across segmented Docker Compose networks or Kubernetes namespaces:

- **Data Plane (DMZ / Hot Path — Edge PEP & WAF Engine)**: Pure request inspection, Zero-Trust policy enforcement, and reverse-proxy forwarding.
  - Must **never** depend synchronously on the Control Plane, primary relational databases (e.g., PostgreSQL), or Observability/Analytics stores (e.g., ClickHouse) during request evaluation.
  - Must continue enforcing its last valid compiled in-memory snapshot autonomously if Control Plane or Observability containers are unavailable or partitioned.
  - Blocking file I/O in the hot path is prohibited. Hot-path network I/O is restricted strictly to local IPC or authenticated internal RPC between Edge PEP and WAF/Authz engines, bounded-timeout lookups to a dedicated ephemeral state store when enabled, and upstream forwarding.
- **Control Plane (Management Network — `cmd/waf-api`, SOC UI, Persistent Config Store, xDS)**: Management API, RBAC, persistent configuration storage (PostgreSQL or embedded store), dynamic Edge PEP control (xDS), and hot-reload distribution (e.g., pub/sub).
  - Strictly forbidden from participating inline in per-request data plane inspection.
  - Must remain isolated on a private management network (accessible only via VPN/ZTNA or dedicated administrative ingress; never exposed on the public Data Plane edge).
- **Observability & Telemetry Plane (Internal Network — Async Only)**: Buffered event streaming (e.g., NATS JetStream or bounded ring buffers), enrichment/ingestion workers (local GeoIP, PII redaction), analytical storage (e.g., ClickHouse), and metrics exposition (Prometheus).
  - Data Plane telemetry emission must be strictly **asynchronous and non-blocking** (bounded buffers with explicit drop counters under backpressure). An outage or slowdown in the Observability Plane must never block, stall, or fail HTTP request inspection.
- **Host Enforcement Agent (`cmd/waf-agent` — Optional System Mode)**: Kernel packet filtering (e.g., `nftables`/`ufw`) driven asynchronously via control-plane events. Used only in host/bare-metal deployments and never required by Docker Compose or Kubernetes topologies.

### 1.4 Zero-Trust Boundary Validation & Network Microsegmentation

- **Untrusted Inputs**: Treat all inputs—public HTTP traffic, internal Unix sockets, cross-container gRPC/xDS/broker payloads, and headers—as untrusted. Enforce strict bounded checks on buffer lengths, maximum inspectable body sizes (anti-OOM enforcement at both Edge PEP and WAF Engine), encoding schemas, and character sets before parsing.
- **Network Microsegmentation**: Multi-container deployments (isolated Docker Compose networks and Kubernetes `NetworkPolicies`) must enforce default-deny east-west and ingress segmentation:
  - Only the Edge PEP (Data Plane ingress) may receive untrusted external traffic.
  - Protected upstream applications must be reachable only from the Data Plane Edge PEP (no direct public bypass).
  - Control Plane services, databases, message brokers, and Observability stores must reside on internal-only networks unreachable from untrusted clients.
- **Inter-Service Transport Security**: Cross-container service traffic (Edge PEP <-> WAF/Authz Engine, Edge PEP <-> Upstreams, Control Plane xDS <-> Edge PEP, Engine <-> state/brokers) must use authenticated, encrypted transport (**mTLS** with rotatable certificates via SDS/internal CA in production/Kubernetes, or `0600`/`0660` UDS when co-located in the same pod/host). Plaintext unauthenticated cross-container links are prohibited outside explicitly scoped local development profiles.

---

## 2. Hard Technical Constraints

### 2.1 Target Runtime, Compilation & Container Orchestration

- **Target OS**: Linux (POSIX compliant) is the sole production runtime environment.
- **Go Toolchain**:
  - Standalone daemons (`waf-api`, `waf-agent`, `waffynx`/WAF engine, `appsec-bridge`, async ingestors) must compile as purely static binaries (`CGO_ENABLED=0 GOOS=linux`).
  - Any hybrid modules or C-shared bridges (`bin/*.so`, native Nginx modules) must clearly declare their required toolchain (GCC/Clang) and build flags in the root `Makefile`.
- **Container & Orchestration Standards (Docker Compose & Kubernetes)**:
  - Each plane component must be deployable as a minimal, single-responsibility Linux container running as a **non-root** user (with read-only root filesystems where supported), exposing explicit liveness (`/healthz`) and readiness (`/readyz`) probes, and supporting graceful shutdown (`SIGTERM` connection draining).
  - Data Plane services (`Edge PEP`, `WAF Engine`) must remain **stateless** and horizontally scalable (replica-safe in Docker Compose, HPA-ready in Kubernetes), with durable configuration and ephemeral shared state externalized to their designated stores.
  - Orchestration assets (`docker-compose.yml` with segmented networks/profiles and Kubernetes/Helm manifests with `NetworkPolicies` and resource bounds) are first-class artifacts and must remain declarative and reproducible.
- **Source Integrity**: Standard POSIX line endings (`\n`, LF) are mandatory. CRLF line endings are forbidden.

### 2.2 Cryptographic Rigor, Secrets & Socket Security

- **Zero Secrets in Source or Images**: No credentials, tokens, or private keys may ever be committed to VCS or baked into container images (mock fixtures excepted only if visibly randomized and non-functional). Production secrets must be injected strictly at runtime via environment variables, mounted secret files, or Kubernetes Secrets / external secret managers.
- **Constant-Time Comparison**: Token, key, and signature verifications must strictly use constant-time primitives (e.g., `crypto/subtle.ConstantTimeCompare`) to prevent timing attacks.
- **PII & Credential Redaction**: Sensitive request fields (`Authorization`, `Cookie`, `Set-Cookie`, tokens, passwords, and configured PII attributes) must be masked or stripped before persisting to audit trails, observability streams, or analytical databases.
- **Unix Socket Permissions**: Sockets created under `/var/run/waffynx/` (including shared-pod `emptyDir` volumes in Kubernetes) must enforce restrictive permissions (`0600` or `0660`). World-writable permissions (`0666`, `0777`) will trigger immediate static check failure.

### 2.3 Dependency Discipline

- Standard library packages (`net/http`, `crypto`, `sync`, `context`) must be exhausted before proposing external dependencies.
- Infrastructure clients needed for multi-container orchestration (e.g., PostgreSQL, Redis, gRPC/xDS `go-control-plane`, NATS JetStream, ClickHouse) must be isolated behind clean Go interfaces in adapter packages so core inspection packages (`internal/catalog`, `internal/policy`, `internal/rules`, `internal/parsers`) remain pure, fast, and unit-testable with zero external infrastructure.
- Introducing third-party packages directly into the per-request Data Plane hot path requires an explicit justification (ADR or PR record) backed by benchmark evidence (`allocs/op` and latency impact).

---

## 3. Quality, Testing & Regression Invariants

### 3.1 Verification-First Delivery

- No code may be merged without automated verification demonstrating compliance with acceptance criteria.
- Low-level parsers, policy evaluators, and protocol decoders must maintain both standard unit suites and active fuzzing targets (`go test -fuzz`).

### 3.2 Regression Immutability

- Any bug fix or security patch addressing a known vulnerability must include a permanently retained regression test replicating the attack vector.

### 3.3 Static Analysis Compliance

- Code must pass `golangci-lint` (with strict security and performance linters enabled) and static C analyzers with zero errors or unhandled warnings before merging.

### 3.4 Multi-Container Resilience & Safe Rollout

- **Autonomy Under Outage**: Integration verification must confirm that the Data Plane continues inspecting and enforcing its last valid compiled snapshot when the Control Plane, primary database, or Observability stack is stopped or unreachable.
- **Shadow Mode & Performance Gates**: Major Data Plane changes (new Edge PEP integrations, inspection engines, or rule compilers) must support non-blocking observe/shadow evaluation before production enforcement and must pass allocation and inventory gates (`make gatecheck`).

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
