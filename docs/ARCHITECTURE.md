# Waffynx Multi-Container Zero-Trust Architecture Guide

This document describes the operational architecture, plane boundaries, network microsegmentation, request lifecycle, and distributed API surface of Waffynx. Supreme architectural laws live in [`constitution.md`](../constitution.md).

---

## 1. Plane Separation & Network Microsegmentation

Waffynx isolates workloads across **four constitutional planes** so no database, message broker, analytics store, or management API is ever exposed on the public ingress path:

| Plane | Services | Compose Networks | Host Ports | External Access |
| :--- | :--- | :--- | :--- | :--- |
| **Data Plane (Edge PEP)** | `envoy` (`envoyproxy/envoy:v1.32-latest`) | `dmz-net`, `data-plane-net`, `control-net`, `upstream-net` | `8080`, `8443` | Public DMZ Ingress |
| **Data Plane (Inspection)** | `waf-engine` (`cmd/waf-engine`), `redis` | `data-plane-net` *(internal)*, `observability-net` *(internal)* | None | Internal only |
| **Protected Upstreams** | `backend` (your apps) | `upstream-net` *(internal)* | None | Reachable **only** from `envoy` |
| **Control Plane** | `ui`, `control-api` (`cmd/waf-api`), `postgres` | `control-net` | `127.0.0.1:9090` (`ui` only) | Localhost / VPN / ZTNA only |
| **Observability Plane** | `nats` (JetStream), `log-ingestor`, `clickhouse` | `observability-net` *(internal)* | None | Internal only (`control-api` read queries) |
| **Host Agent *(optional)*** | `waf-agent` (`cmd/waf-agent`) | Bare-metal host only | None | Never started in Compose/K8s |

In Kubernetes (`deploy/helm/waffynx/templates/networkpolicy.yaml`), equivalent **default-deny `NetworkPolicies`** enforce that:
- `waf-engine` accepts gRPC (`50051`) **only** from `envoy`.
- `control-api` accepts REST (`9090`) **only** from `ui` and xDS gRPC (`18000`) **only** from `envoy`.
- `log-ingestor` rejects all ingress traffic (`ingress: []`).

---

## 2. End-to-End Request Lifecycle

1. **Ingress (`envoy`):** Receives HTTP/1.1, HTTP/2, or TLS 1.3 (via SDS `waffynx_edge_tls`). Unknown hosts are answered immediately with `404` (default-deny). `/healthz` and `/health` bypass inspection for orchestrator probes.
2. **Continuous Authorization (`ext_authz` over TLS 1.3 mTLS → `waf-engine:50051`):**
   - Strips untrusted client `x-waffynx-*` headers.
   - Evaluates lock-free compiled `ZeroTrustPolicy` rules (`atomic.Pointer`): GeoIP country blocklist, CIDR allowlist, device posture header, JWT signature/expiry/issuer/scopes.
   - Fails closed (`401`/`403`) on violation (or logs `shadow_block` when `shadow_mode: true`), and injects verified `x-waffynx-user`, `x-waffynx-role`, `x-waffynx-scopes` on `OK`.
3. **L7 Inspection (`ext_proc` over TLS 1.3 mTLS → `waf-engine:50051`):**
   - Enforces anti-OOM body ceiling (`WAFFYNX_MAX_BODY_BYTES`, default `1 MiB` → `413 Payload Too Large`).
   - Runs staged pipeline:
     1. Snapshot in-memory IP bans (`atomic.Pointer`) + Redis ephemeral IP Jails (`<= 10ms` timeout).
     2. Redis Lua sliding-window rate limiter (`<= 10ms` timeout, fail-closed by default; controlled fail-open optional without weakening L7 rules).
     3. Managed Aho–Corasick ruleset (42 rules) with dynamic **Exclusion** bypass check.
     4. Plugin chain (`request-validation`, `bot-protection`, etc.).
     5. Lock-free Custom Rules (`atomic.Pointer`).
     6. Policy Engine.
     7. AppSec ML Anomaly Scorer (fail-closed by default).
   - Returns `ImmediateResponse` (`403`/`413`/`429`) or `Continue` (or attaches `x-waffynx-shadow-rule` in shadow mode).
4. **Async Telemetry (Fire-and-Forget):**
   - `waf-engine` scrubs all credentials/PII (`internal/telemetry/redact.go`) and pushes the event to a bounded Go channel (`4096` slots). If full, it increments `waffynx_telemetry_dropped_total` and never blocks the HTTP response.
   - Background publisher writes to NATS JetStream stream `WAFFYNX_EVENTS` (`waffynx.events.*`).
   - `cmd/log-ingestor` consumes batches (`500` events or `1s` flush), enriches local GeoIP (`maxminddb-golang`), re-applies PII redaction, and bulk-inserts via HTTP `JSONEachRow` into ClickHouse `waffynx.security_events` (daily partitioned `MergeTree`, 30-day TTL).

---

## 3. Dynamic Configuration, Hot-Reload & Outage Autonomy

- **Route & Cluster Updates (Envoy xDS):** Every `POST`/`PUT`/`DELETE /api/v1/sites` persists to PostgreSQL, increments `config_revisions`, compiles a consistent Envoy v3 snapshot (CDS/RDS/LDS/SDS), and pushes it over ADS mTLS gRPC to all connected Envoy replicas immediately.
- **Policy, Rule, Exclusion & IP Ban Updates (Redis Pub/Sub):** Every mutation writes to PostgreSQL, stores the immutable `PolicySnapshot` at Redis key `waffynx:snapshot:latest` (for cold-booting replicas), and publishes it on `waffynx:hotreload`. Every `waf-engine` replica compiles the snapshot off the hot path and swaps it atomically via `atomic.Pointer`.
- **Total Control/DB/Observability Outage Resilience (Constitution §3.4):** `waf-engine` never connects to PostgreSQL or ClickHouse. If `control-api`, `postgres`, `nats`, and `clickhouse` are stopped simultaneously, `envoy` and `waf-engine` continue serving benign traffic (`200`), blocking attacks (`403`), and enforcing Zero-Trust policies (`401`/`403`) on their last valid in-memory snapshot with zero interruption.

---

## 4. Distributed Control Plane API Reference

All endpoints require `Authorization: Bearer <jwt>` (except `/health`, `/healthz`, `/readyz`, and `POST /api/v1/auth/login`). Mutating endpoints require role `admin`.

| Method & Path | Purpose |
| :--- | :--- |
| `GET /healthz`, `GET /readyz` | Liveness and PostgreSQL-aware readiness probes |
| `GET /api/v1/cluster/topology` | Live plane health, connected Envoy xDS replicas, xDS version, policy revision, mTLS status |
| `GET/POST/PUT/DELETE /api/v1/sites` | Manage protected sites (persisted in PostgreSQL + pushed live via Envoy xDS) |
| `GET/POST/DELETE /api/v1/custom-rules` | Manage custom L7 rules (PostgreSQL + Redis `atomic.Pointer` hot-reload) |
| `GET/POST/DELETE /api/v1/exclusions` | Manage false-positive exclusions per rule/host/path/param (1-click in SOC UI) |
| `GET/POST/PUT/DELETE /api/v1/zero-trust/policies` | Manage `ext_authz` continuous authorization policies (JWT, scopes, CIDR, GeoIP, device header, shadow mode) |
| `GET/POST/DELETE /api/v1/firewall/...` | Manage IP bans persisted in PostgreSQL, synced to Redis IP Jails and Data Plane snapshots |
| `GET /api/v1/analytics/events` | Parameterized ClickHouse security event explorer (`q`, `action`, `host`, `remote_ip`, `rule_id`, `country`, `since_hours`, `limit`, `offset`) |
| `GET /api/v1/analytics/summary` | Aggregated KPIs, top rules, top IPs, top countries, and hourly timeline (`window_hours`) |
| `GET/POST/DELETE /api/v1/users` | Manage PostgreSQL RBAC operators (`admin`, `operator`, `viewer`) |

---

## 5. Internal PKI & mTLS Certificate Rotation

- **Docker Compose:** The one-shot `pki-init` container runs `waffynx-bootstrap --pki-only --pki-dir /etc/waffynx/certs` as non-root UID `10001`, provisioning an ECDSA P-256 CA (`ca.crt`/`ca.key`) and leaf keypairs (`envoy`, `waf-engine`, `control-api`, `backend`, `log-ingestor`) with `0600` private keys.
- **Kubernetes:** Mount certificates managed by **cert-manager**, **step-ca**, or **SPIRE** into Secret `waffynx-mesh-certs` (`defaultMode: 0400`). `internal/pki.Reloader` automatically detects updated certificate files on disk via `GetCertificate`/`GetClientCertificate` without restarting pods.
