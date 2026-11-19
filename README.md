<div align="center">
  <h1>🛡️ Waffynx</h1>
  <p><b>Self-Hosted Zero-Trust Web Application Firewall &amp; Reverse Proxy</b></p>
  <p>Envoy Proxy Edge PEP (Dynamic xDS + TLS 1.3 mTLS) • Stateless Go WAF Engine (<code>ext_authz</code> + <code>ext_proc</code>) • PostgreSQL &amp; Redis Hot-Reload • Async NATS → ClickHouse Observability • Enterprise SOC Control Room</p>
</div>

<br/>

Waffynx is a self-hosted, container-first **Zero-Trust Web Application Firewall (NIST SP 800-207)** and reverse proxy built for **Docker Compose** and **Kubernetes**. It delivers Cloudflare/SafeLine-grade L7 inspection and continuous authorization on hardware you control — with no license checks, no feature tiers, and no phone-home telemetry.

It supports two deployment topologies from one repository:
1. **Multi-Container Zero-Trust Stack (Default):** Envoy Proxy Edge PEP configured dynamically over **xDS**, calling horizontally scalable stateless Go **`waf-engine`** replicas over **TLS 1.3 mTLS gRPC** (`ext_authz` + `ext_proc`), backed by **PostgreSQL** (config/RBAC), **Redis** (sliding-window rate limits, IP jails, `atomic.Pointer` hot-reload Pub/Sub), and an asynchronous **NATS JetStream → `log-ingestor` → ClickHouse** observability pipeline.
2. **Single-Container Standalone Mode:** Upstream Nginx with the native `ngx_waffynx` C module talking to the Go sidecar over a `0600` Unix socket (`deploy/docker/Dockerfile` & `deploy/docker/docker-compose.standalone.yml`).

---

## 🚀 Key Capabilities

* **Envoy Proxy Dynamic Edge PEP (`internal/xds`)**: Routes, upstream clusters, TLS 1.3 edge certificates (SDS), and fail-closed `ext_authz`/`ext_proc` filters are pushed live from PostgreSQL via `go-control-plane` with zero restarts and zero static route files.
* **Zero-Trust Continuous Authorization (`internal/authz` — `ext_authz`)**: Per-route JWT/OIDC verification, required scopes, issuer checks, CIDR allowlists, GeoIP country posture, device posture headers, spoofed `x-waffynx-*` header stripping, and shadow mode — evaluated lock-free via `atomic.Pointer`.
* **Stateless L7 Inspection (`internal/envoy` — `ext_proc`)**: Strict `1 MiB` anti-OOM body guard (`413`), managed Aho–Corasick catalog (42 tested signatures across SQLi, XSS, RCE, LFI/RFI, SSRF, XXE, Log4Shell, scanners), deep JSON/form/GraphQL/upload body decoding, plugin chain, custom rules, false-positive exclusions, AppSec anomaly scoring, and shadow/observe rollout mode.
* **Lock-Free Hot-Reload & Outage Autonomy (`internal/hotreload`, `internal/rules`)**: Mutations in PostgreSQL broadcast a compiled immutable snapshot via Redis Pub/Sub; `waf-engine` swaps policies atomically via `atomic.Pointer` with zero dropped connections and continues enforcing its last valid snapshot even during total Control Plane, DB, or Observability outages.
* **Distributed Sliding-Window Rate Limits & IP Jails (`internal/ratelimit`)**: Atomic Redis Lua sliding-window counters and temporary IP jails with strict `<= 10ms` hot-path timeouts and configurable controlled fail-open without weakening L7 rules.
* **Internal Zero-Trust PKI & TLS 1.3 mTLS (`internal/pki`)**: Pure stdlib ECDSA P-256 internal CA (`waffynx-bootstrap --pki-only`) with `0600` private keys and hot-reloading TLS 1.3 mTLS across `envoy`, `waf-engine`, and `control-api` (and SPIRE / cert-manager ready in Kubernetes).
* **Strictly Async Observability & Mandatory PII Redaction (`internal/telemetry`, `cmd/log-ingestor`, `internal/analytics`)**: Non-blocking buffered NATS JetStream emission → batched Go worker (`500` events or `1s` flush) with local MaxMind GeoIP enrichment and mandatory credential/PII scrubbing (`Authorization`, cookies, JWTs, PANs, query secrets including `:path`/`Referer`) → ClickHouse `MergeTree` analytics.
* **Enterprise SOC Control Room UI (`ui/`)**: React 19 + TypeScript SPA served from a minimal non-root container (`nginx-unprivileged`), featuring dual themes (*Obsidian Edge SOC* & *Daylight Ops*), Command Palette (`Ctrl+K`), ClickHouse + live SSE forensics, **1-click "Create Exclusion"** false-positive tuning, Zero-Trust policy management, and live multi-plane Envoy xDS cluster topology.

---

## 🏗️ Multi-Container Zero-Trust Architecture

All components are isolated into dedicated planes and microsegmented networks. Only Envoy receives external ingress; protected upstreams, databases, message brokers, and analytics stores have zero direct public exposure.

```mermaid
flowchart TB
    Internet([Internet TLS 1.3]) --> Envoy

    subgraph DMZ["Data Plane (dmz-net / data-plane-net / upstream-net)"]
        Envoy["Envoy Proxy Edge PEP\n(:8080 / :8443 TLS 1.3 SDS)"]
        Engine["waf-engine (Stateless Go)\next_authz + ext_proc\natomic.Pointer + sync.Pool"]
        Redis[("Redis 7\nSliding Window / IP Jails\nHot-Reload Pub/Sub")]
        Backend[("Protected Upstreams\n(upstream-net internal only)")]

        Envoy -- "mTLS gRPC (TLS 1.3)" --> Engine
        Engine <-- "<=10ms bounded" --> Redis
        Envoy -- "Reverse Proxy" --> Backend
    end

    subgraph OBS["Observability Plane (observability-net — Async Only)"]
        NATS["NATS JetStream\n(WAFFYNX_EVENTS)"]
        Ingestor["log-ingestor (Go)\nBatch + GeoIP + PII Redact"]
        CH[("ClickHouse\nsecurity_events")]

        Engine -. "Async Fire-and-Forget" .-> NATS
        NATS --> Ingestor
        Ingestor -- "Bulk JSONEachRow" --> CH
    end

    subgraph CTRL["Control Plane (control-net — VPN / ZTNA Management)"]
        UI["React SOC Control Room\n(nginx-unprivileged)"]
        API["control-api (Go)\nREST API + Envoy v3 xDS"]
        PG[("PostgreSQL 16\nSites, Rules, Exclusions,\nZT Policies, RBAC Users")]

        UI --> API
        API <--> PG
        API -- "mTLS gRPC xDS (:18000)" --> Envoy
        API -- "Redis Pub/Sub Snapshot" --> Redis
        API -- "Parameterized SQL Queries" --> CH
    end
```

For deep design details, network segmentation tables, and API contracts, see **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)** and **[constitution.md](constitution.md)**.

---

## ⚡ Quick Start

> Waffynx targets **Linux** containers (non-root, zero host privileges required). The optional kernel host-firewall daemon (`waf-agent`) is for bare-metal system mode only.

### 1. Multi-Container Zero-Trust Stack (Docker Compose — Recommended)

```bash
git clone --recurse-submodules https://github.com/jackby03/waffynx.git
cd waffynx

# 1. Configure secrets and ports (never commit .env)
cp .env.example .env
# Edit .env and replace all REPLACE_WITH_* placeholders with strong secrets

# 2. Build and start all 4 isolated planes (waits until every service is healthy)
docker compose up -d --build --wait

# 3. Verify all services are Up (healthy)
docker compose ps
```

Verify live Zero-Trust WAF enforcement through Envoy:

```bash
# Benign HTTP & HTTPS (TLS 1.3 via Envoy SDS) -> 200 OK
curl -i -H 'Host: app.example.test' http://127.0.0.1:8080/
curl -ik --tlsv1.3 -H 'Host: app.example.test' https://127.0.0.1:8443/

# Unknown host (default-deny) -> 404
curl -i -H 'Host: unknown.example.test' http://127.0.0.1:8080/

# Attacks blocked at Envoy PEP via mTLS ext_proc -> 403 Forbidden
curl -i -H 'Host: app.example.test' 'http://127.0.0.1:8080/?q=UNION+SELECT+1,2,3'
curl -i -H 'Host: app.example.test' -H 'User-Agent: sqlmap/1.7.2' http://127.0.0.1:8080/
curl -i -H 'Host: app.example.test' -H 'Content-Type: application/json' \
  -d '{"q":"<script>alert(1)</script>"}' http://127.0.0.1:8080/

# Open the SOC Control Room UI (bound to 127.0.0.1 by default):
# http://127.0.0.1:9090  (login with WAFFYNX_ADMIN_USER / WAFFYNX_ADMIN_PASSWORD from .env)
```

Scale stateless Data Plane inspection replicas horizontally:

```bash
docker compose up -d --scale waf-engine=3
```

UI live HMR development against the running stack:

```bash
docker compose --profile dev up --build
# Open http://127.0.0.1:5173 (proxies /api, /metrics and /health to control-api:9090)
```

### 2. Kubernetes Deployment (Helm Chart)

The Helm chart in [`deploy/helm/waffynx/`](deploy/helm/waffynx/) deploys separate non-root Deployments for `envoy`, `waf-engine`, `control-api`, `ui`, and `log-ingestor`, with HPAs, PodDisruptionBudgets, `/healthz` + `/readyz` probes, and strict default-deny Kubernetes `NetworkPolicies`:

```bash
# 1. Create runtime secrets (zero secrets in values.yaml)
kubectl create secret generic waffynx-secrets \
  --from-literal=jwt-secret="$(openssl rand -hex 32)" \
  --from-literal=admin-password="CHANGE_ME_STRONG_PASSWORD" \
  --from-literal=postgres-dsn="postgres://waffynx:PASS@postgres:5432/waffynx?sslmode=require" \
  --from-literal=redis-password="CHANGE_ME_REDIS_PASS" \
  --from-literal=clickhouse-password="CHANGE_ME_CH_PASS"

# 2. Provision mTLS bundle (via cert-manager, SPIRE, or waffynx-bootstrap --pki-only)
#    into Secret `waffynx-mesh-certs`, then install:
helm upgrade --install waffynx ./deploy/helm/waffynx \
  --namespace waffynx --create-namespace
```

### 3. Single-Container Standalone Mode (Nginx C Module)

Prefer one self-contained Nginx + Go sidecar container with zero external databases?

```bash
# Via standalone Compose file:
docker compose -f deploy/docker/docker-compose.standalone.yml up -d --build

# Or single `docker run` with zero config file:
docker build -f deploy/docker/Dockerfile -t waffynx .
docker network create waffynx
docker run -d --name app --network waffynx nginx:alpine
docker run -d --name waffynx --network waffynx -p 8080:8080 -p 9090:9090 \
  -v waffynx-data:/opt/waffynx/data \
  -e WAFFYNX_SITE_HOST=app.example.com \
  -e WAFFYNX_SITE_UPSTREAM=app:80 \
  waffynx
```

---

## ⚙️ Key Environment Variables

See [`.env.example`](.env.example) for the complete template:

| Variable | Plane | Description |
| :--- | :--- | :--- |
| `WAFFYNX_SITE_HOST` / `WAFFYNX_SITE_UPSTREAM` | Control / Data | Initial site seeded at boot (`app.example.test` → `backend:80`) |
| `WAFFYNX_ADMIN_USER` / `WAFFYNX_ADMIN_PASSWORD` | Control | Initial admin operator credentials (bcrypt hashed; fail-closed if missing) |
| `WAFFYNX_JWT_SECRET` | Control / Data | Shared JWT signing secret (`>= 32` chars) used by API and `ext_authz` |
| `WAFFYNX_POSTGRES_DSN` | Control | PostgreSQL connection string for durable sites, rules, exclusions, ZT policies & RBAC |
| `WAFFYNX_REDIS_ADDR` / `WAFFYNX_REDIS_PASSWORD` | Data / Control | Redis endpoint for sliding-window rate limits, IP jails & hot-reload Pub/Sub |
| `WAFFYNX_REDIS_TIMEOUT_MS` / `WAFFYNX_RATE_LIMIT_FAIL_OPEN` | Data | Bounded Redis lookup timeout (default `10ms`) and controlled rate-limit degradation |
| `WAFFYNX_XDS_LISTEN` / `WAFFYNX_MTLS_ENABLED` | Control / Data | Envoy v3 xDS gRPC listen address (`:18000`) and strict TLS 1.3 mTLS enforcement |
| `WAFFYNX_MAX_BODY_BYTES` / `WAFFYNX_SHADOW_MODE` | Data | Anti-OOM body inspection ceiling (default `1 MiB`) and non-blocking shadow mode |
| `WAFFYNX_NATS_URL` / `WAFFYNX_CLICKHOUSE_URL` | Observability | Async JetStream telemetry bus and ClickHouse analytics store |

---

## 🧪 Verification & Quality Gates

Waffynx enforces verification-first delivery (Constitution §3):

```bash
# Static Linux builds for all 7 binaries (CGO_ENABLED=0)
CGO_ENABLED=0 GOOS=linux go build -o bin/ ./cmd/...

# Strict security & performance static analysis (must return 0 issues)
GOOS=linux CGO_ENABLED=0 golangci-lint run ./...

# Full unit test suite, race detector (Linux), coverage floors, benchmark & fuzz inventories
make test
make cover
make gatecheck

# Functional pipeline self-test (no network or proxy needed)
waffynx verify -c configs/waffynx.yaml

# Frontend TypeScript check, security invariants suite & production build
cd ui && npm run lint && npm test && npm run build
```

---

## 🗺️ Status & Roadmap

NGFW, VPN, SD-WAN, DLP and forward-proxy work is explicitly out of scope: Waffynx is a Zero-Trust WAF and reverse proxy.

### ✅ Implemented & Verified

* **Multi-Container Zero-Trust Stack (Compose & Kubernetes Helm):** Envoy Proxy Edge PEP (dynamic ADS xDS + TLS 1.3 SDS), stateless `waf-engine` (`ext_authz` + `ext_proc` over TLS 1.3 mTLS), `control-api`, non-root `ui`, and async `log-ingestor`.
* **Persistent Control Plane & Lock-Free Hot-Reload:** PostgreSQL (`pgx/v5`) schema + migrations, Redis sliding-window rate limits & IP jails, Redis Pub/Sub snapshot distribution swapped via `atomic.Pointer`, full Data Plane outage autonomy.
* **Zero-Trust Continuous Authorization (`ext_authz`):** Per-route JWT/OIDC verification, required scopes, CIDRs, GeoIP country blocks, device posture headers, spoofed header stripping, and shadow mode.
* **Deep L7 Inspection Pipeline:** 42 tested Aho–Corasick managed rules, anti-OOM body guard, JSON/form/GraphQL/upload decoders, plugin chain, custom rules, false-positive exclusions, and pluggable AppSec anomaly scoring (in-process Go scorer or external `open-appsec` socket bridge).
* **Async Observability Pipeline:** Non-blocking NATS JetStream emission → batched GeoIP + mandatory PII/credential redaction → ClickHouse bulk inserts & parameterized analytics queries.
* **Enterprise SOC Control Room UI:** 12-view React 19 console with Overview, ClickHouse + SSE Security Events, 1-click **"Create Exclusion"**, Protected Sites, Zero Trust & Mesh topology, Managed/Custom Rules, IP Bans, Learning, Pipeline, Marketplace, Audit Log, and System Config.
* **Standalone Single-Container Nginx Mode:** Upstream Nginx with native `ngx_waffynx` C module + `0600` Unix socket sidecar + `waffynx verify`.

### 📅 Next

* Published multi-arch OCI images (`linux/amd64`, `linux/arm64`) for `waf-engine`, `control-api`, `log-ingestor`, `ui`, and standalone `waffynx`.
* Formal `LICENSE` selection and file.
* Optional out-of-band AI SOC co-pilot (triage explanations and natural-language rule drafting strictly on the Control Plane, never in the hot path).

---

## 📖 Documentation

* **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)**: Multi-plane topology, network microsegmentation, request lifecycle, Kubernetes deployment, and distributed API reference.
* **[constitution.md](constitution.md)**: Supreme architectural law, security invariants, latency budgets, and multi-container resilience rules.
* **[AGENTS.md](AGENTS.md)**: Operational directives, repository layout, and verification commands.
* **[SECURITY.md](SECURITY.md)**: Vulnerability disclosure policy, mTLS/secrets guarantees, and upstream Nginx CVE patching workflow.
* **[configs/waffynx.yaml](configs/waffynx.yaml)**: Runtime configuration template.

---

## 📄 License

**Not yet chosen.** No `LICENSE` file exists in this repository, so no rights are granted beyond what GitHub's terms allow. A public commitment will land with the `LICENSE` file.
