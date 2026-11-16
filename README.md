<div align="center">
  <h1>🛡️ Waffynx</h1>
  <p><b>The self-hosted Web Application Firewall that runs as one container</b></p>
  <p>Native Nginx integration • High-performance Go sidecar • Pluggable AI • No feature gating</p>
</div>

<br/>

Waffynx is a self-hosted Web Application Firewall and reverse proxy. It is meant to be
Cloudflare-WAF-grade protection on hardware you control: one container, no host
privileges, and every capability available to everyone — there is no license check,
no feature tier and no telemetry.

Requests are inspected by a native Nginx C module that hands evaluation to a
high-performance Go sidecar over a `0600` Unix socket: plugins, a policy engine and
an ML scorer, in that order.

---

## 🚀 Key Features

* **Native Nginx Integration**: Intercepts requests at the ACCESS phase with near-zero latency. Uses a heavily optimized, stripped-down Nginx binary (868KB).
* **Multi-Stage Evaluation Pipeline**: Traffic flows through a chain of dynamic plugins, a robust policy engine, and finally an ML anomaly scorer.
* **Deep Body Inspection**: Detects SQLi, XSS, Command Injection, and Path Traversal even within complex POST bodies (JSON, GraphQL, File Uploads).
* **Built-in Protection Plugins**:
  * `request-validation`: Strict schema enforcement.
  * `bot-protection`: Advanced bot mitigation.
  * `rate-limit`: Distributed token bucket (Redis-backed).
  * `geo-block`: MaxMind IP intelligence.
* **C++ Machine Learning Bridge**: Swappable ML engine (integrates with open-appsec) for behavioral entropy analysis and pattern detection.
* **Management Plane**: REST API with JWT/OIDC authentication and RBAC, a single-page control-room UI, and Prometheus metrics out of the box.
* **Privilege-free IP blocking**: bans are enforced at the WAF layer, so they work in a container with no `NET_ADMIN`. Kernel-level `nftables`/`ufw` drops are an *optional* system-mode enhancement (`waf-agent`).
* **`waffynx verify`**: a functional self-test that drives benign and malicious requests through the real inspection pipeline and reports what was blocked and why.

## 🏗️ Architecture

Waffynx decouples the proxy layer from the security evaluation layer to maximize throughput:

```mermaid
flowchart LR
    Client([Client]) --> Nginx[Nginx WAF Module]
    Nginx -- Unix Socket --> Sidecar[Go Evaluation Engine]
    
    subgraph Waffynx Pipeline
        Sidecar --> Plugins[Plugins]
        Plugins --> Policy[Policy Engine]
        Policy --> ML[ML Bridge]
    end
    
    ML -. 204 Allow .-> Nginx
    ML -. 403 Block .-> Nginx
    
    Nginx --> Backend[(Upstream Servers)]
```

## ⚡ Quick Start

> Waffynx targets **Linux**. The container path requires no host privileges; the
> host-firewall agent is system mode only.

### Container (recommended, no host privileges)

```bash
git clone --recurse-submodules https://github.com/jackby03/waffynx.git
cd waffynx

docker build -f deploy/docker/Dockerfile -t waffynx .

# The management API refuses to start with the placeholder JWT secret, so
# generate a real one in a config you mount:
cp configs/waffynx.yaml waffynx.local.yaml
sed -i "s/change-me-in-production/$(openssl rand -hex 32)/" waffynx.local.yaml

docker run --rm -p 8080:8080 -p 8443:8443 -p 9090:9090 \
  -v "$PWD/waffynx.local.yaml:/opt/waffynx/config/waffynx.yaml:ro" \
  waffynx
```

A published multi-arch image and a one-command bootstrap (no file editing at all)
are Phase 0 work in progress — see [docs/ROADMAP.md](docs/ROADMAP.md).

### Verify that it actually protects

```bash
waffynx verify -c waffynx.local.yaml
```

Runs benign and malicious requests through the real inspection pipeline and exits
non-zero on any mismatch. No proxy, upstream or network needed.

```
       CASE                         WANT   GOT    DETAIL
  ok   benign: prose query          allow  allow
  ok   sqli: comment terminator     block  block  waf pattern: '--
  ok   xss: script tag              block  block  waf pattern: <script
  skip scanner: sqlmap              block  allow  bot-protection mode=log

  20 passed, 0 failed, 1 skipped (of 21)
```

### From source (system mode / host agent)

```bash
sudo apt-get update && sudo apt-get install -y build-essential libpcre2-dev libssl-dev zlib1g-dev

make nginx-checkout && make nginx-configure && make nginx-build
make build && make bridge-build
```

For a full sandbox, `make vagrant-up && make vagrant-ssh` provisions a Linux VM
with Waffynx running:

```bash
curl http://localhost:8080/                          # 200 OK (allowed)
curl "http://localhost:8080/?q=UNION+SELECT+1,2,3"   # 403 Forbidden (blocked)
```

## 🗺️ Roadmap

Product scope, phases and the Cloudflare-WAF parity matrix live in
[**docs/ROADMAP.md**](docs/ROADMAP.md). NGFW, VPN, SD-WAN, DLP and forward-proxy
work is explicitly out of scope and parked in [docs/FUTURE.md](docs/FUTURE.md).

### ✅ Working today

* **Native Nginx ingress C module + Go sidecar** over a `0600` Unix socket.
* **L7 policy engine**: SQLi, XSS, path traversal, command injection, scanner signatures.
* **WAF-layer IP blocking** with no privileges, plus optional kernel drop in system mode.
* **Rate limiting**, in-memory and Redis-backed.
* **ML anomaly scoring**, bundled (pure Go) or through the open-appsec bridge.
* **Management API** (JWT/OIDC, RBAC) and the React control room.
* **`waffynx verify`** functional self-test.

### 🚧 Phase 0 — in progress

* Site management (domain → upstream → TLS) from the API and CLI.
* Bootstrap from environment variables, so `docker run` needs no file editing.
* Published multi-arch image.

### 📅 Next

* **Phase 1**: rule expression language, managed rule catalog, IP/geo/ASN lists, staged mode, security events.
* **Phase 2**: bot defense, API schema validation, SIEM export.
* **Phase 3**: pluggable external AI (Anthropic, OpenAI, Gemini, Vertex, local) with per-provider privacy controls — the differentiator, deliberately last.
* **GUI work comes after the CLI and API settle.**

## 📖 Documentation

* **[AGENTS.md](AGENTS.md)**: Detailed architecture specs, development gotchas, and internal component mapping.
* **Configuration**: Check out `configs/waffynx.yaml` for a full production configuration template.

## 📄 License

**Not yet chosen.** No `LICENSE` file exists in this repository, so no rights are
granted beyond what GitHub's terms allow. The licence is deliberately pending a
market study; a public commitment will land with the `LICENSE` file.

This README previously declared MIT without shipping the file, which is a claim the
repository could not back. Tracked in [docs/ROADMAP.md](docs/ROADMAP.md) §7 (gap 5).
