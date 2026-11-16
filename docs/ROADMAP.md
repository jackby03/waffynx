# Waffynx Roadmap — Self-Hosted WAF, Container-First

> **Product:** a self-hosted Web Application Firewall and reverse proxy that runs as one container, is set up in minutes, and does not cap a single capability behind a paywall.
>
> **Positioning:** near-total parity with **Cloudflare WAF** (WAF only). We do not compete on edge infrastructure — we compete on being the thing you run on your own machine, with your own data, and your own AI provider.
>
> **Decision record:** [ADR-0003](adr/0003-product-scope-waf.md). The previous 14-pillar NGFW direction is parked in [`FUTURE.md`](FUTURE.md) and is **not** part of the product.

---

## 1. Thesis

| | |
|---|---|
| **Who it is for** | A technical person or a company that wants Cloudflare-WAF-grade protection on their own infrastructure, without a procurement cycle. |
| **How it is bought** | It isn't. The software is free and complete. Revenue comes from **professional services**: custom deployments, integrations, support contracts. |
| **Why the free tier is complete** | Because gating features would make the product worse at the only thing it competes on: being the easiest self-hosted WAF. There is no license check, no feature flag, no activation server. |
| **The differentiator** | The AI layer is **pluggable and optional**: plug in Claude, GPT, Gemini, Vertex, Claude Enterprise, or a local model, and choose the data-privacy policy per provider. The bundled local engine (Open-AppSec) keeps working with zero external calls if you never configure one. |

### What that means for engineering decisions

1. **Easy beats complete when they conflict** — but a capability is never removed to make something easier.
2. **Container is priority 0.** Anything that requires host privileges is optional and off by default.
3. **No telemetry phone-home.** Never add an analytics or "license validation" call.
4. **Zero external dependency for the core path.** A deployment with no internet access, no LLM and no license must fully protect a site.
5. **Every "protected" claim must be true.** Reporting success for an action that did not happen is a defect of the highest severity (see §7).

---

## 2. Deployment modes

| Mode | Priority | Privileges | How blocks are enforced |
|---|---|---|---|
| **Container** (Docker / Podman) | **P0** | none (`NET_ADMIN` not required) | WAF-layer deny in the reverse proxy. Kernel-level filtering is *not* used. |
| **System** (systemd, bare metal / VM) | **P1** | root + `nftables` or `ufw` | WAF-layer deny **plus** kernel drop via the host agent. |

The consequence is architectural, not cosmetic: **"block this IP" must have a WAF-layer implementation that works in both modes**, and the kernel drop is an enhancement only in system mode. Today it does not — see §7, gap 1.

---

## 3. Explicit non-goals

These appeared in the old roadmap. They are **out of scope**, and code for them must not be extended:

NGFW / L2–L4 packet filtering · App-ID / User-ID / Device-ID · IPS/IDS signature engines (Suricata/Snort) · sandboxing · forward proxy, SWG, CASB · outbound SSL interception / SSL orchestration · VPN, ZTNA, SSL-VPN · SD-WAN · DLP · HA clustering, VRRP/CARP, state sync · iRules / Wasm scripting · VRFs, BGP/OSPF, CGNAT, NAT64 · TLS inspection of outbound traffic.

**Exception, deliberately kept:** the host enforcement agent (`cmd/waf-agent`, `internal/firewall`) stays in the codebase as a **system-mode-only** capability. It is a genuine advantage over Cloudflare (they cannot drop packets on your host) but it is P1 and must never be required.

---

## 4. Cloudflare WAF parity matrix

WAF scope only. "Today" reflects the code, not intentions.

| Capability | Cloudflare WAF | Waffynx today | Phase |
|---|---|---|---|
| Managed ruleset (vendor-maintained CVE/virtual-patch rules) | Yes | ❌ none | 1 |
| Community ruleset ingestion (OWASP CRS or equivalent) | OWASP CRS available | ❌ none | 1 |
| Custom rules with boolean expression language | Yes | ⚠️ rules exist in YAML, conditions compiled in Go; no expression language, no editor | 1 |
| Rule actions: block / challenge / log / skip | Yes | ⚠️ `allow`, `block`, `deny`, `log` — no challenge, no skip | 1 |
| Staged / monitor mode before enforcing | Yes | ⚠️ learning engine records, no explicit staging toggle | 1 |
| Rate limiting (per IP, path, header; counting windows) | Yes | ⚠️ fixed window, memory + Redis; not exposed in UI | 1 |
| IP / CIDR / country / ASN lists | Yes | ⚠️ geo plugin + config blocklist; no list CRUD, no ASN | 1 |
| Security events / WAF analytics | Yes | ⚠️ forensics UI, audit ring, SSE — no query/aggregation | 1 |
| Exposed / leaked credentials check | Yes | ❌ | 1 |
| **Site / Proxy Host management** (the core UX) | via zone setup | ❌ **not possible without editing YAML** | **0** |
| Bot management (bot score, verified bots) | Yes | ⚠️ heuristics only (`plugins/bot-protection`) | 2 |
| JS challenge / managed challenge | Yes | ❌ | 2 |
| API Shield (OpenAPI/JSON-schema validation) | Yes | ❌ (GraphQL parsing only) | 2 |
| Logpush / SIEM export | Yes | ⚠️ events publisher + audit file; no push to SIEM | 2 |
| ML attack score classification (SQLi/XSS/RCE) | Yes | ⚠️ local scorer: entropy + pattern heuristics | 3 |
| **Pluggable external AI + privacy controls** | ❌ | ❌ **(the differentiator — deliberately last)** | **3** |
| TLS certificate lifecycle | edge-managed | ⚠️ ACME/autocert + manager; no UI | 1 |
| No capability gating | ❌ (tiered) | ✅ already true: no license, telemetry or gating code exists | ✅ |

### The honest read of that table

Three of the "⚠️" rows are **not** near-parity:

- **Managed rulesets are the single biggest gap.** Without a vendor- or community-maintained rule catalog, a new CVE is not covered until someone writes the rule by hand. Every serious WAF ships this. It is also what makes §7 gap 5 (no LICENSE) urgent.
- **Custom rules without an expression language** cannot express what users actually write on Cloudflare (`http.request.uri.path contains "/admin" and ip.geoip.country in {"CN","RU"} and not cf.bot_management.verified_bot`).
- **Security events without query/aggregation** are a log viewer, not analytics.

---

## 5. Phases

Sequenced by "what makes it a product" — not by "what is interesting to build".

### Phase 0 — The product exists *(current)*

- **Sites / Proxy Hosts CRUD** (API + UI): domain, upstream, TLS, which policies apply. Without this the only way to protect a site is editing a 136-line YAML.
- **Bootstrap from environment variables + first-run wizard**: admin password, listen ports, default upstream. No file editing before first boot.
- **Publish the image** (GHCR, multi-arch) and a one-command compose with automatic TLS. `deploy/helm/values.yaml` already points at `ghcr.io/jackby03/waffynx`; nothing publishes it.
- **Fix the container-mode IP block** (§7 gap 1).

### Phase 1 — Parity basics

- Rule expression language + rule editor in the UI.
- Managed rule catalog with versioned updates, toggles and per-rule exceptions.
- Rate-limit, IP/CIDR/country/ASN list management in the UI.
- Staged (monitor-only) mode as a first-class setting.
- Security events: filtering, aggregation, retention policy.
- Certificate management UI.

### Phase 2 — Bot and API

- Bot scoring, verified-bot handling, JS/managed challenge.
- API Shield: OpenAPI and JSON-schema validation, sequence mitigation.
- Logpush-style export (syslog, HTTP, Kafka).

### Phase 3 — AI *(deliberately last; it is the differentiator, not the foundation)*

- Provider abstraction + adapters: Anthropic, OpenAI, Gemini, Vertex, local (Ollama/llama.cpp), plus the existing Open-AppSec bridge as the bundled local engine.
- Per-provider data-privacy policy: what leaves the box, redaction of PII/headers/body, retention, opt-in per site.
- "Explain this verdict" in the forensics drawer, grounded in the rule/score that fired.
- ML attack-score classification across SQLi/XSS/RCE.

### Phase 4 — Operations

- Declarative IaC (Terraform provider / Ansible collection) over the existing REST API.
- Horizontal replicas sharing configuration (no HA clustering — see non-goals).

---

## 6. Code scope decisions

| Path | Scope | Decision |
|---|---|---|
| `modules/ngx_waffynx`, `internal/engine`, `internal/policy`, `internal/parsers`, `internal/plugin`, `internal/upstream`, `internal/rules`, `internal/ratelimit` | Data plane | **Core.** Keep building. |
| `internal/appsec` | Data plane | **Core** — the bundled local AI engine. |
| `internal/api`, `internal/auth`, `internal/config`, `internal/audit`, `internal/events`, `internal/tls`, `internal/logging`, `internal/metrics`, `internal/learning` | Control plane | **Core.** |
| `ui/` | Control plane | **Core.** Must grow a Sites view. |
| `cmd/waffynx`, `cmd/waf-api`, `cmd/appsec-bridge` | — | **Core.** |
| `internal/firewall`, `cmd/waf-agent` | Host agent | **P1 / system mode only.** Never started in the container. Do not extend until Phase 1 is done. |
| `internal/gateway` (forward proxy) | — | **Out of scope. Frozen.** Move to `FUTURE.md` when it needs maintenance. |
| `internal/marketplace` | — | **Out of scope. Frozen.** A plugin store is not a WAF feature. |

---

## 7. Known gaps and defects

Ordered by severity. All verified in the code, not assumed.

1. **IP blocking silently reports success in container mode.** `internal/api/handlers_firewall.go` calls `_ = s.firewall.BlockIP(req.IP)` — the error is discarded — and `s.firewall` is the host `nftables`/`ufw` manager. In a container it either fails or only touches the container's own netns, and the API returns `201 Created` with a ban record either way. That is a fail-open "protected" claim, which violates Constitution §1.1. Needs a WAF-layer deny that works with no privileges.
2. **No site/Proxy Host CRUD.** Topology lives only in YAML (`routes:`).
3. **No environment-variable bootstrap.** The only env var read is `WAFFYNX_UI_DIR`; everything else is a 136-line YAML copied into the image.
4. **The image is never published.** No workflow builds or pushes it, so `docker pull` is impossible and the Helm chart references a registry path that does not exist.
5. **No `LICENSE` file.** The product is described as the open-source alternative to Cloudflare WAF, but the repository grants no license. This also blocks adoption and any managed-ruleset contribution. Needs a deliberate choice (e.g. Apache-2.0 for adoption vs AGPL-3.0 to deter closed SaaS resale).
6. **`firewall.enabled: true` in the container's default config** while `entrypoint.sh` never starts `waf-agent`, so the setting is misleading in P0 mode.

---

## 8. How this document is used

- Anything not in §4 or §5 is out of scope, including ideas that sound valuable.
- Adding a phase item requires deleting one or explicitly arguing why the ordering changed.
- New capabilities must appear in the parity matrix before they appear in code.
