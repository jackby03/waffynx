# ADR-0003: Product Scope — Self-Hosted WAF, Container-First

* **Status:** Accepted
* **Date:** 2026-11-16
* **Supersedes:** [ADR-0002](0002-unified-network-security-engine.md) (Unified Tri-Architecture NGFW + SASE Engine)
* **Author(s):** Waffynx Core Team
* **Deciders:** Engineering Lead, Product Owner

---

## Context and Problem Statement

ADR-0002 defined Waffynx as a **tri-architecture enterprise security engine**: an inline L2–L4 NGFW, a full-proxy ADC/WAF, and a forward-proxy SASE/SWG platform, consolidated from F5, Palo Alto Networks, Fortinet, Check Point and Cisco.

That decision shaped `docs/ROADMAP.md` into 14 pillars — stateful packet inspection, App-ID/User-ID, IPS with Suricata/Snort rulesets, sandboxing, SWG/CASB, SSL orchestration, VPN/ZTNA, SD-WAN, DLP, HA clustering, iRules — and it shaped the codebase: 1,906 of 14,888 Go lines (13%) sit in forward proxy, marketplace and host-firewall subsystems that are not WAF features.

The actual product is narrower and clearer than that:

> A self-hosted WAF and reverse proxy that runs as one container, is set up in minutes, and has no capability gated behind a paywall. Near-total feature parity with **Cloudflare WAF — WAF only**. Revenue comes from professional services, not from feature tiers.

The mismatch had three concrete costs:

1. **Direction.** Every roadmap item competed with an NGFW vendor, none of them made the product easier to adopt. "The easiest self-hosted WAF" was not on the roadmap.
2. **Scope creep.** Work landed in `internal/gateway` (forward proxy), `internal/marketplace` (plugin store) and a host packet filter that requires root, while the missing feature was "add a site without editing YAML".
3. **False claims.** IP blocking in container mode reports success while enforcing nothing (see Consequences below), because host-level `nftables`/`ufw` is the only backend.

## Decision Drivers

1. **Adoption over breadth.** The competing products (SafeLine, Nginx Proxy Manager, BunkerWeb, OpenAppSec) win on time-to-first-protected-site, not on protocol coverage.
2. **Container is priority 0, system is priority 1.** Nothing in the core path may require host privileges.
3. **No capability gating.** The free tier must be complete; there is no license server, feature flag, or mandatory telemetry.
4. **The AI layer is the differentiator but not the foundation.** It ships last, and it must be pluggable (Anthropic, OpenAI, Gemini, Vertex, local) with user-controlled privacy. The bundled local engine must keep the product fully functional with zero external calls.
5. **Separation of planes stays.** Constitution §1.3 is unchanged; this ADR narrows *product scope*, not architecture.

## Considered Options

1. **Keep ADR-0002 (unified NGFW).** Preserve breadth, accept that the product has no adoptable identity.
2. **Narrow to the WAF, park the rest.** One container, Cloudflare-WAF parity, container-first, AI pluggable, no gating.
3. **Split into two products.** Ship a WAF now and an NGFW later as a separate artifact sharing the engine.

## Decision Outcome

**Chosen option: 2 — narrow to the WAF and park the rest.**

The NGFW/SWG/ZTNA material is preserved verbatim in [`docs/FUTURE.md`](../FUTURE.md) — it is parked, not discarded — and remains available if option 3 is ever revisited. The active scope is [`docs/ROADMAP.md`](../ROADMAP.md).

### In scope

Reverse proxy, WAF inspection pipeline (nginx module + Go sidecar), rule engine, parsers, plugin chain, rate limiting, IP/geo/ASN lists, bot defense, API schema validation, TLS lifecycle, audit/events/analytics, management API, control-room UI, the bundled local AI engine, and the pluggable external-AI layer.

### Out of scope

L2–L4/NGFW packet filtering as a product, App-ID/User-ID, IPS signature engines, sandboxing, forward proxy/SWG/CASB, outbound SSL interception, VPN/ZTNA, SD-WAN, DLP, HA clustering, iRules, VRFs/BGP/OSPF/CGNAT.

**Deliberate exception:** `cmd/waf-agent` + `internal/firewall` stay as a **system-mode-only** capability (host `nftables`/`ufw` drop is something Cloudflare cannot do). They are priority 1, off in container mode, and not to be extended until Phase 1 of the roadmap is complete.

### Positive Consequences

- The roadmap now contains only things that make the product adoptable.
- "Container is priority 0" becomes an enforceable rule, not a preference.
- The AI layer gets an explicit slot (Phase 3) instead of competing with packet filtering for attention.
- Two real defects are now tracked instead of invisible: container-mode IP blocking that reports success without enforcing, and the absence of any site-management UX.

### Negative Consequences / Trade-offs

- Abandons the "one engine replaces F5 + Palo Alto + Fortinet" narrative, and the differentiation that came with it.
- 1,906 lines of Go become frozen maintenance (no new features, still must compile).
- **There is no `LICENSE` file.** Claiming an open-source alternative to Cloudflare WAF without a license is a defect of the product statement, and it blocks any managed-ruleset contribution. Choosing it is now a tracked roadmap gap (§7, gap 5).
- Managed rulesets — the largest parity gap — depend on a license choice and on a maintenance process, not just on code.

---

## Pros and Cons of Options

### Option 1: Keep the unified NGFW scope
- Good, because it preserves the ambitious architecture and the research already written.
- Good, because an NGFW and a WAF genuinely share an inspection engine.
- Bad, because the product has no identity a user can adopt. "Everything for everyone" has no time-to-value story.
- Bad, because the missing pieces (site CRUD, easy bootstrap, published image) keep losing priority to new pillars.
- Bad, because each pillar implies a support surface the team cannot staff.

### Option 2: Narrow to the WAF (chosen)
- Good, because it makes the roadmap a to-do list for a shippable product.
- Good, because container-first removes the root-privilege requirement that blocks most self-hosted adoption.
- Good, because Cloudflare-WAF parity is measurable (see the parity matrix).
- Bad, because it discards real research and the "unified engine" differentiator.
- Bad, because the AI differentiator is deliberately deferred to last, so the product must win on WAF fundamentals first — a harder fight.

### Option 3: Ship a WAF now, an NGFW later
- Good, because it separates release cadences and lets the WAF ship first.
- Bad, because it doubles the packaging, documentation and support surface before either has users.
- Bad, because it keeps the out-of-scope subsystems alive and consuming attention.
