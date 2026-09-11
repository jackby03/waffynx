# ADR-0002: Unified Tri-Architecture Network & Application Security Engine (NGFW + ADC/WAF + SASE/ZTNA)

* **Status:** Accepted
* **Date:** 2026-09-10
* **Author(s):** Waffynx Core Architecture Team
* **Deciders:** Engineering Lead, Security Architect, Agent Governance

---

## Context and Problem Statement

Modern enterprise environments typically deploy fragmented security appliances from multiple vendors to achieve full-stack protection:
- **F5 BIG-IP** for Application Delivery Control (ADC), Full-Proxy L7 WAF (ASM), Access Policy Manager (APM), and iRules.
- **Palo Alto Networks / Fortinet / Check Point / Cisco** for Next-Generation Firewall (NGFW), Stateful L2–L4 packet filtering, App-ID, User-ID, IPS, and Sandboxing.
- **Cloudflare / Zscaler** for Cloud Edge WAF, Bot Management, and SASE / Zero Trust Network Access (ZTNA).

This fragmentation creates massive operational friction, high latency due to multiple hops of encryption/decryption, high licensing costs, and blind spots across inspection planes. Waffynx seeks to consolidate these enterprise capabilities into a single, unified open-source engine.

However, a single monolithic architecture cannot address wire-speed L2–L4 packet filtering and complex L7 application stream inspection with equal efficiency without severe performance compromises.

---

## Decision Drivers

1. **Hot-Path Latency & Throughput:** L2–L4 filtering must operate at wire-speed with sub-microsecond overhead, while L7 WAF inspection must remain under 2ms P99 latency.
2. **Separation of Planes (Constitution Law):** Data plane (packet/stream processing) must remain completely independent of the control plane (management REST API, SIEM telemetry, UI).
3. **Fail-Closed Security & Default-Deny:** In accordance with `constitution.md`, failure of any inspection module must default to deny/block.
4. **Architectural Tri-Convergence:** Must natively support:
   - **Inline Packet/Stream Engine (NGFW):** Transparent L2 Bridge, V-Wire, or L3 Gateway.
   - **Full-Proxy Inverso (ADC / WAF):** Reverse proxy with deep L7 inspection, SSL termination, and bot defense.
   - **Forward Proxy / SASE (SWG / ZTNA):** Outbound SSL MitM inspection, URL categorization, and application micro-tunnels.
5. **Hardware & Kernel Acceleration:** Exploit Linux Netfilter, eBPF, XDP, and hardware SYN cookies rather than recreating packet routing in userspace.

---

## Considered Options

1. **Option 1: Monolithic Userspace Go Daemon:** Implement all L2–L7 networking, proxying, and filtering inside pure Go.
   - *Rejected:* Userspace packet handling in Go suffers from GC pauses, high context switching overhead, and cannot achieve wire-speed L2/L4 throughput compared to kernel Netfilter/eBPF.
2. **Option 2: Standalone Disjoint Daemons without Unified Control:** Run separate open-source tools (Suricata + Nginx + StrongSwan + nftables) as disconnected services.
   - *Rejected:* Lacks coordinated policy enforcement, creates multiple TLS termination hops, and provides no unified SOC telemetric plane.
3. **Option 3: Tri-Architectural Converged Model (Chosen):**
   - **Kernel & Stream Layer (NGFW):** Linux `nftables`/eBPF with hardware offload driven asynchronously by `waf-agent` for L2–L4 SPI, SYN cookies, and volumetric flood defense.
   - **Full-Proxy Ingress & Egress (ADC/WAF & SASE):** Native Nginx C module (`modules/ngx_waffynx`) managing TLS termination, HTTP pipelining, and forward/reverse proxying, communicating via zero-copy Unix sockets with the Go/C++ inspection sidecar (`internal/engine`).
   - **Unified Control Plane & SOC UI:** `cmd/waf-api` orchestrating configuration, declarative IaC, and the React 19 Control Room.

---

## Decision Outcome

**Chosen Option:** **Option 3: Tri-Architectural Converged Model**, because it combines the raw wire-speed performance of the Linux kernel for L2–L4 with the battle-tested HTTP parsing robustness of Nginx and the low-latency extensibility of the Go/C++ inspection sidecar.

### Positive Consequences
* Single pane of glass for enterprise security: replaces separate NGFW, WAF, SWG, and ADC appliances.
* Single TLS termination hop: SSL Offloading and SSL Orchestration allow decrypting once and evaluating across App-ID, IPS, and WAF simultaneously.
* Full alignment with `constitution.md`: preserves pure static binaries, zero-copy IPC over `0600` sockets, and strict fail-closed security.
* High-Speed Logging (HSL) allows real-time export to enterprise SIEMs without dragging down packet processing threads.

### Negative Consequences / Trade-offs
* Multi-layer testing requires integration verification across Linux VM / Vagrant environments for kernel/eBPF components.
* Higher conceptual complexity in policy mapping (coordinating L2–L4 rules with L7 URL/header inspection).

---

## Pros and Cons of the Chosen Option

* **Good,** because kernel-level Netfilter/eBPF handles DDoS and SYN floods at wire speed before TCP socket allocation.
* **Good,** because Nginx C module provides enterprise-grade TLS 1.3, HTTP/2, and HTTP/3 support with minimal memory overhead.
* **Good,** because the Go sidecar provides clean memory safety, concurrency, and rapid extensibility for ML scoring (`open-appsec`) and dynamic iRules scripting.
* **Bad,** because production deployment requires Linux kernel 5.15+ for complete eBPF / nftables driver support.
