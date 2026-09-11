# Waffynx Master Roadmap: The Unified Open-Source Network & Application Security Engine

> **Architectural Vision:** Consolidating the enterprise capabilities of **F5 BIG-IP, Palo Alto Networks, Fortinet, Check Point, Cisco Secure Firewall, and Cloudflare** into a single, modular, open-source high-performance engine.
>
> **Core Tri-Architecture:**
> 1. **Inline Packet/Stream Engine (NGFW)** — Wire-speed L2–L4 stateful inspection, App-ID, IPS/IDS, streaming AV, and hardware offload.
> 2. **Full-Proxy Inverso (ADC / WAF)** — L7 application inspection, reverse proxy, load balancing, SSL offload, bot defense, and real-time programmability (iRules).
> 3. **Forward Proxy / SASE (SWG / ZTNA)** — Outbound SSL/TLS decryption (MitM), URL filtering, inline CASB, and zero-trust application micro-tunnels.
>
> **Governance & Invariants:** Strictly adheres to [`constitution.md`](../constitution.md), [`specs/HARNESS.md`](../specs/HARNESS.md), and [`docs/adr/0002-unified-network-security-engine.md`](adr/0002-unified-network-security-engine.md).

---

### Global System Architecture

#### 🎛️ Control & Management Plane
* **Interfaces:** REST API (`:9090`), gRPC Control, and Waffynx Control Room UI (SOC Dashboard).
* **Operations & IaC:** Declarative configuration (Terraform / Ansible) and High-Speed Logging (HSL) telemetry export to SIEM / Data Lakes.

| ⚡ Inline Packet & Stream Engine (NGFW Core) | 🛡️ Application & Proxy Engine (ADC / SASE) |
| :--- | :--- |
| **L2–L4 Offload:** Netfilter, eBPF, XDP, and hardware NIC offload. | **Full-Proxy Reverse:** Native Nginx C module + ultra-low-latency Go sidecar. |
| **Stateful Inspection:** Bidirectional state tracking for TCP, UDP, ICMP, SCTP, and GRE. | **Forward Proxy / SWG:** Outbound SSL/TLS MitM decryption with local enterprise CA and legal bypass. |
| **App-ID:** Deep application classification via behavioral analysis and binary patterns. | **Advanced WAF:** OWASP Top 10, positive security models, and ML-assisted scoring. |
| **User-ID:** Identity mapping via Active Directory, Kerberos, RADIUS, Syslog, and 802.1X. | **Bot Defense:** JavaScript cryptographic Proof-of-Work, dynamic CAPTCHA, and JA3/JA4 fingerprints. |
| **Device-ID & IoT:** mDNS signatures, DHCP option heuristics, and OUI microsegmentation. | **API Shield:** Strict OpenAPI v2/v3, JSON Schema, and gRPC schema enforcement. |
| **IPS Signature Engine:** Native integration with open Suricata and Snort 3 rule sets. | **Client-Side DataSafe:** In-browser encryption of sensitive input fields (anti-formjacking). |
| **Streaming Antivirus:** Real-time stream-based malware detection and sandbox connectors. | **iRules & Programmability:** Event-driven real-time traffic scripting via Lua and WebAssembly (Wasm). |
| **Advanced Routing:** VRF, Route Domains, BGPv4/v6, OSPF, PBR, and CGNAT. | **ZTNA & Secure Access:** Per-application micro-tunnels and browser-based WireGuard / SSL-VPN portal. |
| **Secure Interconnect:** IPsec Site-to-Site (VTI / ADVPN) and multi-link SD-WAN. | **Cloaking & Obfuscation:** Server header suppression and secure custom 4xx/5xx error tripwires. |

---

## 🏛️ Comprehensive Pillar Specifications

---

### 1. Network Engine & Packet Filtering Core (L2–L4 - AFM / NGFW Core)

* **Stateful Packet Inspection (SPI):**
  * High-capacity bidirectional connection tracking table for TCP, UDP, ICMP, SCTP, and GRE with configurable protocol-specific expiration timers.
* **L2/L3 Deployment Modes:**
  * **Routed Mode (L3 Gateway):** Classical routed deployment with perimeter firewalling and hop-by-hop forwarding.
  * **Transparent Bridge Mode (L2 without IP):** Bump-in-the-wire inline deployment without modifying network topology or assigning IP addresses.
  * **Virtual Wire Mode (V-Wire):** Transparent binding of physical interface pairs without MAC/IP allocation, performing wire-speed deep inspection.
* **Network Segmentation & Dynamic Routing:**
  * VRF (*Virtual Routing and Forwarding*) and isolated Route Domains for strict multi-tenant boundary separation.
  * Dynamic routing protocols: BGPv4/v6 with communities and route maps, OSPFv2/v3, RIPv2, and IS-IS.
  * Policy-Based Routing (PBR by source/destination IP, port, identified application, or ingress interface).
* **Comprehensive NAT Engine:**
  * Static and dynamic SNAT (Source NAT with IP Masquerade and outbound IP pools).
  * DNAT (Port Forwarding, inbound Virtual IPs, and 1:1 NAT).
  * Carrier-Grade NAT (CGNAT / NAT444) for large-scale environments, NAT64, and DNS64 translation.
  * Application Layer Gateways (ALGs) with in-flight payload packet rewriting for SIP, active/passive FTP, and H.323.
* **Packet Sanity Validation & L3/L4 Evasion Mitigation:**
  * In-kernel drop of invalid TCP flag combinations (Xmas, NULL scan, SYN-FIN, Land Attack).
  * IP fragment reassembly and overlap prevention (Teardrop attacks and intentional micro-fragmentation).
  * In-kernel/driver **SYN Cookie** generation to defeat volumetric TCP SYN floods without connection table exhaustion.
  * Volumetric amplification and reflection mitigation (ICMP, Smurf, Fraggle, NTP, Memcached, DNS reflection).
  * Rate limiting of new connections per second and concurrent connection caps per source IP.

---

### 2. Application & Identity Inspection (App-ID / User-ID)

* **App-ID (Port-Agnostic Deep Application Classification):**
  * Deep packet classification using binary signatures, protocol handshake semantics, and behavioral heuristics, independent of TCP/UDP port numbers.
  * Granular application micro-function control (e.g., allow `Slack-Chat`, block `Slack-File-Transfer`; allow `YouTube-Watch`, block `YouTube-Upload`).
  * Evasive tunnel decoding and mitigation (SSH encapsulated over port 443, DNS-over-HTTPS/DoH, chained HTTP proxies).
* **User-ID (Identity-to-IP Binding):**
  * Ingestion and correlation of IP-to-User bindings via Microsoft Active Directory Security Event Logs, Syslog from authentication servers, WMI, Kerberos, RADIUS, and 802.1X.
  * Integrated Captive Portal for authenticating unknown endpoints, guests, or BYOD devices.
  * Security policy authoring and enforcement based on directory groups and Organizational Units (LDAP / Azure AD / Okta).
* **Device-ID & IoT Profiling:**
  * Passive device fingerprinting leveraging DHCP options (Option 55/60), User-Agent headers, mDNS, SSDP, and MAC OUI database lookups.
  * Automated dynamic microsegmentation assigning least-privilege security profiles based on detected device classification (IP cameras, printers, medical devices).

---

### 3. Intrusion Prevention & Threat Detection (IPS / IDS)

* **Inline IPS Engine with Stream Reassembly:**
  * Full protocol normalization across network and application layers prior to signature matching to defeat fragmentation and encoding evasions.
  * Inline detection and blocking of vulnerability exploits targeting operating systems, network services, and application runtimes (SMB/EternalBlue, RPC, RDP/BlueKeep, DNS, SSH, HTTP, TLS).
  * Native compatibility with open **Suricata** and **Snort 3** signature rule sets, compiled into deterministic Aho-Corasick automaton trees.
* **Command & Control (C2) Detection:**
  * Detection and disruption of periodic beacons to C2 infrastructure using statistical time-interval jitter analysis.
  * Identification and blocking of covert data exfiltration tunnels over ICMP payloads and DNS query tunneling.
* **Streaming Antivirus & Anti-Malware Engine:**
  * Real-time file stream scanning on the fly without staging the full payload to disk prior to forwarding.
  * In-memory recursive decompression of nested archive formats (ZIP, RAR, 7z, GZIP, TAR) with strict zip-bomb protections (expansion ratio and depth limits).
  * True file type validation via Magic Bytes verification to defeat extension-renaming evasion tactics (e.g., `.exe` disguised as `.pdf`).

---

### 4. Sandboxing & Zero-Day Threat Analysis

* **In-Flight Object Extraction:**
  * Automated wire extraction of executable binaries (Windows PE, Linux ELF, macOS Mach-O), packed executables, scripts (PowerShell, VBScript, Bash, Python), and macro-enabled documents (PDF, Microsoft Office).
* **In-Engine Static Pre-Filtering:**
  * Instant cryptographic hashing (MD5, SHA-256), section entropy analysis for detecting packers/crypters, suspicious OS API import tables, and code signing certificate verification.
* **Dynamic Sandbox Integration:**
  * Asynchronous streaming dispatch to isolated detonation environments (integrations with **CAPEv2**, **Cuckoo Sandbox**, or cloud sandbox APIs).
  * System call monitoring, Windows registry mutation analysis, process injection tracking, and unresolved outbound DNS telemetry.
* **Verdict Distribution & Quarantine:**
  * Real-time automated distribution of sandbox malicious verdicts to the local and cluster-wide threat cache (*Zero-Day Blacklist*) for instant enterprise-wide quarantine.

---

### 5. SSL/TLS Cryptography & Inspection (SSL Orchestration)

* **Forward Proxy SSL/TLS (Outbound Internet Inspection):**
  * Transparent Man-in-the-Middle (MitM) decryption of outbound user traffic toward the Internet via dynamic certificate re-signing signed by a local enterprise root CA.
  * Policy-driven SSL bypass whitelist based on legal, regulatory, and ethical categories (banking, healthcare, government portals, employee privacy).
* **Reverse Proxy SSL/TLS (Inbound Application Termination):**
  * Hardware/driver cryptographic offloading (*SSL Offloading / Termination*), secure re-encryption toward backend origin pools (*SSL Bridging*), and uninspected SNI pass-through (*SSL Passthrough*).
  * Modern TLS 1.2 and 1.3 termination with strict cipher suite ordering and mandatory Perfect Forward Secrecy (PFS with ECDHE-ECDSA / ECDHE-RSA; ChaCha20-Poly1305, AES-GCM; complete ban on CBC and static RSA).
  * Mutual TLS (**mTLS**) authentication enforcing client X.509 certificate validation against enterprise trust stores.
  * Real-time certificate revocation status checks via CRL caches and OCSP queries with **OCSP Stapling** support.
* **SSL Orchestration (Security Service Chaining):**
  * Decrypt once and chain traffic through multiple external security inspection appliances (DLP, secondary IPS, specialized malware analyzers) before re-encrypting toward the final destination.

---

### 6. Secure Web Gateway & Forward Proxy (SWG / CASB)

* **Web & URL Filtering:**
  * Real-time categorization of domains and full URLs against threat databases (phishing, C2 malware, weapons, gambling, social media).
  * Automated proactive blocking of Newly Registered Domains (NRD with domain registration age under 30 days).
* **DNS Protocol Security:**
  * Detection and sinkholing of Domain Generation Algorithms (DGA) used by botnets via linguistic randomness and entropy metrics.
  * Response Rate Limiting (RRL) on DNS resolution paths to mitigate DNS amplification and reflection attacks.
  * Strict DNSSEC trust chain validation and Response Policy Zones (**DNS RPZ**) support.
* **Inline CASB (Cloud Access Security Broker):**
  * Granular Tenant Restriction via dynamic injection of provider-specific HTTP headers (e.g., `X-Goog-Allowed-Domains`, `Restrict-Access-To-Tenants`) to enforce corporate account usage on public SaaS services (Google Workspace, Microsoft 365, AWS).

---

### 7. Web Application Firewall (WAF / ASM / Reverse Proxy)

* **Complete OWASP Top 10 Mitigation:**
  * Protection against SQL Injection (SQLi), Cross-Site Scripting (XSS), Remote Code Execution (RCE), Local/Remote File Inclusion (LFI/RFI), Server-Side Request Forgery (SSRF), Insecure Deserialization, session fixation, and Broken Access Control.
* **Positive Security Model (Whitelisting):**
  * Strict policy profiles accepting only known-good URIs, parameter types, HTTP methods, headers, and parameter length constraints, enforcing `Default Deny` on unmapped inputs.
* **API Shield:**
  * Runtime ingestion and schema validation for **OpenAPI / Swagger (v2.0, v3.0, v3.1)** specifications.
  * In-line validation of JSON Schemas and XML/WSDL schemas within request payloads.
* **Layer 7 DoS/DDoS Mitigation:**
  * Defense against slow HTTP attacks (Slowloris, Slow POST, Slow Read, RUDY) via minimum throughput enforcement per socket.
  * Adaptive rate limiting and request throttling keyed by source IP, session cookie, JWT claim, or custom HTTP headers.
* **Bot Defense & Anti-Automation:**
  * Transparent or interactive JavaScript cryptographic Proof-of-Work challenges and adaptive CAPTCHA on traffic spikes.
  * Headless browser and automation framework fingerprinting (Puppeteer, Playwright, Selenium, Headless Chrome).
  * Client TLS fingerprinting (JA3 / JA4) and HTTP/2 protocol frame consistency verification.
* **Client-Side DataSafe (In-Browser Encryption):**
  * Real-time client-side field-level encryption of credentials and sensitive input fields prior to form submission, preventing credential theft via banking trojans or DOM keyloggers.
* **Server Cloaking & Information Disclosure Prevention:**
  * Dynamic stripping of debugging stack traces, server banners (`Server`, `X-Powered-By`), and backend infrastructure headers.
  * Hardened custom error responses (404, 403, 500, 502) integrated with directory scanning tripwires.

---

### 8. Data Loss Prevention (DLP)

* **Decrypted Outbound Stream Inspection:**
  * Detection and masking of Payment Card Industry (PCI-DSS) Primary Account Numbers (PAN) verified via the **Luhn algorithm**.
  * Identification of National Identification Numbers (SSN, DNI, NIE), cleartext credentials, and proprietary source code markers.
  * Detection of leaked cryptographic private keys and API tokens (`-----BEGIN RSA PRIVATE KEY-----`, AWS keys, GitHub PATs).
* **Corporate Metadata Sanitization:**
  * Automated stripping of EXIF metadata (GPS coordinates, camera serial numbers), document author properties, and internal network UNC paths from files transferred across web gateways.

---

### 9. VPN, Secure Connectivity & Remote Access (ZTNA / SSL-VPN)

* **IPsec Site-to-Site:**
  * Route-based tunnels (VTI - *Virtual Tunnel Interfaces*) and policy-based crypto ACL tunnels.
  * IKEv1 and IKEv2 negotiation supporting modern cipher suites: AES-256-GCM, SHA-384, ChaCha20-Poly1305, and Curve25519 / ECP384 Diffie-Hellman groups.
  * Dynamic multipoint VPN mesh support (equivalent to **ADVPN / DMVPN**) for direct spoke-to-spoke tunnels without hub hairpinning.
* **Remote Access VPN (SSL-VPN / WireGuard):**
  * Full Tunnel and Split Tunnel routing topologies.
  * Clientless Web VPN portal providing in-browser HTML5 remote desktop (RDP), SSH terminal, and VNC access without desktop agent installations.
* **Zero Trust Network Access (ZTNA):**
  * Per-application micro-tunnels granting access solely to authorized services rather than entire network subnets.
  * Continuous endpoint security posture evaluation (*Host Checking*): active antivirus, operating system patch level, disk encryption status, and machine certificate validation.

---

### 10. Software-Defined WAN (SD-WAN)

* **Real-Time Link SLA Probing:**
  * Continuous active synthetic probes measuring one-way latency, packet loss, and jitter across multiple WAN transports (fiber, LTE/5G, satellite).
* **Application-Aware Multi-Link Routing:**
  * Dynamic steering of critical business traffic (VoIP, video conferencing, ERP) to the best-performing path in real time without tearing down active TCP sessions.
* **WAN Path Remediation:**
  * Forward Error Correction (FEC) and selective packet duplication to maintain session stability across lossy or degraded transport links.

---

### 11. Threat Intelligence & Reputation

* **Continuous Threat Feed Ingestion:**
  * Automated polling and ingestion of malicious IP lists, CIDR blocks, malicious domains, and malware hashes via REST APIs, CSV feeds, and **STIX / TAXII** standards.
* **Geographic & ASN Policy Enforcement:**
  * Country-level, regional, or Autonomous System (BGP ASN) traffic filtering powered by localized MaxMind DB lookups and live BGP tables.
* **Dynamic Auto-Blacklisting:**
  * Automated temporary isolation and quarantine of source IPs exceeding port scanning thresholds (L4) or repeated high-severity WAF/IPS violations (L7), managed with exponential decay cooldowns.

---

### 12. Real-Time Programmability (F5 iRules Engine)

* **High-Performance Event-Driven Execution:**
  * Capability to execute compiled scripts (LuaJIT, WebAssembly / Wasm, or dynamic Rust hooks) hooked directly into network and application lifecycle events:
    * **L4 Events:** `CLIENT_ACCEPTED`, `SERVER_CONNECTED`, `CLIENT_DATA`, `SERVER_DATA`, `CLIENT_CLOSED`.
    * **L7 Events:** `HTTP_REQUEST`, `HTTP_REQUEST_HEADERS`, `HTTP_REQUEST_DATA`, `HTTP_RESPONSE`, `HTTP_RESPONSE_HEADERS`, `HTTP_RESPONSE_DATA`.
* **In-Flight Header & Payload Mutation:**
  * Dynamic URL rewriting, request/response header modification, live data masking, affinity cookie injection, and sub-millisecond pool selection.

---

### 13. High Availability (HA) & Distributed State Management

* **Active/Passive (A/P) Failover:**
  * Sub-second stateful failover with redundant heartbeat links over dedicated interfaces and seamless virtual IP migration via **VRRP** or **CARP**.
* **Active/Active (A/A) Clustering:**
  * Symmetric traffic distribution across synchronized cluster nodes for massive horizontal scalability.
* **Distributed State Synchronization:**
  * Real-time peer replication of stateful connection tables, TCP session timers, rate-limiting token buckets, and active VPN user states across all nodes (preventing session drops on failover).

---

### 14. Telemetry, Audit & Automation (Enterprise Operations)

* **High-Speed Logging (HSL):**
  * Asynchronous, lock-free streaming of millions of audit events per second without stalling packet inspection threads (via Syslog UDP/TCP/TLS, IPFIX, NetFlow v9, or Apache Kafka).
* **Declarative / API-First Management:**
  * Full REST and gRPC management interfaces for provisioning all objects, virtual servers, and security policies via Infrastructure-as-Code (Terraform, Ansible, and GitOps pipelines).
* **Audit & Simulation Modes (*Staging / Monitor-Only*):**
  * Simulation mode where security rules inspect, score, and generate rich forensic alerts without dropping packets, facilitating false-positive calibration prior to active enforcement.

---

## 📅 Architectural Convergence Matrix & Milestone Timeline

| Phase | Module / Pillar | Key Technology | Code Subsystem | Status |
|---|---|---|---|---|
| **P0** | **Core WAF & Sidecar** | Nginx C + Go Sidecar + nftables agent + open-appsec | `modules/ngx_waffynx`, `internal/engine` | ✅ **Completed** |
| **P0** | **SOC Control Room UI v2** | React 19 + Mock Backend + SSE Stream + F5 Dark Design | `cmd/waf-api/ui` | ✅ **Completed** |
| **P1** | **Reverse Proxy & Traffic Director** | Upstream pools, health checks, custom error pages (404/500), server cloaking | `internal/upstream`, `cmd/waf-api` | 🚧 **Active** |
| **P2** | **L7 ASM & Bot Defense** | Positive security, OpenAPI validation, JS challenges, JA3/JA4, DLP | `plugins/`, `internal/policy` | 📅 **Queued** |
| **P3** | **L2–L4 Network Firewall (AFM)** | Stateful Netfilter, SYN cookies, flood mitigation, ACLs, VRF, CGNAT | `cmd/waf-agent`, `internal/firewall` | 📅 **Queued** |
| **P4** | **IPS / IDS & Threat Prevention** | Suricata/Snort3 engine, C2 beacon jitter, streaming antivirus (magic bytes) | `internal/ips`, `third_party/` | 📅 **Queued** |
| **P5** | **SSL / TLS Cryptography & Orchestration** | Outbound MitM Forward Proxy, Reverse SSL Offload, mTLS, CRL/OCSP, SSL-O | `modules/ngx_waffynx`, `internal/crypto` | 📅 **Queued** |
| **P6** | **SWG & Outbound Web Security** | URL categorization, NRD blocking, DNS RRL/DGA/RPZ, inline CASB tenant control | `internal/swg`, `internal/dns` | 📅 **Queued** |
| **P7** | **Zero-Day Sandboxing** | Object extraction, PE/ELF entropy, CAPEv2/Cuckoo dynamic integration | `internal/sandbox` | 📅 **Queued** |
| **P8** | **VPN, Secure Access & ZTNA** | IPsec VTI, WireGuard/SSL-VPN, Clientless RDP/SSH portal, ZTNA host checking | `cmd/waf-vpn`, `internal/ztna` | 📅 **Queued** |
| **P9** | **SD-WAN Engine** | Synthetic SLA probing (latency/jitter/loss), dynamic multi-link routing, FEC | `internal/sdwan` | 📅 **Queued** |
| **P10** | **Threat Intelligence & GeoIP** | STIX/TAXII feed ingestion, MaxMind GeoIP/ASN, dynamic auto-blacklists | `internal/threatintel` | 📅 **Queued** |
| **P11** | **iRules Programmability** | Real-time event-driven scripting engine (LuaJIT / Wasm / Rust dynamic hooks) | `internal/rulesengine` | 📅 **Queued** |
| **P12** | **High Availability & State Sync** | Active/Passive VRRP/CARP, Active/Active clustering, distributed session sync | `internal/cluster` | 📅 **Queued** |
| **P13** | **High-Speed Logging & Telemetry** | HSL asynchronous Syslog/IPFIX/Kafka, declarative REST/gRPC API-first | `internal/logging`, `cmd/waf-api` | 📅 **Queued** |
