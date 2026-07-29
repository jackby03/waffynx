<div align="center">
  <h1>🛡️ Waffynx</h1>
  <p><b>Next-generation Web Application Firewall</b></p>
  <p>Native Nginx integration • High-performance Go sidecar • ML Anomaly Detection</p>
</div>

<br/>

Waffynx is a modern Web Application Firewall (WAF) designed for zero-latency overhead and advanced threat protection. It seamlessly integrates directly into Nginx via a custom C module and evaluates requests through a high-performance Go sidecar utilizing rule-based policies and Machine Learning anomaly scoring.

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
* **Enterprise Management**: REST API with JWT authentication, a single-page Dashboard UI, and Prometheus metrics out of the box.
* **Host Firewall Agent**: Automated IP blocking via nftables/UFW integration.

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

> **Note**: Waffynx requires a Linux environment (Debian/Ubuntu) or WSL.

### 1. Prerequisites
Ensure you have the required build tools and Go installed:
```bash
sudo apt-get update && sudo apt-get install -y build-essential libpcre2-dev libssl-dev zlib1g-dev
```

### 2. Clone & Build
```bash
git clone --recurse-submodules https://github.com/jackby03/waffynx.git
cd waffynx

# Build the custom Nginx proxy
make nginx-checkout
make nginx-configure
make nginx-build

# Build the Go components (CLI, Agent, API, Bridge)
make build
make bridge-build
```

### 3. Run Locally (Development)
You can utilize our Vagrant environment for a complete out-of-the-box sandbox:
```bash
make vagrant-up
make vagrant-ssh

# Inside the VM, Waffynx is automatically provisioned and running:
curl http://localhost:8080/                              # 200 OK (Allowed)
curl "http://localhost:8080/?q=UNION+SELECT+1,2,3"       # 403 Forbidden (Blocked)
```

## 🗺️ Roadmap

**✅ Implemented & Working:**
- Native Nginx module & Sidecar socket communication
- Core Policy Engine (Rule-based HTTP method matching)
- UFW / nftables automated blocking agent
- Memory & Redis-backed distributed rate-limiting
- Load balancer proxy (upstream module)
- C++ `open-appsec` bridge integration
- Unit & Fuzz testing across core packages (~64 tests)
- Kubernetes Helm Charts (Ingress + HPA support)
- Docker Multi-arch support (`linux/amd64` & `linux/arm64`)

**🚧 Pending / In Development:**
- React/Vue single-page dashboard UI
- gRPC API migration for sidecar evaluation
- Full JWT enforcement on all API routes
- Dynamic Plugin Marketplace

## 📖 Documentation

* **[AGENTS.md](AGENTS.md)**: Detailed architecture specs, development gotchas, and internal component mapping.
* **Configuration**: Check out `configs/waffynx.yaml` for a full production configuration template.

## 📄 License

This project is licensed under the MIT License.
