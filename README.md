# Waffynx

**Next-generation Web Application Firewall** — nginx native integration, Go sidecar, ML anomaly detection, plugin marketplace.

```
HTTP Request → nginx (C module, ACCESS phase) → Unix socket → Go Sidecar
  → Plugin Chain (4 plugins) → Policy Engine → ML Scorer (BasicScorer or open-appsec bridge)
  → 204 Allow / 403 Block → nginx → Backend
```

## Features

- **Native nginx integration** — C module intercepts requests at ACCESS phase, zero latency overhead
- **Multi-stage evaluation** — plugins → policy rules → ML anomaly scoring
- **Body inspection** — SQLi, XSS, command injection, path traversal in request bodies (POST)
- **4 built-in plugins**: request-validation, bot-protection, rate-limit (token bucket), geo-block (MaxMind)
- **ML scorer** — entropy analysis, char distribution, pattern detection, rate tracking
- **open-appsec bridge** — swap BasicScorer for real C++ ML engine via Unix socket
- **Management API** — REST API with JWT auth (status, config, metrics, plugins)
- **Dashboard** — embedded single-page UI (login, status cards, plugins, memory)
- **Firewall agent** — nftables/UFW management with IP blocklist
- **Stripped nginx** — 868KB binary, only 5 essential modules + waffynx module

## Architecture

```
┌──────────┐    Unix socket     ┌──────────────┐
│  nginx   │ ──── HTTP/1.0 ───▶ │   Sidecar    │
│ C module │                    │  (Go, in-engine) │
└────┬─────┘                    └──────┬───────┘
     │                                │
     │                         ┌──────┼──────┐
     │                         ▼      ▼       ▼
     │                    Plugins  Policy  Scorer
     │                         │      │       │
     │                         └──────┼───────┘
     │                                │
     ▼                                ▼
┌──────────┐                   ┌──────────────┐
│ Backend  │ ◀── proxy_pass ── │  204 / 403   │
└──────────┘                   └──────────────┘
```

| Component | Path | Purpose |
|-----------|------|---------|
| nginx C module | `modules/ngx_waffynx/` | ACCESS phase handler, Unix socket client |
| Go sidecar | `internal/engine/sidecar.go` | 3-stage evaluation pipeline |
| Plugins | `plugins/{name}/plugin.go` | 4 built-in WAF plugins |
| Policy engine | `internal/policy/` | Rule-based allow/deny/block |
| ML scorer | `internal/appsec/` | BasicScorer (Go) + BridgeScorer (open-appsec) |
| appsec-bridge | `cmd/appsec-bridge/` | Standalone ML daemon (swappable with C++ engine) |
| waf-api | `cmd/waf-api/` | Management REST API + embedded dashboard |
| waf-agent | `cmd/waf-agent/` | nftables/UFW firewall manager |
| waffynx | `cmd/waffynx/` | Main CLI (start, check, version) |

## Quick Start (WSL)

```bash
# Prerequisites: Debian/Ubuntu with build tools
sudo apt-get install -y build-essential libpcre2-dev libssl-dev zlib1g-dev

# Install Go 1.22+
wget https://go.dev/dl/go1.22.4.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.22.4.linux-amd64.tar.gz
export PATH=/usr/local/go/bin:$PATH

# Clone with submodules
git clone --recurse-submodules https://github.com/jackby03/waffynx.git
cd waffynx

# Strip CRLF (Windows → Linux)
find . -type f -not -path "*/.git/*" -exec sed -i 's/\r$//' {} \; 2>/dev/null || true

# Build nginx with waffynx module
cd third_party/nginx
bash auto/configure \
    --prefix=/opt/waffynx/nginx \
    --with-http_ssl_module --with-http_v2_module \
    --with-http_realip_module --with-http_stub_status_module \
    --without-http_charset_module --without-http_gzip_module \
    --without-http_ssi_module --without-http_userid_module \
    --without-http_access_module --without-http_auth_basic_module \
    --without-http_mirror_module --without-http_autoindex_module \
    --without-http_geo_module --without-http_map_module \
    --without-http_split_clients_module --without-http_referer_module \
    --without-http_fastcgi_module --without-http_uwsgi_module \
    --without-http_scgi_module --without-http_memcached_module \
    --without-http_grpc_module --without-http_limit_conn_module \
    --without-http_limit_req_module --without-http_empty_gif_module \
    --without-http_browser_module --without-http_upstream_hash_module \
    --without-http_upstream_ip_hash_module --without-http_upstream_least_conn_module \
    --without-http_upstream_random_module --without-http_upstream_zone_module \
    --without-http_upstream_keepalive_module \
    --without-mail_pop3_module --without-mail_imap_module --without-mail_smtp_module \
    --add-module=../../modules/ngx_waffynx
make -j$(nproc)

# Build Go binaries
cd ../..
CGO_ENABLED=0 go build -ldflags="-s -w" -o bin/waffynx ./cmd/waffynx
CGO_ENABLED=0 go build -ldflags="-s -w" -o bin/appsec-bridge ./cmd/appsec-bridge
CGO_ENABLED=0 go build -ldflags="-s -w" -o bin/waf-api ./cmd/waf-api
CGO_ENABLED=0 go build -ldflags="-s -w" -o bin/waf-agent ./cmd/waf-agent
```

### Run the WAF

```bash
# Install to /opt/waffynx
sudo mkdir -p /opt/waffynx/{bin,config,logs,nginx/{sbin,conf,logs},certs}
sudo cp third_party/nginx/objs/nginx /opt/waffynx/nginx/sbin/
sudo cp bin/* /opt/waffynx/bin/

# Create config (see configs/waffynx.yaml for full example)
# Create nginx.conf (see configs/nginx.conf)

# Generate self-signed cert for HTTPS
openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout /opt/waffynx/certs/server.key \
    -out /opt/waffynx/certs/server.crt \
    -days 365 -subj "/CN=localhost"

# Start appsec-bridge (ML daemon)
sudo /opt/waffynx/bin/appsec-bridge -s /opt/waffynx/open-appsec.sock &

# Start waffynx (sidecar + nginx)
sudo /opt/waffynx/bin/waffynx start --config /opt/waffynx/config/waffynx.yaml &

# Start management API (optional)
sudo /opt/waffynx/bin/waf-api --config /opt/waffynx/config/waffynx.yaml &

# Start test backend
python3 -m http.server 3000 --bind 127.0.0.1 &

# Test
curl http://localhost:8080/                              # 200 (allowed)
curl "http://localhost:8080/?q=UNION+SELECT+1,2,3"       # 403 (blocked)
curl -k https://localhost:8443/                          # 200 (HTTPS)
```

## Testing

### Unit tests
```bash
go test ./...
# 33 tests: BasicScorer (13), policy engine (8), plugin chain (12)
```

### Integration tests (WSL)
```bash
# Test via sidecar Unix socket
curl --unix-socket /opt/waffynx/waffynx.sock \
    -H "X-WN-M: GET" -H "X-WN-U: /api/health" \
    -H "X-WN-H: example.com" -H "X-WN-IP: 1.2.3.4" \
    -H "X-WN-UA: Mozilla/5.0" \
    http://localhost/evaluate
# Expected: HTTP 204

# Test SQLi block
curl --unix-socket /opt/waffynx/waffynx.sock \
    -H "X-WN-M: GET" -H "X-WN-U: /users?q=UNION+SELECT+1,2,3" \
    -H "X-WN-H: example.com" -H "X-WN-IP: 1.2.3.4" \
    http://localhost/evaluate
# Expected: HTTP 403
```

### Integration tests (Vagrant)
```bash
make vagrant-full-test   # destroy old VM, create, provision, test
make vagrant-up          # start VM
make vagrant-ssh         # shell into VM
```

## API Reference

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET` | `/health` | No | Health check |
| `POST` | `/api/v1/auth/login` | No | Login, returns JWT |
| `GET` | `/api/v1/status` | JWT | Engine status, version, memory |
| `GET` | `/api/v1/config` | JWT | Current config (secrets redacted) |
| `PUT` | `/api/v1/config` | JWT | Hot-reload config |
| `GET` | `/api/v1/metrics` | JWT | Runtime metrics snapshot |
| `GET` | `/api/v1/plugins` | JWT | List registered plugins |
| `GET` | `/api/v1/plugins/{name}` | JWT | Plugin details |
| `GET` | `/` | No | Dashboard UI |

## Configuration

See `configs/waffynx.yaml` for the full production configuration. Key sections:

- **sidecar** — socket path, timeout, fail_open
- **nginx** — binary path, worker config
- **appsec** — engine (basic-go or open-appsec), bridge socket
- **plugins** — 4 built-in plugins with individual configs
- **api** — management API listen address, JWT auth

## Forks

- **nginx** (`jackby03/ngx_waffynx`) — stripped to HTTP proxy + SSL + V2 + waffynx module (868KB)
- **open-appsec** (`jackby03/appsec_waffynx`) — stripped to core ML engine (components/ + core/)

## Development

```bash
make build         # build all Go binaries (CGO_ENABLED=0)
make nginx-build   # build stripped nginx
make test          # run unit tests
make lint          # golangci-lint
```

Read `AGENTS.md` for architecture details, gotchas, and development workflow.

## License

MIT
