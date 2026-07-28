# AGENTS.md — Waffynx

## Dev environment

**Linux is the only supported runtime.** `engine_windows.go` is a stub that errors. On Windows, use WSL (Windows Subsystem for Linux) or Vagrant:

### WSL (Windows Subsystem for Linux)
Since WSL provides a native Linux environment, you can run normal Linux build and test commands directly within your WSL shell (e.g., Ubuntu):
```bash
# Build Go binaries
make build

# Run Go tests
go test ./...
```

### Vagrant
Alternatively, you can run a full VirtualBox VM via Vagrant:
```bash
# Full test cycle: destroy old VM, create fresh, provision, run tests
make vagrant-full-test

# Or step-by-step
make vagrant-up          # starts Ubuntu 22.04 VM (ports 80->8080, 9090->9090)
make vagrant-test        # runs test.sh inside VM
make vagrant-ssh         # shell into VM
```

The VM mounts the project root at `/waffynx` via vboxsf. Services run on `localhost:8080` (nginx/WAF), `localhost:9090` (API).

## Submodules

Must be initialized before anything else:

```bash
git submodule update --init --recursive
```

Two forks: `jackby03/ngx_waffynx` (`third_party/nginx`) and `jackby03/appsec_waffynx` (`third_party/open-appsec`). The nginx module links both in at build time via `--add-module`.

## Build

### Go binaries (cross-compiled for Linux from any OS)
```bash
make build          # build-cli + build-agent + build-api (CGO_ENABLED=0)
```
Outputs to `bin/`: `waffynx`, `waf-agent`, `waf-api`. The `appsec-bridge` binary is built by Vagrant provisioning only — no Makefile target for it.

### Nginx (Linux only, or inside Vagrant VM)
```bash
make nginx-checkout   # init submodule (already handled by git submodule update)
make nginx-configure  # runs auto/configure with --add-module for both submodules
make nginx-build      # make -j inside third_party/nginx
```

**Vagrant builds nginx automatically** — see `vagrant/provision.sh`. It copies source to `/tmp/nginx-build` because nginx's `auto/configure` fails on vboxsf shared folders.

## Architecture

```
HTTP request -> nginx (ACCESS phase, C module) --unix socket--> Go sidecar
  -> plugin chain (4 plugins, priority-ordered)
  -> policy engine (rule-based allow/deny/block)
  -> appsec scorer (BasicScorer or BridgeScorer)
  -> 204 (allow) or 403 (block) back to nginx
```

- **C module**: `modules/ngx_waffynx/ngx_http_waffynx_module.c` — intercepts req, forwards metadata via custom `X-WN-*` headers over Unix socket
- **Go sidecar**: `internal/engine/sidecar.go` — Unix socket HTTP server running 3-stage evaluation pipeline
- **appsec-bridge**: `cmd/appsec-bridge/main.go` — optional standalone daemon, same socket protocol as real open-appsec. The sidecar connects via `BridgeScorer` if `engine: "open-appsec"` is configured.
- **Plugins**: 4 built-ins in `plugins/` register via `init()` and are loaded by blank imports in `cmd/waffynx/main.go`
- **waf-agent**: `cmd/waf-agent/main.go` — manages nftables/UFW rules
- **waf-api**: `cmd/waf-api/main.go` — management API on :9090 (currently a stub, closes connections immediately)

## Key gotchas

### CRLF from Windows breaks nginx build
When developing on Windows with autocrlf, files synced into the Vagrant VM via vboxsf will have CRLF. nginx's `auto/configure` and C compilation fail on these. The provision script handles this:

```bash
find . -type f -exec sed -i 's/\r$//' {} \;
```

If you add new C files to `modules/ngx_waffynx/` or `third_party/`, ensure they end up with LF in the VM build context. Don't strip CRLF in-place in `third_party/nginx` (that dir is a submodule — strip in the /tmp copy instead).

### nginx configure can't run from vboxsf
The `auto/configure` script performs filesystem checks that fail on VirtualBox shared folders. Always copy source to a local path (e.g., `/tmp/nginx-build`) before configuring — see `vagrant/provision.sh`.

### No Go tests exist
`make test` runs `go test -race ./...` but there are zero `*_test.go` files. The only automated tests are integration tests in `vagrant/test.sh`. When adding Go code, you should add test files — there's no existing test infrastructure to follow.

### Build flag requirements
Go binaries: `CGO_ENABLED=0 GOOS=linux GOARCH=amd64` for the VM. Nginx module: compiled with the full nginx source tree, `--add-module` for both `third_party/open-appsec/modules/nginx` and `modules/ngx_waffynx`.

### Plugin registration
New plugins go in `plugins/<name>/plugin.go` implementing `plugin.Plugin`. They must be registered via `init()` calling `plugin.Register()`. Import them in `cmd/waffynx/main.go` with a blank import (`_ "github.com/jackby03/waffynx/plugins/<name>"`).

### Config loading
Production config: `configs/waffynx.yaml` (120 lines, full config with all sections). Vagrant generates its own config at `/opt/waffynx/config/waffynx.yaml` during provisioning. The nginx.conf lives at `configs/nginx.conf` with `waffynx on;` directives — the Vagrant VM copies this into the built nginx conf dir.

### Dead & stub code
- `plugins/rate-limit/plugin.go` — rate limiting logic is behind `if false`
- `plugins/geo-block/plugin.go` — entirely a stub (no enforcement)
- `cmd/waf-api/main.go` — closes connections without handling
- `internal/firewall/firewall.go` — `ListRules()` returns nil

### Vagrant test script issue
`vagrant/test.sh` hangs after health checks — the backend Python server management is broken. Sidecar-direct socket tests and bridge connectivity tests work fine.

## Directory map

| Path | Purpose |
|------|---------|
| `cmd/waffynx/` | Main WAF engine CLI (cobra: start, check, version) |
| `cmd/waf-agent/` | Host firewall agent (nftables/UFW) |
| `cmd/waf-api/` | Management REST API (stub) |
| `cmd/appsec-bridge/` | ML daemon (BasicScorer, swap-out for real open-appsec) |
| `internal/engine/` | Runtime orchestrator, sidecar, policy store |
| `internal/plugin/` | Plugin interface, registry, chain |
| `internal/policy/` | Rule-based policy evaluator |
| `internal/appsec/` | ML scoring (BasicScorer, BridgeScorer, Features) |
| `internal/config/` | YAML config loading with defaults |
| `internal/logging/` | zerolog wrapper |
| `internal/gateway/` | TCP HTTP reverse proxy (router + middleware) |
| `internal/firewall/` | nftables/UFW manager |
| `internal/auth/` | JWT auth manager |
| `internal/metrics/` | Prometheus metrics |
| `internal/marketplace/` | Plugin marketplace (in-memory store) |
| `internal/tls/` | TLS cert manager |
| `internal/upstream/` | Load balancer (round-robin, least-conn) |
| `internal/version/` | Build info (ldflags) |
| `modules/ngx_waffynx/` | nginx C module + addon config |
| `plugins/` | 4 built-in WAF plugins |
| `configs/` | Production config (waffynx.yaml, nginx.conf) |
| `vagrant/` | VM provisioning + integration tests |
| `deploy/systemd/` | Systemd unit files |
| `deploy/docker/` | Dockerfile (waf-api only) + compose |
| `third_party/nginx/` | Forked nginx (submodule) |
| `third_party/open-appsec/` | Forked open-appsec (submodule) |
| `pkg/proto/` | Proto definitions (not yet generated) |
| `bin/` | Prebuilt Linux Go binaries (may be stale) |
| `test/` | JSON test payloads (eval_normal.json, eval_sqli.json) |
| `scripts/` | (empty) |
| `ui/` | Frontend (React, not yet built) |
