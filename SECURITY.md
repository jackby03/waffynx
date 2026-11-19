# Security policy

## Reporting a vulnerability

Report privately through GitHub Security Advisories
(`Security` → `Report a vulnerability`) on this repository. Do not open a public
issue for a suspected vulnerability.

Please include: affected version or commit, a minimal reproduction, and the impact
you believe it has. We will acknowledge the report, reproduce it, and coordinate
disclosure with you before publishing.

## Scope

Waffynx is a Zero-Trust Web Application Firewall and reverse proxy, so the following are all in scope:

- The Go Data Plane (`cmd/waf-engine`, `internal/envoy`, `internal/authz`, `internal/engine`,
  `internal/catalog`, `internal/policy`, `internal/rules`, `internal/ratelimit`, `plugins/`,
  `internal/parsers`) and the Control Plane (`cmd/waf-api`, `internal/api`, `internal/xds`,
  `internal/storage`, `internal/hotreload`, `internal/pki`).
- The Async Observability Plane (`cmd/log-ingestor`, `internal/telemetry`, `internal/analytics`,
  `internal/ingestor`), specifically **PII/credential redaction** (`internal/telemetry/redact.go`)
  and parameterized ClickHouse queries (`internal/analytics/clickhouse.go`).
- **Bypasses**: any input that reaches an upstream without being inspected or authorized while
  enforcement is enabled, including header spoofing (`x-waffynx-*`), body-limit evasions, and
  network microsegmentation bypasses.
- The Envoy v3 xDS / `ext_authz` / `ext_proc` TLS 1.3 mTLS transport and the native nginx
  module `modules/ngx_waffynx` + Unix-socket protocol (`0600`/`0660`).
- Container images and Kubernetes Helm manifests: non-root privileges, `0600` key/socket
  permissions, default-deny `NetworkPolicies`, and exposed ports defined in Constitution §1.4 & §2.2.

Out of scope: findings that require a compromised host or root inside the
container, and missing hardening headers on the management UI.

## Supported versions

Only the tip of `main` is supported. There are no maintenance branches yet; fixes
land on `main` and are released as a new tag.

## Dependency patching: nginx

nginx is not a dependency in the usual sense — it terminates TLS and serves every
request, so **every nginx CVE is a Waffynx CVE**. Two rules keep that manageable:

1. **`third_party/nginx` is pinned to an upstream release tag.** It is not a fork.
   What gets compiled is chosen by `--without-*` flags in the Dockerfile and the
   `Makefile`, never by deleting sources. A stripped fork had to be re-stripped on
   every release, which is precisely how a security update gets postponed.
2. **Dependabot watches the submodule commit** ([`.github/dependabot.yml`](.github/dependabot.yml)).
   A new release tag opens a PR; the `container-e2e` CI job builds nginx, boots the
   image and asserts that benign traffic is proxied and an attack is still blocked,
   so the update cannot silently disable enforcement.

Upgrading by hand:

```bash
git -C third_party/nginx fetch upstream --tags
git -C third_party/nginx checkout release-X.Y.Z   # the tag, never a branch
git add third_party/nginx
make build && docker build -f deploy/docker/Dockerfile -t waffynx:test .
```

Then check the [nginx security advisories](https://nginx.org/en/security_advisories.html)
against the version you left, and note in the PR which advisories the bump closes.

### Modules that are compiled, and why that matters

The build enables `--with-http_ssl_module`, `--with-http_v2_module`,
`--with-http_realip_module` and `--with-http_stub_status_module`, and disables most
others. This determines which advisories actually apply: a stream or mail proxy
CVE does not affect this image because those modules are not built. When triaging an
advisory, check the flags in [`deploy/docker/Dockerfile`](deploy/docker/Dockerfile)
before assuming the product is affected.

HTTP/3 is **not** built, so `ngx_http_v3_module` advisories do not apply today.
Enabling it later means re-triaging the HTTP/3 advisory history.

## Secrets & Inter-Service Transport

- No secret, password, token, or private key is ever committed to source or baked into images (Constitution §2.2). Local `.env` files are gitignored; Kubernetes deployments inject secrets exclusively via `existingSecret` (`secretKeyRef`).
- The JWT signing key is supplied via `WAFFYNX_JWT_SECRET` (`>= 32` characters) or generated once on first boot and persisted `0600` under `$WAFFYNX_DATA_DIR`. Daemons abort startup if credentials are missing or placeholders (Constitution §1.1).
- Multi-container inter-service RPCs (`envoy ↔ control-api` xDS and `envoy ↔ waf-engine` `ext_authz`/`ext_proc`) enforce strict **TLS 1.3 mTLS** using `0600` private keys provisioned by `waffynx-bootstrap --pki-only` (Compose) or cert-manager / SPIRE (Kubernetes).
- Sensitive request headers (`Authorization`, `Cookie`, `Set-Cookie`, `X-Api-Key`, `X-Auth-Token`), bearer/JWT tokens, PANs, and secret query parameters (including HTTP/2 `:path` and `Referer`) are redacted before leaving the Data Plane or persisting to ClickHouse.
