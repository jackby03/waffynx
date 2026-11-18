# Security policy

## Reporting a vulnerability

Report privately through GitHub Security Advisories
(`Security` → `Report a vulnerability`) on this repository. Do not open a public
issue for a suspected vulnerability.

Please include: affected version or commit, a minimal reproduction, and the impact
you believe it has. We will acknowledge the report, reproduce it, and coordinate
disclosure with you before publishing.

## Scope

Waffynx is a Web Application Firewall, so the following are all in scope:

- The Go data plane (`internal/engine`, `internal/policy`, `internal/rules`,
  `plugins/`, `internal/parsers`) and the control plane (`internal/api`,
  `cmd/waf-api`).
- **Bypasses**: any input that reaches an upstream without being inspected while
  inspection is enabled. A WAF that can be walked around is a vulnerability, not a
  bug.
- The native nginx module `modules/ngx_waffynx` and the Unix-socket protocol it uses
  to reach the engine.
- The Docker image: privilege level, file modes, exposed ports, and the socket
  permissions defined in Constitution §2.2.

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

## Secrets

No secret is ever committed. The JWT signing key is generated at first boot and
persisted `0600` under `$WAFFYNX_DATA_DIR`; losing that volume invalidates issued
tokens. The engine refuses to start if the configured secret is a known placeholder.
