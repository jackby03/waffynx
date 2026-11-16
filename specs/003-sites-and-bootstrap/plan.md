# Technical Architecture Plan: Site Management & Zero-File Bootstrap

**Status:** Draft — awaiting review
**Related Spec:** [`spec.md`](./spec.md)
**Author(s):** Waffynx Core Team
**Last Updated:** 2026-11-16

---

## 1. Architectural Overview & Boundaries

### 1.1 High-Level Design

The key insight that shapes this plan: **the data plane already works, but its
topology is a static file**. So the work is a control-plane renderer plus a safe
apply step — not a new proxy path.

```
                ┌──────────────────────────────┐
 CLI / curl ───▶│  POST /api/v1/sites          │  (internal/api)
                └──────────────┬───────────────┘
                               │ 1. validate (config.Parse)
                               ▼
                ┌──────────────────────────────┐
                │  SiteStore  (in-memory +     │  new: internal/sites
                │  source of truth)            │
                └──────────────┬───────────────┘
                               │ 2. render
                               ▼
                ┌──────────────────────────────┐
                │  nginx renderer (text)       │  new: internal/sites/render.go
                └──────────────┬───────────────┘
                               │ 3. atomic write + nginx -t
                               ▼
                ┌──────────────────────────────┐
                │  /opt/waffynx/nginx/conf/    │
                │  sites/*.conf + nginx.conf   │
                └──────────────┬───────────────┘
                               │ 4. reload
                               ▼
                     engine.Reload()  ──▶ nginx -s reload (existing)
                               │
                               ▼
              [ nginx + ngx_waffynx ] ──▶ Go sidecar ──▶ upstream
```

Steps 1–3 must be transactional: if any step fails, nothing is applied and the
previous configuration stays live.

### 1.2 Affected Packages & Components

- `internal/sites` **(new)** — site model, validation, renderer, atomic apply.
- `internal/config` — new `sites:` key; environment overlay; `Parse` gains site
  validation. `routes:` is left untouched for the frozen gateway.
- `internal/api` — `/api/v1/sites` handlers, RBAC, audit records.
- `internal/engine` — expose a way to apply a rendered config and reload, and to
  report the last apply error.
- `cmd/waffynx` — `site` subcommands and the `verify --target` mode.
- `deploy/docker` — `entrypoint.sh` applies env bootstrap before starting nginx;
  `nginx.conf` becomes a template that `include sites/*.conf`.
- `configs/waffynx.yaml` — new `sites:` example.

### 1.3 Why a new package instead of extending `internal/config`

`internal/config` is a pure parser with no I/O beyond reading a file and no
knowledge of nginx. Rendering nginx syntax and shelling out to `nginx -t` is a
different responsibility, and mixing it in would make the parser untestable
without a filesystem. `internal/sites` depends on `internal/config`, not the
reverse.

---

## 2. Data Contracts

```go
// Site is one protected host in the reverse proxy.
type Site struct {
    Host     string    `yaml:"host"`               // "example.com", "*.example.com" (wildcard allowed)
    Upstream string    `yaml:"upstream"`           // "10.0.0.5:8080" or "http://backend:80"
    TLS      *TLSPair  `yaml:"tls,omitempty"`      // nil = plain HTTP only
    Paths    []PathRule `yaml:"paths,omitempty"`   // optional; default "/" → upstream
    Plugins  []string  `yaml:"plugins,omitempty"`  // empty = all enabled plugins
    Headers  map[string]string `yaml:"headers,omitempty"`
}

type TLSPair struct{ CertFile, KeyFile string }

type PathRule struct {
    Path     string `yaml:"path"`      // prefix, must start with "/"
    Upstream string `yaml:"upstream"`  // optional override
}
```

Rendered per site, into `/opt/waffynx/nginx/conf/sites/<hash>.conf`:

```nginx
server {
    listen 8443 ssl;
    server_name example.com;
    ssl_certificate     /opt/waffynx/certs/example.com.crt;
    ssl_certificate_key /opt/waffynx/certs/example.com.key;
    location / {
        waffynx on;
        waffynx_socket /opt/waffynx/waffynx.sock;
        waffynx_timeout 1000;
        waffynx_fail_open off;
        waffynx_max_body_size 64k;
        proxy_pass http://10.0.0.5:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

`nginx.conf` keeps the `http {}` block and gains `include /opt/waffynx/nginx/conf/sites/*.conf;`.
The `/health` location is preserved on the plain listener.

---

## 3. Validation Rules (untrusted input, Constitution §1.4)

These run before anything is rendered. A `host` containing `;` `{` `}` or a
newline would inject nginx directives, so it is rejected, not escaped.

| Field | Rule |
|---|---|
| `host` | lowercase, `[a-z0-9.-]` plus an optional leading `*.`, length 1–253, no `..`, must not be an IP literal for TLS sites |
| `upstream` | `host:port` with port 1–65535, or `http(s)://host[:port]`; no userinfo, no path, no query |
| `tls` | both files required together; files must exist and be readable |
| `paths[].path` | must start with `/`, no whitespace, no `..` |
| duplicates | same `(host, path)` → `409` |

---

## 4. Apply Protocol (transactional)

1. `config.Parse` validates the whole configuration with the candidate site.
2. Render to a temporary directory.
3. `nginx -t -c <tmpdir>/nginx.conf` — abort on non-zero, return nginx stderr.
4. Move rendered files into place (rename), keep a `.bak` of the previous set.
5. `engine.Reload()` → `nginx -s reload`.
6. Persist the `sites:` list into the YAML config with temp-file + rename, `0600`.
7. On any error in 2–6: restore the previous files and return `500` with the
   reason. The proxy is never left with an unvalidated configuration.

Concurrency: a single `applyMu` mutex serialises applies; concurrent site writes
queue instead of interleaving renders.

---

## 5. Environment Bootstrap

Read once at startup, before nginx:

| Variable | Effect |
|---|---|
| `WAFFYNX_JWT_SECRET` | API signing key. If unset, generate 32 random bytes, persist `$DATA/jwt.secret` `0600`, log that it was generated. |
| `WAFFYNX_SITE_HOST` | first site host; requires the next two |
| `WAFFYNX_SITE_UPSTREAM` | first site upstream |
| `WAFFYNX_SITE_TLS_CERT` / `_KEY` | optional TLS for the first site |
| `WAFFYNX_LISTEN` | public listener, default `:8443` |

Env values are an **overlay applied before validation**, not a second config
format: the same `config.Parse` validator runs on the merged result, so there is
one set of rules. If `sites:` already has entries the env site is ignored unless
`WAFFYNX_SITE_HOST` names an existing host, in which case the upstream is updated.

---

## 6. CLI Surface

```
waffynx site add <host> --upstream <host:port> [--tls-cert F --tls-key F]
                        [--plugins a,b] [--path /prefix --path-upstream h:p]
waffynx site list
waffynx site show <host>
waffynx site remove <host>
```

Transport: HTTP against the API (`--server`, default `http://127.0.0.1:9090`;
token from `WAFFYNX_API_TOKEN` or `--token`). A single write path means the CLI
cannot drift from the API.

The shorthand you pictured — `waffynx -rp -h sitio.com -d 127.0.10.4 -https` — is
deliberately **not** in this spec. Named subcommands are self-documenting and
compose; a shorthand flag form can be added later as sugar over `site add`.

`verify --target <url>` sends benign and malicious requests to a running instance
and asserts 2xx / 403 respectively.

---

## 7. Risks & Mitigations

| Risk | Mitigation |
|---|---|
| A bad render takes the proxy down | `nginx -t` + rollback before reload (§4) |
| nginx directive injection via `host` | strict charset validation, reject not escape (§3) |
| Reload storm from rapid CLI calls | single `applyMu`, coalesce within 250 ms |
| Secret lost on restart | persist generated secret `0600`, reuse |
| Drift between `sites:` and rendered files | rendered files are derived; a `waffynx site sync` re-renders from config |
| Orphaned `routes:` confusion | documented: `routes:` belongs to the frozen gateway, `sites:` to the reverse proxy |

---

## 8. Verification Strategy

- Unit: renderer golden files (site → expected nginx block), validator table
  tests including injection attempts (`host` = `a;\nreturn 200;`).
- Integration: apply a site against a temp dir with a fake `nginx -t`, assert
  rollback on failure.
- End-to-end (CI, Linux): start the container with env bootstrap, `curl` benign
  and SQLi, expect 200/403.
- `waffynx verify --target` becomes the manual smoke test for a deployment.
