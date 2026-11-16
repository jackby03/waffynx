# Clarifications & Open Decisions: Site Management & Zero-File Bootstrap

**Related Spec:** [`spec.md`](./spec.md)

---

## Resolved during specification

**Q: ¿No basta con exponer un CRUD sobre `cfg.Routes`?**
No. Se verificó en el código: `cfg.Routes` solo lo consume `internal/gateway` (el
proxy directo que ADR-0003 dejó fuera de alcance) y el handler de config para
mostrarlo. **No genera configuración de nginx ni afecta al reverse proxy.** La
topología real está hardcodeada en `deploy/docker/nginx.conf`
(`proxy_pass http://backend:80`, `server_name localhost`). Un CRUD sobre `routes:`
devolvería `201 Created` sin proteger nada — el mismo defecto fail-open que el
handler de bloqueo de IP.

**Q: ¿Por qué un paquete nuevo `internal/sites` y no ampliar `internal/config`?**
`config` es un parser puro sin I/O más allá de leer el fichero, y no sabe nada de
nginx. Renderizar sintaxis nginx y ejecutar `nginx -t` es otra responsabilidad;
meterlo ahí haría el parser imposible de testear sin filesystem. La dependencia va
`internal/sites → internal/config`, nunca al revés.

**Q: ¿Qué pasa con `routes:`?**
Se queda como está, sirviendo al gateway congelado. `sites:` es la clave nueva del
reverse proxy. Se documenta la distinción para que nadie las confunda.

---

## Resolved decisions

All five were settled on 2026-11-16. The chosen option is in bold.

### 1. JWT secret generation — **generate and persist**

If `WAFFYNX_JWT_SECRET` is unset, generate 32 random bytes and persist them to
`$DATA/jwt.secret` with `0600`, reusing them across restarts.

Requiring the variable instead would keep the current behaviour, which is exactly
what blocks `docker run` without mounted files. The risk of losing the volume and
silently rotating the secret is mitigated by logging at `WARN` that it was
generated and where it lives.

### 2. Renderer scope — **fragments only**

The renderer writes `conf/sites/*.conf`; `nginx.conf` stays a template that
`include`s them. Regenerating the whole file would let a `site add` silently eat
any directive an operator added by hand.

### 3. TLS scope — **certificate paths only, no ACME**

This spec accepts `cert_file` / `key_file`. Automatic issuance needs port 80,
renewal scheduling and persisted ACME state; that is its own spec. `--tls-auto`
does not exist yet and the README does not promise it.

### 4. CLI transport — **API is the single write path**

When the CLI lands it talks to the management API. Bootstrap is covered by
environment variables, so there is no need for an offline file-writing mode.

### 5. Shorthand syntax (`waffynx -rp -h … -d … -https`) — **deferred**

Named subcommands first. The shorthand can be added later as sugar over
`site add` without touching anything else. **The entire CLI surface for sites is
deferred out of this spec**: the API is enough to drive it with `curl`, and the
syntax should be designed once the behaviour is settled.

---

## Notas de riesgo

- **El mayor riesgo técnico es el rollback.** Un `nginx -t` que pasa pero un
  reload que falla deja el proceso sirviendo la configuración vieja: hay que
  detectar ese caso y no dar `201`. Está cubierto en `tasks.md` 2.1.
- **Inyección de directivas por `host`.** Un `host` con `;` o `{` inyecta nginx.
  Por eso se valida y se rechaza, no se escapa. Es el punto más delicado del
  renderer y tiene test dedicado.
- **Cobertura cruzada.** El pipeline del sidecar se ejercita desde
  `cmd/waffynx verify` pero el informe del CI no lo cuenta (`-coverpkg`). El
  umbral del `tasks.md` 7.3 debe medirse con `-coverpkg=./internal/sites`.
