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

## Open decisions — need your call before implementation

### 1. Generación del secreto JWT (bloqueante)

Si `WAFFYNX_JWT_SECRET` no está definido, hay dos caminos:

- **(a) Generar y persistir** en `$DATA/jwt.secret` con `0600`, reutilizándolo en
  reinicios. Es lo que hacen NPM y compañía: `docker run` funciona de verdad.
- **(b) Exigirlo y abortar** si falta. Máximo rigor (§1.1 fail-closed), pero
  rompe el objetivo «un comando» y obliga a un `-e` extra.

**Propuesta: (a)**, porque (b) ya es el comportamiento actual del código y es
justo lo que impide el `docker run` sin ficheros. El riesgo de (a) —que alguien
pierda el volumen y rote el secreto sin saberlo— se mitiga logueando en `WARN`
que se generó y dónde.

### 2. ¿El renderer reescribe `nginx.conf` o solo `sites/*.conf`?

- **(a) Solo fragmentos** en `conf/sites/*.conf`, con `nginx.conf` como plantilla
  estática que los incluye. Cambios pequeños, menos riesgo de romper el bloque
  `http {}`.
- **(b) Regenerar `nginx.conf` completo** desde cero en cada apply. Control total,
  pero cualquier directiva que añadas a mano se pierde silenciosamente.

**Propuesta: (a).** Menos superficie de rotura y el operador conserva la
posibilidad de ajustar `nginx.conf` a mano sin que el siguiente `site add` se lo
coma.

### 3. Alcance de TLS en esta iteración

Este spec acepta **rutas a certificados existentes**. La emisión automática
(ACME/Let's Encrypt) queda fuera y necesita su propio spec, porque implica
exponer el puerto 80, gestionar renovaciones y persistir estado de ACME.

**Propuesta:** confirmarlo así. Sin esto, `--tls-auto` no existe todavía y el
README debe decirlo (hoy ya no lo promete).

### 4. ¿`waffynx site` habla con el API o escribe el fichero?

- **(a) API** (propuesto): un único camino de escritura, funciona contra un
  contenedor remoto, valida en caliente. Requiere token.
- **(b) Fichero** directo: sin auth, útil para IaC, pero no vale contra un
  contenedor remoto ni para el caso de uso principal.

**Propuesta: (a).** Para bootstrap existe el camino de variables de entorno, así
que no hace falta un modo offline.

### 5. Sintaxis taquigráfica (`waffynx -rp -h sitio.com -d 127.0.10.4 -https`)

La que imaginabas. **Propuesta: no implementarla en este spec.** Los subcomandos
con nombre son autodocumentados y componibles; la forma corta se puede añadir
después como azúcar sobre `site add` sin tocar nada más. Si la prefieres como
interfaz principal, dímelo y la pongo como alias desde el principio.

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
