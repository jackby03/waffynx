# Plan de Acción — Waffynx

## Estado actual

**WAF funcional end-to-end:** nginx → sidecar → 4 plugins → policy engine → ML scorer.
Bloquea SQLi, XSS, path traversal, command injection (URL y POST body). 33 unit tests pasando.

**Forks descompuestos como componentes internos:**
- nginx: solo HTTP proxy + ssl + v2 + nuestro módulo (868KB stripped)
- open-appsec: solo core/ + components/ ML engine

---

## Completado

| Fase | Commits | Resultado |
|------|---------|-----------|
| 1 | `55e7d23`, `c65f0ae`, `e4d95cf` | C module: recv loop, socket inheritance, shutdown, isdigit, buffers |
| | | Provision: fixes varios, test.sh: trap + health check + conteo |
| | | agent.yaml creado + LoadAgent parsea YAML |
| 2 | `b615194`, `2c581c5`, `c9d9e79`, `000bd3a` | waf-api REST (status, config, metrics, plugins, JWT auth) |
| | | rate-limit: token bucket por IP |
| | | geo-block: MaxMind GeoLite2 (allow/block modes) |
| | | firewall.ListRules(): parsea nft/ufw output |
| 3 | `13c7639`, `aa2e364` | Body forwarding nginx→sidecar (ngx_http_read_client_request_body) |
| | | Sidecar: io.ReadAll body → policy.Request → wn_body |
| | | BasicScorer: SQLi/XSS en body + entropy + char dist |
| | | request-validation: body pattern matching |
| | | test.sh: assert_status_unix_post (3 tests body) |
| 4 | `fe7e6a7`, `c6a5d75`, `134753d`, `5d836dd`, `88712fd` | FirewallConfig.BlockList, agent.yaml expandido |
| | | Socket path /opt/waffynx/ para systemd ProtectSystem |
| | | appsec-bridge en Makefile |
| | | open-appsec --add-module removido (no es módulo nginx) |
| | | 33 --without-* flags en nginx configure |
| | | open-appsec: stripped deployment/examples/attachments/contrib |
| 5 | `254ec6e` | 33 unit tests: BasicScorer (13), policy engine (8), plugin chain (12) |
| | | GitHub Actions CI (build + test + coverage) |
| Descomp. | `2974c82`, `62eab23` | nginx fork: -256 archivos (mail, stream, v3, quic, win32, docs) |
| | | open-appsec fork: -620 archivos (nodes, charts, docker, k8s, events) |

---

## Próximos pasos

### 1. Validación end-to-end con nginx stripped
- [ ] Instalar stack en WSL (nginx stripped + sidecar + appsec-bridge)
- [ ] Correr test.sh completo (health, normal traffic, ataques, body)
- [ ] Verificar que `ngx_http_finalize_request` no rompe el ciclo de vida

### 2. HTTPS / TLS
- [ ] Generar certificados de prueba
- [ ] Configurar nginx.conf SSL en :443
- [ ] Verificar WAF en tráfico HTTPS

### 3. Dashboard UI
- [ ] `ui/` — crear React/Vue mínimo con:
  - [ ] Status (conexiones, bloqueos, uptime)
  - [ ] Plugins activos
  - [ ] Últimos requests bloqueados

### 4. Documentación
- [ ] README.md: arquitectura, quick start (WSL/Vagrant), testing

### 5. Dockerizar
- [ ] Dockerfile multi-stage (nginx + sidecar + appsec-bridge)
- [ ] docker-compose (WAF + backend de prueba)

### 6. Compilar open-appsec C++ (largo plazo)
- [ ] Verificar que core/ + components/ stripped compila con CMake
- [ ] Crear bridge CGo para llamar ML engine desde Go
- [ ] Reemplazar BasicScorer con motor real

---

## Commits totales: 20

```
62eab23 chore(submodules): bump nginx + open-appsec (stripped)
2974c82 chore(submodules): bump nginx (stripped, 868KB binary)
88712fd chore(submodules): bump open-appsec (stripped)
5d836dd fix(build): verify nginx WSL build, fix ngx_buf_t, remove invalid flags
134753d perf(nginx): strip to 5 essential modules
c6a5d75 fix(build): remove open-appsec --add-module
fe7e6a7 fix(production): agent blocklist, socket path systemd, appsec-bridge Makefile
254ec6e test: 33 unit tests + GitHub Actions CI
aa2e364 test(body): POST body inspection tests
13c7639 feat(body): forward request body nginx→sidecar, SQLi/XSS in body
000bd3a fix(firewall): ListRules parse nft/ufw output
c9d9e79 feat(geo-block): MaxMind GeoLite2 country lookup
2c581c5 feat(rate-limit): token bucket IP-based
b615194 feat(waf-api): REST API (status, config, metrics, plugins, JWT)
e4d95cf fix(agent): agent.yaml config, LoadAgent parses YAML
c65f0ae fix(vagrant): test.sh robustness, provision cleanup
55e7d23 fix(nginx-module): C module hardening (recv, socket, shutdown, isdigit)
ba358a8 docs: AGENTS.md
3489303 chore: reset nginx submodule, update gitignore
fc96ab7 (initial commits)
```
