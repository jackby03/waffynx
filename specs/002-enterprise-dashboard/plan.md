# Technical Plan: Enterprise Security Center Dashboard

**Spec Reference:** [`spec.md`](./spec.md)
**Status:** Approved

## 1. Architecture Strategy

La arquitectura de frontend se dividirá en módulos desacoplados bajo `cmd/waf-api/ui/src/`:
- `components/Sidebar.tsx`: Navegación principal, selector de vistas, status pill.
- `components/Topbar.tsx`: Indicadores de modo (Blocking / Transparent), salud del engine, botón Sign Out.
- `components/ThreatRadar.tsx`: Gráfica temporal SVG (Spline Throughput/Blocks) y radar de amenazas OWASP.
- `components/AttackForensics.tsx`: Tabla en vivo y Drawer lateral (`ForensicDrawer.tsx`) con payload viewer y quick action de baneo.
- `components/SecurityPolicies.tsx`: Políticas de seguridad, switch de enforcement mode, firmas OWASP.
- `components/HostFirewall.tsx`: Tabla de IPs bloqueadas en kernel `nftables` y formulario de baneo con TTL.
- `components/MarketplaceView.tsx`: Control visual de módulos (`rate-limit`, `geo-block`, `bot-protection`, `request-validation`).

En el backend (`cmd/waf-api/main.go`):
- Exponer `GET /api/v1/firewall/rules`, `POST /api/v1/firewall/block`, `DELETE /api/v1/firewall/unblock/{ip}` integrados con el gestor de firewall.
- Validar `requireRole("admin")` en operaciones mutantes.

---

## 2. Implementation Phases

1. **Phase 1: Backend Firewall API Endpoints**
   - Integrar endpoints de firewall en `cmd/waf-api/main.go`.
   - Pruebas unitarias en `cmd/waf-api/main_test.go`.

2. **Phase 2: Frontend Data Services & Styles**
   - Actualizar `api.ts` con tipos y métodos extendidos.
   - Expandir `styles.css` con el sistema de diseño Cyber-Ops (paleta oscura, variables CSS, layout con Sidebar y Drawer).

3. **Phase 3: Componentes de Visualización y Forense**
   - Implementar `Sidebar`, `ThreatRadar`, `AttackForensics` (con Drawer) y `SecurityPolicies`.
   - Implementar `HostFirewall` y `MarketplaceView`.

4. **Phase 4: Integración y Ensamblaje en `main.tsx`**
   - Ensamblar las vistas con estado compartido (eventos en vivo, métricas, estado de conexión).
   - Validar `npm run lint` y `npm run build`.

5. **Phase 5: Validación End-to-End en VM Vagrant**
   - Desplegar en la VM Vagrant y validar navegación e interactividad.
