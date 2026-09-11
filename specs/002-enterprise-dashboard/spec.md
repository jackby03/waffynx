# Feature Specification: Enterprise Security Center Dashboard

**Feature ID:** `002-enterprise-dashboard`
**Status:** Approved
**Created:** 2026-09-10
**Author:** Waffynx Architecture Team

## 1. Executive Summary

Evolucionar la interfaz gráfica de Waffynx hacia un **Centro de Operaciones de Seguridad (SOC)** de nivel empresarial inspirado en consolas comerciales líderes como F5 BIG-IP ASM / Advanced WAF, Cloudflare Enterprise e Imperva. El sistema proveerá visibilidad perimetral profunda, análisis forense de incidentes con resaltado de payload, control de modo de enforcement (Blocking vs Monitoring/Transparent), gestión del firewall del kernel (nftables) y configuración visual de plugins de seguridad.

---

## 2. In-Scope vs Out-of-Scope

### In-Scope
- **Sidebar de Navegación Profesional:** Barra lateral persistente con selector de vistas:
  1. *Threat Radar & Analytics* (Métricas clave, gráficas SVG de rendimiento y vectores OWASP).
  2. *Attack Forensics* (Tabla avanzada en vivo con filtrado y Drawer de inspección forense con volcado de cabeceras y payload).
  3. *Security Policies* (Selector de modo de enforcement: Blocking vs Transparent, estado de reglas).
  4. *Host Firewall (L3/L4)* (Listado de IPs baneadas en kernel, acción de bloqueo/desbloqueo inmediato con TTL).
  5. *WAF Extensions & Marketplace* (Configuración visual de Rate Limiting, GeoIP, Bot Protection y Request Validation).
- **Backend API Additions:**
  - Endpoints en `waf-api` para listar, bloquear y desbloquear IPs en el firewall del host (`/api/v1/firewall/rules`, `/block`, `/unblock/{ip}`).
- **Estética Cyber-Ops de Alta Fidelidad:**
  - Paleta oscura grafito, indicadores de severidad CVSS/WAF, tipografía moderna, Drawer modal con micro-animaciones CSS y gráficos SVG puros sin dependencias pesadas.

### Out-of-Scope
- Autenticación federada SAML (mantenemos JWT/OIDC actual).
- Recompilación del módulo Nginx C (usamos los canales de socket y API existentes).

---

## 3. Functional Requirements (FR)

- **FR-01 (Multi-View Navigation):** El usuario podrá alternar fluidamente entre las 5 secciones mediante el Sidebar sin perder el estado de la sesión ni la conexión SSE en vivo.
- **FR-02 (Threat Radar Visualizations):** La vista principal mostrará gráficas de volumen de tráfico (Throughput vs Blocked requests) y un desglose porcentual de categorías de ataque detectadas.
- **FR-03 (Incident Deep Forensics):** Al hacer clic en cualquier ataque del feed en vivo, se abrirá un panel lateral (Drawer) que expondrá:
  - Resumen del ataque (IP de origen, timestamp, método HTTP, URI, User-Agent).
  - Regla o plugin que activó el bloqueo.
  - Subcadena maliciosa detectada o desglose de razones del motor ML.
  - Botón de acción rápida: *"Ban IP in Kernel Firewall"*.
- **FR-04 (Enforcement Mode Switching):** La barra superior expondrá el modo actual (**Blocking** vs **Transparent / Monitoring**) con capacidad de cambiar de modo dinámicamente vía API (`PUT /api/v1/config`).
- **FR-05 (Host Firewall Management):** La vista de Firewall permitirá visualizar las reglas activas de `nftables`/`ufw`, agregar una IP o rango CIDR a la lista negra con un TTL en segundos, o retirar el baneo.
- **FR-06 (Plugin Configuration Hub):** La vista de Marketplace permitirá encender/apagar plugins y ajustar parámetros clave (umbrales de Rate Limiting, países de GeoIP, límites de tamaño de cuerpo).

---

## 4. Non-Functional Requirements & Security Invariants

- **NFR-01 (Strict Zero Unauthorized Dependencies):** La UI se construirá usando React 19 y Vanilla CSS con gráficos SVG nativos; no se añadirán librerías de gráficos pesadas para mantener la superficie de ataque mínima.
- **NFR-02 (Fail-Closed Security):** Los errores de carga en vistas auxiliares no afectarán la conexión de eventos en vivo ni el estado de protección del WAF.
- **NFR-03 (Input Sanitization & Safe DOM):** Todos los campos de ataques (URIs, cabeceras, payloads) se renderizarán estrictamente como texto seguro en el DOM (previene XSS en la consola de administración).
- **NFR-04 (RBAC Enforcement):** Las operaciones de baneo de IP y cambio de modo de enforcement requerirán rol de `admin`.
