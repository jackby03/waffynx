# Clarifications: Enterprise Security Center Dashboard

## Session Decisions

- **Q: Enforcement Mode Toggle**
  - **Decision:** The top navigation bar will feature an active mode toggle: "Blocking" (WAF rejects attacks with 403) vs "Monitoring / Transparent" (WAF evaluates and alerts without blocking). This reflects enterprise WAF architecture (e.g. F5 ASM Policy Enforcement Mode).
  - **Rationale:** Allows security operators to safely deploy new policies in staging or production before enforcing strict blocking.

- **Q: Kernel Firewall Integration**
  - **Decision:** Include a 1-click action "Ban IP in Kernel (L3/L4)" directly inside the Forensic Attack Drawer.
  - **Rationale:** Provides immediate containment against aggressive scanning or brute-force bots without waiting for manual CLI access.

- **Q: Zero Third-Party UI Chart Dependencies**
  - **Decision:** Use handcrafted, responsive SVG spline curves and SVG donut charts.
  - **Rationale:** Strictly adheres to Rule 2 in `constitution.md` (Zero Unauthorized Dependencies) and keeps the production bundle under 150KB.
