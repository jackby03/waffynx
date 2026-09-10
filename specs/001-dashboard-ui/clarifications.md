# Clarifications & Q/A: Dashboard UI

**Related Spec:** [`spec.md`](./spec.md)  
**Related Plan:** [`plan.md`](./plan.md)  

---

## Log of Clarifications

### Q-001: UI Framework and Styling Preference
- **Raised by:** Agent
- **Date:** 2026-09-09
- **Question:**  
  *Which frontend framework and styling solution is preferred for the `ui/` directory?*
- **Proposed Options:**  
  1. React + Vite + Tailwind CSS (Modern sleek dark mode WAF console).  
  2. Vue 3 + Vite.  
- **Resolution / Decision:**  
  **Option 1 (React 18 + TypeScript + Vite + Tailwind CSS)**. Enables a dark-theme, high-density SOC console UI without heavy runtime component libraries.
- **Status:** Resolved

### Q-002: Token Storage Strategy
- **Raised by:** Architect / Constitution Review
- **Date:** 2026-09-09
- **Question:**  
  *Where should the session JWT be persisted to prevent persistent XSS exposure?*
- **Resolution / Decision:**  
  `sessionStorage`. Cleared automatically on browser/tab close. `localStorage` is prohibited to mitigate long-term session hijacking on operational security consoles.
- **Status:** Resolved