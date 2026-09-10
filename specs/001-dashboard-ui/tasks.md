# Atomic Tasks: Dashboard UI

**Related Spec:** [`spec.md`](./spec.md)  
**Related Plan:** [`plan.md`](./plan.md)  
**Status:** Pending Spec Approval  

---

<!-- 
[Will be fully populated once spec.md is filled and approved]
-->

## Phase 1: Project Scaffolding & Setup
- [ ] Task 1.1: Initialize Vite React/TypeScript app under `ui/`.
- [ ] Task 1.2: Configure design system, color tokens, and base layout shell (Header, Sidebar).
- [ ] Task 1.3: Configure API client with Bearer token injection and 401 interception.

## Phase 2: Authentication & Session
- [ ] Task 2.1: Implement Login page and form validation.
- [ ] Task 2.2: Implement AuthGuard router wrapper.

## Phase 3: Dashboard Views & Features
- [ ] Task 3.1: Implement Overview KPI cards (Status, Total Requests, Blocked Attacks).
- [ ] Task 3.2: Implement Live Event Stream table with SSE client.
- [ ] Task 3.3: Implement Plugins & Marketplace explorer view.

## Phase 4: Polish, Security Verification & Build
- [ ] Task 4.1: Verify XSS defense (DOM rendering checks).
- [ ] Task 4.2: Verify responsive design and dark mode palette.
- [ ] Task 4.3: Verify production build (`npm run build`).
