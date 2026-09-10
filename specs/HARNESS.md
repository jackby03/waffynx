# Agent Harness — Spec-Driven Development (SDD)

> **Agent Execution Manual**  
> This harness defines the operational workflow, execution loop, and quality gates that any AI agent must execute when implementing features or refactoring modules in Waffynx.

---

## 1. The SDD Hierarchy

Every task follows a top-down governance model:

```
[ Level 1: Global Governance ]
  ├── constitution.md           <-- Supreme laws, security invariants, constraints
  └── AGENTS.md                 <-- Dev environment setup, CLI commands, gotchas
            │
            ▼
[ Level 2: Feature Lifecycle (under specs/<feature-id>-<name>/) ]
  ├── spec.md                   <-- Functional Specification (What & Why, Scope)
  ├── plan.md                   <-- Technical Architecture Plan (How, Contracts, Data models)
  ├── tasks.md                  <-- Atomic Task Checklist with Definition of Done
  └── clarifications.md         <-- Q&A Log resolving ambiguities before coding
            │
            ▼
[ Level 3: Architectural Memory ]
  └── docs/adr/                 <-- Architecture Decision Records (ADR)
```

---

## 2. The Agent Execution Protocol

When assigned a task, the agent MUST follow these 5 phases sequentially:

### Phase 1: Ingestion & Invariant Check
1. Read `constitution.md` to refresh non-negotiable security and architectural rules.
2. Read the target feature specification: `specs/<feature>/spec.md`.
3. Verify that the requested feature does not violate:
   - Linux-only runtime assumptions.
   - Fail-closed security design.
   - Constant-time comparison for secrets/tokens.
   - Socket permissions (`0600`/`0660`).
4. If ambiguities or missing specifications exist, record them in `clarifications.md` and clarify with the user before proceeding.

### Phase 2: Technical Architecture Plan (`plan.md`)
1. Define the system boundaries and component mapping.
2. Draft explicit data contracts (Go structs, Protobuf definitions, JSON schemas).
3. Document failure modes, edge cases, and fallback mechanisms.
4. Establish the testing strategy (unit tests, fuzz tests, integration tests).

### Phase 3: Task Breakdown (`tasks.md`)
1. Deconstruct the work into small, sequential, atomic tasks.
2. Order tasks to support Test-Driven Development (TDD):
   - Step A: Test cases and mock fixtures.
   - Step B: Data models and interfaces.
   - Step C: Core implementation.
   - Step D: Integration with the runtime engine/pipeline.
3. Every task must have an explicit **Definition of Done (DoD)** (e.g. `go test -v -run TestX passes`).

### Phase 4: Implementation Loop
1. Take one task from `tasks.md` at a time.
2. Implement code strictly within the declared `In-Scope` boundary.
3. Verify the task's DoD immediately.
4. Mark the task as completed (`[x]`).

### Phase 5: Verification & Harness Evaluation
1. Run the package test suite:
   ```bash
   go test -v ./...
   ```
2. If the feature touches parsers or evaluators, run fuzz tests:
   ```bash
   go test -fuzz=Fuzz<Target> -fuzztime=10s ./...
   ```
3. Ensure no regressions against `.jules/sentinel.md` vulnerability invariants.
4. Update or document any major architectural shifts in `docs/adr/`.

---

## 3. Agent Guardrails & Anti-Patterns

| Prohibited Action | Required Behavior |
| :--- | :--- |
| **Silent assumptions** | Log open questions in `clarifications.md`. |
| **Scope creep** | Check `spec.md` `Out-of-Scope` section. Refuse to add unrequested bells and whistles. |
| **Skipping tests** | Write verification tests before or alongside code. Untested code is incomplete code. |
| **Losing documentation** | Preserve all existing comments and explanations in modified files. |
| **Hardcoding secrets/defaults** | Enforce startup validation with minimum length and entropy requirements. |

---

## 4. Directory Structure for New Features

When creating a new feature lifecycle, copy the templates from `specs/templates/`:

```bash
mkdir -p specs/001-feature-name
cp specs/templates/spec.md specs/001-feature-name/spec.md
cp specs/templates/plan.md specs/001-feature-name/plan.md
cp specs/templates/tasks.md specs/001-feature-name/tasks.md
cp specs/templates/clarifications.md specs/001-feature-name/clarifications.md
```
