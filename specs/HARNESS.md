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

When assigned a task, the agent MUST follow these 5 phases sequentially. The agent MUST stop at an approval gate and ask the user for approval; it must not infer approval from a draft file or from the presence of tasks.

### Phase 1: Ingestion & Invariant Check
1. Read `constitution.md` to refresh non-negotiable security and architectural rules.
2. Read the target feature specification: `specs/<feature>/spec.md`.
3. Verify that the requested feature does not violate:
   - Linux-only runtime assumptions.
   - Fail-closed security design.
   - Constant-time comparison for secrets/tokens.
   - Socket permissions (`0600`/`0660`).
4. If ambiguities or missing specifications exist, record them in `clarifications.md` and clarify with the user before proceeding.

**Gate 1:** `spec.md` MUST exist, have status `Approved`, and contain no unresolved blocking clarification.

### Phase 2: Technical Architecture Plan (`plan.md`)
1. Define the system boundaries and component mapping.
2. Draft explicit data contracts (Go structs, Protobuf definitions, JSON schemas).
3. Document failure modes, edge cases, and fallback mechanisms.
4. Establish the testing strategy (unit tests, fuzz tests, integration tests).

**Gate 2:** `plan.md` MUST have status `Approved` and reference the approved specification. The plan MUST identify affected components, contracts, failure modes, security controls, and verification commands.

### Phase 3: Task Breakdown (`tasks.md`)
1. Deconstruct the work into small, sequential, atomic tasks.
2. Order tasks to support Test-Driven Development (TDD):
   - Step A: Test cases and mock fixtures.
   - Step B: Data models and interfaces.
   - Step C: Core implementation.
   - Step D: Integration with the runtime engine/pipeline.
3. Every task must have an explicit **Definition of Done (DoD)** (e.g. `go test -v -run TestX passes`).

**Gate 3:** `tasks.md` MUST contain atomic tasks with explicit files, scope, dependencies, and DoD. Only one task may be marked `in_progress` at a time. Implementation cannot start until the user approves the spec, plan, and task list.

### Phase 4: Implementation Loop
1. Take one task from `tasks.md` at a time.
2. Implement code strictly within the declared `In-Scope` boundary.
3. Verify the task's DoD immediately.
4. Mark the task as completed (`[x]`).

Before editing, record the task as `in_progress`. Before completion, verify its DoD and confirm every changed file is inside the task's declared scope. Do not modify unrelated user changes.

### Phase 5: Verification & Harness Evaluation
1. Run the Go verification suite:
    ```bash
    go test -race ./...
    gofmt -s -l .
    golangci-lint run ./...
    ```
2. Build the supported Go targets:
    ```bash
    make build
    ```
3. If the feature touches parsers or evaluators, run the named fuzz target for its package:
    ```bash
    go test -fuzz=Fuzz<Target> -fuzztime=10s ./internal/<package>
    ```
4. For frontend changes, run the package-manager-appropriate lockfile install, build, lint, and tests from the UI directory. The exact commands MUST be recorded in `plan.md`.
5. For Linux-only, Nginx, C, or C++ changes, run `make vagrant-test` or the relevant Linux verification command. Windows-only results are not sufficient.
6. Ensure no regressions against `.jules/sentinel.md` vulnerability invariants.
7. Update or document any major architectural shifts in `docs/adr/`.

**Gate 4:** A feature is complete only when all applicable verification commands pass, all tasks are checked off, and the final diff contains no out-of-scope files. If an environment limitation prevents a check, document it explicitly and do not claim the gate passed.

---

## 3. Agent Guardrails & Anti-Patterns

| Prohibited Action | Required Behavior |
| :--- | :--- |
| **Silent assumptions** | Log open questions in `clarifications.md`. |
| **Scope creep** | Check `spec.md` `Out-of-Scope` section. Refuse to add unrequested bells and whistles. |
| **Skipping tests** | Write verification tests before or alongside code. Untested code is incomplete code. |
| **Losing documentation** | Preserve all existing comments and explanations in modified files. |
| **Hardcoding secrets/defaults** | Enforce startup validation with minimum length and entropy requirements. |
| **Implementing a draft** | Stop at the approval gate and request explicit user approval. |
| **Unverified integration** | Add a test that exercises the real boundary, not only isolated mocks. |

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

Use the status values from the templates consistently: `Draft`, `Under Review`, `Approved`, or `Superseded`. A clarification marked `Pending` blocks approval when it affects security, API contracts, data flow, scope, or acceptance criteria.
