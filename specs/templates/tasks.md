# Atomic Tasks: [Feature Name]

**Related Spec:** [`spec.md`](./spec.md)  
**Related Plan:** [`plan.md`](./plan.md)  
**Progress:** 0 / [Total] Tasks Completed  

---

## Guidelines for Execution
1. Work through tasks sequentially. Do not jump ahead.
2. Follow Test-Driven Development (TDD): Write or scaffold tests/mocks first.
3. Check off tasks (`[x]`) only when the **Definition of Done (DoD)** is completely satisfied.

---

## Phase 1: Test & Fixture Scaffolding (TDD)

- [ ] **Task 1.1: Create mock fixtures and unit test skeletons**
  - **Files:** `internal/<pkg>/<feature>_test.go`
  - **Action:** Define test scenarios matching the acceptance criteria in `spec.md`.
  - **Definition of Done:** `go test ./internal/<pkg>` compiles and fails for the expected reasons (red stage).

- [ ] **Task 1.2: Add negative and boundary test cases**
  - **Files:** `internal/<pkg>/<feature>_test.go`
  - **Action:** Add test cases for nil input, empty string, oversized payload, unauthorized access.
  - **Definition of Done:** Test suite covers edge cases defined in `plan.md`.

---

## Phase 2: Contracts, Types & Data Models

- [ ] **Task 2.1: Define Go types, interfaces, or Protobuf messages**
  - **Files:** `internal/<pkg>/types.go` or `pkg/proto/...`
  - **Action:** Implement structures specified in `plan.md` Section 2.
  - **Definition of Done:** Package compiles with `go build ./...`.

---

## Phase 3: Core Implementation

- [ ] **Task 3.1: Implement business logic and state management**
  - **Files:** `internal/<pkg>/<feature>.go`
  - **Action:** Implement core methods, ensuring thread-safety and constant-time comparisons where required.
  - **Definition of Done:** Unit tests from Phase 1 pass cleanly (`go test -v ./internal/<pkg>`).

- [ ] **Task 3.2: Wire into pipeline or HTTP handler**
  - **Files:** `cmd/<binary>/main.go` or `internal/engine/sidecar.go`
  - **Action:** Connect component to router, middleware (`withAuth`), or sidecar chain.
  - **Definition of Done:** Manual or automated request verifies the integration path.

---

## Phase 4: Verification, Benchmarking & Documentation

- [ ] **Task 4.1: Run full package and regression tests**
  - **Command:** `go test -race -v ./...`
  - **Definition of Done:** All tests pass with zero race conditions detected.

- [ ] **Task 4.2: Run fuzz testing (if applicable)**
  - **Command:** `go test -fuzz=Fuzz<Name> -fuzztime=15s ./internal/<pkg>`
  - **Definition of Done:** Zero crashes or unexpected panics reported.

- [ ] **Task 4.3: Update documentation & ADR (if needed)**
  - **Files:** `README.md`, `docs/adr/`, or OpenAPI spec
  - **Definition of Done:** Docs accurately reflect newly implemented behavior.
