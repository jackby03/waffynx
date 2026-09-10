# ADR-0001: Record Architecture Decisions

* **Status:** Accepted
* **Date:** 2026-09-09
* **Author(s):** Waffynx Core Team

---

## Context and Problem Statement
In an AI-agent-assisted, spec-driven development workflow, architectural choices, technology selections, and non-negotiable invariants can easily be forgotten, re-debated, or unintentionally rewritten by subsequent agent sessions or contributors. We need a standardized, version-controlled mechanism to document significant architectural decisions.

## Decision Drivers
* Retain institutional knowledge across agent and human development sessions.
* Prevent AI agents from making arbitrary technology replacements or violating past architectural consensus.
* Provide clear rationale for trade-offs (e.g. Unix sockets over TCP, in-memory vs database, CGO flags).

## Considered Options
1. Informal commit messages or PR notes.
2. Architecture Decision Records (ADRs) in `docs/adr/`.
3. Architecture wiki external to the Git repository.

## Decision Outcome
**Chosen option:** "Architecture Decision Records (ADRs) in `docs/adr/`", because ADRs are stored alongside source code in Git, readable by both human developers and LLM agents, and remain immutable historical records of system evolution.

### Positive Consequences
* Clear historical tracking of architectural choices.
* Explicit reference points for agents during the `plan.md` phase.

### Negative Consequences / Trade-offs
* Requires lightweight discipline to author an ADR when introducing architectural shifts.
