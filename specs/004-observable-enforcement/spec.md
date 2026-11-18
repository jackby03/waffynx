# Functional Specification: Observable Enforcement (Monitor Mode & Security Events)

**Status:** Draft — awaiting approval of §6
**Feature ID:** `SPEC-004`
**Author(s):** Waffynx Core Team
**Created:** 2026-11-18
**Target Milestone:** v0.3.0 (Phase 1 of [`docs/ROADMAP.md`](../../docs/ROADMAP.md))

---

## 1. Objective & Context

### 1.1 Problem Statement

Waffynx blocks well and explains nothing. Today an operator adopting it has exactly
two options, both bad: block blind, or not run the WAF.

**Evidence, verified in the code — not assumed:**

- **`log` and `allow` record nothing.** `internal/policy/policy.go` defines
  `ActionLog`, and `internal/engine/sidecar.go:199,207` deliberately treat it as
  "not blocked", but no code path writes an event for it. Measured consequence: a
  rule set to `log` is *indistinguishable from an absent rule*. There is no way to
  ask "what would have been blocked?".
- **Only blocks are recorded, only after the fact.** `sidecar.go:516` writes an
  `audit.Event` solely when `verdict == "block"`, and `sidecar.go:527-536` publishes
  a `WafEvent` under the same condition. Allowed traffic leaves no trace even with
  `learning` enabled (`learning.Record`, `sidecar.go:503`) because that feeds
  suggestions, not an audit trail.
- **Enforcement is all-or-nothing per process.** The only knobs are
  `sidecar.fail_open` and the plugin chain. There is no per-site or per-rule way to
  run one host in monitor mode while another blocks — which is how every real
  rollout actually happens.
- **A 403 cannot be joined to an event.** The C module (`modules/ngx_waffynx/`,
  608 lines) reads only the **HTTP status** from the sidecar (`204` = allow,
  otherwise block; `ngx_http_waffynx_module.c:277-293`). It never parses the body
  and never adds a response header, so the user who reports "I got a 403 at 14:02"
  cannot be matched to a record. Cloudflare's `cf-ray` exists precisely for this.
- **Stage evaluation short-circuits.** Each stage in `Decide` (`sidecar.go:168-265`)
  returns on first match, so once a regex hits, the ML score and the remaining
  stages are never computed. Acceptable when enforcing; wrong when the whole point
  is visibility.

### 1.2 Why this is the next feature

[`docs/ROADMAP.md`](../../docs/ROADMAP.md) lists monitor mode at parity gap **1**
("⚠️ learning engine records, no explicit staging toggle"). Every remaining Phase 1
item — expression language, managed ruleset, IP/geo lists — multiplies the number of
rules that can produce a false positive. Shipping more detection **before** the means
to observe it makes the product more dangerous, not more capable. Monitor mode plus
a queryable event stream is the prerequisite, and it is also what makes the product
demonstrable: "run this for a week, here is what it would have blocked".

---

## 2. Scope

### 2.1 In scope

1. A first-class **`mode: enforce | monitor`**, global with per-site override.
2. A **security event** for every non-allow decision — enforced or suppressed —
   carrying the would-be action, the actual action, and the stage that produced it.
3. A **bounded, non-blocking** event store with query and stream APIs.
4. **All-stage evaluation in monitor mode**, so one request reports every signal
   (regex, custom rule, ML) instead of only the first.
5. **Redaction by default**: no request bodies, no raw query values, bounded field
   lengths.
6. A **correlation ID** surfaced to the client, so a user's report can be matched to
   a record.

### 2.2 Out of scope

- The rule expression language, managed rule catalog, IP/geo/ASN lists (SPEC-005+).
- Storing events in an external database or shipping them to a SIEM (Phase 2).
- Persistent analytics, dashboards, or charts. The API returns records; the GUI is
  a later feature.
- Retroactive re-evaluation of past requests.
- Changing `fail_open` semantics; monitor mode interacts with it (§5) but does not
  replace it.

---

## 3. User stories

- **US-1** As an operator, I set a site to `monitor` and its traffic is served
  normally, while every request the WAF would have blocked appears in the event feed.
- **US-2** As an operator, I read a specific event and see which rule fired, on what
  input, and what the WAF would have done — enough to decide whether the rule is
  wrong or the request really was malicious.
- **US-3** As an operator rolling out to a second host, I keep host A enforcing and
  put host B in monitor, without restarting the process.
- **US-4** As a user who received a 403, I quote the correlation ID from the response
  and support finds the exact decision.
- **US-5** As an operator sizing a deployment, I see how many events were dropped
  because the buffer was full, instead of silently losing data.

---

## 4. Functional requirements

**FR-1 — Mode resolution.** `mode` may be set at `policy.mode` (global default) and
at `sites[].mode`. Resolution is per request: the site's value when set, else the
global value. An unknown value is a **startup error**, never a silent default to
`enforce` or `monitor` (fail-closed on misconfiguration, §2.1 of the Constitution).

**FR-2 — Monitor suppresses, it does not enforce.** In `monitor` mode no automatic
stage may produce a 4xx/5xx. The decision is recorded with
`enforced: false` and `would_be_action: block`, and the request is forwarded
upstream. Manual `deny` entries remain enforcing (see D2).

**FR-3 — Every non-allow decision produces one event.** An event is a single
documented struct, populated for both `enforce` and `monitor`, and for `log` actions.
An `allow` produces no event.

**FR-4 — All stages are evaluated in monitor mode.** `Decide` must not return at the
first match when the effective mode is `monitor`; it collects one finding per stage
that fired and the event reports all of them. In `enforce` mode the existing
short-circuit behaviour is preserved.

**FR-5 — Bounded store, non-blocking write.** The store has a fixed capacity
(`security_events.capacity`, default 10 000) and evicts oldest-first. Insertion from
the request path must be non-blocking: if the buffer is momentarily full, the event is
dropped and a counter incremented. Memory is bounded regardless of traffic.

**FR-6 — Query API.** `GET /api/v1/security/events` returns events newest-first with
filters `since`, `until`, `host`, `rule_id`, `stage`, `ip`, `action`
(`would_be_action`), `enforced`; cursor pagination; authenticated (existing
middleware, read scope). `GET /api/v1/security/events/{id}` returns one event or 404.
A live stream reuses the existing broker/SSE mechanism.

**FR-7 — Correlation ID.** Each event carries an ID that is also returned to the
client as a response header, so a blocked user can quote it. See D3 for the phase
split (this is the only requirement that touches C).

**FR-8 — Redaction.** By default the event stores: timestamp, ID, host, client IP,
method, path, status, stage, rule ID, reason, matched pattern, user agent, and
query **parameter names with values replaced by `[redacted]`**. Bodies are never
stored. All string fields are truncated to a configured maximum before storage
(§1.4 of the Constitution). `security_events.capture_payload: true` opts into
storing the raw query and a bounded body snippet, and the configuration loader must
say so loudly at startup.

**FR-9 — Drop visibility.** The number of events dropped for capacity or pressure is
exposed on `/metrics` and returned in the events API response metadata, so "no
events" can never be confused with "no attacks".

---

## 5. Constitutional constraints

- **§1.1 Fail-closed:** an unreadable or invalid `mode` aborts startup. Monitor mode
  is never the default and must be requested explicitly.
- **§1.2 Zero-allocation hot path:** no event is constructed on the `allow` path.
  Event creation happens only after a non-allow decision, and the existing benchmarks
  must not regress; a benchmark asserts the allow path is allocation-free.
- **§1.3 Separation of planes:** the store and query API live in the control plane;
  the data plane only publishes. No I/O, no locks with unbounded wait, no network in
  the request path.
- **§1.4 Untrusted input:** every field written into an event is length-bounded and
  treated as hostile; the redaction step runs before storage, not at render time.
- **§3.1 Verification-first:** unit tests for mode resolution, redaction, eviction and
  filters; a fuzz target for the redactor; a regression test proving a `log` action
  now records an event (this was the bug).

---

## 6. Decisions requiring approval

| # | Question | Recommendation | Why |
|---|---|---|---|
| **D1** | Scope of `mode` | Global default **plus** per-site override | Per-site is how rollouts actually happen; a global flag forces all-or-nothing again. |
| **D2** | Does a manual `deny` (IP ban) still block in monitor mode? | **Yes.** Only automatic detection is suppressed | An operator's emergency ban is intent, not a heuristic. Silently downgrading it to `log` would break the one control they reached for in an incident — and nothing would announce it. |
| **D3** | Correlation ID in the response header | **Yes**, as a separate phase (needs the C module) | It is the only requirement that touches `modules/ngx_waffynx`. Splitting it means Go work ships first and the C change is reviewed on its own. |
| **D4** | Retention | Bounded ring in memory (10 000) + optional append-only JSONL in the data dir, **off by default** | No database in Phase 1. JSONL reuses the `internal/audit` sink pattern already in the tree. |
| **D5** | Payload capture | **Never bodies by default**; query values redacted by default | WAF logs are a privacy liability. Redacting at write time (not read time) means unredacted data never exists on disk or in memory. |
| **D6** | Stage evaluation in monitor mode | Evaluate **all** stages, report every finding | Otherwise a regex hit hides the ML score and the custom rules. The point of monitor is total visibility; the latency cost exists only while monitoring. |

---

## 7. Acceptance criteria

1. With `mode: monitor`, `curl '?q=UNION+SELECT+1,2,3'` returns **200** and one event
   exists with `enforced: false`, `would_be_action: "block"`, `stage: "plugin-chain"`.
2. With `mode: enforce`, the same request returns **403** and one event exists with
   `enforced: true`.
3. A rule with `action: log` produces an event. *(Regression test for the defect in
   §1.1.)*
4. Two sites, one `enforce` and one `monitor`, behave differently **in the same
   process**, verified through the rendered nginx fragments and the sidecar.
5. `policy.mode: "audit"` (a typo) aborts startup with an error naming the field.
6. Capacity 100 with 1 000 blocked requests: the store holds exactly 100, the drop
   counter reads 900, and the API reports the drops.
7. The query API filters by host, rule, stage and `enforced`; a cursor returns the
   next page without duplicates or gaps.
8. An event for `?token=secret&q=<script>` contains `q=[redacted]` and stores no body.
9. `go test -bench` shows the allow path unchanged within noise, and no allocation.
10. A `deny` for an IP still returns 403 while the site is in `monitor` mode (D2).

---

## 8. Risks

| Risk | Mitigation |
|---|---|
| Monitor mode becomes permanent and the WAF never enforces | The event API reports the age of the oldest unenforced event per site; a warning metric when a site has been in monitor beyond a threshold. |
| Event volume swamps the ring buffer on a busy host | Bounded capacity, drop counter, and per-site counters surfaced in `/metrics` (FR-9). Sampling is deliberately **not** introduced in Phase 1: it hides attacks and complicates the acceptance criteria. |
| Redaction misses a field and leaks secrets | The redactor is the only writer of stored fields; a fuzz target plus a test asserting the struct's every string field is bounded. |
| All-stage evaluation in monitor changes verdicts on switching to enforce | Documented: monitor reports findings that enforce would short-circuit. The API returns them ordered by stage so the switchover is predictable. |
