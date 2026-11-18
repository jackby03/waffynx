# Plugging in a scoring engine

Waffynx ships with a deterministic in-process scorer. It can also delegate scoring
to a separate process over a Unix socket, which is how a learned model — for example
[open-appsec](https://github.com/openappsec/openappsec) — gets attached without any
of its code being vendored here.

This document is the whole contract. If a process speaks it, the engine will use it.

---

## Where the scorer sits

```
client → nginx worker → waffynx.sock → Go engine
                                         │
                          1. plugin chain      (signatures, schema, rate)
                          2. custom rules      (IP bans, operator rules)
                          3. policy engine     (YAML policy)
                          4. scorer  ──────────┼──► appsec.sock → your engine
                                         │
                                     204 allow / 403 block → nginx
```

Stages 1–3 are deterministic and always run. Stage 4 is **optional** and only runs
when `appsec.enabled` is true. It can only make the verdict stricter: it never
un-blocks a request an earlier stage already denied.

## The contract

One Unix socket. HTTP/1.1. Two endpoints. No authentication — the socket's file mode
is the access control (Constitution §2.2: `0600` or `0660`, never world-accessible).

### `GET /health`

Return `200` and any JSON body. The engine treats a non-`200` or a dial failure as
"engine unhealthy".

```json
{"status":"ok","service":"my-engine"}
```

### `POST /evaluate`

Request body — the decoded request, as JSON. Field names are the Go struct's, and
decoding is case-insensitive:

| Field | Type | Notes |
|---|---|---|
| `Method` | string | `GET`, `POST`, … |
| `URI` | string | path **plus** query string |
| `Host` | string | `Host` header |
| `ClientIP` | string | as seen by nginx |
| `UserAgent` | string | |
| `ContentType` | string | |
| `Referer` | string | |
| `Body` | string | **base64**, because it is `[]byte` in Go. Empty when absent. |
| `URILength` | int | |
| `QueryParams` | object | decoded name → value |
| `HasPayload` | bool | |
| `PayloadSize` | int64 | bytes |
| `HeadersCount` | int | currently not populated by the engine |

Response body:

| Field | Type | Notes |
|---|---|---|
| `verdict` | string | `allow`, `suspicious` or `block`. Only `block` denies. |
| `score` | float | `0.0` safe … `1.0` malicious |
| `confidence` | float | the engine's own confidence |
| `reasons` | []string | human-readable, shown in events and logs |
| `anomalies` | []string | e.g. `["sqli"]`, `["xss"]` |
| `model_name` | string | overwritten by the client with `open-appsec` |

Verdict thresholds are the **engine's** decision, not Waffynx's. If you want the
same bands the built-in scorer uses, they are:

```go
score >= 0.70 → block
score >= 0.40 → suspicious
otherwise     → allow
```

`reasons` is the only field a human sees when triaging, so put the *why* there, not
just a number.

## Configuration

```yaml
appsec:
  enabled: true
  engine: open-appsec            # anything other than this selects the in-process scorer
  bridge_socket: "/var/run/open-appsec.sock"
  timeout_ms: 100                # per evaluation; also the dial timeout
```

The engine logs which scorer it selected at startup:

```
ML scorer initialized (bridge mode)          socket=/var/run/open-appsec.sock
ML scorer initialized (built-in Go mode)     engine=basic-go
```

## Verify in two commands

```bash
curl --unix-socket /var/run/open-appsec.sock http://localhost/health

curl --unix-socket /var/run/open-appsec.sock \
  -H 'Content-Type: application/json' \
  -d '{"Method":"GET","URI":"/search?q=UNION SELECT 1","Host":"app.example.com","ClientIP":"203.0.113.9"}' \
  http://localhost/evaluate
```

## Two ways to run an engine

### A. The reference implementation

`bin/appsec-bridge` speaks the protocol and wraps the built-in Go scorer. Use it to
exercise the seam, to test a client, or as a skeleton for your own engine.

```bash
appsec-bridge -s /var/run/open-appsec.sock
```

It is **not started by the container**: the engine scores in-process by default, and
starting a second process that nobody points at is how an unused socket ends up in
the process list.

### B. The real open-appsec engine

open-appsec is Apache-2.0, so embedding or redistributing it is compatible with any
licence choice this project makes. It is deliberately **not vendored**:

- Their engine is C++ with a large build (CMake, Boost, its own SDK). Keeping it in
  tree meant re-stripping and re-patching it on their release cadence.
- The previous in-tree bridge compiled a **stub**: `WAFFYNX_REAL_ENGINE` was defined
  in no script, CI or Dockerfile, so the `#else` branch — its own pattern matcher —
  was what shipped. It never scored a request.

To use it, run their engine as its own process or container and put a shim in front
that speaks the JSON above and calls their SDK (`Waap2Transaction`: `start`,
`set_method`, `set_uri`, `add_request_hdr`, …). That shim is the only code you write,
and it lives outside this repository, so their releases never touch our tree.

```
┌──────────────────┐    unix socket     ┌───────────────────────┐
│ Waffynx engine   │ ─────────────────► │ your shim             │
│ BridgeScorer     │  POST /evaluate    │  → open-appsec SDK    │
└──────────────────┘ ◄───────────────── └───────────────────────┘
                      {verdict, score}      (separate container
                                             or process, any language)
```

## Failure semantics — read this before enabling it

**The scorer client fails open.** If the socket is missing, the dial times out, or
the engine is down, `BridgeScorer.Evaluate` returns `allow` with the reason
`bridge unavailable: …` and traffic continues.

That is deliberate — a scoring engine is an enhancement, not the enforcement path —
but it is also a gap against Constitution §1.1, which asks for fail-closed behaviour
according to configured policy. Today there is no knob to make the scorer a hard
dependency; it is tracked in [`ROADMAP.md`](ROADMAP.md) §7. Until that changes:

- If you need the ML verdict to be guaranteed, pair it with deterministic rules that
  still block when the engine is away.
- Watch `reasons` for `bridge unavailable` in the event stream; a silent allow on
  every request looks exactly like a quiet, healthy site.

## What not to do

- **No network hops.** The scorer is reached over a Unix socket on the same host or
  pod. Anything else puts a remote call inside the request path, which §1.3 forbids
  and which turns an upstream outage into your latency.
- **No blocking on a cold start.** Load models before serving `/health`; a scorer
  that answers `200` while still warming returns `allow` for everything.
- **No unbounded bodies.** The engine truncates at 64 KB before sending, but the
  nginx body buffer is smaller (see ROADMAP §7): a body above the buffer never
  reaches the scorer at all.
