import test from "node:test";
import assert from "node:assert/strict";

import { asStatsFrame, parseSSEFrame, toWafEvent } from "../src/api/events.ts";

/**
 * These run the real functions, not a text match against the source.
 *
 * The frame parser is where the dashboard crashed on first login: the stats frame
 * from the same stream has no rule_id, and treating it as an event took the whole
 * React tree down with it.
 */

const statsFrame = { type: "stats", total: 12, blocked: 3, allowed: 9, max: 2000 };

test("a stats frame is never an event", () => {
  assert.equal(toWafEvent(statsFrame), null);
  assert.equal(toWafEvent({ type: "stats" }), null);
});

test("a stats frame keeps its counters", () => {
  const stats = asStatsFrame(statsFrame);
  assert.ok(stats);
  assert.equal(stats.type, "stats");
  assert.equal(stats.total, 12);
  assert.equal(stats.blocked, 3);
  assert.equal(stats.allowed, 9);
  assert.equal(stats.max, 2000);
});

test("a real block event derives its verdict and keeps the engine fields", () => {
  const event = toWafEvent({
    type: "blocked",
    timestamp: "2026-01-01T00:00:00Z",
    method: "GET",
    path: "/?q=UNION+SELECT+1",
    remote_ip: "203.0.113.9",
    rule_id: "WAF-SQLI-001",
    reason: "SQL UNION SELECT (matched in query)",
  });

  assert.ok(event);
  assert.equal(event.action, "deny");
  assert.equal(event.rule_id, "WAF-SQLI-001");
  assert.equal(event.remote_ip, "203.0.113.9");
  assert.equal(event.matched_value, "SQL UNION SELECT (matched in query)");
});

test("a rate_limited event is not reported as a plain deny", () => {
  const event = toWafEvent({ type: "rate_limited", rule_id: "rate", timestamp: "2026-01-01T00:00:00Z" });
  assert.ok(event);
  assert.equal(event.action, "rate_limited");
});

test("uses the payload as the matched value when the engine sends one", () => {
  const event = toWafEvent({
    type: "blocked",
    rule_id: "WAF-XSS-001",
    reason: "XSS: script tag",
    payload: "<script>",
    timestamp: "2026-01-01T00:00:00Z",
  });
  assert.ok(event);
  assert.equal(event.matched_value, "<script>");
  assert.equal(event.matched_field, "XSS: script tag");
});

test("an event with no rule and no reason carries no information and is dropped", () => {
  assert.equal(toWafEvent({ type: "blocked", timestamp: "2026-01-01T00:00:00Z" }), null);
});

test("garbage from the socket cannot throw", () => {
  for (const bad of [null, undefined, 42, "text", [], { type: 7 }]) {
    assert.doesNotThrow(() => toWafEvent(bad));
  }
});

test("parseSSEFrame separates the two payload kinds", () => {
  const blocked = parseSSEFrame(
    JSON.stringify({ type: "blocked", rule_id: "WAF-SQLI-001", reason: "SQL", timestamp: "t" })
  );
  assert.ok(blocked.event);
  assert.equal(blocked.stats, null);

  const stats = parseSSEFrame(JSON.stringify({ type: "stats", total: 1 }));
  assert.equal(stats.event, null);
  assert.ok(stats.stats);

  const broken = parseSSEFrame("{not json");
  assert.equal(broken.event, null);
  assert.equal(broken.stats, null);
});
