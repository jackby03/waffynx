import type { LiveStatsFrame, Verdict, WafEvent, WireWafEvent } from "./types";

/**
 * SSE frame handling.
 *
 * The stream carries two different things on the same connection: WAF events and
 * periodic stats frames. Treating a stats frame as an event is what blanked the
 * dashboard on first login (`rule_id` was undefined and the drawer crashed on
 * `.includes`).
 */

const str = (v: unknown): string => (typeof v === "string" ? v : "");

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null;
}

/** Returns the stats frame when the payload is one, otherwise null. */
export function asStatsFrame(raw: unknown): LiveStatsFrame | null {
  if (!isRecord(raw) || raw.type !== "stats") return null;
  const num = (v: unknown): number | undefined => (typeof v === "number" ? v : undefined);
  return {
    type: "stats",
    timestamp: str(raw.timestamp) || undefined,
    total: num(raw.total),
    blocked: num(raw.blocked),
    allowed: num(raw.allowed),
    rate_limited: num(raw.rate_limited),
    max: num(raw.max),
  };
}

/**
 * Derives the verdict the console shows.
 *
 * The engine sends `type` only, so this mapping is the single place where a
 * display action is invented — and it is documented as a derivation, not as
 * server data.
 */
function deriveVerdict(type: string, explicit: string): Verdict {
  if (explicit === "deny" || explicit === "allow" || explicit === "challenge" || explicit === "rate_limited") {
    return explicit;
  }
  if (type === "blocked") return "deny";
  if (type === "rate_limited") return "rate_limited";
  return "allow";
}

/**
 * Normalises a wire event into the shape the views render.
 *
 * Returns null for anything that is not an event, including stats frames and
 * malformed payloads, so a bad frame can never take down a view.
 */
export function toWafEvent(raw: unknown): WafEvent | null {
  if (!isRecord(raw)) return null;
  const type = str(raw.type);
  if (type === "stats") return null;

  const wire: WireWafEvent = {
    type: type || undefined,
    timestamp: str(raw.timestamp),
    method: str(raw.method),
    path: str(raw.path),
    remote_ip: str(raw.remote_ip),
    rule_id: str(raw.rule_id),
    reason: str(raw.reason) || undefined,
    payload: str(raw.payload) || undefined,
  };

  // An event with no rule and no reason carries no information; dropping it keeps
  // the table honest instead of showing an empty row that looks like a bug.
  if (wire.rule_id === "" && !wire.reason) return null;

  return {
    ...wire,
    action: deriveVerdict(type, str(raw.action)),
    matched_field: wire.reason ?? "",
    matched_value: wire.payload ?? wire.reason ?? "",
  };
}

/** Parses one `data:` payload from the stream. */
export function parseSSEFrame(data: string): { event: WafEvent | null; stats: LiveStatsFrame | null } {
  let parsed: unknown;
  try {
    parsed = JSON.parse(data);
  } catch {
    return { event: null, stats: null };
  }
  return { event: toWafEvent(parsed), stats: asStatsFrame(parsed) };
}
