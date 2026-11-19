import type { WafEvent } from "./types";

const str = (v: unknown): string => (typeof v === "string" ? v : "");

/**
 * toWafEvent maps the server's event contract onto the richer shape the views
 * use, and returns null for frames that are not events.
 *
 * The SSE stream carries two things: WAF events and periodic stats frames.
 * Treating a stats frame as an event is what crashed the dashboard on first
 * login, because it has no rule_id.
 */
export function toWafEvent(raw: unknown): WafEvent | null {
  if (!raw || typeof raw !== "object") return null;
  const r = raw as Record<string, unknown>;
  const type = str(r.type);
  if (type === "stats") return null;

  const action = str(r.action);
  const derived: WafEvent["action"] =
    action === "deny" || action === "allow" || action === "challenge" || action === "rate_limited"
      ? (action as WafEvent["action"])
      : type === "blocked"
        ? "deny"
        : type === "rate_limited"
          ? "rate_limited"
          : "allow";

  const payload = r.payload;
  return {
    type: type || undefined,
    reason: str(r.reason) || undefined,
    timestamp: str(r.timestamp) || new Date().toISOString(),
    rule_id: str(r.rule_id),
    action: derived,
    remote_ip: str(r.remote_ip),
    method: str(r.method),
    path: str(r.path),
    matched_field: str(r.matched_field) || (r.reason ? "unknown" : ""),
    matched_value: str(r.matched_value) || (typeof payload === "string" ? payload : str(r.reason)),
  };
}
