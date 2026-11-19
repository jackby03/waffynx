import type { WafEvent } from "../api/types";

const pad = (n: number): string => String(n).padStart(2, "0");

export function formatTime(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso || "--:--:--";
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

export function formatDateTime(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso || "—";
  return d.toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

export function formatRelativeTime(iso: string, nowMs = Date.now()): string {
  const ts = Date.parse(iso);
  if (Number.isNaN(ts)) return "—";
  const diffSec = Math.round((nowMs - ts) / 1000);
  if (diffSec < 5) return "just now";
  if (diffSec < 60) return `${diffSec}s ago`;
  if (diffSec < 3600) return `${Math.floor(diffSec / 60)}m ago`;
  if (diffSec < 86400) return `${Math.floor(diffSec / 3600)}h ago`;
  return `${Math.floor(diffSec / 86400)}d ago`;
}

export function formatCountdown(expiresAtIso: string, nowMs = Date.now()): { label: string; expired: boolean } {
  const ts = Date.parse(expiresAtIso);
  if (Number.isNaN(ts)) return { label: "—", expired: false };
  const remainingSec = Math.floor((ts - nowMs) / 1000);
  if (remainingSec <= 0) return { label: "Expired", expired: true };
  if (remainingSec < 60) return { label: `${remainingSec}s`, expired: false };
  const mins = Math.floor(remainingSec / 60);
  if (mins < 60) return { label: `${mins}m ${remainingSec % 60}s`, expired: false };
  const hours = Math.floor(mins / 60);
  if (hours < 24) return { label: `${hours}h ${mins % 60}m`, expired: false };
  const days = Math.floor(hours / 24);
  return { label: `${days}d ${hours % 24}h`, expired: false };
}

export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes < 0) return "—";
  if (bytes < 1024) return `${bytes} B`;
  const kb = bytes / 1024;
  if (kb < 1024) return `${kb.toFixed(1)} KB`;
  const mb = kb / 1024;
  if (mb < 1024) return `${mb.toFixed(1)} MB`;
  return `${(mb / 1024).toFixed(2)} GB`;
}

export function formatDurationNs(ns: number): string {
  if (!Number.isFinite(ns) || ns < 0) return "—";
  if (ns < 1_000) return `${ns} ns`;
  if (ns < 1_000_000) return `${(ns / 1_000).toFixed(1)} µs`;
  return `${(ns / 1_000_000).toFixed(2)} ms`;
}

export interface TimeBucket {
  minute: number;
  label: string;
  count: number;
}

export function buildMinuteBuckets(events: WafEvent[], windowMinutes: number, nowMs = Date.now()): TimeBucket[] {
  const buckets: TimeBucket[] = [];
  const start = Math.floor(nowMs / 60_000) * 60_000 - (windowMinutes - 1) * 60_000;

  for (let i = 0; i < windowMinutes; i += 1) {
    const minute = start + i * 60_000;
    const d = new Date(minute);
    buckets.push({
      minute,
      label: `${pad(d.getHours())}:${pad(d.getMinutes())}`,
      count: 0,
    });
  }

  const index = new Map(buckets.map((b, i) => [b.minute, i]));
  for (const ev of events) {
    const ts = Date.parse(ev.timestamp);
    if (Number.isNaN(ts)) continue;
    const minute = Math.floor(ts / 60_000) * 60_000;
    const idx = index.get(minute);
    if (idx !== undefined) buckets[idx].count += 1;
  }

  return buckets;
}

export type AttackVector =
  | "sqli"
  | "xss"
  | "traversal"
  | "rce"
  | "scanner"
  | "log4shell"
  | "rate_limit"
  | "ip_ban"
  | "appsec"
  | "other";

export const VECTOR_LABELS: Record<AttackVector, string> = {
  sqli: "SQL Injection",
  xss: "Cross-Site Scripting",
  traversal: "Path Traversal / LFI",
  rce: "Command Injection / RCE",
  scanner: "Scanner / Recon",
  log4shell: "Log4Shell / JNDI",
  rate_limit: "Rate Limit",
  ip_ban: "IP Ban / Custom Rule",
  appsec: "AppSec / ML Anomaly",
  other: "Other Policy",
};

export function classifyEventVector(event: WafEvent): AttackVector {
  const id = (event.rule_id || "").toLowerCase();
  const reason = (event.reason || "").toLowerCase();
  if (event.action === "rate_limited" || id.includes("rate")) return "rate_limit";
  if (id.startsWith("ip-ban-") || id.includes("nftables") || id.includes("custom")) return "ip_ban";
  if (id.includes("sqli") || id.includes("sql") || reason.includes("sql")) return "sqli";
  if (id.includes("xss") || reason.includes("xss") || reason.includes("script")) return "xss";
  if (id.includes("lfi") || id.includes("trav") || id.includes("path") || reason.includes("traversal")) return "traversal";
  if (id.includes("rce") || id.includes("cmd") || reason.includes("command")) return "rce";
  if (id.includes("log4") || id.includes("jndi") || reason.includes("jndi")) return "log4shell";
  if (id.includes("scan") || id.includes("bot") || id.includes("vcs") || reason.includes("scanner")) return "scanner";
  if (id.includes("appsec") || id.includes("ml") || id.includes("anomaly") || reason.includes("entropy")) return "appsec";
  return "other";
}

export type PipelineStage = "custom" | "catalog" | "plugins" | "scorer";

export function detectPipelineStage(event: WafEvent): PipelineStage {
  const id = (event.rule_id || "").toLowerCase();
  if (id.startsWith("waf-")) return "catalog";
  if (id.startsWith("ip-ban-") || id.includes("custom") || id.includes("nftables")) return "custom";
  if (id.includes("appsec") || id.includes("ml") || id.includes("anomaly")) return "scorer";
  return "plugins";
}

export function eventIdentity(event: WafEvent): string {
  return JSON.stringify([event.timestamp, event.rule_id, event.path, event.remote_ip]);
}
