import type { WafEvent } from "../api/types";

/**
 * Neutralizes spreadsheet formula injection (CWE-1236) and escapes RFC 4180 CSV cells.
 */
function escapeCsvCell(value: unknown): string {
  const raw = value === null || value === undefined ? "" : String(value);
  const safe = /^[=+\-@\t\r]/.test(raw) ? `'${raw}` : raw;
  if (/[",\r\n]/.test(safe)) {
    return `"${safe.replace(/"/g, '""')}"`;
  }
  return safe;
}

function triggerDownload(filename: string, content: string, mime: string): void {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export function downloadJSON(filename: string, data: unknown): void {
  triggerDownload(filename, JSON.stringify(data, null, 2), "application/json;charset=utf-8");
}

export function downloadCSV<T>(
  filename: string,
  rows: T[],
  columns: { header: string; value: (row: T) => unknown }[]
): void {
  const headerLine = columns.map((c) => escapeCsvCell(c.header)).join(",");
  const bodyLines = rows.map((row) =>
    columns.map((c) => escapeCsvCell(c.value(row))).join(",")
  );
  triggerDownload(filename, [headerLine, ...bodyLines].join("\n"), "text/csv;charset=utf-8");
}

export function formatEventAsRawHttp(event: WafEvent): string {
  const method = event.method || "GET";
  const path = event.path || "/";
  const lines = [
    `${method} ${path} HTTP/1.1`,
    `X-Forwarded-For: ${event.remote_ip || "unknown"}`,
    `X-Waffynx-Rule: ${event.rule_id || "none"}`,
    `X-Waffynx-Verdict: ${event.action}`,
  ];
  if (event.reason) lines.push(`X-Waffynx-Reason: ${event.reason}`);
  if (event.payload) {
    lines.push("", "# Matched normalized fragment", event.payload);
  }
  return lines.join("\n");
}

export function formatEventAsCurl(event: WafEvent, host = "app.example.test"): string {
  const method = event.method || "GET";
  const safePath = (event.path || "/").replace(/'/g, "'\\''");
  const safeHost = host.replace(/'/g, "'\\''");
  return `curl -i -X ${method} -H 'Host: ${safeHost}' 'http://localhost:8080${safePath}'`;
}
