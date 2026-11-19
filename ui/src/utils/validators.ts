import type { Site } from "../api/types";

/**
 * Client-side validators mirroring `internal/sites/site.go` and `net.ParseIP`.
 * The server always performs authoritative validation; these provide immediate,
 * accurate feedback without rejecting valid wildcards or scheme-prefixed upstreams.
 */

const DNS_LABEL_RE = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;
const HOST_FORBIDDEN_RE = /[ \t\r\n;{}\"'`\\/$#&|<>()[\]=+*?,]/;
const UPSTREAM_FORBIDDEN_RE = /[ \t\r\n;{}\"'`\\]/;
const PATH_FORBIDDEN_RE = /[ \t\r\n;{}"]/;
const TLS_FORBIDDEN_RE = /[\r\n;{}"]/;

const IPV4_RE =
  /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;

export function isValidIPv4(value: string): boolean {
  return IPV4_RE.test(value.trim());
}

export function isValidIPv6(value: string): boolean {
  const v = value.trim();
  if (!v.includes(":")) return false;
  if (/[^0-9a-fA-F:.]/.test(v)) return false;
  const doubleColons = v.split("::").length - 1;
  if (doubleColons > 1) return false;
  const parts = v.split(":").filter((p) => p !== "");
  if (doubleColons === 0 && parts.length !== 8) return false;
  if (doubleColons === 1 && parts.length > 7) return false;
  return parts.every((p) => /^[0-9a-fA-F]{1,4}$/.test(p) || isValidIPv4(p));
}

export function isValidIP(value: string): boolean {
  const trimmed = value.trim();
  return isValidIPv4(trimmed) || isValidIPv6(trimmed);
}

export function isValidCIDR(value: string): boolean {
  const trimmed = value.trim();
  const slash = trimmed.indexOf("/");
  if (slash <= 0) return false;
  const ip = trimmed.slice(0, slash);
  const prefixRaw = trimmed.slice(slash + 1);
  if (!/^\d+$/.test(prefixRaw)) return false;
  const prefix = Number(prefixRaw);
  if (isValidIPv4(ip)) return prefix >= 0 && prefix <= 32;
  if (isValidIPv6(ip)) return prefix >= 0 && prefix <= 128;
  return false;
}

export function validateHostname(raw: string): string | null {
  const host = raw.trim().toLowerCase();
  if (!host) return "Hostname is required (e.g., app.example.com or *.example.com).";
  if (host === "*") return "Wildcard host requires a domain (e.g., *.example.com).";
  if (host.length > 253) return "Hostname must be 253 characters or fewer.";
  if (isValidIP(host)) return "Use a DNS hostname, not an IP literal.";
  if (host.startsWith(".") || host.endsWith(".")) return "Hostname must not start or end with a dot.";
  if (host.includes("..")) return "Hostname contains an empty label.";

  const checkable = host.startsWith("*.") ? host.slice(2) : host;
  if (HOST_FORBIDDEN_RE.test(checkable)) {
    return "Hostname contains disallowed characters (no scheme, path, port, or punctuation).";
  }

  const labels = host.split(".");
  for (let i = 0; i < labels.length; i += 1) {
    const label = labels[i];
    if (i === 0 && label === "*") continue;
    if (!DNS_LABEL_RE.test(label)) {
      return `DNS label "${label}" is not valid.`;
    }
  }
  return null;
}

export function validateUpstream(raw: string): string | null {
  const upstream = raw.trim();
  if (!upstream) return "Upstream is required (e.g., backend:8080 or http://10.0.0.5:8080).";
  if (UPSTREAM_FORBIDDEN_RE.test(upstream)) return "Upstream contains disallowed characters.";

  let candidate = upstream;
  if (upstream.includes("://")) {
    let parsed: URL;
    try {
      parsed = new URL(upstream);
    } catch {
      return "Upstream is not a valid URL.";
    }
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      return "Upstream scheme must be http or https.";
    }
    if (parsed.username || parsed.password) {
      return "Credentials in the upstream URL are not allowed.";
    }
    if (parsed.search || parsed.hash) {
      return "Query strings and fragments are not allowed in upstreams.";
    }
    if (parsed.pathname && parsed.pathname !== "/") {
      return "Path suffixes are not allowed in the upstream URL.";
    }
    candidate = parsed.host;
  }

  const lastColon = candidate.lastIndexOf(":");
  if (lastColon <= 0) {
    return "Upstream must include an explicit port (host:port).";
  }
  const hostPart = candidate.slice(0, lastColon);
  const portPart = candidate.slice(lastColon + 1);
  if (!hostPart) return "Upstream host cannot be empty.";
  const port = Number(portPart);
  if (!/^\d+$/.test(portPart) || port < 1 || port > 65535) {
    return "Upstream port must be between 1 and 65535.";
  }
  return null;
}

export interface SiteFieldErrors {
  host?: string;
  upstream?: string;
  tls?: string;
  paths?: string;
  headers?: string;
}

export function validateSite(site: Site): SiteFieldErrors {
  const errors: SiteFieldErrors = {};

  const hostErr = validateHostname(site.host);
  if (hostErr) errors.host = hostErr;

  const upstreamErr = validateUpstream(site.upstream);
  if (upstreamErr) errors.upstream = upstreamErr;

  if (site.tls) {
    const cert = site.tls.cert_file.trim();
    const key = site.tls.key_file.trim();
    if (Boolean(cert) !== Boolean(key)) {
      errors.tls = "Both certificate and key paths are required when TLS is configured.";
    } else if ((cert && TLS_FORBIDDEN_RE.test(cert)) || (key && TLS_FORBIDDEN_RE.test(key))) {
      errors.tls = "TLS file paths contain disallowed characters.";
    }
  }

  if (site.paths && site.paths.length > 0) {
    const seen = new Set<string>();
    for (let i = 0; i < site.paths.length; i += 1) {
      const p = site.paths[i];
      if (!p.path.startsWith("/")) {
        errors.paths = `Path rule #${i + 1} must start with '/'.`;
        break;
      }
      if (PATH_FORBIDDEN_RE.test(p.path) || p.path.includes("..")) {
        errors.paths = `Path rule "${p.path}" contains disallowed characters or '..'.`;
        break;
      }
      if (seen.has(p.path)) {
        errors.paths = `Duplicate path rule "${p.path}".`;
        break;
      }
      seen.add(p.path);
      if (p.upstream && p.upstream.trim()) {
        const pUpErr = validateUpstream(p.upstream);
        if (pUpErr) {
          errors.paths = `Path "${p.path}" upstream: ${pUpErr}`;
          break;
        }
      }
    }
  }

  if (site.headers) {
    for (const name of Object.keys(site.headers)) {
      if (!name.trim() || PATH_FORBIDDEN_RE.test(name)) {
        errors.headers = `Header name "${name}" contains disallowed characters.`;
        break;
      }
    }
  }

  return errors;
}
