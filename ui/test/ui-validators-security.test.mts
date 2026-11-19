import test from "node:test";
import assert from "node:assert/strict";
import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";

import { asStatsFrame } from "../src/api/events.ts";
import { isValidCIDR, isValidIP, validateSite } from "../src/utils/validators.ts";
import { tokenizeHostilePayload } from "../src/utils/payloadHighlight.ts";

async function walkSourceFiles(dir: string): Promise<string[]> {
  const entries = await readdir(dir, { withFileTypes: true });
  const files: string[] = [];
  for (const entry of entries) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      files.push(...(await walkSourceFiles(full)));
    } else if (/\.(ts|tsx)$/.test(entry.name)) {
      files.push(full);
    }
  }
  return files;
}

test("site validator mirrors backend nginx-injection guards and accepts wildcards", () => {
  assert.deepEqual(
    validateSite({
      host: "*.api.example.com",
      upstream: "https://backend.internal:8443",
      tls: { cert_file: "/opt/waffynx/certs/a.crt", key_file: "/opt/waffynx/certs/a.key" },
      paths: [{ path: "/v2", upstream: "v2-svc:9000" }],
      headers: { "X-Frame-Options": "DENY" },
    }),
    {}
  );

  const injected = validateSite({ host: "evil.com; return 200", upstream: "backend:80" });
  assert.ok(injected.host);

  const ipHost = validateSite({ host: "127.0.0.1", upstream: "backend:80" });
  assert.ok(ipHost.host);

  const missingPort = validateSite({ host: "app.example.com", upstream: "backend" });
  assert.ok(missingPort.upstream);

  const halfTls = validateSite({
    host: "app.example.com",
    upstream: "backend:80",
    tls: { cert_file: "/a.crt", key_file: "" },
  });
  assert.ok(halfTls.tls);

  const traversalPath = validateSite({
    host: "app.example.com",
    upstream: "backend:80",
    paths: [{ path: "/../etc" }],
  });
  assert.ok(traversalPath.paths);
});

test("IP and CIDR validators accept IPv4/IPv6 and reject malformed input", () => {
  assert.equal(isValidIP("203.0.113.9"), true);
  assert.equal(isValidIP("2001:db8::1"), true);
  assert.equal(isValidIP("999.0.0.1"), false);
  assert.equal(isValidCIDR("203.0.113.0/24"), true);
  assert.equal(isValidCIDR("2001:db8::/32"), true);
  assert.equal(isValidCIDR("203.0.113.0/33"), false);
});

test("hostile payload tokenizer marks attack indicators without raw HTML", () => {
  const tokens = tokenizeHostilePayload("GET /?q=1 UNION SELECT password FROM users");
  assert.ok(tokens.some((t) => t.hostile && /UNION SELECT/i.test(t.text)));
  assert.equal(tokens.map((t) => t.text).join(""), "GET /?q=1 UNION SELECT password FROM users");
});

test("asStatsFrame preserves live Go runtime telemetry fields", () => {
  const stats = asStatsFrame({
    type: "stats",
    timestamp: "2026-01-01T00:00:00Z",
    goroutines: 42,
    heap_mb: 18.5,
    engine: "basic-go",
  });
  assert.ok(stats);
  assert.equal(stats.goroutines, 42);
  assert.equal(stats.heap_mb, 18.5);
  assert.equal(stats.engine, "basic-go");
});

test("UI source tree enforces zero-mock, zero-XSS, and header-auth SSE invariants", async () => {
  const srcRoot = new URL("../src", import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, "$1");
  const files = await walkSourceFiles(srcRoot);
  assert.ok(files.length > 10, "expected UI source files to be scanned");

  for (const file of files) {
    const raw = await readFile(file, "utf8");
    // Strip block and line comments so explanatory comments never false-positive.
    const code = raw.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/.*$/gm, "");
    assert.doesNotMatch(code, /dangerouslySetInnerHTML|\binnerHTML\b/, `${file} must not inject raw HTML`);
    assert.doesNotMatch(code, /new EventSource|\?token=/, `${file} must not put tokens in URLs or use EventSource`);
    assert.doesNotMatch(code, /Math\.random\s*\(/, `${file} must not synthesize fake telemetry`);
  }
});
