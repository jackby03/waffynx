import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

test("dashboard UI package exposes the required verification scripts", async () => {
  const packageJSON = await import("../package.json", { with: { type: "json" } });
  assert.equal(typeof packageJSON.default.scripts.build, "string");
  assert.equal(typeof packageJSON.default.scripts.lint, "string");
  assert.equal(typeof packageJSON.default.scripts.test, "string");
});

// This test used to read `src/services/event-stream.ts`, a file that has never
// existed in this repository, so it failed with ENOENT instead of guarding
// anything. Meanwhile the real client put the JWT in the query string, which is
// exactly what the test was written to prevent: EventSource cannot send an
// Authorization header, so the token ends up in the nginx access log.
test("the event stream authenticates with a header, never a query token", async () => {
  const api = await readFile(new URL("../src/api/wafApi.ts", import.meta.url), "utf8");

  assert.match(api, /Authorization/, "the stream must send the bearer token as a header");
  assert.doesNotMatch(api, /new EventSource/, "EventSource cannot set headers, so it forces the token into the URL");
  assert.doesNotMatch(api, /\?token=/, "a token in the query string lands in access logs and browser history");
});

test("the client entry point does not inject HTML or persist the session itself", async () => {
  const app = await readFile(new URL("../src/main.tsx", import.meta.url), "utf8");
  assert.doesNotMatch(app, /localStorage|dangerouslySetInnerHTML|innerHTML/);
});
