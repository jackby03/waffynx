import test from "node:test";
import assert from "node:assert/strict";

test("dashboard UI package exposes the required verification scripts", async () => {
  const packageJSON = await import("../package.json", { with: { type: "json" } });
  assert.equal(typeof packageJSON.default.scripts.build, "string");
  assert.equal(typeof packageJSON.default.scripts.lint, "string");
  assert.equal(typeof packageJSON.default.scripts.test, "string");
});

test("dashboard security invariants stay explicit in the client", async () => {
  const stream = await (await import("node:fs/promises")).readFile(new URL("../src/services/event-stream.ts", import.meta.url), "utf8");
  const app = await (await import("node:fs/promises")).readFile(new URL("../src/main.tsx", import.meta.url), "utf8");
  assert.match(stream, /Authorization/);
  assert.doesNotMatch(stream, /EventSource/);
  assert.doesNotMatch(app, /localStorage|dangerouslySetInnerHTML|innerHTML/);
});
