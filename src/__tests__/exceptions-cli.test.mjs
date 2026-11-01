// End to end (main() against a stubbed network) : an active `.slopgrade-exceptions` entry turns one blocking finding into
// an excepted warning and the build passes ; an expired entry, or none, still blocks. Expert panel P1-6.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { main } from "../../isolation-gate.mjs";

const PRO_FREE = { ok: false, status: 402, json: async () => ({ error: "plan-required", gateLevel: "none" }) };
const VERDICT = {
  ok: true, pattern: "none", tenantKey: null, conformancePct: null, hardLeaks: 0, byId: 0, reliable: false,
  gateEntitled: true, leaks: [], gateLevel: "paid", fixableCount: 0, packBlocking: 1,
  sqli: { count: 1, hidden: 0, blocking: 1, findings: [{ rule: "concat-sql", table: "src/report.js:10", detail: "request data in SQL", severity: "high" }] },
};

async function run(exceptionsText) {
  const ws = mkdtempSync(join(tmpdir(), "sg-exc-"));
  if (exceptionsText !== null) writeFileSync(join(ws, ".slopgrade-exceptions"), exceptionsText);
  const env = {
    GITHUB_ACTIONS: "true", GITHUB_SHA: "0123456789abcdef0123456789abcdef01234567", GITHUB_WORKSPACE: ws, FW_UPLOAD_SARIF: "false",
    ACTIONS_ID_TOKEN_REQUEST_URL: "https://oidc.example/token?api-version=2", ACTIONS_ID_TOKEN_REQUEST_TOKEN: "runner-token",
  };
  const realFetch = globalThis.fetch, realLog = console.log, out = [];
  globalThis.fetch = async (url) => {
    if (String(url).startsWith("https://oidc.example/")) return { ok: true, status: 200, json: async () => ({ value: "eyJ.oidc.token" }) };
    if (String(url).endsWith("/api/ci/pro-extractors")) return PRO_FREE;
    return { ok: true, status: 200, json: async () => VERDICT };
  };
  console.log = (...a) => out.push(a.join(" "));
  try { return { code: await main(["--gate"], env), out }; }
  finally { globalThis.fetch = realFetch; console.log = realLog; rmSync(ws, { recursive: true, force: true }); }
}

const future = new Date(Date.now() + 30 * 86_400_000).toISOString().slice(0, 10);

test("without an exception the blocking finding fails the build", async () => {
  const { code, out } = await run(null);
  assert.equal(code, 1);
  assert.ok(out.some((l) => l.startsWith("::error file=src/report.js,line=10")));
});

test("an active exception for that finding passes the build and still reports it, as excepted", async () => {
  const { code, out } = await run(`sqli src/report.js:10 until=${future} owner=@data-team reason=read-only reporting replica, no user input\n`);
  assert.equal(code, 0);
  assert.ok(out.some((l) => l.startsWith("::warning file=src/report.js,line=10")), "annotated as a warning, not an error");
  assert.ok(!out.some((l) => l.startsWith("::error file=src/report.js")));
});

test("an expired exception blocks again and says so", async () => {
  const { code, out } = await run("sqli src/report.js:10 until=2026-01-01 owner=@data-team reason=read-only reporting replica, no user input\n");
  assert.equal(code, 1);
  assert.ok(out.some((l) => l.includes("expired on 2026-01-01")));
});
