// End to end (main() against a stubbed network) : the Action input `untrusted-inputs` (env FW_UNTRUSTED_INPUTS) turns
// CLI arguments / queue payloads into untrusted sources for THIS repo only (expert panel P1-5 ; opt-in per repo).
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { main } from "../../isolation-gate.mjs";

const CLI = `import os, sys\n\ndef main():\n    target = sys.argv[1]\n    os.system("ping -c 1 " + target)\n`;

async function sentCmdi(untrusted) {
  const ws = mkdtempSync(join(tmpdir(), "sg-optin-"));
  mkdirSync(join(ws, "tool"), { recursive: true });
  writeFileSync(join(ws, "tool", "ping.py"), CLI);
  const env = { GITHUB_ACTIONS: "true", GITHUB_SHA: "0123456789abcdef0123456789abcdef01234567", GITHUB_WORKSPACE: ws, FW_UPLOAD_SARIF: "false",
    ACTIONS_ID_TOKEN_REQUEST_URL: "https://oidc.example/token?api-version=2", ACTIONS_ID_TOKEN_REQUEST_TOKEN: "runner-token",
    ...(untrusted === undefined ? {} : { FW_UNTRUSTED_INPUTS: untrusted }) };
  const realFetch = globalThis.fetch, realLog = console.log, out = [];
  let body = null;
  globalThis.fetch = async (url, init) => {
    if (String(url).startsWith("https://oidc.example/")) return { ok: true, status: 200, json: async () => ({ value: "eyJ.oidc.token" }) };
    if (String(url).endsWith("/api/ci/pro-extractors")) return { ok: false, status: 402, json: async () => ({ error: "plan-required", gateLevel: "none" }) };
    if (init?.body) body = JSON.parse(init.body);
    return { ok: true, status: 200, json: async () => ({ ok: true, pattern: "none", hardLeaks: 0, leaks: [], gateLevel: "free", packBlocking: 0 }) };
  };
  console.log = (...a) => out.push(a.join(" "));
  try { await main([], env); } finally { globalThis.fetch = realFetch; console.log = realLog; rmSync(ws, { recursive: true, force: true }); }
  return { hits: (body?.cmdiFingerprint?.files ?? []).flatMap((f) => f.hits).length, out };
}

test("default : a CLI tool's own argv is not sent as command injection", async () => {
  const r = await sentCmdi(undefined);
  assert.equal(r.hits, 0);
  assert.ok(!r.out.some((l) => l.includes("extra untrusted sources")));
});

test("untrusted-inputs: cli — argv reaching os.system is sent, and the log names the opt-in", async () => {
  const r = await sentCmdi("cli");
  assert.equal(r.hits, 1);
  assert.ok(r.out.some((l) => l.includes("extra untrusted sources on for this repo : cli")));
});

test("CONTROL : the opt-in does not persist into the next run of the same process", async () => {
  await sentCmdi("cli");
  assert.equal((await sentCmdi(undefined)).hits, 0);
});

test("a typo in untrusted-inputs is named as a warning, never silently ignored", async () => {
  const r = await sentCmdi("cli argv");
  assert.equal(r.hits, 1, "the known token still applies");
  assert.ok(r.out.some((l) => l.startsWith("::warning") && l.includes("untrusted-inputs : ignored argv")));
});
