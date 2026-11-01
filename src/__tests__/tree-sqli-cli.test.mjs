// End to end (main() against a stubbed network) : the client reads Python / JS / TS SQL on the syntax tree, with the
// vendored runtime (vendor/tree-sitter/). A bound parameter tuple that carries an f-string is not sent as SQL injection
// (the line reader flagged it — 2026-11-01 real-code sweep) ; an interpolated query still is.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { main } from "../../isolation-gate.mjs";
import { extractSqliFingerprint } from "../sqli-extract.mjs";
import { vendoredRuntime } from "../ts-vendor.mjs";

const BOUND = `@app.post("/transfer")\ndef transfer(data: TransferIn):\n    to_user_id = data.to_user_id\n    cursor.execute(\n        "INSERT INTO tx (user_id, description) VALUES (?, ?)",\n        (1, f'Transfer to user {to_user_id}'),\n    )\n`;
const VULN = `def q():\n    n = request.args["n"]\n    cur.execute(f"SELECT * FROM t WHERE n = '{n}'")\n`;

async function sentSqli() {
  const ws = mkdtempSync(join(tmpdir(), "sg-tree-"));
  mkdirSync(join(ws, "app"), { recursive: true });
  writeFileSync(join(ws, "app", "bound.py"), BOUND);
  writeFileSync(join(ws, "app", "vuln.py"), VULN);
  const env = { GITHUB_ACTIONS: "true", GITHUB_SHA: "0123456789abcdef0123456789abcdef01234567", GITHUB_WORKSPACE: ws, FW_UPLOAD_SARIF: "false",
    ACTIONS_ID_TOKEN_REQUEST_URL: "https://oidc.example/token?api-version=2", ACTIONS_ID_TOKEN_REQUEST_TOKEN: "runner-token" };
  const realFetch = globalThis.fetch, realLog = console.log;
  let body = null;
  globalThis.fetch = async (url, init) => {
    if (String(url).startsWith("https://oidc.example/")) return { ok: true, status: 200, json: async () => ({ value: "eyJ.oidc.token" }) };
    if (String(url).endsWith("/api/ci/pro-extractors")) return { ok: false, status: 402, json: async () => ({ error: "plan-required", gateLevel: "none" }) };
    if (init?.body) body = JSON.parse(init.body);
    return { ok: true, status: 200, json: async () => ({ ok: true, pattern: "none", hardLeaks: 0, leaks: [], gateLevel: "free", packBlocking: 0 }) };
  };
  console.log = () => {};
  try { await main([], env); } finally { globalThis.fetch = realFetch; console.log = realLog; rmSync(ws, { recursive: true, force: true }); }
  return Object.fromEntries((body?.sqliFingerprint?.files ?? []).map((f) => [f.file.split("/").pop(), f.hits.length]));
}

test("the vendored runtime loads (vendor/tree-sitter/ ships with the client) and parses Python", async () => {
  const rt = vendoredRuntime();
  assert.equal(typeof rt?.Parser, "function", "vendor/tree-sitter/tree-sitter.js exports Parser");
  assert.equal(typeof rt?.Language?.load, "function", "and Language.load");
  assert.match(rt.dir.replace(/\\/g, "/"), /vendor\/tree-sitter$/);
  const { initIr, parseFile } = await import("../ts-ir.mjs");
  await initIr(["python"], rt);
  const p = parseFile("cur.execute(q)\n", "a.py");
  assert.equal(p.lang, "python");
  assert.equal(p.tree.rootNode.type, "module");
  assert.equal(p.tree.rootNode.namedChildren[0].type, "expression_statement");
});

test("on the tree : the bound f-string is not sent, the interpolated query is", async () => {
  assert.ok(extractSqliFingerprint(BOUND, "app/bound.py", new Map()).hits.length > 0, "precondition : the line reader alone flags BOUND");
  const sent = await sentSqli();
  assert.equal(sent["vuln.py"], 1);
  assert.equal(sent["bound.py"], undefined);
});
