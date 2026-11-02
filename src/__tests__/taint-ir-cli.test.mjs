// The shared tree engine in the client, through the VENDORED runtime (python / javascript / typescript / tsx only) :
// php / go are mapped in ts-ir but their wasm is absent — initIr must skip them, not throw (a throw turns the tree off
// for every language through isolation-gate's catch). Mirror of maxor-tech/slopgrade#1587.
import { test, before } from "node:test";
import assert from "node:assert/strict";
import { initIr, irReady } from "../ts-ir.mjs";
import { vendoredRuntime } from "../ts-vendor.mjs";
import { extractSqliIr } from "../sqli-ir.mjs";

before(async () => {
  const vr = vendoredRuntime();
  assert.ok(vr, "the vendored runtime loads");
  await initIr(undefined, vr);   // the exact call isolation-gate.mjs makes : every mapped grammar, php / go included
});

test("the vendored runtime keeps the tree for its grammars and skips the absent ones", () => {
  assert.equal(irReady("a.py"), true);
  assert.equal(irReady("a.ts"), true);
  assert.equal(irReady("a.php"), false);
  assert.equal(irReady("a.go"), false);
});

test("sweep shapes : regex .exec and a ternary condition are not SQL ; a real build still fires", () => {
  assert.deepEqual(extractSqliIr("export async function POST(req) {\n  const t = await req.text();\n  let m;\n  while ((m = fileRegex.exec(t)) !== null) { out.push('SELECT ' + m[1]); }\n}\n", "route.ts"), []);
  assert.deepEqual(extractSqliIr('def rm(conn, path, ids=()):\n    ph = ",".join("?" for _ in ids)\n    conn.execute("SELECT 1 FROM h WHERE p=?" + (f" AND id NOT IN ({ph})" if ids else ""), (path, *ids))\n', "gen.py"), []);
  assert.deepEqual((extractSqliIr("def q():\n    cur.execute(\"SELECT * FROM t WHERE n = '%s'\" % request.args['n'])\n", "a.py") ?? []).map((h) => h.line), [2]);
});
