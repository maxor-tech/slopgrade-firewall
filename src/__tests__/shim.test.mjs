// Verifies the OSS carve: the taint-interproc shim disables the inter-procedural pass
// (empty/false) WHILE keeping intra-function detection (taint-core) operational.
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  findSinkWrappers, interprocHit, buildWrapperRegistries,
  resolveImportedWrappers, buildWrapperRegistry, splitFunctions,
} from "../taint-interproc.mjs";
import { extractSqliFingerprint } from "../sqli-extract.mjs";

test("shim: findSinkWrappers returns an empty Map (inter-proc branch inert)", () => {
  const w = findSinkWrappers(["function run(q){ db.execute(q); }"], { sinkTest: () => true });
  assert.ok(w instanceof Map);
  assert.equal(w.size, 0);
});

test("shim: interprocHit always returns false", () => {
  assert.equal(interprocHit("run(userQuery)", new Map(), () => true), false);
});

test("shim: buildWrapperRegistries returns {} and resolveImportedWrappers an empty Map", () => {
  const regs = buildWrapperRegistries([{ path: "a.js", text: "x" }], { sqli: {} });
  assert.deepEqual(regs, {});
  const r = resolveImportedWrappers("import x", "a.js", regs.sqli /* undefined */);
  assert.ok(r instanceof Map);
  assert.equal(r.size, 0);
});

test("shim: helpers do not throw and return the empty shape", () => {
  assert.ok(buildWrapperRegistry([], {}) instanceof Map);
  assert.deepEqual(splitFunctions(["a", "b"]), []);
});

test("integration: INTRA-function SQLi detected DESPITE the shim (taint-core OSS)", () => {
  const src = [
    "function handler(req, res) {",
    "  const q = \"SELECT * FROM users WHERE id = \" + req.query.id;",
    "  db.execute(q);",
    "}",
  ].join("\n");
  const { hits } = extractSqliFingerprint(src, "handler.js");
  assert.ok(hits.length >= 1, `expected >=1 intra-function hit, got ${JSON.stringify(hits)}`);
  // The hit comes from the intra pass (taint-core), not inter-proc (disabled by the shim).
  assert.ok(hits.some((h) => h.kind !== "taint-interproc" && h.kind !== "taint-xfile"),
    `expected a non-interproc hit, got ${JSON.stringify(hits)}`);
});

test("integration: a CONSTANT query (no user data) does not fire", () => {
  const src = [
    "function safe() {",
    "  const q = \"SELECT * FROM users WHERE id = 1\";",
    "  db.execute(q);",
    "}",
  ].join("\n");
  const { hits } = extractSqliFingerprint(src, "safe.js");
  assert.equal(hits.length, 0, `expected 0 hits on a constant query, got ${JSON.stringify(hits)}`);
});
