// Vérifie le carve OSS : le shim taint-interproc désactive la passe inter-procédurale
// (vide/false) TOUT EN gardant la détection intra-fonction (taint-core) opérationnelle.
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  findSinkWrappers, interprocHit, buildWrapperRegistries,
  resolveImportedWrappers, buildWrapperRegistry, splitFunctions,
} from "../taint-interproc.mjs";
import { extractSqliFingerprint } from "../sqli-extract.mjs";

test("shim: findSinkWrappers rend une Map vide (branche inter-proc inerte)", () => {
  const w = findSinkWrappers(["function run(q){ db.execute(q); }"], { sinkTest: () => true });
  assert.ok(w instanceof Map);
  assert.equal(w.size, 0);
});

test("shim: interprocHit rend toujours false", () => {
  assert.equal(interprocHit("run(userQuery)", new Map(), () => true), false);
});

test("shim: buildWrapperRegistries rend {} et resolveImportedWrappers une Map vide", () => {
  const regs = buildWrapperRegistries([{ path: "a.js", text: "x" }], { sqli: {} });
  assert.deepEqual(regs, {});
  const r = resolveImportedWrappers("import x", "a.js", regs.sqli /* undefined */);
  assert.ok(r instanceof Map);
  assert.equal(r.size, 0);
});

test("shim: helpers ne throwent pas et rendent la forme vide", () => {
  assert.ok(buildWrapperRegistry([], {}) instanceof Map);
  assert.deepEqual(splitFunctions(["a", "b"]), []);
});

test("intégration: SQLi INTRA-fonction détectée MALGRÉ le shim (taint-core OSS)", () => {
  const src = [
    "function handler(req, res) {",
    "  const q = \"SELECT * FROM users WHERE id = \" + req.query.id;",
    "  db.execute(q);",
    "}",
  ].join("\n");
  const { hits } = extractSqliFingerprint(src, "handler.js");
  assert.ok(hits.length >= 1, `attendu >=1 hit intra-fonction, obtenu ${JSON.stringify(hits)}`);
  // Le hit vient de la passe intra (taint-core), pas de l'inter-proc (désactivée par le shim).
  assert.ok(hits.some((h) => h.kind !== "taint-interproc" && h.kind !== "taint-xfile"),
    `attendu un hit non-interproc, obtenu ${JSON.stringify(hits)}`);
});

test("intégration: une requête CONSTANTE (sans user data) ne fire pas", () => {
  const src = [
    "function safe() {",
    "  const q = \"SELECT * FROM users WHERE id = 1\";",
    "  db.execute(q);",
    "}",
  ].join("\n");
  const { hits } = extractSqliFingerprint(src, "safe.js");
  assert.equal(hits.length, 0, `attendu 0 hit sur requête constante, obtenu ${JSON.stringify(hits)}`);
});
