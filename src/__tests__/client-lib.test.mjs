// The egress boundary — sanitizePackFingerprints must let ONLY the whitelisted metadata leave the runner. Its whole
// job is that a future extractor bug growing a source-bearing hit field can never ride to the server, so the tests
// assert the DROP of an unknown field as much as the passthrough of the known ones.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { sanitizePackFingerprints, collectPackBlocks, packLabel, buildSarif, sarifLevel, CLIENT_VERSION } from "../client-lib.mjs";

// ── release-audit B-P0-2 : the report must be DATA-DRIVEN over the server's pack keys, never a hardcoded list ──
test("collectPackBlocks returns every pack object with count>0, in server order, skipping scalars/arrays/tenant fields", () => {
  const verdict = {
    ok: true, pattern: "none", hardLeaks: 0, reliable: false, gateEntitled: false, leaks: [], gateLevel: "none",
    sqli: { count: 2, hidden: 1, blocking: 0, findings: [{ rule: "gated", table: "a.js:10", detail: "", severity: "high" }] },
    secrets: { count: 1, hidden: 0, blocking: 0, findings: [] },
    xss: { count: 0, hidden: 0, blocking: 0, findings: [] },   // empty → not rendered
    brandNewPack: { count: 3, findings: [] },                    // unknown to the label map → still rendered
    fixableCount: 0, packBlocking: 0,                            // scalars → skipped
  };
  const blocks = collectPackBlocks(verdict);
  assert.deepEqual(blocks.map((b) => b.key), ["sqli", "secrets", "brandNewPack"]);
  assert.equal(blocks[0].label, "SQL injection");
  assert.equal(blocks[1].label, "hardcoded secrets");
  assert.equal(blocks[2].label, "brand new pack");           // camelCase split, never the raw key, never empty
  assert.equal(blocks[0].block.hidden, 1);
  assert.deepEqual(collectPackBlocks(null), []);
  assert.deepEqual(collectPackBlocks("x"), []);
});

test("packLabel covers the 10 free-tier classes + go/dotnet variants and degrades gracefully", () => {
  for (const k of ["sqli", "cmdi", "xss", "ssrf", "xxe", "insecureDeser", "pathTraversal", "secrets", "weakCrypto", "cors", "goSqli", "dotnetCors"]) {
    assert.notEqual(packLabel(k), k, `${k} must have a human label`);
  }
  assert.equal(packLabel(undefined), "finding");
  assert.equal(packLabel(""), "finding");
});

test("buildSarif emits one rule per pack + one result per located pack finding, with severity→level mapping", () => {
  const sarif = buildSarif(["src/db.ts:12  [orders]  unscoped SELECT"], {
    version: "9.9.9",
    findings: [
      { file: "a.js", line: 10, pack: "sqli", rule: "gated", detail: "", severity: "high" },
      { file: "a.js", line: 20, pack: "sqli", rule: "gated", detail: "second", severity: "critical" },
      { file: "b.py", line: 3, pack: "weakCrypto", rule: "md5", detail: "md5 on a secret", severity: "medium" },
      { file: "", line: 1, pack: "xss", rule: "r", detail: "no file → skipped", severity: "high" },
    ],
  });
  const run = sarif.runs[0];
  assert.equal(run.tool.driver.version, "9.9.9");
  assert.deepEqual(run.tool.driver.rules.map((r) => r.id), ["cross-tenant-isolation-leak", "sqli", "weakCrypto"]);
  assert.equal(run.results.length, 4);                                  // 1 leak + 3 located findings (the file-less one skipped)
  assert.equal(run.results[0].ruleId, "cross-tenant-isolation-leak");
  assert.equal(run.results[1].ruleId, "sqli");
  assert.equal(run.results[1].level, "error");
  assert.equal(run.results[1].message.text, "SQL injection finding");   // empty detail → labelled, never an empty message
  assert.equal(run.results[1].locations[0].physicalLocation.region.startLine, 10);
  assert.equal(run.results[3].ruleId, "weakCrypto");
  assert.equal(run.results[3].level, "warning");
  assert.equal(sarifLevel("low"), "note");
  assert.equal(sarifLevel(undefined), "note");
});

test("CLIENT_VERSION tracks package.json (release-audit B-P3-1 : telemetry was stuck at 0.6.0)", () => {
  const pkg = JSON.parse(readFileSync(new URL("../../package.json", import.meta.url), "utf8"));
  assert.equal(CLIENT_VERSION, pkg.version);
});

test("drops any non-whitelisted hit field (a source-bearing 'snippet' never egresses)", () => {
  const dirty = { sqliFingerprint: { files: [{ file: "app/db.js", hits: [
    { line: 12, kind: "concat-sql", snippet: "SELECT * FROM users WHERE id=" + "'secret-value'", raw: "the whole source line" },
  ] }] } };
  const clean = sanitizePackFingerprints(dirty);
  const hit = clean.sqliFingerprint.files[0].hits[0];
  assert.deepEqual(Object.keys(hit).sort(), ["kind", "line"]); // ONLY line + kind survived
  assert.equal(hit.snippet, undefined);
  assert.equal(hit.raw, undefined);
  assert.equal(clean.sqliFingerprint.files[0].file, "app/db.js");
});

test("preserves the real scalar tags (secrets entropy/placeholder, deser/crypto high/secCtx/srcCtx)", () => {
  const clean = sanitizePackFingerprints({
    secretFingerprint: { files: [{ file: "cfg.py", hits: [{ line: 3, kind: "aws-access-key", entropy: 4.2, placeholder: false }] }] },
    deserFingerprint: { files: [{ file: "x.java", hits: [{ line: 9, kind: "java-readobject", high: true, srcCtx: true }] }] },
  });
  assert.deepEqual(clean.secretFingerprint.files[0].hits[0], { line: 3, kind: "aws-access-key", entropy: 4.2, placeholder: false });
  assert.deepEqual(clean.deserFingerprint.files[0].hits[0], { line: 9, kind: "java-readobject", high: true, srcCtx: true });
});

test("coerces types + bounds identifiers; never throws on a malformed shape", () => {
  const clean = sanitizePackFingerprints({
    weird: { files: [{ file: 123, hits: [{ line: "45", kind: "x".repeat(500), placeholder: 1 }] }] },
    bad: null, alsoBad: { files: "not-an-array" },
  });
  const hit = clean.weird.files[0].hits[0];
  assert.equal(hit.line, 45);              // "45" → 45
  assert.equal(hit.kind.length, 200);      // bounded
  assert.equal(hit.placeholder, true);     // 1 → true
  assert.deepEqual(clean.bad, { files: [] });   // a null pack coerces to an empty shape — never throws
  assert.deepEqual(clean.alsoBad.files, []);    // non-array files → []
});

test("empty / non-object input → {} (never throws)", () => {
  assert.deepEqual(sanitizePackFingerprints(undefined), {});
  assert.deepEqual(sanitizePackFingerprints(null), {});
  assert.deepEqual(sanitizePackFingerprints("nope"), {});
});
