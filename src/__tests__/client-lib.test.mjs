// The egress boundary — sanitizePackFingerprints must let ONLY the whitelisted metadata leave the runner. Its whole
// job is that a future extractor bug growing a source-bearing hit field can never ride to the server, so the tests
// assert the DROP of an unknown field as much as the passthrough of the known ones.
import { test } from "node:test";
import assert from "node:assert/strict";
import { sanitizePackFingerprints } from "../client-lib.mjs";

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
