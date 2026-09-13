// The egress boundary — sanitizePackFingerprints must let ONLY the whitelisted metadata leave the runner. Its whole
// job is that a future extractor bug growing a source-bearing hit field can never ride to the server, so the tests
// assert the DROP of an unknown field as much as the passthrough of the known ones.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  sanitizePackFingerprints, collectPackBlocks, packLabel, buildSarif, sarifLevel, CLIENT_VERSION,
  sanitizeProFingerprints, runProPacks, validProBundleResponse, MAX_PRO_BUNDLE_BYTES,
} from "../client-lib.mjs";

// ── release-audit B-P1-7 : the PRO extractors (paid repos) — egress boundary, runner, response guard ──
test("sanitizeProFingerprints keeps numbers/booleans/short strings under identifier keys and DROPS source-bearing keys", () => {
  const clean = sanitizeProFingerprints({
    dotnetSqliFingerprint: { files: [{ file: "R.cs", hits: [{ line: 4, kind: "concat", snippet: "SELECT * FROM x WHERE a='" + "leak" + "'", text: "no", raw: "no", high: true, ports: ["0-65535"] }] }] },
    acFingerprint: { tableCols: { "public.orders": ["id", "org_id"] }, policies: [{ table: "public.orders", roles: ["authenticated"], permitUsing: true }], grants: [], rlsOn: ["public.orders"], sql: "create table …" },
    dockerFingerprint: { files: [{ file: "Dockerfile", froms: [{ line: 1, pinned: false, reason: "latest" }], adds: [] }] },
    "bad name!": { files: [] },
  });
  const hit = clean.dotnetSqliFingerprint.files[0].hits[0];
  assert.deepEqual(hit, { line: 4, kind: "concat", high: true, ports: ["0-65535"] });   // snippet / text / raw gone
  assert.deepEqual(clean.acFingerprint.tableCols, { "public.orders": ["id", "org_id"] }); // dotted identifier keys survive
  assert.equal(clean.acFingerprint.sql, undefined);                                        // `sql` is a source carrier → dropped
  assert.deepEqual(clean.dockerFingerprint.files[0].froms[0], { line: 1, pinned: false, reason: "latest" });
  assert.equal(clean["bad name!"], undefined);
});

test("sanitizeProFingerprints bounds strings (200), array length, depth ; drops functions, NaN, null ; never throws", () => {
  const deep = { a: { b: { c: { d: { e: { f: { g: 1 } } } } } } };
  const clean = sanitizeProFingerprints({
    p: { s: "x".repeat(1000), n: NaN, nil: null, fn: () => 1, list: Array.from({ length: 5 }, (_, i) => i), deep },
  }, { maxItems: 3, maxDepth: 4 });
  assert.equal(clean.p.s.length, 200);
  assert.equal(clean.p.n, undefined);
  assert.equal(clean.p.nil, undefined);
  assert.equal(clean.p.fn, undefined);
  assert.deepEqual(clean.p.list, [0, 1, 2]);
  assert.deepEqual(clean.p.deep, { a: { b: {} } });                                     // cut at maxDepth (pack=0 → deep=1 → a=2 → b=3 → c dropped), never a throw
  assert.deepEqual(sanitizeProFingerprints(null), {});
  assert.deepEqual(sanitizeProFingerprints("x"), {});
  assert.deepEqual(sanitizeProFingerprints({ arr: [1, 2] }), {});                        // a pack must be an object
});

test("runProPacks : file mode keeps only results that carry a list, manifest mode merges deps, sql mode runs once, throws are counted, lockfiles skipped", () => {
  const texts = { "/r/a.js": "x", "/r/b.js": "y", "/r/package.json": "{}", "/r/sub/package.json": "{}", "/r/m/0001.sql": "create table t(id int);", "/r/m/0002.sql": "alter table t;", "/r/package-lock.json": "{}" };
  const seenSql = [];
  const packs = [
    { fpField: "fileFingerprint", mode: "file", match: /\.js$/i, run: (t, f) => ({ file: f, hits: f.endsWith("a.js") ? [{ line: 1, kind: "k" }] : [] }) },
    { fpField: "boomFingerprint", mode: "file", match: /\.js$/i, run: () => { throw new Error("boom"); } },
    { fpField: "scFingerprint", mode: "manifest", match: /(^|\/)package(-lock)?\.json$/i, run: (t, f) => ({ deps: [{ name: "dep-" + f.length, spec: "^1" }] }) },
    { fpField: "acFingerprint", mode: "sql", match: /\.sql$/i, run: (sql) => { seenSql.push(sql); return { tableCols: {}, policies: [], grants: [], rlsOn: [] }; } },
    { fpField: "brokenPack", mode: "file" /* no match regex */, run: () => ({ file: "x", hits: [{ line: 1 }] }) },
  ];
  const { wire, errors, ran } = runProPacks(packs, Object.keys(texts), { read: (f) => texts[f], rel: (f) => f.slice(3) });
  assert.deepEqual(wire.fileFingerprint, { files: [{ file: "a.js", hits: [{ line: 1, kind: "k" }] }] });   // b.js had no hits → not carried
  assert.equal(errors, 2);                                                                              // boom on a.js + b.js
  assert.equal(wire.boomFingerprint, undefined);
  assert.equal(wire.scFingerprint.deps.length, 2);                                                       // two manifests merged, lockfile skipped
  assert.equal(seenSql.length, 1);
  assert.match(seenSql[0], /create table t\(id int\);\nalter table t;\n/);                                // whole schema, once
  assert.equal(wire.brokenPack, undefined);                                                              // a pack without a match regex never runs
  assert.equal(ran, 2 + 2 + 1);                                                                          // file(a,b) + manifest(2) + sql(1)
});

test("validProBundleResponse : accepts a bounded, hashed, well-formed response and refuses everything else", () => {
  const sha = (s) => (s === "bundle" ? "f".repeat(64) : "0".repeat(64));
  const good = { ok: true, version: "v1", sha256: "f".repeat(64), packs: ["dotnetSqliFingerprint"], bundle: "bundle" };
  assert.deepEqual(validProBundleResponse(good, sha), { ok: true });
  assert.equal(validProBundleResponse({ ...good, sha256: "0".repeat(64) }, sha).reason, "hash mismatch");
  assert.equal(validProBundleResponse({ ...good, bundle: "" }, sha).reason, "empty bundle");
  assert.equal(validProBundleResponse({ ...good, bundle: "b".repeat(MAX_PRO_BUNDLE_BYTES + 1) }, () => "f".repeat(64)).reason, "bundle too large");
  assert.equal(validProBundleResponse({ ...good, packs: ["bad key!"] }, sha).reason, "bad pack list");
  assert.equal(validProBundleResponse({ ...good, packs: [] }, sha).reason, "bad pack list");
  assert.equal(validProBundleResponse({ ...good, version: 7 }, sha).reason, "missing version");
  assert.equal(validProBundleResponse({ error: "plan-required" }, sha).reason, "not an ok response");
  assert.equal(validProBundleResponse(null, sha).ok, false);
});

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
