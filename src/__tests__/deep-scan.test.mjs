// deep scan — the opt-in source-egress path. These pin WHAT leaves (only sink-bearing, engine-modelled files, bounded),
// that a server answer cannot annotate a file we did not send, and that every failure is a no-answer (fail open).
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  sinkFiles, selectDeepUnits, validHeisenResponse, evidenceLine, heisenFeed, requestDeepScan,
  DEEP_MAX_UNITS, DEEP_MAX_UNIT_CHARS, DEEP_MAX_TOTAL_CHARS,
} from "../deep-scan.mjs";

test("sinkFiles = the files a pack recorded hits for (deduped, sorted); hitless files are not candidates", () => {
  const fps = {
    sqliFingerprint: { files: [{ file: "b/db.py", hits: [{ line: 3 }] }, { file: "c/none.py", hits: [] }] },
    cmdiFingerprint: { files: [{ file: "a/run.js", hits: [{ line: 1 }] }, { file: "b/db.py", hits: [{ line: 9 }] }] },
    junk: null,
  };
  assert.deepEqual(sinkFiles(fps), ["a/run.js", "b/db.py"]);
  assert.deepEqual(sinkFiles(undefined), []);
});

test("selectDeepUnits keeps engine-modelled files only and enforces every cap", () => {
  const read = (p) => ({ "a.py": "import os", "b.cs": "x", "big.py": "x".repeat(DEEP_MAX_UNIT_CHARS + 1), "empty.js": "" }[p] ?? null);
  const r = selectDeepUnits(["a.py", "b.cs", "big.py", "empty.js", "gone.go"], read);
  assert.deepEqual(r.units, [{ path: "a.py", code: "import os" }], ".cs has no engine; oversize/empty/unreadable are skipped");
  assert.equal(r.skipped, 3);
  const many = Array.from({ length: DEEP_MAX_UNITS + 5 }, (_, i) => `f${i}.py`);
  const r2 = selectDeepUnits(many, () => "x");
  assert.equal(r2.units.length, DEEP_MAX_UNITS);
  assert.equal(r2.skipped, 5);
  const chunk = "x".repeat(DEEP_MAX_UNIT_CHARS);
  const r3 = selectDeepUnits(Array.from({ length: 20 }, (_, i) => `g${i}.py`), () => chunk);
  assert.ok(r3.chars <= DEEP_MAX_TOTAL_CHARS);
  assert.equal(r3.units.length, Math.floor(DEEP_MAX_TOTAL_CHARS / DEEP_MAX_UNIT_CHARS));
});

test("a throwing reader is a skipped file, never a crash", () => {
  const r = selectDeepUnits(["a.py"], () => { throw new Error("EACCES"); });
  assert.deepEqual(r, { units: [], skipped: 1, chars: 0 });
});

test("validHeisenResponse accepts the route's shape and rejects anything else", () => {
  const ok = { ok: true, findings: [{ path: "a.py", cwe: "CWE-78", p: 0.94, evidence: "e" }], scanned: 1, unanswered: 0, blocking: 0 };
  assert.equal(validHeisenResponse(ok), true);
  assert.equal(validHeisenResponse({ ...ok, ok: false }), false);
  assert.equal(validHeisenResponse({ ...ok, findings: [{ path: "a.py", cwe: "78", p: 1, evidence: "" }] }), false);
  assert.equal(validHeisenResponse({ ...ok, scanned: "1" }), false);
  assert.equal(validHeisenResponse(null), false);
});

test("evidenceLine takes the SINK line from the engine evidence", () => {
  assert.equal(evidenceLine("ast-taint: the request value read at line 6 reaches os.system() at line 7 (CWE-78)"), 7);
  assert.equal(evidenceLine("something at line 4"), 4);
  assert.equal(evidenceLine("no location"), 1);
});

test("heisenFeed drops a finding on a path this run never sent, and is advisory (medium)", () => {
  const feed = heisenFeed([
    { path: "a.py", cwe: "CWE-78", p: 0.94, evidence: "the request value read at line 2 reaches os.system() at line 3" },
    { path: "../../etc/passwd", cwe: "CWE-22", p: 0.94, evidence: "spoofed" },
  ], ["a.py"]);
  assert.deepEqual(feed, [{ file: "a.py", line: 3, pack: "heisen", rule: "CWE-78", detail: "the request value read at line 2 reaches os.system() at line 3", severity: "medium" }]);
});

test("requestDeepScan: 402 → plan-required, 5xx / malformed / throw → unavailable, 200 → ok with the body", async () => {
  const resp = (status, body) => async () => ({ status, json: async () => body });
  let sentUrl = "", sentBody = "";
  const capture = async (url, body) => { sentUrl = url; sentBody = body; return { status: 200, json: async () => ({ ok: true, findings: [], scanned: 1, unanswered: 0 }) }; };
  const ok = await requestDeepScan(capture, "https://app.slopgrade.ai", "tok", "sha1", [{ path: "a.py", code: "x" }]);
  assert.equal(ok.state, "ok");
  assert.equal(sentUrl, "https://app.slopgrade.ai/api/ci/heisen");
  assert.deepEqual(JSON.parse(sentBody), { oidcToken: "tok", sha: "sha1", units: [{ path: "a.py", code: "x" }] });
  assert.deepEqual(await requestDeepScan(resp(402, {}), "o", "t", "s", []), { state: "plan-required" });
  assert.deepEqual(await requestDeepScan(resp(503, {}), "o", "t", "s", []), { state: "unavailable", status: 503 });
  assert.deepEqual(await requestDeepScan(resp(200, { ok: true }), "o", "t", "s", []), { state: "unavailable", status: "malformed" });
  assert.deepEqual(await requestDeepScan(async () => { throw new Error("ECONNRESET"); }, "o", "t", "s", []), { state: "unavailable", status: "network" });
});
