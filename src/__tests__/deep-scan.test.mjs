// deep scan — the opt-in source-egress path. These pin WHAT leaves (only sink-bearing, engine-modelled files, bounded),
// that a server answer cannot annotate a file we did not send, and that every failure is a no-answer (fail open).
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  sinkFiles, selectDeepUnits, hasSinkMarker, prChangedPaths, validHeisenResponse, evidenceLine, heisenFeed, requestDeepScan, splitAgainstFeed, deepScanNudge, isPaidVerdict,
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

test("selectDeepUnits: hit files first, then files with a sink marker; a file with no sink marker is never sent", () => {
  const src = {
    "a.py": "import os",                                   // extractor hit (no marker needed)
    "helper.py": "def f(p):\n    return subprocess.check_output(p, shell=True)", // no hit, but a sink marker
    "pure.py": "def add(a, b):\n    return a + b",          // no hit, no marker → stays on the runner
    "b.cs": "Process.Start(x)",                            // no engine for C#
    "big.py": "x".repeat(DEEP_MAX_UNIT_CHARS + 1),
    "empty.js": "",
  };
  const read = (p) => src[p] ?? null;
  const r = selectDeepUnits(Object.keys(src), read, ["a.py", "big.py"]);
  assert.deepEqual(r.units.map((u) => u.path), ["a.py", "helper.py"]);
  assert.equal(r.skipped, 1, "the oversize hit file is counted as skipped");
});

test("every (language × class) the hosted engines model passes the pre-filter — no detector is unreachable", () => {
  const fx = JSON.parse(readFileSync(new URL("./fixtures/heisen-classes.json", import.meta.url), "utf8"));
  const cells = Object.entries(fx).filter(([k]) => k !== "_note").flatMap(([lang, m]) => Object.entries(m).map(([cls, code]) => [`${lang}:${cls}`, code]));
  assert.ok(cells.length >= 116, `the fixture covers every modelled cell (got ${cells.length})`);
  const missed = cells.filter(([, code]) => !hasSinkMarker(code)).map(([id]) => id);
  assert.deepEqual(missed, [], "a class whose positive never matches SINK_HINTS is a detector no customer file can reach");
});

test("files with no security marker stay on the runner (the egress promise holds after widening)", () => {
  const plain = [
    "def add(a, b):\n    return a + b\n",
    "export function formatPrice(n) { return `$${n.toFixed(2)}`; }\n",
    "package util\nfunc Max(a, b int) int { if a > b { return a }; return b }\n",
    "public class Point { int x; int y; Point(int x, int y) { this.x = x; this.y = y; } }\n",
    "class Greeter\n  def hello(name)\n    \"Hello, #{name}\"\n  end\nend\n",
    "import React from 'react';\nexport const Title = ({ children }) => <h1 className=\"title\">{children}</h1>;\n",
  ];
  for (const code of plain) assert.equal(hasSinkMarker(code), false, code);
});

test("selectDeepUnits: under the cap, a marker file that ALSO reads request input goes before a marker-only one", () => {
  const src = { "a_config.py": "SESSION_COOKIE_SECURE = False", "z_view.py": "def v(request):\n    return open(request.GET['f'])" };
  const r = selectDeepUnits(Object.keys(src), (p) => src[p]);
  assert.deepEqual(r.units.map((u) => u.path), ["z_view.py", "a_config.py"]);
});

test("selectDeepUnits: on a PR, the files it changed go first — but being in the PR never widens egress", () => {
  const src = { "a_hit.py": "import os", "b_view.py": "def v(request):\n    return open(request.GET['f'])", "z_pr.py": "SESSION_COOKIE_SECURE = False", "z_pr_plain.py": "def add(a, b):\n    return a + b" };
  const r = selectDeepUnits(Object.keys(src), (p) => src[p], ["a_hit.py"], ["z_pr.py", "z_pr_plain.py"]);
  assert.deepEqual(r.units.map((u) => u.path), ["z_pr.py", "a_hit.py", "b_view.py"], "PR file first; a PR file with no marker stays on the runner");
  assert.equal(r.fromPr, 1);
});

test("selectDeepUnits: under the cap, the PR's files survive when the repo has more candidates than DEEP_MAX_UNITS", () => {
  const many = Array.from({ length: DEEP_MAX_UNITS + 10 }, (_, i) => `a${String(i).padStart(3, "0")}.py`);
  const r = selectDeepUnits([...many, "zz_changed.py"], () => "os.system(x)", [], ["zz_changed.py"]);
  assert.equal(r.units[0].path, "zz_changed.py");
  assert.equal(r.units.length, DEEP_MAX_UNITS);
});

test("prChangedPaths reads the PR's files from git (base...head), null off-PR or when git cannot answer", () => {
  const base = "a".repeat(40), head = "b".repeat(40);
  const ev = () => ({ pull_request: { base: { sha: base }, head: { sha: head } } });
  let seen = null;
  const git = (args) => { seen = args; return "src/a.py\0lib/b.js\0"; };
  assert.deepEqual(prChangedPaths({ GITHUB_EVENT_NAME: "pull_request" }, ev, git), ["src/a.py", "lib/b.js"]);
  assert.deepEqual(seen, ["diff", "--name-only", "--diff-filter=d", "-z", `${base}...${head}`]);
  assert.equal(prChangedPaths({ GITHUB_EVENT_NAME: "push" }, ev, git), null, "push runs keep the repo-wide order");
  assert.equal(prChangedPaths({ GITHUB_EVENT_NAME: "pull_request" }, () => ({ pull_request: { base: { sha: "main" }, head: { sha: head } } }), git), null, "a ref name is not a SHA — never passed to git");
  assert.equal(prChangedPaths({ GITHUB_EVENT_NAME: "pull_request" }, ev, () => { throw new Error("bad object"); }), null, "shallow checkout → null");
  assert.equal(prChangedPaths({ GITHUB_EVENT_NAME: "pull_request" }, () => { throw new Error("ENOENT"); }, git), null);
});

test("selectDeepUnits enforces the file and character caps", () => {
  const many = Array.from({ length: DEEP_MAX_UNITS + 5 }, (_, i) => `f${String(i).padStart(2, "0")}.py`);
  const r2 = selectDeepUnits(many, () => "os.system(x)");
  assert.equal(r2.units.length, DEEP_MAX_UNITS);
  assert.equal(r2.skipped, 5);
  const chunk = "open(" + "x".repeat(DEEP_MAX_UNIT_CHARS - 5);
  const r3 = selectDeepUnits(Array.from({ length: 20 }, (_, i) => `g${String(i).padStart(2, "0")}.py`), () => chunk);
  assert.ok(r3.chars <= DEEP_MAX_TOTAL_CHARS);
  assert.equal(r3.units.length, Math.floor(DEEP_MAX_TOTAL_CHARS / DEEP_MAX_UNIT_CHARS));
});

test("a throwing reader is a skipped hit file, never a crash", () => {
  const r = selectDeepUnits(["a.py"], () => { throw new Error("EACCES"); }, ["a.py"]);
  assert.deepEqual(r, { units: [], skipped: 1, chars: 0, fromPr: 0 });
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

test("splitAgainstFeed: a deep-scan row on a location another pack already reported only confirms it", () => {
  const feed = [{ file: "app/views.py", line: 10, pack: "cmdiFingerprint", rule: "command-injection" }];
  const rows = [
    { file: "app/views.py", line: 10, pack: "heisen", rule: "CWE-78" },
    { file: "app/views.py", line: 22, pack: "heisen", rule: "CWE-89" },
  ];
  const { fresh, confirmed } = splitAgainstFeed(rows, feed);
  assert.deepEqual(fresh.map((r) => r.line), [22]);
  assert.deepEqual(confirmed.map((r) => r.line), [10]);
});

test("isPaidVerdict: gateLevel is exact — public / free-oss are entitled but NOT paid; gateEntitled only as a fallback", () => {
  assert.equal(isPaidVerdict({ gateLevel: "paid", gateEntitled: true }), true);
  assert.equal(isPaidVerdict({ gateLevel: "public", gateEntitled: true }), false, "a public repo is entitled, not paid");
  assert.equal(isPaidVerdict({ gateLevel: "free-oss", gateEntitled: true }), false, "the free private repo is not paid");
  assert.equal(isPaidVerdict({ gateLevel: "none", gateEntitled: false }), false);
  assert.equal(isPaidVerdict({ gateEntitled: true }), true, "old server without gateLevel: previous behavior");
  assert.equal(isPaidVerdict(null), false);
});

test("deepScanNudge: only a PAID repo without the deep scan is invited", () => {
  const msg = deepScanNudge({ deepScan: false, paid: true });
  assert.match(msg, /deep-scan: "true"/);
  assert.match(msg, /Opt-in/);
  assert.equal(deepScanNudge({ deepScan: true, paid: true }), null, "already on");
  assert.equal(deepScanNudge({ deepScan: false, paid: false }), null, "public / free-oss / none: the deep scan would 402");
});
