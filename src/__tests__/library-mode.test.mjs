// library mode (0.10.6) — the repo-kind detector decides whether the library tier is ever asked, so it is pinned on
// the manifest shapes of the measured corpus: 22 real applications (0 may read as a library) and real libraries.
import { test } from "node:test";
import assert from "node:assert/strict";
import { repoKind, libraryCandidates, requestDeepScan, candidateOutcomesLine, CANDIDATE_DISMISS_HINT, CANDIDATES_RANKED_NOTE } from "../deep-scan.mjs";

test("libraryCandidates takes the detector's per-sink line when present (heisen-slop aea8aa9), else the evidence's", () => {
  const ev = "library-tier (…): ast-taint: the request value read at line 2 reaches os.system() at line 3 (CWE-78)";
  const rows = libraryCandidates([
    { path: "a.py", cwe: "CWE-78", evidence: ev, line: 9 },
    { path: "a.py", cwe: "CWE-78", evidence: ev },
    { path: "a.py", cwe: "CWE-78", evidence: ev, line: 0 },
  ], ["a.py"]);
  assert.deepEqual(rows.map((r) => r.line), [9, 3, 3]);
});

test("candidateOutcomesLine: one line from the server's outcome counts; null when absent or malformed", () => {
  assert.equal(candidateOutcomesLine({ new: 1, persisting: 2, resolved: 3, dismissed: 1, unscanned: 0 }),
    "since the last library run: 3 resolved · 1 dismissed (heisen-ignore) · 2 still open · 1 new");
  assert.match(candidateOutcomesLine({ new: 0, persisting: 0, resolved: 0, dismissed: 0, unscanned: 4 }), /4 not re-scanned$/);
  assert.equal(candidateOutcomesLine(undefined), null, "first library run / older server: nothing printed");
  assert.equal(candidateOutcomesLine({ new: 1, persisting: -1, resolved: 0, dismissed: 0, unscanned: 0 }), null);
  assert.equal(candidateOutcomesLine({ new: "1", persisting: 0, resolved: 0, dismissed: 0, unscanned: 0 }), null);
  assert.match(CANDIDATE_DISMISS_HINT, /heisen-ignore/);
});

const fsOf = (files) => (rel) => (rel in files ? files[rel] : null);

test("a published npm package is a library; an app manifest is not (start script, private, no published surface)", () => {
  const lib = { "package.json": JSON.stringify({ name: "got", exports: "./dist/index.js", files: ["dist"] }) };
  assert.equal(repoKind(fsOf(lib)).kind, "library");
  const dvna = { "package.json": JSON.stringify({ name: "dvna", main: "server.js", scripts: { start: "node server.js" } }) };
  assert.equal(repoKind(fsOf(dvna)).kind, "app", "an Express app publishes a main but has a start script");
  const outline = { "package.json": JSON.stringify({ name: "outline", private: true, exports: "./x" }) };
  assert.equal(repoKind(fsOf(outline)).kind, "app", "a private monorepo root is never a library");
  const pretix = { "package.json": JSON.stringify({ name: "pretix", main: "index.js" }), "pyproject.toml": "[build-system]\n[project]\nname = 'pretix'\n" };
  assert.equal(repoKind(fsOf(pretix)).kind, "app", "a main with no files/exports/types is not a published surface");
});

test("a Python package is a library unless it carries a web-app entry point or depends on a web framework", () => {
  const requests = { "pyproject.toml": "[build-system]\nrequires = ['setuptools']\n[project]\nname = 'requests'\ndependencies = ['urllib3']\n" };
  assert.equal(repoKind(fsOf(requests)).kind, "library");
  const netbox = { ...requests, "netbox/manage.py": "import django" };
  assert.equal(repoKind(fsOf(netbox), () => ["netbox"]).kind, "app", "a manage.py one level down makes it a Django app");
  const flaskApp = { "pyproject.toml": "[build-system]\n[project]\nname = 'shop'\ndependencies = ['flask>=3']\n" };
  assert.equal(repoKind(fsOf(flaskApp)).kind, "app", "a web-framework dependency means an application");
  const setup = { "setup.py": "from setuptools import setup\nsetup(name='markupsafe', packages=['markupsafe'])\n" };
  assert.equal(repoKind(fsOf(setup)).kind, "library");
  assert.equal(repoKind(fsOf({})).kind, "app", "no manifest at all is never assumed to be a library");
  assert.equal(repoKind(fsOf({ "package.json": "{not json" })).kind, "app", "an unreadable manifest is never a library");
});

test("libraryCandidates: only paths this run sent, malformed rows dropped, line taken from the evidence", () => {
  const rows = libraryCandidates([
    { path: "lib/read.js", cwe: "CWE-22", evidence: "library-tier (caller-controlled param → sink; human-triage, not 0-FP): ast-taint: … reaches fs.readFileSync() at line 3 (CWE-22)" },
    { path: "not/sent.js", cwe: "CWE-78", evidence: "x at line 1" },
    { path: "lib/read.js", cwe: "78", evidence: "bad cwe" },
  ], ["lib/read.js"]);
  assert.deepEqual(rows, [{ file: "lib/read.js", line: 3, rule: "CWE-22", detail: rows[0].detail }]);
  assert.deepEqual(libraryCandidates(undefined, ["a"]), []);
});

test("requestDeepScan sends `library: true` only when asked", async () => {
  const bodies = [];
  const post = async (_u, body) => { bodies.push(JSON.parse(body)); return { status: 200, json: async () => ({ ok: true, findings: [], scanned: 0, unanswered: 0 }) }; };
  await requestDeepScan(post, "https://app.slopgrade.ai", "t", "s", []);
  await requestDeepScan(post, "https://app.slopgrade.ai", "t", "s", [], true);
  assert.equal("library" in bodies[0], false);
  assert.equal(bodies[1].library, true);
});

test("the ranked note names the rule it applied (fixed first, heisen-ignore last)", () => {
  assert.match(CANDIDATES_RANKED_NOTE, /fixed before/);
  assert.match(CANDIDATES_RANKED_NOTE, /heisen-ignore/);
});
