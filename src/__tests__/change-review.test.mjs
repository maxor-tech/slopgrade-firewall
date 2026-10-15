// Change review (0.10.13): the PR's hunks go to heisen-slop's diff-reading 55M. These pin the hunk parsing (what leaves
// the runner), the order and cap (removals first, 64 max), the response validation, and prHunks on a REAL repository.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, rmSync, mkdirSync, readFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parseHunks, selectHunks, prHunks, validChangeReview, windowsOf, CHANGE_MAX_HUNKS, CHANGE_REVIEW_EXTS, CHANGE_REVIEW_PATHSPEC } from "../change-review.mjs";

const sh = (cwd, ...args) => execFileSync("git", args, { cwd, encoding: "utf8" });

// C (0.10.21, heisen-slop §4.10) and C++ (0.10.22, routed detector §4.12) are measured for the diff reviewer only. The
// deep scan has none of these engines, so its extension list stays without them. Rust (0.10.23, §4.13) too.
test("C (.c / .h), C++ (.cpp .cc .cxx .hpp .hh) and Rust (.rs) hunks are reviewed; the deep scan's list stays without them", async () => {
  const { DEEP_SCAN_EXTS, DEEP_SCAN_PATHSPEC } = await import("../deep-scan.mjs");
  const file = (p) => [`diff --git a/${p} b/${p}`, `--- a/${p}`, `+++ b/${p}`, "@@ -3,3 +3,2 @@", " int n = len;", "-if (n > cap) return -1;", " memcpy(buf, src, n);"];
  const r = parseHunks([...file("src/io.c"), ...file("include/IO.H"), ...file("src/io.cpp"), ...file("src/io.HPP"), ...file("src/lib.rs")].join("\n"));
  assert.deepEqual(r.map((h) => [h.path, h.newStart, h.removes]), [["src/io.c", 3, 1], ["include/IO.H", 3, 1], ["src/io.cpp", 3, 1], ["src/io.HPP", 3, 1], ["src/lib.rs", 3, 1]]);
  for (const p of ["a.py", "a.tsx", "a.phtml", "a.go", "a.cc", "a.cxx", "a.hh"]) assert.ok(CHANGE_REVIEW_EXTS.test(p), `${p}: reviewed`);
  for (const p of ["src/io.c", "io.h", "io.cpp", "io.hpp", "lib.rs"]) assert.ok(!DEEP_SCAN_EXTS.test(p), `${p} never becomes a deep-scan unit`);
  assert.deepEqual(CHANGE_REVIEW_PATHSPEC, [...DEEP_SCAN_PATHSPEC, ...["c", "h", "cpp", "cc", "cxx", "hpp", "hh", "rs"].map((e) => `:(glob,icase)**/*.${e}`)]);
});

test("parseHunks: ' '/'-'/'+' lines with the new-side start; a new file is a window; unmodelled and newline-marker lines left out", () => {
  const diff = [
    "diff --git a/app/files.py b/app/files.py",
    "index 1..2 100644",
    "--- a/app/files.py",
    "+++ b/app/files.py",
    "@@ -10,5 +10,3 @@ def read(p):",
    " def read(p):",
    "-    if '..' in p:",
    "-        raise ValueError(p)",
    "     return open(p)",
    "\\ No newline at end of file",
    "diff --git a/new.py b/new.py",
    "new file mode 100644",
    "--- /dev/null",
    "+++ b/new.py",
    "@@ -0,0 +1 @@",
    "+x = 1",
    "diff --git a/README.md b/README.md",
    "--- a/README.md",
    "+++ b/README.md",
    "@@ -1 +1 @@",
    "-a",
    "+b",
  ].join("\n");
  assert.deepEqual(parseHunks(diff), [{
    path: "app/files.py", newStart: 10, removes: 2,
    text: " def read(p):\n-    if '..' in p:\n-        raise ValueError(p)\n     return open(p)",
  }, { path: "new.py", newStart: 1, removes: 0, text: "+x = 1" }]);
});

// 0.10.15 dropped new files and hunks over 40 lines: 52 % of the commits that really introduced a held-out CVE put the
// bug in one (heisen-slop docs/55M-REAL-CVE.md §4.6). They are now cut into windows the reviewer can read — the same cut
// as heisen-slop scripts/action_hunks.py windows_of (tests/test_szz_eval.py pins the same cases).
test("parseHunks: a hunk over 40 lines is cut into windows, not dropped", () => {
  const big = ["--- a/a.js", "+++ b/a.js", "@@ -1,41 +1,41 @@", ...Array.from({ length: 41 }, (_, i) => `-l${i}`)].join("\n");
  const r = parseHunks("diff --git a/a.js b/a.js\n" + big);
  assert.deepEqual(r.map((h) => [h.newStart, h.text.split("\n").length, h.removes]), [[1, 40, 40], [1, 1, 1]]);
});

test("windowsOf: <= 40 lines and <= 4,000 characters each, new-side line numbers kept, unchanged windows dropped", () => {
  const lines = [...Array.from({ length: 90 }, (_, i) => `+line ${i}`), "-gone", " ctx"];
  const ws = windowsOf("a.py", 10, lines);
  assert.deepEqual(ws.map((w) => w.text.split("\n").length), [40, 40, 12]);
  assert.deepEqual(ws.map((w) => w.newStart), [10, 50, 90]);
  assert.deepEqual(windowsOf("a.py", 1, Array(5).fill("+" + "x".repeat(1500))).map((w) => w.text.split("\n").length), [2, 2, 1]);
  assert.deepEqual(windowsOf("a.py", 1, [...Array(41).fill(" ctx"), "+x"]).map((w) => w.newStart), [41]);
  assert.ok(windowsOf("a.py", 1, ["+" + "y".repeat(9000)]).every((w) => w.text.length <= 4000), "an over-long line is cut");
});

test("selectHunks: hunks that delete lines go first, then path and line; at most CHANGE_MAX_HUNKS, the rest counted", () => {
  const add = (i) => ({ path: `a${String(i).padStart(3, "0")}.py`, newStart: 1, text: "+x", removes: 0 });
  const del = { path: "z.py", newStart: 9, text: "-check()", removes: 1 };
  const r = selectHunks([...Array.from({ length: 70 }, (_, i) => add(i)), del]);
  assert.equal(r.hunks.length, CHANGE_MAX_HUNKS);
  assert.equal(r.skipped, 71 - CHANGE_MAX_HUNKS);
  assert.deepEqual(r.hunks[0], { path: "z.py", newStart: 9, text: "-check()" }, "a removal first, without the removes counter");
});

test("validChangeReview: well-formed block kept, malformed rows dropped, a malformed block ignored", () => {
  assert.equal(validChangeReview(null), null);
  assert.equal(validChangeReview({ reviewed: 1 }), null);
  assert.deepEqual(validChangeReview({ reviewed: 2, unreviewed: 0, threshold: 0.9994, flagged: [{ path: "a.py", newStart: 3, p: 0.9998 }, { path: "b.py", newStart: 0, p: 1 }] }),
    { reviewed: 2, unreviewed: 0, threshold: 0.9994, flagged: [{ path: "a.py", newStart: 3, p: 0.9998 }] });
});

test("unreviewed hunks are named by language (a C++ detector outage reads as « C++ 12 »); unknown keys never printed", async () => {
  const { unreviewedNote } = await import("../change-review.mjs");
  const block = validChangeReview({ reviewed: 4, unreviewed: 13, threshold: 0.5, flagged: [],
    unreviewedByLanguage: { cpp: 12, python: 1, "<script>": 3, rust: 0, c: 1.5 } });
  assert.deepEqual(block.unreviewedByLanguage, { cpp: 12, python: 1 }, "known languages with a positive whole count only");
  assert.equal(unreviewedNote(block), " · 13 not reviewed (partial: C++ 12, Python 1)");
  assert.equal(unreviewedNote(validChangeReview({ reviewed: 0, unreviewed: 2, threshold: 0.5, flagged: [] })),
    " · 2 not reviewed (partial)", "an older server without the field: the old wording");
  assert.equal(unreviewedNote(validChangeReview({ reviewed: 3, unreviewed: 0, threshold: 0.5, flagged: [] })), "", "all reviewed");
  assert.equal(validChangeReview({ reviewed: 1, unreviewed: 1, threshold: 0.5, flagged: [], unreviewedByLanguage: [1] }).unreviewedByLanguage,
    undefined, "an array is not a language map");
});

test("prHunks on a real repository: the PR's removed check is a hunk on the checked-out line numbers; off-PR → null", (t) => {
  const dir = mkdtempSync(join(tmpdir(), "fw-change-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  sh(dir, "init", "-q", "-b", "main");
  sh(dir, "config", "user.email", "t@example.com"); sh(dir, "config", "user.name", "t");
  sh(dir, "config", "core.autocrlf", "false");
  mkdirSync(join(dir, "app"));
  const safe = "import os\nBASE = '/srv'\n\ndef read(name):\n    path = os.path.join(BASE, name)\n    if not os.path.realpath(path).startswith(BASE):\n        raise ValueError(name)\n    return open(path).read()\n";
  writeFileSync(join(dir, "app/files.py"), safe);
  writeFileSync(join(dir, "package-lock.json"), "{}\n");
  sh(dir, "add", "."); sh(dir, "commit", "-qm", "base");
  const base = sh(dir, "rev-parse", "HEAD").trim();
  sh(dir, "checkout", "-qb", "pr");
  writeFileSync(join(dir, "app/files.py"), safe.replace("    if not os.path.realpath(path).startswith(BASE):\n        raise ValueError(name)\n", ""));
  writeFileSync(join(dir, "package-lock.json"), "{}\n".repeat(30));
  sh(dir, "commit", "-qam", "simplify read");
  const head = sh(dir, "rev-parse", "HEAD").trim();

  const env = { GITHUB_EVENT_NAME: "pull_request" };
  const ev = () => ({ pull_request: { base: { sha: base }, head: { sha: head } } });
  const r = prHunks(env, ev, (args) => sh(dir, ...args));
  assert.equal(r.hunks.length, 1);
  assert.equal(r.hunks[0].path, "app/files.py");
  assert.match(r.hunks[0].text, /^-    if not os\.path\.realpath\(path\)\.startswith\(BASE\):$/m);
  assert.equal(r.hunks.some((h) => h.path.includes("package-lock")), false, "only engine-modelled files");
  assert.equal(prHunks({ GITHUB_EVENT_NAME: "push" }, ev, () => { throw new Error("must not run"); }), null);
});

// The measured claim is stated in three places (action.yml input, --help, the run summary line). All three must state
// the SAME two measurements, and no copy of an older wording may remain: a stale number tells a user what a model that
// is no longer served did. The two halves are both required: 36 % is measured on security fixes played BACKWARDS; on the
// commits that really introduced a CVE (heisen-slop docs/55M-REAL-CVE.md §4.8), the two served detectors flag 19 % of
// commits against 2.1 % of ordinary ones. Stating the first without the second is the over-claim 0.10.14 shipped.
test("the change-review measurement is stated the same in action.yml, --help and the run summary", () => {
  const root = new URL("../../", import.meta.url);
  const yml = readFileSync(new URL("action.yml", root), "utf8");
  const gate = readFileSync(new URL("isolation-gate.mjs", root), "utf8");
  const undone = /(\d+)% of security fixes undone(?: \(a check removed\))? caught at (\d+\.\d+)% false alarms/g;
  const real = /(\d+)% of commits flagged vs (\d+\.\d+)% of ordinary commits/g;
  const a = [...yml.matchAll(undone), ...gate.matchAll(undone)].map((m) => `${m[1]}%@${m[2]}%`);
  const b = [...yml.matchAll(real), ...gate.matchAll(real)].map((m) => `${m[1]}%vs${m[2]}%`);
  assert.equal(a.length, 3, `action.yml input + --help + summary line: ${a.join(", ")}`);
  assert.equal(b.length, 3, `each copy also states the real-introducing-commit number: ${b.join(", ")}`);
  assert.deepEqual([...new Set(a)], ["36%@0.23%"], "the served union with diff-v13: 36.4 % of 6,269 reversed fixes at 0.23 %");
  assert.deepEqual([...new Set(b)], ["19%vs2.1%"], "SZZ held-out, served union with diff-v13, 5,468 CVEs: 19.3 % of introducing commits vs 2.14 %");
  assert.doesNotMatch(yml + gate, /vulnerability-introducing changes caught/, "the 0.10.14 over-claim is gone");
});

// 0.10.19 shipped C claims measured at 400 hunks per commit (withdrawn in 0.10.20). The re-measured C (0.10.21, heisen-slop
// §4.10) is stated with counts; no shipped text may carry a withdrawn C number (CHANGELOG keeps the history).
test("C claims: the 0.10.21 numbers are stated with counts, no withdrawn 0.10.19 number ships", async () => {
  const { C_REVIEW_NOTE, noticeHint } = await import("../change-review.mjs");
  for (const s of ["114 of 1,091", "1.5%", "277 of 8,049", "no notice is not a clearance", ".h files are read as C"])
    assert.ok(C_REVIEW_NOTE.includes(s), s);
  const { CPP_REVIEW_NOTE } = await import("../change-review.mjs");   // C++ (0.10.22, §4.12), stated with counts too
  for (const s of ["27 of 217", "on the buggy hunk in 1.8%", "67 of 3,493", "no notice is not a clearance"])
    assert.ok(CPP_REVIEW_NOTE.includes(s), s);
  const { RUST_REVIEW_NOTE } = await import("../change-review.mjs");   // Rust (0.10.26: + the Rust route, §4.16)
  for (const s of ["22 of 214", "on the buggy hunk in 2.3%", "108 of 6,107", "no notice is not a clearance"])
    assert.ok(RUST_REVIEW_NOTE.includes(s), s);
  const root = new URL("../../", import.meta.url);
  const shipped = ["action.yml", "isolation-gate.mjs", "src/change-review.mjs"].map((f) => readFileSync(new URL(f, root), "utf8")).join("\n");
  for (const old of ["10.7 %", "10.7%", "1,669", "1.60 %", "1.60%", "11% of the C commits", "1.6% of ordinary C", "8 of 356", "19 of 230", "65 of 6,298"])
    assert.ok(!shipped.includes(old), `withdrawn C claim still shipped: ${old}`);
  const yml = readFileSync(new URL("action.yml", root), "utf8");
  for (const s of ["got a notice in 10%", "on the buggy hunk in 1.5%", "3.4% (277 of 8,049)", "10% (22 of 214)", "1.8% (108 of 6,107)"]) assert.ok(yml.includes(s), `action.yml C claim: ${s}`);
  assert.equal(noticeHint([{ path: "a.c", newStart: 3, text: " x\n-if (n > cap) return -1;\n y" }], { path: "a.c", newStart: 3 }), "review the removed lines");
  assert.equal(noticeHint([{ path: "a.c", newStart: 3, text: " x\n+memcpy(buf, src, n);" }], { path: "a.c", newStart: 3 }), "review the added code");
});
