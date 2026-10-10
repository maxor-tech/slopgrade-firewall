// Change review (0.10.13): the PR's hunks go to heisen-slop's diff-reading 55M. These pin the hunk parsing (what leaves
// the runner), the order and cap (removals first, 64 max), the response validation, and prHunks on a REAL repository.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, rmSync, mkdirSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parseHunks, selectHunks, prHunks, validChangeReview, CHANGE_MAX_HUNKS } from "../change-review.mjs";

const sh = (cwd, ...args) => execFileSync("git", args, { cwd, encoding: "utf8" });

test("parseHunks: ' '/'-'/'+' lines with the new-side start; new, binary, unmodelled and newline-marker lines left out", () => {
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
  }]);
});

test("parseHunks: a hunk over 40 lines is never sent", () => {
  const big = ["--- a/a.js", "+++ b/a.js", "@@ -1,41 +1,41 @@", ...Array.from({ length: 41 }, (_, i) => `-l${i}`)].join("\n");
  assert.deepEqual(parseHunks("diff --git a/a.js b/a.js\n" + big), []);
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
