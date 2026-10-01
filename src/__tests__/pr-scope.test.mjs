// PR-scoped deep scan (0.10.11): a PR's own files carry the line ranges the PR changed, so the hosted engine analyses
// the functions the PR touched instead of the whole file. These pin the diff parsing on a REAL git repository (rename,
// deletion, new file, GitHub's merge-commit checkout) and that the ranges never widen what leaves the runner.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, rmSync, mkdirSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parseChangedRanges, prChangedRanges, selectDeepUnits, DEEP_MAX_CHANGED_RANGES } from "../deep-scan.mjs";

test("parseChangedRanges: added / modified lines, a pure deletion marks its neighbours, new / binary / quoted files get none", () => {
  const diff = [
    "diff --git a/app/views.py b/app/views.py",
    "index 1..2 100644",
    "--- a/app/views.py",
    "+++ b/app/views.py",
    "@@ -10,2 +10,3 @@ def a():",
    "-x", "-y", "+x", "+y", "+z",
    "@@ -30 +31 @@",
    "-q", "+r",
    "@@ -40,2 +40,0 @@",
    "-gone", "-gone2",
    "@@ -1,1 +0,0 @@",
    "-first",
    "diff --git a/new.py b/new.py",
    "new file mode 100644",
    "--- /dev/null",
    "+++ b/new.py",
    "@@ -0,0 +1,3 @@",
    "+a", "+b", "+c",
    "diff --git a/img.png b/img.png",
    "Binary files a/img.png and b/img.png differ",
    "diff --git \"a/we\\tird.py\" \"b/we\\tird.py\"",
    "--- \"a/we\\tird.py\"",
    "+++ \"b/we\\tird.py\"",
    "@@ -1 +1 @@",
    "-a", "+b",
    "diff --git a/sp ace.py b/sp ace.py",
    "--- a/sp ace.py\t",
    "+++ b/sp ace.py\t",
    "@@ -2 +2 @@",
    "-a", "+b",
  ].join("\n");
  const m = parseChangedRanges(diff);
  assert.deepEqual(m.get("app/views.py"), [[10, 12], [31, 31], [40, 41], [1, 1]]);
  assert.equal(m.has("new.py"), false, "a new file is analysed whole");
  assert.equal(m.has("img.png"), false);
  assert.equal([...m.keys()].some((k) => k.includes("ird")), false, "a quoted path is analysed whole, never guessed");
  assert.deepEqual(m.get("sp ace.py"), [[2, 2]], "git's trailing tab after a path with a space is not part of the name");
});

function sh(cwd, ...args) {
  return execFileSync("git", args, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
}

test("prChangedRanges on a real repository: GitHub's merge checkout gets the line numbers of the files actually sent", (t) => {
  const dir = mkdtempSync(join(tmpdir(), "fw-prscope-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  sh(dir, "init", "-q", "-b", "main");
  sh(dir, "config", "user.email", "t@example.com"); sh(dir, "config", "user.name", "t");
  sh(dir, "config", "core.autocrlf", "false");
  const lines = (n, tag) => Array.from({ length: n }, (_, i) => `${tag}${i + 1}`).join("\n") + "\n";
  mkdirSync(join(dir, "app"));
  writeFileSync(join(dir, "app/views.py"), lines(20, "v"));
  writeFileSync(join(dir, "app/old_name.py"), lines(10, "o"));
  writeFileSync(join(dir, "app/dead.py"), lines(5, "d"));
  sh(dir, "add", "."); sh(dir, "commit", "-qm", "base");
  const mergeBase = sh(dir, "rev-parse", "HEAD").trim();

  // the PR: edit line 15 of views.py, rename old_name.py (edit its line 3), delete dead.py, add new.py
  sh(dir, "checkout", "-qb", "pr");
  writeFileSync(join(dir, "app/views.py"), lines(20, "v").replace("v15\n", "v15-changed\n"));
  sh(dir, "mv", "app/old_name.py", "app/new_name.py");
  writeFileSync(join(dir, "app/new_name.py"), lines(10, "o").replace("o3\n", "o3-changed\n"));
  sh(dir, "rm", "-q", "app/dead.py");
  writeFileSync(join(dir, "app/new.py"), "x = 1\n");
  writeFileSync(join(dir, "package-lock.json"), "{}\n".repeat(50));   // churn the deep scan never sends
  writeFileSync(join(dir, "Views.PY"), "a\n");                        // upper-case extension still counts
  sh(dir, "add", "."); sh(dir, "commit", "-qm", "pr");
  const head = sh(dir, "rev-parse", "HEAD").trim();

  // meanwhile main inserts 5 lines at the TOP of views.py → in the merge commit the PR's line 15 is line 20
  sh(dir, "checkout", "-q", "main");
  writeFileSync(join(dir, "app/views.py"), lines(5, "top") + lines(20, "v"));
  sh(dir, "commit", "-qam", "main moves on");
  const base = sh(dir, "rev-parse", "HEAD").trim();
  sh(dir, "merge", "-q", "--no-ff", "--no-edit", "pr");          // what actions/checkout puts on disk for pull_request

  const env = { GITHUB_EVENT_NAME: "pull_request" };
  const ev = () => ({ pull_request: { base: { sha: base }, head: { sha: head } } });
  let seenArgs = [], seenOut = "";
  const git = (args) => { seenArgs = args; seenOut = sh(dir, ...args); return seenOut; };
  const m = prChangedRanges(env, ev, git);
  assert.deepEqual(m.get("app/views.py"), [[20, 20]], "line 15 of the PR head is line 20 of the checked-out merge");
  assert.deepEqual(m.get("app/new_name.py"), [[3, 3]], "a renamed file keeps only its edited line");
  assert.equal(m.has("app/dead.py"), false);
  assert.equal(m.has("app/new.py"), false, "a new file is analysed whole");
  assert.deepEqual(seenArgs.filter((a) => a.startsWith(":(")).length, 12, "the diff is limited to sendable extensions");
  assert.equal(seenOut.includes("package-lock.json"), false, "lockfile churn never reaches the buffer");
  assert.equal(seenOut.includes("Views.PY"), true, "the pathspec is case-insensitive like DEEP_SCAN_EXTS");
  // the precondition that makes the working-tree diff necessary: base...head numbers would be off by 5
  const naive = parseChangedRanges(sh(dir, "diff", "-U0", `${mergeBase}...${head}`));
  assert.deepEqual(naive.get("app/views.py"), [[15, 15]]);

  assert.equal(prChangedRanges({ GITHUB_EVENT_NAME: "push" }, ev, git), null, "push runs: whole files");
  assert.equal(prChangedRanges(env, ev, () => { throw new Error("bad object"); }), null, "shallow checkout → whole files");
});

test("selectDeepUnits: only a PR file carries its ranges; ranges never add a file nor any source", () => {
  const src = { "pr.py": "os.system(x)\n", "other.py": "os.system(y)\n", "pr_plain.py": "def add(a, b):\n    return a + b\n" };
  const ranges = new Map([["pr.py", [[1, 1]]], ["other.py", [[1, 1]]], ["pr_plain.py", [[1, 2]]]]);
  const r = selectDeepUnits(Object.keys(src), (p) => src[p], [], ["pr.py", "pr_plain.py"], ranges);
  assert.deepEqual(r.units, [{ path: "pr.py", code: "os.system(x)\n", changed: [[1, 1]] }, { path: "other.py", code: "os.system(y)\n" }]);
  assert.equal(r.scoped, 1);
  assert.equal(r.fromPr, 1);
  const tooMany = new Map([["pr.py", Array.from({ length: DEEP_MAX_CHANGED_RANGES + 1 }, () => [1, 1])]]);
  const w = selectDeepUnits(["pr.py"], (p) => src[p], [], ["pr.py"], tooMany);
  assert.equal(w.units[0].changed, undefined, "past the detector's range cap the file is sent whole");
  assert.equal(selectDeepUnits(["pr.py"], (p) => src[p], [], ["pr.py"]).units[0].changed, undefined, "no ranges → whole file, as before");
});
