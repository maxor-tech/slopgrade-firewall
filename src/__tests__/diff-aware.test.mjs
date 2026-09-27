// « Clean as you code » (0.10.0) — the PR is judged on what IT introduced, not on the repo's backlog. Found dogfooding
// slopGrade on its own repo : a 6-file onboarding PR got 26 repo-wide findings (0 of them its own, 0 inline) and, in
// gate mode, would have been blocked by them. These tests pin the classification, the scoped gate counts (including
// the fail-closed rules for findings the feed could not locate) and the review body.
import { test } from "node:test";
import assert from "node:assert/strict";
import { parseChangedLines, fetchPrDiff, classifyAgainstDiff, scopedBlocking, diffSummaryMarkdown, postFindingReview } from "../pr-suggest.mjs";
import { firewallVerdict } from "../gate-verdict.mjs";
import { stepSummaryMarkdown } from "../client-lib.mjs";

const diffOf = ({ changed = [], commentable = [], files = [], unpatched = [] } = {}) =>
  ({ ok: true, changed: new Set(changed), commentable: new Set(commentable), files: new Set(files), unpatched: new Set(unpatched) });

test("parseChangedLines keeps only '+' lines (context lines are commentable, not authored by the PR)", () => {
  const patch = "@@ -1,3 +10,4 @@\n context10\n+added11\n-removed\n+added12\n@@ -20 +30,2 @@\n+added30\n context31";
  assert.deepEqual([...parseChangedLines(patch)].sort((a, b) => a - b), [11, 12, 30]);
  assert.equal(parseChangedLines(undefined).size, 0);
});

test("fetchPrDiff paginates, separates changed vs commentable, and records patch-less files as unpatched", async () => {
  const page1 = Array.from({ length: 100 }, (_, i) => ({ filename: `f${i}.js`, patch: "@@ -1 +1,2 @@\n ctx\n+new" }));
  const page2 = [{ filename: "big.min.js" }, { filename: "gone.js", status: "removed", patch: "@@ -1 +0,0 @@\n-x" }];
  const urls = [];
  const fetchImpl = async (url) => { urls.push(url); return { ok: true, json: async () => (/[?&]page=1$/.test(url) ? page1 : page2) }; };
  const d = await fetchPrDiff({ owner: "o", name: "r", number: 7 }, "t", fetchImpl);
  assert.equal(d.ok, true);
  assert.equal(urls.length, 2, "a full first page (100) fetches the next one");
  assert.ok(d.changed.has("f0.js:2") && !d.changed.has("f0.js:1"), "context line 1 is not 'changed'");
  assert.ok(d.commentable.has("f0.js:1") && d.commentable.has("f0.js:2"));
  assert.ok(d.unpatched.has("big.min.js") && d.files.has("big.min.js"));
  assert.ok(!d.files.has("gone.js"), "a removed file carries no head-side finding");
});

test("fetchPrDiff fails OPEN to ok:false on an HTTP error (the caller keeps whole-repo judging)", async () => {
  const warnings = [];
  const d = await fetchPrDiff({ owner: "o", name: "r", number: 7 }, "t", async () => ({ ok: false, status: 403 }), (m) => warnings.push(m));
  assert.equal(d.ok, false);
  assert.match(warnings[0], /403/);
});

test("classifyAgainstDiff: introduced (changed line / unpatched file / no location) · touched · debt", () => {
  const diff = diffOf({ changed: ["app/a.ts:5"], files: ["app/a.ts", "app/big.js"], unpatched: ["app/big.js"] });
  const out = classifyAgainstDiff([
    { file: "app/a.ts", line: 5, rule: "sqli" },     // on a changed line
    { file: "app/a.ts", line: 40, rule: "xss" },     // same file, untouched line
    { file: "app/big.js", line: 3, rule: "cmdi" },   // file changed but no patch → can't prove old
    { file: "lib/old.ts", line: 1, rule: "ssrf" },   // not in the PR
    { file: "", line: 0, rule: "?" },                // unlocatable
  ], diff).map((f) => f.scope);
  assert.deepEqual(out, ["introduced", "touched", "introduced", "debt", "introduced"]);
});

test("the dogfood PR : 26 pre-existing findings, none on its lines → the gate does NOT block, the review leads with 0 introduced", () => {
  const diff = diffOf({ changed: ["app/welcome/onboarding.tsx:10"], files: ["app/welcome/onboarding.tsx"] });
  const feed = Array.from({ length: 26 }, (_, i) => ({ file: `supabase/migrations/00${i}.sql`, line: 3, pack: "dbSafety", rule: "rls-without-grant", severity: i < 6 ? "high" : "medium" }));
  const cls = classifyAgainstDiff(feed, diff);
  const v = { hardLeaks: 0, packBlocking: 6, reliable: true, gateEntitled: true };
  const s = scopedBlocking(v, cls, { diff });
  assert.deepEqual({ hard: s.hardLeaks, pack: s.packBlocking, pre: s.preexistingBlocking }, { hard: 0, pack: 0, pre: 6 });
  assert.equal(firewallVerdict({ gateMode: true, reliable: true, hardLeaks: s.hardLeaks, gateEntitled: true, packBlocking: s.packBlocking }).block, false);
  // …whereas the whole-repo counts (push run / unreadable diff) still block, exactly as before.
  assert.equal(firewallVerdict({ gateMode: true, reliable: true, hardLeaks: 0, gateEntitled: true, packBlocking: 6 }).block, true);
  const body = diffSummaryMarkdown(cls, { origin: "https://x", gateMode: true });
  assert.match(body, /This PR introduces no new finding/);
  assert.match(body, /Existing debt elsewhere in the repo\*\* — 26 findings this PR did not cause/);
  assert.match(body, /blocks only on critical\/high findings this PR introduces/);
});

test("a blocking finding the PR adds on its own line blocks — and only it counts", () => {
  const diff = diffOf({ changed: ["api/q.ts:12"], files: ["api/q.ts"] });
  const cls = classifyAgainstDiff([
    { file: "api/q.ts", line: 12, pack: "sqli", rule: "taint-sql", severity: "high" },
    { file: "api/q.ts", line: 80, pack: "sqli", rule: "taint-sql", severity: "high" },
    { file: "lib/x.ts", line: 1, pack: "xss", rule: "xss", severity: "critical" },
  ], diff);
  const s = scopedBlocking({ hardLeaks: 0, packBlocking: 3 }, cls, { diff });
  assert.equal(s.packBlocking, 1);
  assert.equal(s.preexistingBlocking, 2);
  assert.equal(firewallVerdict({ gateMode: true, reliable: true, hardLeaks: 0, gateEntitled: true, packBlocking: s.packBlocking }).block, true);
  const body = diffSummaryMarkdown(cls, { gateMode: true });
  assert.match(body, /This PR introduces 1 finding · 1 blocking/);
  assert.match(body, /Already in the files you changed/);
});

test("fail-closed : a blocking pack count the feed could not locate is attributed to the PR", () => {
  const diff = diffOf({ files: ["a.ts"] });
  const s = scopedBlocking({ hardLeaks: 0, packBlocking: 2 }, classifyAgainstDiff([{ file: "old.ts", line: 1, pack: "sqli", severity: "high" }], diff), { diff });
  assert.equal(s.packBlocking, 1, "2 reported − 1 located (debt) = 1 unlocated → counted against the PR");
});

test("unlocated hard leaks : attributed to the PR only when it touches a schema file (the server locates ≤ 20)", () => {
  const v = { hardLeaks: 25, packBlocking: 0 };
  const located = Array.from({ length: 20 }, (_, i) => ({ file: `db/m${i}.sql`, line: 1, pack: "cross-tenant", severity: "high" }));
  const codeOnly = diffOf({ changed: ["app/page.tsx:3"], files: ["app/page.tsx"] });
  const s1 = scopedBlocking(v, classifyAgainstDiff(located, codeOnly), { diff: codeOnly });
  assert.equal(s1.hardLeaks, 0, "a UI-only PR is not blocked by a 25-leak backlog");
  assert.equal(s1.preexistingBlocking, 25);
  const schema = diffOf({ changed: ["supabase/migrations/0200_new.sql:4"], files: ["supabase/migrations/0200_new.sql"] });
  const s2 = scopedBlocking(v, classifyAgainstDiff(located, schema), { diff: schema });
  assert.equal(s2.hardLeaks, 5, "a PR touching the schema owns the 5 leaks nobody could locate");
});

test("deep-scan blocking is capped by what the PR introduced", () => {
  const diff = diffOf({ changed: ["a.py:2"], files: ["a.py"] });
  const cls = classifyAgainstDiff([
    { file: "a.py", line: 2, pack: "heisen", severity: "high" },
    { file: "b.py", line: 9, pack: "heisen", severity: "high" },
  ], diff);
  assert.equal(scopedBlocking({ hardLeaks: 0, packBlocking: 0 }, cls, { deepBlocking: 2, diff }).deepBlocking, 1);
});

test("the review body escapes finding text (no HTML / table break / newline injection from a detail)", () => {
  const body = diffSummaryMarkdown([{ scope: "introduced", file: "a.ts", line: 1, rule: "x", detail: "<img src=x>|\nNEWLINE", severity: "high" }]);
  assert.ok(!body.includes("<img"), "angle brackets stripped");
  assert.ok(!/\nNEWLINE/.test(body), "a detail cannot start a new markdown line");
});

test("the review row drops a detail's repeated `file:line` prefix and cuts long text on a word, with an ellipsis", () => {
  const detail = "scripts/p.mjs:5 — a Node eval / child_process.exec / new Function built from a request value — attacker input runs as code or a shell command (RCE). Never pass user input to eval/exec or a shell; use a fixed command and pass arguments as an array";
  const body = diffSummaryMarkdown([{ scope: "introduced", file: "scripts/p.mjs", line: 5, rule: "command-injection", detail, severity: "high" }]);
  const row = body.split("\n").find((l) => l.startsWith("- 🔴"));
  assert.match(row, /^- 🔴 `scripts\/p\.mjs:5` · \*\*command-injection\*\* — a Node eval/, "location not repeated");
  assert.match(row, /…$/, "long detail ends with an ellipsis");
  assert.ok(!/eval\/…$/.test(row) && !/\s…$/.test(row), "cut on a word boundary");
});

test("postFindingReview reuses a diff the caller already fetched (one diff read per run)", async () => {
  const env = { GITHUB_TOKEN: "t", GITHUB_REPOSITORY: "o/r", GITHUB_EVENT_NAME: "pull_request" };
  const gets = [];
  const posts = [];
  const fetchImpl = async (url, opts = {}) => {
    if (!opts.method || opts.method === "GET") { gets.push(url); return { ok: true, json: async () => [] }; }
    posts.push(JSON.parse(opts.body));
    return { ok: true };
  };
  const diff = diffOf({ commentable: ["b.py:9"], changed: ["b.py:9"], files: ["b.py"] });
  const r = await postFindingReview(env, [{ file: "b.py", line: 9, rule: "ssrf", severity: "high" }], "body",
    { fetchImpl, readEvent: () => ({ pull_request: { number: 3, head: { sha: "H" } } }), diff });
  assert.deepEqual(r, { comments: 1, review: "posted" });
  assert.ok(!gets.some((u) => u.includes("/files")), "the PR files were NOT fetched a second time");
  assert.equal(posts[0].comments[0].path, "b.py");
});

test("stepSummaryMarkdown with a PR scope says what the gate counted, never the repo-wide totals", () => {
  const v = { pattern: "rls", hardLeaks: 25, packBlocking: 6, conformancePct: 90, leaks: [] };
  const md = stepSummaryMarkdown(v, { decision: "gate-blocked", scope: { introduced: 1, blocking: 1, preexistingBlocking: 30 } });
  assert.match(md, /Blocked — 1 blocking finding introduced by this PR/);
  assert.match(md, /30 pre-existing blocking \(reported, never blocks this PR\)/);
  assert.ok(!/25 hard cross-tenant leaks/.test(md));
  // no scope (push run) → unchanged banner
  assert.match(stepSummaryMarkdown(v, { decision: "gate-blocked" }), /Blocked — 25 hard cross-tenant leaks · 6 blocking findings/);
});

test("server kill switch (0.10.1) : gateScope \"repo\" → whole-repo gate ; anything else keeps the PR scope", async () => {
  const { gateScopeOf } = await import("../pr-suggest.mjs");
  assert.equal(gateScopeOf({ gateScope: "repo" }), "repo");
  for (const v of [{}, { gateScope: "pr" }, { gateScope: "REPO" }, { gateScope: 1 }, null, undefined]) assert.equal(gateScopeOf(v), "pr");
  const body = diffSummaryMarkdown([{ scope: "debt", file: "a.ts", line: 1, severity: "high" }], { gateMode: true, wholeRepo: true });
  assert.match(body, /temporarily judging the whole repo/);
  assert.ok(!/never blocks your PR/.test(body), "never promises PR scoping while it is paused");
});
