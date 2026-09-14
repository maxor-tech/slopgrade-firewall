// Inline PR suggestion surface — zero-egress-to-slopGrade (posts to the consumer's own GitHub about their own PR).
// The builders are pure; postSuggestions is fail-open and per-comment isolated. These prove the wire shape a
// customer's PR depends on: a ```suggestion``` block, PR-context resolution, and that a non-diff line never breaks CI.
import { test } from "node:test";
import assert from "node:assert/strict";
import { suggestionBody, buildReviewComments, resolvePrContext, postSuggestions, findingCommentBody, buildFindingComments, parseAddedLines, postFindingReview, postSummaryComment, FINDING_MARKER, SUMMARY_MARKER } from "../pr-suggest.mjs";

test("suggestionBody wraps the fixed line in a GitHub ```suggestion``` block with attribution", () => {
  const body = suggestionBody({ after: "r = requests.get(u, verify=True)", note: "verify False->True (verify TLS certs)" });
  assert.match(body, /```suggestion\nr = requests\.get\(u, verify=True\)\n```/);
  assert.match(body, /slopGrade Firewall/);
  assert.match(body, /verify TLS certs/);
  // no note -> still a valid suggestion block with a generic label
  assert.match(suggestionBody({ after: "x=1" }), /```suggestion\nx=1\n```/);
});

test("buildReviewComments maps only verified single-line fixes to {path,line,side,commit_id,body}", () => {
  const comments = buildReviewComments([
    { file: "a.py", line: 5, after: "verify=True", verified: true, note: "n" },
    { file: "b.py", line: 2, verified: false, reason: "pattern-not-on-line" },   // dropped
    { file: "c.py", line: 0, after: "x", verified: true },                        // dropped (line<1)
    { verified: true, after: "x" },                                               // dropped (no file)
  ], "deadbeef");
  assert.equal(comments.length, 1);
  assert.deepEqual({ path: comments[0].path, line: comments[0].line, side: comments[0].side, commit_id: comments[0].commit_id },
    { path: "a.py", line: 5, side: "RIGHT", commit_id: "deadbeef" });
  assert.match(comments[0].body, /```suggestion\nverify=True\n```/);
});

test("resolvePrContext returns null off-PR and the {owner,name,number,headSha} on a PR event", () => {
  assert.equal(resolvePrContext({ GITHUB_REPOSITORY: "o/r", GITHUB_EVENT_NAME: "push" }, () => ({})), null, "push event -> null");
  assert.equal(resolvePrContext({ GITHUB_EVENT_NAME: "pull_request" }, () => ({})), null, "no repo -> null");
  const env = { GITHUB_REPOSITORY: "acme/webapp", GITHUB_EVENT_NAME: "pull_request" };
  assert.equal(resolvePrContext(env, () => ({ pull_request: { number: 7 } })), null, "missing head.sha -> null");
  const ctx = resolvePrContext(env, () => ({ pull_request: { number: 7, head: { sha: "abc123" } } }));
  assert.deepEqual(ctx, { owner: "acme", name: "webapp", number: 7, headSha: "abc123" });
  assert.equal(resolvePrContext(env, () => { throw new Error("bad json"); }), null, "unreadable event payload -> null (never throws)");
});

test("postSuggestions: no token -> warns, posts nothing, never throws", async () => {
  let warned = "";
  const posted = await postSuggestions({}, [{ file: "a.py", line: 1, after: "x", verified: true }], { warn: (m) => (warned = m) });
  assert.equal(posted, 0);
  assert.match(warned, /GITHUB_TOKEN/);
});

test("postSuggestions: PR context + one in-diff, one off-diff (422) -> posts the good one, skips the 422, fail-open", async () => {
  const env = { GITHUB_TOKEN: "t", GITHUB_REPOSITORY: "o/r", GITHUB_EVENT_NAME: "pull_request" };
  const calls = [];
  const fetchImpl = async (url, opts) => {
    calls.push({ url, body: JSON.parse(opts.body) });
    return calls.length === 1 ? { ok: true, status: 201 } : { ok: false, status: 422 };
  };
  const warnings = [];
  const posted = await postSuggestions(env, [
    { file: "a.py", line: 5, after: "verify=True", verified: true, note: "n" },
    { file: "b.py", line: 9, after: "debug=False", verified: true, note: "n" },
  ], { fetchImpl, readEvent: () => ({ pull_request: { number: 3, head: { sha: "HEAD1" } } }), warn: (m) => warnings.push(m) });
  assert.equal(posted, 1, "the in-diff suggestion posts; the 422 is skipped");
  assert.equal(calls.length, 2, "one API call per verified fix (per-comment isolation)");
  assert.match(calls[0].url, /\/repos\/o\/r\/pulls\/3\/comments$/);
  assert.equal(calls[0].body.commit_id, "HEAD1", "comment pinned to the PR HEAD sha");
  assert.equal(calls[0].body.side, "RIGHT");
  assert.equal(warnings.length, 1, "the off-diff line warns, does not throw");
});

test("postSuggestions: a thrown fetch (network) is caught per-comment and never breaks the build", async () => {
  const env = { GITHUB_TOKEN: "t", GITHUB_REPOSITORY: "o/r", GITHUB_EVENT_NAME: "pull_request" };
  const warnings = [];
  const posted = await postSuggestions(env, [{ file: "a.py", line: 1, after: "x", verified: true }], {
    fetchImpl: async () => { throw new Error("ECONNRESET"); },
    readEvent: () => ({ pull_request: { number: 1, head: { sha: "h" } } }),
    warn: (m) => warnings.push(m),
  });
  assert.equal(posted, 0);
  assert.match(warnings[0], /ECONNRESET/);
});

// ── The finding FEED (all findings, not just the fixable ones) ──────────────
test("findingCommentBody: severity icon + rule + detail + dedup marker, and NOT a ```suggestion``` block", () => {
  const b = findingCommentBody({ rule: "hardcoded-secret", detail: "an AWS key at a.py:5", severity: "high" });
  assert.match(b, /slopGrade Firewall/);
  assert.match(b, /hardcoded-secret/);
  assert.match(b, /an AWS key at a\.py:5/);
  assert.match(b, /🔴/);
  assert.ok(b.includes(FINDING_MARKER), "carries the dedup marker");
  assert.ok(!b.includes("```suggestion"), "a finding comment is not a fix suggestion");
});

test("buildFindingComments keeps only findings with a real file:line", () => {
  const cs = buildFindingComments([
    { file: "a.py", line: 5, rule: "sqli", detail: "d", severity: "high" },
    { file: "", line: 3, rule: "x", detail: "d", severity: "high" },       // dropped (no file)
    { file: "b.py", line: 0, rule: "x", detail: "d", severity: "high" },   // dropped (line<1)
    { rule: "cross-tenant", detail: "no loc", severity: "high" },          // dropped (no file/line)
  ], "sha1");
  assert.equal(cs.length, 1);
  assert.equal(cs[0].path, "a.py");
  assert.equal(cs[0].line, 5);
  assert.equal(cs[0].commit_id, "sha1");
  assert.equal(cs[0].side, "RIGHT");
});

test("parseAddedLines: hunk header sets the RIGHT counter; +/context advance it, - does not", () => {
  const patch = "@@ -1,3 +10,4 @@\n context10\n+added11\n-removed\n+added12\n@@ -20 +30,2 @@\n+added30\n context31";
  assert.deepEqual([...parseAddedLines(patch)].sort((a, b) => a - b), [10, 11, 12, 30, 31]);
  assert.equal(parseAddedLines(null).size, 0, "non-string -> empty");
  assert.equal(parseAddedLines("no hunk header\n+x").size, 0, "a body with no @@ header commits nothing");
});

test("postFindingReview: ONE review carrying the summary body + only on-diff, non-dup findings inline (F8: one email)", async () => {
  const env = { GITHUB_TOKEN: "t", GITHUB_REPOSITORY: "o/r", GITHUB_EVENT_NAME: "pull_request" };
  const calls = [];
  const fetchImpl = async (url, opts = {}) => {
    const method = opts.method || "GET";
    if (method === "GET" && url.includes("/pulls/") && url.includes("/comments")) // existing comments (dedup source)
      return { ok: true, status: 200, json: async () => [{ path: "a.py", line: 5, body: `old ${FINDING_MARKER}` }] };
    if (method === "GET" && url.includes("/files")) // the PR diff -> only b.py:9 is commentable
      return { ok: true, status: 200, json: async () => [{ filename: "b.py", patch: "@@ -1 +9,1 @@\n+leak" }] };
    calls.push({ url, method, body: JSON.parse(opts.body) });
    return { ok: true, status: 200 };
  };
  const review = await postFindingReview(env, [
    { file: "a.py", line: 5, rule: "sqli", detail: "d", severity: "high" }, // already commented -> skipped
    { file: "b.py", line: 9, rule: "ssrf", detail: "d", severity: "high" }, // on-diff + new -> inline
    { file: "c.py", line: 3, rule: "xss", detail: "d", severity: "high" },  // off-diff -> not inline (lives in summary)
  ], "## summary body", { fetchImpl, readEvent: () => ({ pull_request: { number: 3, head: { sha: "H" } } }) });
  assert.deepEqual(review, { comments: 1, review: "posted" });
  assert.equal(calls.length, 1, "exactly ONE review POST -> ONE notification, not one per finding");
  assert.match(calls[0].url, /\/repos\/o\/r\/pulls\/3\/reviews$/);
  assert.equal(calls[0].body.event, "COMMENT");
  assert.equal(calls[0].body.commit_id, "H");
  assert.match(calls[0].body.body, /summary body/, "the summary rides in the ONE review body");
  assert.equal(calls[0].body.comments.length, 1);
  assert.equal(calls[0].body.comments[0].path, "b.py");
  assert.equal(calls[0].body.comments[0].line, 9);
});

test("postFindingReview: review API refuses -> falls back to ONE summary comment (fail-open)", async () => {
  const env = { GITHUB_TOKEN: "t", GITHUB_REPOSITORY: "o/r", GITHUB_EVENT_NAME: "pull_request" };
  const posts = [];
  const fetchImpl = async (url, opts = {}) => {
    const method = opts.method || "GET";
    if (method === "GET" && url.includes("/pulls/") && url.includes("/comments")) return { ok: true, status: 200, json: async () => [] };
    if (method === "GET" && url.includes("/files")) return { ok: true, status: 200, json: async () => [{ filename: "b.py", patch: "@@ -1 +9,1 @@\n+x" }] };
    if (url.includes("/reviews")) return { ok: false, status: 422 }; // review refused (e.g. a diff race)
    if (method === "GET" && url.includes("/issues/")) return { ok: true, status: 200, json: async () => [] };
    posts.push({ url, method });
    return { ok: true, status: 201 };
  };
  const warnings = [];
  const review = await postFindingReview(env, [{ file: "b.py", line: 9, rule: "ssrf", detail: "d", severity: "high" }], "sum",
    { fetchImpl, readEvent: () => ({ pull_request: { number: 3, head: { sha: "H" } } }), warn: (m) => warnings.push(m) });
  assert.equal(review.review, "posted", "the summary still lands via the fallback");
  assert.ok(posts.some((c) => c.url.includes("/issues/3/comments") && c.method === "POST"), "posted the summary as one issue comment");
  assert.ok(warnings.some((w) => /review not posted/i.test(w)), "warned about the review fallback, never threw");
});

test("postFindingReview: no token -> warns, skipped, never throws", async () => {
  let warned = "";
  const review = await postFindingReview({}, [{ file: "a.py", line: 1, rule: "x", detail: "d", severity: "high" }], "s", { warn: (m) => (warned = m) });
  assert.deepEqual(review, { comments: 0, review: "skipped" });
  assert.match(warned, /GITHUB_TOKEN/);
});

test("postSummaryComment: UPDATES an existing summary in place (dedup), else POSTs a new one", async () => {
  const env = { GITHUB_TOKEN: "t", GITHUB_REPOSITORY: "o/r", GITHUB_EVENT_NAME: "pull_request" };
  const re = () => ({ pull_request: { number: 3, head: { sha: "H" } } });
  let patchedUrl = null;
  const fetchUpd = async (url, opts = {}) => {
    if (!opts.method || opts.method === "GET") return { ok: true, status: 200, json: async () => [{ id: 42, body: `prev ${SUMMARY_MARKER}` }] };
    if (opts.method === "PATCH") { patchedUrl = url; return { ok: true, status: 200 }; }
    return { ok: true, status: 201 };
  };
  assert.equal(await postSummaryComment(env, "hi", { fetchImpl: fetchUpd, readEvent: re }), "updated");
  assert.match(patchedUrl, /\/issues\/comments\/42$/, "patched the existing summary, no new wall of comments");

  const fetchNew = async (url, opts = {}) => (!opts.method || opts.method === "GET")
    ? { ok: true, status: 200, json: async () => [] }
    : { ok: true, status: 201 };
  assert.equal(await postSummaryComment(env, "hi", { fetchImpl: fetchNew, readEvent: re }), "posted");
});
