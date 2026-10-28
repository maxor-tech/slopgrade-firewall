// The GitHub Step Summary — the rendered run-page report (shows even on push runs, where PR comments don't).
// Pure builders (githubBlobBase, stepSummaryMarkdown) are asserted on content per verdict state + clickable links;
// emitStepSummary is checked for the write path + the off-CI no-op (injected writer, never touches real fs).
import { test } from "node:test";
import assert from "node:assert/strict";
import { githubBlobBase, stepSummaryMarkdown, emitStepSummary } from "../client-lib.mjs";

const blocked = {
  pattern: "explicit-scoping", tenantKey: "org_id", conformancePct: 94.2, hardLeaks: 2, byId: 1, reliable: true,
  packBlocking: 3, leaks: ["lib/db/q.ts:42  unscoped read", "lib/db/l.ts:18  unscoped read"],
  accessControl: { count: 2, hidden: 1, findings: [] },
};

test("githubBlobBase — repo+sha → base ; missing either → null ; GHE server honored", () => {
  assert.equal(githubBlobBase({ GITHUB_REPOSITORY: "acme/app" }, "abc"), "https://github.com/acme/app/blob/abc");
  assert.equal(githubBlobBase({ GITHUB_REPOSITORY: "acme/app", GITHUB_SERVER_URL: "https://ghe.corp" }, "s"), "https://ghe.corp/acme/app/blob/s");
  assert.equal(githubBlobBase({ GITHUB_REPOSITORY: "acme/app" }, null), null);
  assert.equal(githubBlobBase({}, "abc"), null);
});

test("stepSummaryMarkdown — blocked: red banner, facts, clickable leaks, pack counts, manage CTA", () => {
  const md = stepSummaryMarkdown(blocked, { origin: "https://app.slopgrade.ai", blobBase: "https://github.com/acme/app/blob/abc", decision: "gate-blocked" });
  assert.match(md, /### ❌ Blocked — 2 hard cross-tenant leaks · 3 blocking findings/);
  assert.match(md, /\*\*Pattern\*\* `explicit-scoping`.*\*\*Tenant key\*\* `org_id`/);
  assert.match(md, /\*\*Conformance\*\* 94\.2%/);
  assert.match(md, /\*\*\+1\*\* conditional by-id access \(review\)/);
  assert.match(md, /\[`lib\/db\/q\.ts:42`\]\(https:\/\/github\.com\/acme\/app\/blob\/abc\/lib\/db\/q\.ts#L42\)/); // clickable line
  assert.match(md, /\*\*access control\*\* — 2 findings \(\+1 hidden\)/);
  assert.match(md, /See all findings · manage the gate/);
});

test("stepSummaryMarkdown — advisory (unpaid): amber banner + enable-the-gate CTA", () => {
  const md = stepSummaryMarkdown({ pattern: "orm", tenantKey: null, conformancePct: null, hardLeaks: 3, byId: 0, leaks: ["a.ts:1  unscoped read"] },
    { origin: "https://app.slopgrade.ai", blobBase: null, decision: "gate-unpaid" });
  assert.match(md, /### ⚠️ Advisory — 3 hard leaks found, not blocking \(no blocking gate on this repo\)/);
  assert.doesNotMatch(md, /free tier|\$\d/, "0.11.0 : no plan name or price is hard-coded in the client");
  assert.match(md, /\*\*Conformance\*\* n\/a/);
  assert.match(md, /\[Enable the gate on this repo →\]\(https:\/\/app\.slopgrade\.ai\/ci\)/);
  assert.match(md, /\| `a\.ts:1` \|/); // no blobBase → plain code, not a link
  assert.doesNotMatch(md, /\]\(https:\/\/github/);
});

test("stepSummaryMarkdown — clean: green banner, no leak table, no upsell", () => {
  const md = stepSummaryMarkdown({ pattern: "explicit-scoping", tenantKey: "t", conformancePct: 100, hardLeaks: 0, byId: 0, leaks: [] },
    { origin: "https://app.slopgrade.ai", decision: "pass" });
  assert.match(md, /### ✅ Clean — no blocking cross-tenant leaks/);
  assert.doesNotMatch(md, /Cross-tenant leak \|/);
  assert.doesNotMatch(md, /Enable the gate/);
});

test("emitStepSummary — writes to GITHUB_STEP_SUMMARY via the injected writer ; no-op off CI", () => {
  let wrote = null;
  const w = (p, body) => { wrote = { p, body }; };
  assert.equal(emitStepSummary({ GITHUB_STEP_SUMMARY: "/tmp/s.md" }, "## report", w), true);
  assert.equal(wrote.p, "/tmp/s.md");
  assert.ok(wrote.body.endsWith("\n"));
  wrote = null;
  assert.equal(emitStepSummary({}, "## report", w), false); // no summary file → skip
  assert.equal(wrote, null);
  assert.equal(emitStepSummary({ GITHUB_STEP_SUMMARY: "/tmp/s.md" }, "", w), false); // empty body → skip
});

test("emitStepSummary — a write error is swallowed (never breaks the gate)", () => {
  const boom = () => { throw new Error("EACCES"); };
  assert.equal(emitStepSummary({ GITHUB_STEP_SUMMARY: "/tmp/s.md" }, "## report", boom), false);
});

// e2e 2026-10-27 (slopgrade-gate-e2e#9) : the run page showed « This PR 2 new findings » under a green check, with no
// blocking count and no word on Deep Scan or block confidence.
test("stepSummaryMarkdown : the PR line carries the blocking count and Deep Scan says what block confidence kept", () => {
  const v = { pattern: "none", hardLeaks: 0, packBlocking: 0, conformancePct: null, leaks: [] };
  const md = stepSummaryMarkdown(v, { decision: "gate-pass", scope: { introduced: 2, blocking: 0, preexistingBlocking: 0 },
    deep: { findings: 2, mode: "blocking", blocking: 0, kept: 2 } });
  const lines = md.split("\n");
  assert.ok(lines.includes("- **This PR** 2 new findings · 0 blocking"), md);
  assert.ok(lines.includes("- **Deep Scan** (blocking) 2 new findings · 0 blocking · 2 kept as warnings by block confidence (score below the engine threshold)"), md);
  // Advisory Deep Scan : no blocking count, no confidence clause when nothing was kept.
  const adv = stepSummaryMarkdown(v, { decision: "gate-pass", deep: { findings: 1, mode: "advisory", blocking: 0, kept: 0 } });
  assert.ok(adv.split("\n").includes("- **Deep Scan** (advisory) 1 new finding"), adv);
  // No Deep Scan run → no Deep Scan line.
  assert.doesNotMatch(stepSummaryMarkdown(v, { decision: "gate-pass" }), /Deep Scan/);
});
