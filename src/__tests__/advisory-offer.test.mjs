// 0.11.0 — the server's ADVISORY OFFER : why a private repo does not block and who acts. Network data rendered into
// markdown and the log, so it is validated (reason, sizes, links ONLY on the origin the client called) and stripped of
// markdown/HTML metacharacters. Rendered in the step summary, the PR comment footer and the log line ; absent → the
// pre-0.11 generic CTA, with no hard-coded price anywhere.
import { test } from "node:test";
import assert from "node:assert/strict";
import { advisoryOfferOf, offerLinksMarkdown, offerLogLine, stepSummaryMarkdown } from "../client-lib.mjs";
import { diffSummaryMarkdown } from "../pr-suggest.mjs";

const O = "https://app.slopgrade.ai";
const team = {
  reason: "team-pool-full",
  text: "This private repo is outside your Team pool, so its findings are reported but never block a merge.",
  actions: [
    { label: "Ask your Team owner to cover this repo", url: `${O}/seats` },
    { label: "Team owner: cover it from your pool", url: `${O}/ci#repos` },
  ],
};
const verdict = (offer) => ({ pattern: "orm", tenantKey: null, conformancePct: null, hardLeaks: 2, byId: 0, leaks: [], reliable: true, gateEntitled: false, offer });

test("advisoryOfferOf : a well-formed offer passes through unchanged", () => {
  assert.deepEqual(advisoryOfferOf(verdict(team), O), team);
  assert.equal(advisoryOfferOf(verdict(undefined), O), null, "older server : no offer");
});

test("advisoryOfferOf : any malformed part → null (never a half-rendered offer)", () => {
  const bad = [
    { ...team, reason: "upsell" },
    { ...team, text: "" },
    { ...team, text: "x".repeat(301) },
    { ...team, actions: [] },
    { ...team, actions: [team.actions[0], team.actions[0], team.actions[0], team.actions[0]] },
    { ...team, actions: [{ label: "x", url: "https://evil.example/seats" }] },
    { ...team, actions: [{ label: "x", url: "https://app.slopgrade.ai.evil.example/x" }] },
    { ...team, actions: [{ label: "x", url: `${O}/a) [y](https://evil.example` }] },
    { ...team, actions: [{ label: "", url: `${O}/seats` }] },
    { ...team, actions: [{ label: "x".repeat(81), url: `${O}/seats` }] },
    "a string",
  ];
  for (const o of bad) assert.equal(advisoryOfferOf(verdict(o), O), null, JSON.stringify(o).slice(0, 80));
});

test("advisoryOfferOf : text and labels lose markdown / HTML metacharacters and line breaks", () => {
  const o = advisoryOfferOf(verdict({ ...team, text: "Outside *your* [Team](x) <b>pool</b>\nok", actions: [{ label: "Ask `owner` |now|", url: `${O}/seats` }] }), O);
  assert.equal(o.text, "Outside your Team(x) bpool/b ok");
  assert.equal(o.actions[0].label, "Ask owner now");
});

test("rendering : summary banner + CTA name the Team pool and the ask ; PR footer and log line carry the same links", () => {
  const md = stepSummaryMarkdown(verdict(team), { origin: O, decision: "gate-unpaid", offer: team });
  assert.match(md, /### ⚠️ Advisory — 2 hard leaks found, not blocking \(this repo is outside your Team pool\)/);
  assert.match(md, /> \*\*Not blocking —\*\* This private repo is outside your Team pool/);
  assert.match(md, /\*\*\[Ask your Team owner to cover this repo →\]\(https:\/\/app\.slopgrade\.ai\/seats\)\*\* · \*\*\[Team owner: cover it from your pool →\]\(https:\/\/app\.slopgrade\.ai\/ci#repos\)\*\*/);
  assert.doesNotMatch(md, /Enable the gate/);
  assert.equal(offerLinksMarkdown(team).split(" · ").length, 2);
  assert.equal(offerLogLine(team), `${team.text} Ask your Team owner to cover this repo: ${O}/seats · Team owner: cover it from your pool: ${O}/ci#repos`);
  const pr = diffSummaryMarkdown([], { origin: O, gateMode: true, offer: team });
  assert.match(pr, /\*\*Not blocking —\*\* This private repo is outside your Team pool.*\[Ask your Team owner to cover this repo →\]\(https:\/\/app\.slopgrade\.ai\/seats\)/);
  assert.doesNotMatch(pr, /The gate blocks only/, "in gate mode an unentitled repo must not claim the gate blocks");
  // A high finding on an advisory repo is counted as a severity, never as « blocking » (it does not block).
  const high = [{ scope: "introduced", severity: "high", file: "a.ts", line: 4, rule: "sqli" }];
  assert.match(diffSummaryMarkdown(high, { origin: O, gateMode: true, offer: team }), /### This PR introduces 1 finding · 1 critical\/high\n/);
  assert.match(diffSummaryMarkdown(high, { origin: O, gateMode: true }), /### This PR introduces 1 finding · 1 blocking\n/);
});

test("no offer : summary and PR footer keep the generic, price-free CTA", () => {
  const md = stepSummaryMarkdown(verdict(undefined), { origin: O, decision: "gate-unpaid" });
  assert.match(md, /\[Enable the gate on this repo →\]\(https:\/\/app\.slopgrade\.ai\/ci\)/);
  assert.match(diffSummaryMarkdown([], { origin: O, gateMode: true }), /The gate blocks only on critical\/high findings this PR introduces/);
});
