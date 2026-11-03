// The review-suggested band (server slopgrade#1611, 2026-11-03) : `changeReview.review` lists JS/TS hunks just under the
// triage threshold. The client validates it (below the threshold only, ≤ REVIEW_BAND_MAX), prints it under its own
// title, and never counts it as a flag — end to end against a stubbed server on a real PR checkout.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { main } from "../../isolation-gate.mjs";
import { validChangeReview, REVIEW_BAND_MAX, REVIEW_BAND_NOTE, reviewBandHeading } from "../change-review.mjs";

test("validChangeReview : the band keeps only well-formed rows below the threshold, at most REVIEW_BAND_MAX", () => {
  const row = (i, p) => ({ path: `web/f${i}.ts`, newStart: i + 1, p });
  const v = validChangeReview({ reviewed: 9, unreviewed: 0, threshold: 0.5, flagged: [row(0, 0.9)],
    review: [row(1, 0.49), row(2, 0.5), { path: "x.ts", newStart: 0, p: 0.4 }, row(3, 0.45), row(4, 0.4), row(5, 0.35), row(6, 0.3), row(7, 0.27)] });
  assert.equal(REVIEW_BAND_MAX, 5);
  assert.deepEqual(v.review.map((f) => f.path), ["web/f1.ts", "web/f3.ts", "web/f4.ts", "web/f5.ts", "web/f6.ts"],
    "0.5 is not below the threshold, newStart 0 is malformed, the 6th valid row is cut");
  assert.deepEqual(v.flagged.map((f) => f.path), ["web/f0.ts"]);
  const none = validChangeReview({ reviewed: 1, unreviewed: 0, threshold: 0.5, flagged: [] });
  assert.equal(none.review, undefined, "an older server : no band field");
  assert.equal(validChangeReview({ reviewed: 1, unreviewed: 0, threshold: 0.5, flagged: [], review: "x" }).review, undefined);
});

const sh = (cwd, ...args) => execFileSync("git", args, { cwd, encoding: "utf8" });
const PAID = { gateEntitled: true, gateLevel: "paid", packBlocking: 0, pattern: "none", conformancePct: null, hardLeaks: 0, reliable: true, leaks: [] };

test("a band row prints as « review suggested », apart from the triage flags, and never blocks", async (t) => {
  const dir = mkdtempSync(join(tmpdir(), "fw-band-cli-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  sh(dir, "init", "-q", "-b", "main");
  sh(dir, "config", "user.email", "t@example.com"); sh(dir, "config", "user.name", "t"); sh(dir, "config", "core.autocrlf", "false");
  const base = "const { exec } = require('child_process');\nmodule.exports = (req, res) => {\n  exec('ls ' + req.query.d, () => res.end());\n};\n";
  writeFileSync(join(dir, "run.js"), base);
  sh(dir, "add", "."); sh(dir, "commit", "-qm", "base");
  const b = sh(dir, "rev-parse", "HEAD").trim();
  writeFileSync(join(dir, "run.js"), base.replace("module.exports", "const ALLOWED = /^[a-z]+$/;\nmodule.exports"));
  sh(dir, "commit", "-qam", "change");
  const head = sh(dir, "rev-parse", "HEAD").trim();
  const ev = join(dir, "..", `${dir.split(/[\\/]/).pop()}-event.json`);
  writeFileSync(ev, JSON.stringify({ pull_request: { base: { sha: b }, head: { sha: head } } }));
  t.after(() => rmSync(ev, { force: true }));
  const env = { GITHUB_ACTIONS: "true", ACTIONS_ID_TOKEN_REQUEST_URL: "https://oidc.example/token?api-version=2",
    ACTIONS_ID_TOKEN_REQUEST_TOKEN: "runner-token", GITHUB_SHA: head, GITHUB_WORKSPACE: dir, GITHUB_EVENT_NAME: "pull_request", GITHUB_EVENT_PATH: ev };
  const realFetch = globalThis.fetch, realLog = console.log;
  const out = [];
  globalThis.fetch = async (url, opts) => {
    const u = String(url);
    if (u.startsWith("https://oidc.example/")) return { ok: true, status: 200, json: async () => ({ value: "eyJ.oidc.token" }) };
    if (u.endsWith("/api/ci/pro-extractors")) return { ok: false, status: 402, json: async () => ({ error: "plan-required" }) };
    if (u.endsWith("/api/ci/heisen")) {
      const body = JSON.parse(opts.body);
      const h = body.hunks[0];
      return { ok: true, status: 200, json: async () => ({ ok: true, findings: [], scanned: body.units.length, unanswered: 0,
        changeReview: { reviewed: body.hunks.length, unreviewed: 0, threshold: 0.5, flagged: [], review: [{ path: h.path, newStart: h.newStart, p: 0.3 }] } }) };
    }
    return { ok: true, status: 200, json: async () => PAID };
  };
  console.log = (...a) => out.push(a.join(" "));
  try {
    const code = await main(["--gate", "--deep-scan", "--change-review"], env);
    assert.equal(code, 0, "the band never blocks");
    const text = out.join("\n");
    assert.match(text, /change review \(heisen-slop-55m, triage\): 0 of 1 PR hunk\(s\)/, "the band is not counted as a triage flag");
    // each log line is cut at 240 characters : both band lines must arrive whole
    assert.ok(out.includes(reviewBandHeading(1)), text);
    assert.ok(out.includes(REVIEW_BAND_NOTE), text);
    assert.ok(reviewBandHeading(64).length <= 240 && REVIEW_BAND_NOTE.length <= 240);
    // the triage claim arrives whole too (it used to be appended to the summary and cut at 240 characters mid-word)
    assert.ok(out.some((l) => /^ {2}Held-out: 36% .* 19% of commits flagged vs 2\.1% of ordinary commits\.$/.test(l)), text);
    assert.match(text, /::notice file=run\.js,line=\d+,title=slopGrade change review \(review suggested\)::lower confidence \(p=0\.3000\)/);
    assert.doesNotMatch(text, /title=slopGrade change review \(triage\)/, "no triage-titled notice for a band row");
  } finally {
    globalThis.fetch = realFetch;
    console.log = realLog;
  }
});
