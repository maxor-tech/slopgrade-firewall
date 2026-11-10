// End to end: the entry-point pass (0.17.0) on a REAL pull-request checkout with a stubbed provider.
//   · a PR that ADDS a route, first pass flags nothing at 0.5 → a second call with the focused prompt ; flags >= 0.3 print
//   · controls: no new route → one call ; first pass already flagged at >= 0.5 → one call
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { main } from "../../isolation-gate.mjs";
import { AI_FOCUS_SYSTEM, AI_REVIEW_SYSTEM, wantsFocusedPass, focusedResult } from "../ai-review.mjs";

const sh = (cwd, ...args) => execFileSync("git", args, { cwd, encoding: "utf8" });
const VERDICT = { gateEntitled: true, gateLevel: "paid", packBlocking: 0, pattern: "none", conformancePct: null, hardLeaks: 0, reliable: true, leaks: [] };

function prRepo(after) {
  const dir = mkdtempSync(join(tmpdir(), "fw-focus-cli-"));
  sh(dir, "init", "-q", "-b", "main");
  sh(dir, "config", "user.email", "t@example.com"); sh(dir, "config", "user.name", "t"); sh(dir, "config", "core.autocrlf", "false");
  const base = "const express = require('express');\nconst app = express();\nmodule.exports = app;\n";
  writeFileSync(join(dir, "server.js"), base);
  sh(dir, "add", "."); sh(dir, "commit", "-qm", "base");
  const b = sh(dir, "rev-parse", "HEAD").trim();
  writeFileSync(join(dir, "server.js"), after(base));
  sh(dir, "commit", "-qam", "change");
  const head = sh(dir, "rev-parse", "HEAD").trim();
  const ev = join(dir, "..", `${dir.split(/[\\/]/).pop()}-event.json`);
  writeFileSync(ev, JSON.stringify({ pull_request: { base: { sha: b }, head: { sha: head } } }));
  return { dir, ev, head };
}

async function run(after, answers) {
  const { dir, ev, head } = prRepo(after);
  const env = { GITHUB_ACTIONS: "true", ACTIONS_ID_TOKEN_REQUEST_URL: "https://oidc.example/token?api-version=2", ACTIONS_ID_TOKEN_REQUEST_TOKEN: "rt",
    GITHUB_SHA: head, GITHUB_WORKSPACE: dir, GITHUB_EVENT_NAME: "pull_request", GITHUB_EVENT_PATH: ev, FW_AI_REVIEW_KEY: "sk-own" };
  const realFetch = globalThis.fetch, realLog = console.log;
  const provider = [], out = [];
  globalThis.fetch = async (url, opts) => {
    const u = String(url);
    if (u.startsWith("https://oidc.example/")) return { ok: true, status: 200, json: async () => ({ value: "eyJ.oidc.token" }) };
    if (u.endsWith("/api/ci/pro-extractors")) return { ok: false, status: 402, json: async () => ({ error: "plan-required" }) };
    if (u === "https://api.anthropic.com/v1/messages") {
      const body = JSON.parse(opts.body);
      provider.push(body);
      const flags = answers[provider.length - 1] ?? [];
      return { ok: true, status: 200, json: async () => ({ stop_reason: "end_turn", model: "claude-opus-5-5", usage: { input_tokens: 500, output_tokens: 10 },
        content: [{ type: "text", text: JSON.stringify({ flags }) }] }) };
    }
    return { ok: true, status: 200, json: async () => VERDICT };
  };
  console.log = (...a) => out.push(a.join(" "));
  try {
    const code = await main(["--gate", "--ai-review"], env);
    return { code, provider, text: out.join("\n") };
  } finally {
    globalThis.fetch = realFetch; console.log = realLog;
    rmSync(dir, { recursive: true, force: true });
  }
}

const addRoute = (s) => s.replace("module.exports", "app.post('/api/rooms/:id/messages', (req, res) => res.json(store.add(req.params.id, req.body)));\nmodule.exports");
const noRoute = (s) => s.replace("module.exports", "const limit = 10;\nmodule.exports");
const focusFlag = { hunk: 0, class: "missing authorization", confidence: 0.35, why: "any caller posts into any room id" };
const lowFlag = { hunk: 0, class: "missing rate limit", confidence: 0.2, why: "unbounded" };

test("a PR that adds a route, first pass silent → the focused pass runs and its >= 0.3 flags print as entry-point notices", async () => {
  const { code, provider, text } = await run(addRoute, [[], [focusFlag, lowFlag]]);
  assert.equal(code, 0, "notices never block");
  assert.equal(provider.length, 2);
  assert.equal(provider[0].system, AI_REVIEW_SYSTEM);
  assert.equal(provider[1].system, AI_FOCUS_SYSTEM);
  assert.match(text, /AI review, entry-point pass \(your key, claude-opus-5-5, triage\): 1 of 1 PR hunk\(s\) flagged/);
  assert.match(text, /::notice file=server\.js,line=\d+,title=slopGrade AI review \(entry point, triage\)::missing authorization \(confidence 0\.35\)/);
  assert.doesNotMatch(text, /missing rate limit/, "a flag under 0.3 is dropped");
});

test("controls: no new route → one call ; first pass already flagged at 0.5 → one call", async () => {
  const a = await run(noRoute, [[], [focusFlag]]);
  assert.equal(a.provider.length, 1);
  assert.doesNotMatch(a.text, /entry-point pass/);
  const b = await run(addRoute, [[{ hunk: 0, class: "missing authorization", confidence: 0.8, why: "x" }], [focusFlag]]);
  assert.equal(b.provider.length, 1);
  assert.doesNotMatch(b.text, /entry-point pass/);
});

test("wantsFocusedPass / focusedResult: the measured condition and cut, nothing else", () => {
  const surface = { surface: true };
  assert.equal(wantsFocusedPass(surface, { flags: [] }), true);
  assert.equal(wantsFocusedPass(surface, { flags: [{ confidence: 0.49 }] }), true, "a sub-0.5 first-pass flag is « reported none »");
  assert.equal(wantsFocusedPass(surface, { flags: [{ confidence: 0.5 }] }), false);
  assert.equal(wantsFocusedPass({ surface: false }, { flags: [] }), false);
  assert.equal(wantsFocusedPass(surface, { error: "provider HTTP 500" }), false, "an errored first pass is not « reported none »");
  assert.equal(wantsFocusedPass(surface, null), false);
  assert.deepEqual(focusedResult({ flags: [{ confidence: 0.3 }, { confidence: 0.29 }], sent: [] }).flags, [{ confidence: 0.3 }]);
  assert.equal(focusedResult({ flags: [], sent: [] }).focused, true);
  assert.deepEqual(focusedResult({ error: "x" }), { error: "x" });
});
