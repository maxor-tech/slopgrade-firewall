// End to end: `main(["--ai-review"])` on a REAL pull-request checkout against a stubbed server and provider.
//   · WITH a key: the call goes to the provider from the runner, never to slopGrade ;
//   · WITHOUT a key, PAID repo: the hunks go to slopGrade's /api/ci/ai-review AFTER the verdict, with the OIDC proof ;
//   · WITHOUT a key, FREE repo: nothing is sent, one warning says how to turn it on. Never blocking.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { main } from "../../isolation-gate.mjs";

const sh = (cwd, ...args) => execFileSync("git", args, { cwd, encoding: "utf8" });
const VERDICT = (paid) => ({ gateEntitled: paid, gateLevel: paid ? "paid" : "none", packBlocking: 0, pattern: "none", conformancePct: null, hardLeaks: 0, reliable: true, leaks: [] });

function prRepo() {
  const dir = mkdtempSync(join(tmpdir(), "fw-ai-cli-"));
  sh(dir, "init", "-q", "-b", "main");
  sh(dir, "config", "user.email", "t@example.com"); sh(dir, "config", "user.name", "t");
  sh(dir, "config", "core.autocrlf", "false");
  const safe = "def admin(req):\n    if not req.user.is_admin:\n        abort(403)\n    return render()\n";
  writeFileSync(join(dir, "views.py"), safe);
  sh(dir, "add", "."); sh(dir, "commit", "-qm", "base");
  const base = sh(dir, "rev-parse", "HEAD").trim();
  writeFileSync(join(dir, "views.py"), safe.replace("    if not req.user.is_admin:\n        abort(403)\n", ""));
  sh(dir, "commit", "-qam", "simplify");
  const head = sh(dir, "rev-parse", "HEAD").trim();
  const ev = join(dir, "..", `${dir.split(/[\\/]/).pop()}-event.json`);
  writeFileSync(ev, JSON.stringify({ pull_request: { base: { sha: base }, head: { sha: head } } }));
  return { dir, ev, head };
}

async function run({ key = "", paid = true }) {
  const { dir, ev, head } = prRepo();
  const env = {
    GITHUB_ACTIONS: "true", ACTIONS_ID_TOKEN_REQUEST_URL: "https://oidc.example/token?api-version=2",
    ACTIONS_ID_TOKEN_REQUEST_TOKEN: "runner-token", GITHUB_SHA: head, GITHUB_WORKSPACE: dir,
    GITHUB_EVENT_NAME: "pull_request", GITHUB_EVENT_PATH: ev, ...(key ? { FW_AI_REVIEW_KEY: key } : {}),
  };
  const realFetch = globalThis.fetch, realLog = console.log;
  const calls = [], out = [];
  globalThis.fetch = async (url, opts) => {
    const u = String(url);
    calls.push({ url: u, body: opts?.body ? JSON.parse(opts.body) : null, headers: opts?.headers });
    if (u.startsWith("https://oidc.example/")) return { ok: true, status: 200, json: async () => ({ value: "eyJ.oidc.token" }) };
    if (u.endsWith("/api/ci/pro-extractors")) return { ok: false, status: 402, json: async () => ({ error: "plan-required" }) };
    if (u === "https://api.anthropic.com/v1/messages") {
      return { ok: true, status: 200, json: async () => ({ stop_reason: "end_turn", model: "claude-opus-5-5", usage: { input_tokens: 700, output_tokens: 20 },
        content: [{ type: "text", text: JSON.stringify({ flags: [{ hunk: 0, class: "missing authorization", confidence: 0.93, why: "admin check removed" }] }) }] }) };
    }
    if (u.endsWith("/api/ci/ai-review")) {
      const b = JSON.parse(opts.body);
      return { ok: true, status: 200, json: async () => ({ ok: true, model: "claude-opus-5-5", blocking: 0, flags: [{ path: b.hunks[0].path, newStart: b.hunks[0].newStart, class: "missing authorization", confidence: 0.93, why: "admin check removed" }] }) };
    }
    return { ok: true, status: 200, json: async () => VERDICT(paid) };
  };
  console.log = (...a) => out.push(a.join(" "));
  try {
    const code = await main(["--gate", "--ai-review"], env);
    return { code, calls, text: out.join("\n") };
  } finally {
    globalThis.fetch = realFetch;
    console.log = realLog;
    rmSync(dir, { recursive: true, force: true });
  }
}

test("with ai-review-key: the provider is called from the runner, and slopGrade never receives a hunk", async () => {
  const { code, calls, text } = await run({ key: "sk-own" });
  assert.equal(code, 0);
  const provider = calls.filter((c) => c.url === "https://api.anthropic.com/v1/messages");
  assert.equal(provider.length, 1);
  assert.equal(provider[0].headers["x-api-key"], "sk-own");
  assert.equal(calls.filter((c) => c.url.endsWith("/api/ci/ai-review")).length, 0);
  assert.match(text, /AI review \(your key, claude-opus-5-5, triage\): 1 of 1 PR hunk\(s\) flagged · 700 input \+ 20 output tokens billed to your key/);
  assert.match(text, /::notice file=views\.py,line=\d+,title=slopGrade AI review \(triage\)::missing authorization \(confidence 0\.93\)/);
});

test("no key on a PAID repo: the hunks go to slopGrade after the verdict, with the run's OIDC proof", async () => {
  const { code, calls, text } = await run({ paid: true });
  assert.equal(code, 0);
  assert.equal(calls.filter((c) => c.url === "https://api.anthropic.com/v1/messages").length, 0);
  const iVerdict = calls.findIndex((c) => c.url.endsWith("/api/ci/isolation"));
  const iReview = calls.findIndex((c) => c.url.endsWith("/api/ci/ai-review"));
  assert.ok(iVerdict >= 0 && iReview > iVerdict, "the hosted review is asked only after the verdict says the repo is paid");
  const body = calls[iReview].body;
  assert.equal(body.oidcToken, "eyJ.oidc.token");
  assert.equal(body.hunks.length, 1);
  assert.equal(body.hunks[0].path, "views.py");
  assert.match(body.hunks[0].text, /^-    if not req\.user\.is_admin:$/m);
  assert.match(text, /AI review \(slopGrade-hosted, claude-opus-5-5, triage\): 1 of 1 PR hunk\(s\) flagged · 1 hunk\(s\) sent to slopGrade/);
});

test("no key on a FREE repo: nothing is sent anywhere, one warning says how to turn it on, the build is not blocked", async () => {
  const { code, calls, text } = await run({ paid: false });
  assert.equal(code, 0);
  assert.equal(calls.filter((c) => c.url.endsWith("/api/ci/ai-review") || c.url.startsWith("https://api.anthropic.com")).length, 0);
  assert.match(text, /::warning title=slopGrade Firewall::slopGrade Firewall — AI review \(slopGrade-hosted\) unavailable: no ai-review-key, and the hosted AI review needs a paid slot — nothing was sent — verdict unaffected\./);
});
