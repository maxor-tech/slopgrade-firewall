// End to end: `main(["--deep-scan", "--change-review"])` on a REAL pull-request checkout against a stubbed server. The
// PR removes a path check: its hunk is in the /api/ci/heisen body, and the server's changeReview prints as a triage
// notice — never as a finding, never blocking.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { main } from "../../isolation-gate.mjs";

const sh = (cwd, ...args) => execFileSync("git", args, { cwd, encoding: "utf8" });
const PAID = { gateEntitled: true, gateLevel: "paid", packBlocking: 0, pattern: "none", conformancePct: null, hardLeaks: 0, reliable: true, leaks: [] };

function prRepo() {
  const dir = mkdtempSync(join(tmpdir(), "fw-change-cli-"));
  sh(dir, "init", "-q", "-b", "main");
  sh(dir, "config", "user.email", "t@example.com"); sh(dir, "config", "user.name", "t");
  sh(dir, "config", "core.autocrlf", "false");
  const safe = "import os, subprocess\nBASE = '/srv'\n\ndef read(name):\n    path = os.path.join(BASE, name)\n    if not os.path.realpath(path).startswith(BASE):\n        raise ValueError(name)\n    return subprocess.check_output(['cat', path])\n";
  writeFileSync(join(dir, "files.py"), safe);
  sh(dir, "add", "."); sh(dir, "commit", "-qm", "base");
  const base = sh(dir, "rev-parse", "HEAD").trim();
  writeFileSync(join(dir, "files.py"), safe.replace("    if not os.path.realpath(path).startswith(BASE):\n        raise ValueError(name)\n", ""));
  sh(dir, "commit", "-qam", "simplify");
  const head = sh(dir, "rev-parse", "HEAD").trim();
  const ev = join(dir, "..", `${dir.split(/[\\/]/).pop()}-event.json`);
  writeFileSync(ev, JSON.stringify({ pull_request: { base: { sha: base }, head: { sha: head } } }));
  return { dir, ev, head };
}

test("--change-review on a PR: the removed check is sent as a hunk and printed as a triage notice", async (t) => {
  const { dir, ev, head } = prRepo();
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const env = {
    GITHUB_ACTIONS: "true", ACTIONS_ID_TOKEN_REQUEST_URL: "https://oidc.example/token?api-version=2",
    ACTIONS_ID_TOKEN_REQUEST_TOKEN: "runner-token", GITHUB_SHA: head, GITHUB_WORKSPACE: dir,
    GITHUB_EVENT_NAME: "pull_request", GITHUB_EVENT_PATH: ev,
  };
  const realFetch = globalThis.fetch, realLog = console.log;
  const calls = [], out = [];
  globalThis.fetch = async (url, opts) => {
    const u = String(url);
    calls.push({ url: u, opts });
    if (u.startsWith("https://oidc.example/")) return { ok: true, status: 200, json: async () => ({ value: "eyJ.oidc.token" }) };
    if (u.endsWith("/api/ci/pro-extractors")) return { ok: false, status: 402, json: async () => ({ error: "plan-required" }) };
    if (u.endsWith("/api/ci/heisen")) {
      const body = JSON.parse(opts.body);
      const flagged = (body.hunks ?? []).map((h) => ({ path: h.path, newStart: h.newStart, p: 0.9995 }));
      return { ok: true, status: 200, json: async () => ({ ok: true, findings: [], scanned: body.units.length, unanswered: 0,
        changeReview: { reviewed: flagged.length, unreviewed: 0, threshold: 0.9994, flagged } }) };
    }
    return { ok: true, status: 200, json: async () => PAID };
  };
  console.log = (...a) => out.push(a.join(" "));
  try {
    const code = await main(["--gate", "--deep-scan", "--change-review"], env);
    assert.equal(code, 0, "triage never blocks");
    const sent = calls.filter((c) => c.url.endsWith("/api/ci/heisen"));
    assert.equal(sent.length, 1);
    const hunks = JSON.parse(sent[0].opts.body).hunks;
    assert.equal(hunks.length, 1);
    assert.equal(hunks[0].path, "files.py");
    assert.match(hunks[0].text, /^-    if not os\.path\.realpath\(path\)\.startswith\(BASE\):$/m);
    const text = out.join("\n");
    assert.match(text, /change review \(heisen-slop-55m, triage\): 1 of 1 PR hunk\(s\) look like they weaken a security check/);
    assert.match(text, /::notice file=files\.py,line=\d+ title=slopGrade change review \(triage\)::this change may weaken a security check \(p=0\.9995\)/);
  } finally {
    globalThis.fetch = realFetch;
    console.log = realLog;
  }
});

test("without --change-review no hunk is ever sent", async (t) => {
  const { dir, ev, head } = prRepo();
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const env = { GITHUB_ACTIONS: "true", ACTIONS_ID_TOKEN_REQUEST_URL: "https://oidc.example/token?api-version=2",
    ACTIONS_ID_TOKEN_REQUEST_TOKEN: "runner-token", GITHUB_SHA: head, GITHUB_WORKSPACE: dir, GITHUB_EVENT_NAME: "pull_request", GITHUB_EVENT_PATH: ev };
  const realFetch = globalThis.fetch, realLog = console.log;
  const bodies = [];
  globalThis.fetch = async (url, opts) => {
    const u = String(url);
    if (u.startsWith("https://oidc.example/")) return { ok: true, status: 200, json: async () => ({ value: "eyJ.oidc.token" }) };
    if (u.endsWith("/api/ci/pro-extractors")) return { ok: false, status: 402, json: async () => ({ error: "plan-required" }) };
    if (u.endsWith("/api/ci/heisen")) { bodies.push(JSON.parse(opts.body)); return { ok: true, status: 200, json: async () => ({ ok: true, findings: [], scanned: 1, unanswered: 0 }) }; }
    return { ok: true, status: 200, json: async () => PAID };
  };
  console.log = () => {};
  try {
    await main(["--gate", "--deep-scan"], env);
    assert.equal(bodies.length, 1);
    assert.equal("hunks" in bodies[0], false);
  } finally {
    globalThis.fetch = realFetch;
    console.log = realLog;
  }
});
