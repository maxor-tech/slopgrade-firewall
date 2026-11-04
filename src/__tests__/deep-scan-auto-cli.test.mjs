// The Action's deep scan defaults to "auto" : since 0.13.6 on for PUBLIC repos only, read from the runner's own OIDC claim.
// End to end, main() against a stubbed server : a public repo sends the sink-bearing source and says so once ; a private
// repo sends nothing, and a paid one is invited ; an explicit --deep-scan on a free repo still warns. Plus the action.yml wiring.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, rmSync, readFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { main, DEEP_AUTO_NOTICE } from "../../isolation-gate.mjs";

const sh = (cwd, ...args) => execFileSync("git", args, { cwd, encoding: "utf8" });
// A runner's OIDC token as GitHub mints it : the client reads only the visibility claim.
const oidc = (visibility) => `h.${Buffer.from(JSON.stringify({ repository_visibility: visibility })).toString("base64url")}.s`;
const BASE_VERDICT = { packBlocking: 0, pattern: "none", conformancePct: null, hardLeaks: 0, reliable: true, leaks: [] };
const PAID = { ...BASE_VERDICT, gateEntitled: true, gateLevel: "paid" };
const FREE = { ...BASE_VERDICT, gateEntitled: false, gateLevel: "none" };

function repo() {
  const dir = mkdtempSync(join(tmpdir(), "fw-deep-auto-"));
  sh(dir, "init", "-q", "-b", "main");
  sh(dir, "config", "user.email", "t@example.com"); sh(dir, "config", "user.name", "t");
  sh(dir, "config", "core.autocrlf", "false");
  writeFileSync(join(dir, "app.py"), "import os\nfrom flask import Flask, request\napp = Flask(__name__)\n\n@app.route('/run')\ndef run():\n    os.system('ls ' + request.args['d'])\n    return 'ok'\n");
  sh(dir, "add", "."); sh(dir, "commit", "-qm", "base");
  return { dir, head: sh(dir, "rev-parse", "HEAD").trim() };
}

async function run(argv, verdict, { pr = false, token = oidc("private") } = {}) {
  const { dir, head: base } = repo();
  let head = base, prEnv = { GITHUB_EVENT_NAME: "push" }, ev = null;
  if (pr) {
    writeFileSync(join(dir, "app.py"), readFileSync(join(dir, "app.py"), "utf8").replace("return 'ok'", "return 'done'"));
    sh(dir, "commit", "-qam", "change");
    head = sh(dir, "rev-parse", "HEAD").trim();
    ev = join(dir, "..", `${dir.split(/[\\/]/).pop()}-event.json`);
    writeFileSync(ev, JSON.stringify({ pull_request: { base: { sha: base }, head: { sha: head } } }));
    prEnv = { GITHUB_EVENT_NAME: "pull_request", GITHUB_EVENT_PATH: ev };
  }
  const env = { GITHUB_ACTIONS: "true", ACTIONS_ID_TOKEN_REQUEST_URL: "https://oidc.example/token?api-version=2",
    ACTIONS_ID_TOKEN_REQUEST_TOKEN: "runner-token", GITHUB_SHA: head, GITHUB_WORKSPACE: dir, ...prEnv };
  const realFetch = globalThis.fetch, realLog = console.log;
  const heisen = [], out = [];
  globalThis.fetch = async (url, opts) => {
    const u = String(url);
    if (u.startsWith("https://oidc.example/")) return { ok: true, status: 200, json: async () => ({ value: token }) };
    if (u.endsWith("/api/ci/pro-extractors")) return { ok: false, status: 402, json: async () => ({ error: "plan-required" }) };
    if (u.endsWith("/api/ci/heisen")) {
      const body = JSON.parse(opts.body);
      heisen.push(body);
      return { ok: true, status: 200, json: async () => ({ ok: true, findings: [], scanned: body.units.length, unanswered: 0 }) };
    }
    return { ok: true, status: 200, json: async () => verdict };
  };
  console.log = (...a) => out.push(a.join(" "));
  try {
    const code = await main(argv, env);
    return { code, heisen, text: out.join("\n") };
  } finally {
    globalThis.fetch = realFetch;
    console.log = realLog;
    rmSync(dir, { recursive: true, force: true });
    if (ev) rmSync(ev, { force: true });
  }
}

// 0.13.6 (Jeff 2026-11-04) : the private-code pitch stays true. On "auto" a private repo sends nothing, paid or not.
test("auto on a PAID PRIVATE repo: no source leaves, and the log invites the opt-in", async () => {
  const r = await run(["--gate", "--deep-scan", "--deep-scan-auto", "--change-review", "--change-review-auto"], PAID, { pr: true });
  assert.equal(r.code, 0);
  assert.equal(r.heisen.length, 0, "a private repo never sends source on the auto default");
  assert.match(r.text, /Deep scan available on this paid repo: add `deep-scan: "true"`/);
  assert.doesNotMatch(r.text, /deep scan is on by default/);
  assert.doesNotMatch(r.text, /deep scan is a paid feature/);
  assert.doesNotMatch(r.text, /change review/);
});

test("auto with an unreadable token: the repo counts as private, nothing leaves", async () => {
  for (const token of ["eyJ.oidc.token", "not-a-jwt", oidc("internal"), "h." + Buffer.from('{"repository_visibility":["public"]}').toString("base64url") + ".s"]) {
    const r = await run(["--gate", "--deep-scan", "--deep-scan-auto"], PAID, { token });
    assert.equal(r.heisen.length, 0, token);
  }
});

test("an explicit deep-scan: true on a PAID PRIVATE repo sends the source, without the auto notice", async () => {
  const r = await run(["--gate", "--deep-scan"], PAID);
  assert.equal(r.heisen.length, 1);
  assert.deepEqual(r.heisen[0].units.map((u) => u.path), ["app.py"]);
  assert.doesNotMatch(r.text, /deep scan is on by default/);
  assert.doesNotMatch(r.text, /Deep scan available/);
});

test("auto on a PAID PUBLIC repo: the source is sent once and the log names what left and the opt-out", async () => {
  const r = await run(["--gate", "--deep-scan", "--deep-scan-auto"], PAID, { token: oidc("public") });
  assert.equal(r.code, 0);
  assert.equal(r.heisen.length, 1, "one deep-scan request");
  assert.deepEqual(r.heisen[0].units.map((u) => u.path), ["app.py"]);
  assert.ok(r.text.includes(`::notice title=slopGrade Firewall::${DEEP_AUTO_NOTICE(1, 0)}`), r.text);
  assert.match(DEEP_AUTO_NOTICE(1, 0), /this public repo/);
  assert.match(DEEP_AUTO_NOTICE(1, 0), /deep-scan: "false"/);
  assert.doesNotMatch(r.text, /deep scan is a paid feature/);
});

test("auto on a PUBLIC repo, pull request: the source is scanned, the log says so, and no PR hunk ever leaves", async () => {
  const PUBLIC = { ...BASE_VERDICT, gateEntitled: true, gateLevel: "public" };
  const r = await run(["--gate", "--deep-scan", "--deep-scan-auto", "--change-review", "--change-review-auto"], PUBLIC, { pr: true, token: oidc("public") });
  assert.equal(r.code, 0);
  assert.equal(r.heisen.length, 1, "one deep-scan request");
  assert.deepEqual(r.heisen[0].units.map((u) => u.path), ["app.py"]);
  assert.equal(r.heisen[0].hunks, undefined, "change review is paid only : hunks are never sent");
  assert.ok(r.text.includes(`::notice title=slopGrade Firewall::${DEEP_AUTO_NOTICE(1, 0)}`), r.text);
  assert.doesNotMatch(r.text, /change review/);
  // an explicit change-review on a public repo says why nothing was reviewed
  const ex = await run(["--gate", "--deep-scan", "--change-review"], PUBLIC, { pr: true, token: oidc("public") });
  assert.equal(ex.heisen[0].hunks, undefined);
  assert.match(ex.text, /change review is a paid feature — no PR hunk was sent/);
});

test("auto on a FREE repo: no source is sent and the log says nothing about the deep scan", async () => {
  const r = await run(["--gate", "--deep-scan", "--deep-scan-auto"], FREE);
  assert.equal(r.code, 0);
  assert.equal(r.heisen.length, 0, "no source leaves a free repo");
  assert.doesNotMatch(r.text, /deep scan is a paid feature/);
  assert.doesNotMatch(r.text, /deep scan is on by default/);
});

test("an explicit --deep-scan on a FREE repo still sends nothing and still warns (the pre-0.13.1 behaviour)", async () => {
  const r = await run(["--gate", "--deep-scan"], FREE);
  assert.equal(r.heisen.length, 0);
  assert.match(r.text, /deep scan is a paid feature — no source was sent/);
  assert.doesNotMatch(r.text, /deep scan is on by default/);
});

// Live run slopgrade#1612 (v0.13.2) printed « library mode requested, but this repo looks like an application » on an
// app repo that never asked : the auto default must stay silent there ; an explicit library-mode: "true" still informs.
// The same class on change review (judge Ohno, 2026-11-03) : under auto, a PUSH run has no PR by design and must not
// print « not a pull request run — nothing reviewed » on every run.
const FULL_AUTO = ["--gate", "--deep-scan", "--deep-scan-auto", "--library-mode", "--library-mode-auto", "--change-review", "--change-review-auto"];
test("full auto on a PAID application repo, push run : no « requested » / « not a pull request » line ; explicit flags still explain", async () => {
  const auto = await run(FULL_AUTO, PAID, { token: oidc("public") });
  assert.equal(auto.heisen.length, 1);
  assert.equal(auto.heisen[0].library, undefined, "an application is never sent as a library (the field is only sent when true)");
  assert.doesNotMatch(auto.text, /library mode requested/);
  assert.doesNotMatch(auto.text, /change review: not a pull request run/);
  const explicit = await run(["--gate", "--deep-scan", "--library-mode", "--change-review"], PAID);
  assert.match(explicit.text, /library mode requested, but this repo looks like an application/);
  assert.match(explicit.text, /change review: not a pull request run \(or git could not diff the base\) — nothing reviewed/);
});

test("action.yml : deep-scan / library-mode / change-review default to auto, and auto maps to the flags", () => {
  const yml = readFileSync(new URL("../../action.yml", import.meta.url), "utf8");
  for (const input of ["deep-scan", "library-mode", "change-review"]) {
    const block = new RegExp(`\\n  ${input}:\\n(?:    .*\\n)*?    default: "([^"]*)"`).exec(yml);
    assert.ok(block, `input ${input} has a default`);
    assert.equal(block[1], "auto", `${input} default`);
  }
  assert.match(yml, /\[ "\$\{FW_DEEP_SCAN\}" = "auto" \] && ARGS\+=\(--deep-scan --deep-scan-auto\)/);
  assert.match(yml, /\[ "\$\{FW_CHANGE_REVIEW\}" = "auto" \] && \[ "\$\{FW_DEEP_SCAN\}" != "false" \] && ARGS\+=\(--change-review --change-review-auto\)/);
  assert.match(yml, /\[ "\$\{FW_LIBRARY_MODE\}" = "auto" \] && \[ "\$\{FW_DEEP_SCAN\}" != "false" \] && ARGS\+=\(--library-mode --library-mode-auto\)/);
  // deep-scan-block stays an explicit opt-in : the default never blocks on a learned or hosted verdict
  assert.match(yml, /\n  deep-scan-block:\n(?:    .*\n)*?    default: "false"/);
});
