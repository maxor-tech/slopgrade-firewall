// 0.13.1 — the Action's deep scan defaults to "auto" (Jeff 2026-11-03 : default-on for PAID repos). End to end, main()
// against a stubbed server : a paid verdict sends the sink-bearing source and says so once ; a free verdict sends
// nothing and prints nothing about it ; an explicit --deep-scan on a free repo still warns. Plus the action.yml wiring.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, rmSync, readFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { main, DEEP_AUTO_NOTICE } from "../../isolation-gate.mjs";

const sh = (cwd, ...args) => execFileSync("git", args, { cwd, encoding: "utf8" });
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

async function run(argv, verdict) {
  const { dir, head } = repo();
  const env = { GITHUB_ACTIONS: "true", ACTIONS_ID_TOKEN_REQUEST_URL: "https://oidc.example/token?api-version=2",
    ACTIONS_ID_TOKEN_REQUEST_TOKEN: "runner-token", GITHUB_SHA: head, GITHUB_WORKSPACE: dir, GITHUB_EVENT_NAME: "push" };
  const realFetch = globalThis.fetch, realLog = console.log;
  const heisen = [], out = [];
  globalThis.fetch = async (url, opts) => {
    const u = String(url);
    if (u.startsWith("https://oidc.example/")) return { ok: true, status: 200, json: async () => ({ value: "eyJ.oidc.token" }) };
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
  }
}

test("auto on a PAID repo: the sink-bearing source is sent once and the log names what left and the opt-out", async () => {
  const r = await run(["--gate", "--deep-scan", "--deep-scan-auto"], PAID);
  assert.equal(r.code, 0);
  assert.equal(r.heisen.length, 1, "one deep-scan request");
  assert.deepEqual(r.heisen[0].units.map((u) => u.path), ["app.py"]);
  assert.ok(r.text.includes(`::notice title=slopGrade Firewall::${DEEP_AUTO_NOTICE(1, 0)}`), r.text);
  assert.match(DEEP_AUTO_NOTICE(1, 0), /deep-scan: "false"/);
  assert.doesNotMatch(r.text, /deep scan is a paid feature/);
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
  const auto = await run(FULL_AUTO, PAID);
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
