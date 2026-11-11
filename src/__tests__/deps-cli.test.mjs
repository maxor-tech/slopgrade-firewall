// End to end: `main([... "--dependency-scan"])` on a REAL pull-request checkout, OSV stubbed. The PR moves lodash to a
// version with a published advisory: one warning on package-lock.json, exit 0. Controls: option off, no lockfile change.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { main } from "../../isolation-gate.mjs";

const sh = (cwd, ...args) => execFileSync("git", args, { cwd, encoding: "utf8" });
const VERDICT = { gateEntitled: false, gateLevel: "none", packBlocking: 0, pattern: "none", conformancePct: null, hardLeaks: 0, reliable: true, leaks: [] };
const lock = (v, dev = false) => JSON.stringify({ lockfileVersion: 3, packages: { "": { name: "app" }, "node_modules/lodash": { version: v, resolved: `https://registry.npmjs.org/lodash/-/lodash-${v}.tgz`, ...(dev ? { dev: true } : {}) } } }, null, 2);

function prRepo(changeLock, dev = false) {
  const dir = mkdtempSync(join(tmpdir(), "fw-deps-cli-"));
  sh(dir, "init", "-q", "-b", "main");
  sh(dir, "config", "user.email", "t@example.com"); sh(dir, "config", "user.name", "t"); sh(dir, "config", "core.autocrlf", "false");
  writeFileSync(join(dir, "package-lock.json"), lock("4.17.21"));
  writeFileSync(join(dir, "index.js"), "module.exports = 1;\n");
  sh(dir, "add", "."); sh(dir, "commit", "-qm", "base");
  const base = sh(dir, "rev-parse", "HEAD").trim();
  if (changeLock) writeFileSync(join(dir, "package-lock.json"), lock("4.17.15", dev));
  writeFileSync(join(dir, "index.js"), "module.exports = 2;\n");
  sh(dir, "commit", "-qam", "change");
  const head = sh(dir, "rev-parse", "HEAD").trim();
  const ev = join(dir, "..", `${dir.split(/[\\/]/).pop()}-event.json`);
  writeFileSync(ev, JSON.stringify({ pull_request: { base: { sha: base }, head: { sha: head } } }));
  return { dir, ev, head };
}

async function run({ flag = true, changeLock = true, event = "pull_request", dev = false, severity = null, extra = [] } = {}) {
  const { dir, ev, head } = prRepo(changeLock, dev);
  const env = { GITHUB_ACTIONS: "true", ACTIONS_ID_TOKEN_REQUEST_URL: "https://oidc.example/token?api-version=2", ACTIONS_ID_TOKEN_REQUEST_TOKEN: "rt",
    GITHUB_SHA: head, GITHUB_WORKSPACE: dir, GITHUB_EVENT_NAME: event, GITHUB_EVENT_PATH: ev };
  const realFetch = globalThis.fetch, realLog = console.log;
  const osv = [], out = [];
  globalThis.fetch = async (url, opts) => {
    const u = String(url);
    if (u.startsWith("https://oidc.example/")) return { ok: true, status: 200, json: async () => ({ value: "eyJ.oidc.token" }) };
    if (u === "https://api.osv.dev/v1/querybatch") {
      const q = JSON.parse(opts.body).queries;
      osv.push(q);
      return { ok: true, status: 200, json: async () => ({ results: q.map((x) => (x.package.name === "lodash" && x.version === "4.17.15" ? { vulns: [{ id: "GHSA-35jh-r3h4-6jhm" }] } : {})) }) };
    }
    if (severity && u === "https://api.osv.dev/v1/vulns/GHSA-35jh-r3h4-6jhm") return { ok: true, status: 200, json: async () => ({ id: "GHSA-35jh-r3h4-6jhm", aliases: [], database_specific: { severity } }) };
    if (u.endsWith("/api/ci/pro-extractors")) return { ok: false, status: 402, json: async () => ({ error: "plan-required" }) };
    return { ok: true, status: 200, json: async () => VERDICT };
  };
  console.log = (...a) => out.push(a.join(" "));
  try {
    const code = await main(flag ? ["--dependency-scan", ...extra] : [], env);
    return { code, osv, text: out.join("\n") };
  } finally {
    globalThis.fetch = realFetch; console.log = realLog;
    rmSync(dir, { recursive: true, force: true });
  }
}

test("a PR that moves lodash to a version with an advisory: one OSV query with only {name, ecosystem, version}, one warning, exit 0", async () => {
  const { code, osv, text } = await run();
  assert.equal(code, 0, "warnings never block");
  assert.deepEqual(osv, [[{ package: { name: "lodash", ecosystem: "npm" }, version: "4.17.15" }]]);
  assert.match(text, /::warning file=package-lock\.json,line=1,title=slopGrade dependency scan::lodash@4\.17\.15 has 1 published advisory: GHSA-35jh-r3h4-6jhm/);
  assert.match(text, /dependency scan: package-lock\.json — 1 of 1 version\(s\) this PR adds have published advisories \(OSV\)/);
});

test("scheduled run (monitor): every pinned version of the lockfile is checked, worded « pinned », even with no change", async () => {
  const { code, osv, text } = await run({ event: "schedule", changeLock: false });
  assert.equal(code, 0);
  assert.deepEqual(osv, [[{ package: { name: "lodash", ecosystem: "npm" }, version: "4.17.21" }]]);
  assert.match(text, /dependency scan: package-lock\.json — 0 of 1 version\(s\) pinned in this lockfile/);
  // an event that is neither a PR nor a monitor event (e.g. release) sends nothing
  assert.deepEqual((await run({ event: "release", changeLock: false })).osv, []);
});

test("controls: option off → no OSV call ; a PR that changes no lockfile → no OSV call", async () => {
  assert.deepEqual((await run({ flag: false })).osv, []);
  const b = await run({ changeLock: false });
  assert.deepEqual(b.osv, []);
  assert.doesNotMatch(b.text, /dependency scan/);
});

test("default filter end to end: a dev-only MODERATE version is listed in the log, not annotated; --dependency-scan-all annotates it", async () => {
  const quiet = await run({ dev: true, severity: "MODERATE" });
  assert.equal(quiet.code, 0);
  assert.doesNotMatch(quiet.text, /::warning file=package-lock\.json/);
  assert.match(quiet.text, /1 of them below HIGH or dev-only: listed here, not annotated/);
  assert.match(quiet.text, /- lodash@4\.17\.15 \(dev\)  GHSA-35jh-r3h4-6jhm  MODERATE/);
  const loud = await run({ dev: true, severity: "MODERATE", extra: ["--dependency-scan-all"] });
  assert.match(loud.text, /::warning file=package-lock\.json,line=1,title=slopGrade dependency scan::lodash@4\.17\.15 \(dev\) has 1 published advisory \(MODERATE\)/);
  // not dev, HIGH: annotated by default
  assert.match((await run({ severity: "HIGH" })).text, /::warning file=package-lock\.json.*lodash@4\.17\.15 has 1 published advisory \(HIGH\)/);
});
