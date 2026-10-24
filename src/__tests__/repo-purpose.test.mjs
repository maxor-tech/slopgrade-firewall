// Repository purpose (src/repo-purpose.mjs) — a product stays `product` ; a course / lab / CTF / offensive-tool repo is
// classified so its pack + Deep Scan blocks become advisory. READMEs below are PARAPHRASED : no exploit text anywhere.
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { repoPurpose, readmeHead, purposeEnabled, parsePurposeOverride, readPurposeInputs, decidePurpose, purposeAdvisoryLine, PURPOSE_FILE } from "../repo-purpose.mjs";
import { main } from "../../isolation-gate.mjs";

const files = (m) => (rel) => (Object.hasOwn(m, rel) ? m[rel] : null);
const classify = (m, dirs = [], name = "") => repoPurpose(files(m), () => dirs, { name });

// ── 6 non-product READMEs ───────────────────────────────────────────────────────────────────────────────────────────
test("a video course repository is teaching (title + lesson directories)", () => {
  const r = classify({ "README.md": "# Complete Web Development Bootcamp Course\n\nThe code for every lesson of my video course.\n" }, ["lesson-01", "lesson-02", "lesson-03", "lesson-04"]);
  assert.equal(r.purpose, "teaching");
  assert.match(r.why, /course|lesson/i);
});

test("a CTF writeup repository is a lab (title)", () => {
  const r = classify({ "README.md": "# Acme CTF 2024 writeups\n\nSolutions and challenge files from the Acme capture the flag.\n" });
  assert.equal(r.purpose, "lab");
  assert.match(r.why, /CTF/);
});

test("a deliberately vulnerable web application is a lab (first paragraph)", () => {
  const r = classify({ "README.md": "# ShopGoat\n\nShopGoat is a deliberately vulnerable web application, built so students can practise finding flaws.\n" });
  assert.equal(r.purpose, "lab");
  assert.match(r.why, /deliberately vulnerable/);
});

test("a pentest toolkit with a payload collection is offensive", () => {
  const r = classify({ "README.md": "# ShellBox\n\nA pentest toolkit and payload collection for authorized red team engagements.\n" }, ["payloads"]);
  assert.equal(r.purpose, "offensive");
});

test("a Chinese vulnerability range (靶场) is a lab", () => {
  const r = classify({ "README.md": "# 文件包含靶场\n\n本项目是漏洞复现环境，用于学习。\n" });
  assert.equal(r.purpose, "lab");
});

test("a repo with only manifest keywords + exercises/solutions directories is teaching", () => {
  const r = classify({ "package.json": JSON.stringify({ name: "algos", description: "Exercises for the algorithms course", keywords: ["tutorial", "exercises"] }) }, ["exercises", "solutions"]);
  assert.equal(r.purpose, "teaching");
  assert.match(r.why, /directories|package/);
});

// ── 6 product READMEs that mention example / lab / course in passing ────────────────────────────────────────────────
test("a billing API that says « example », « lab » and « course of action » stays product", () => {
  const r = classify({ "README.md": "# Acme Billing\n\nBilling API for SaaS teams. See the example below. Our test lab runs on every commit, and the course of action on a failed charge is configurable.\n" }, ["src", "docs", "examples"]);
  assert.equal(r.purpose, "product");
});

test("create-next-app boilerplate (« learn », « tutorial ») stays product", () => {
  const r = classify({ "README.md": "This is a [Next.js](https://nextjs.org/) project bootstrapped with [`create-next-app`](https://github.com/vercel/next.js/tree/canary/packages/create-next-app).\n\n## Learn More\n\nTo learn more, take a look at the Next.js tutorial and the course.\n" }, ["app", "components"], "owner/shop");
  assert.equal(r.purpose, "product");
});

test("a library that links a tutorial and a cheat sheet in its intro stays product (weak intro needs three terms)", () => {
  const r = classify({ "README.md": "# fastparse\n\nA fast streaming parser. New here? Read the tutorial, then keep the cheat sheet open. Examples live in /examples.\n" }, ["src", "examples"]);
  assert.equal(r.purpose, "product");
});

test("a laboratory-information product (« lab » with no security word) stays product", () => {
  const r = classify({ "README.md": "# LabTrack\n\nLIMS software to track wet lab samples, reagents and equipment bookings.\n" }, ["server", "web"], "acme/labtrack");
  assert.equal(r.purpose, "product");
});

test("a course-management SaaS (manifest says « course ») stays product", () => {
  const r = classify({ "package.json": JSON.stringify({ name: "schoolhub", description: "Course platform for schools", keywords: ["saas"] }), "README.md": "# SchoolHub\n\nTimetables, grades and parent messaging.\n" }, ["apps", "packages"]);
  assert.equal(r.purpose, "product");
});

test("an OAuth server that signs a « payload » stays product (one weak word)", () => {
  const r = classify({ "README.md": "# AuthKit\n\nOAuth 2.1 server. Tokens carry a signed payload; the example client shows the flow.\n" }, ["server", "client"]);
  assert.equal(r.purpose, "product");
});

// ── mechanics ──────────────────────────────────────────────────────────────────────────────────────────────────────
test("no README, no manifest, no directories → product", () => {
  assert.deepEqual(classify({}), { purpose: "product", why: "no teaching / lab / offensive signal" });
});

test("a generic « labs » name needs a security word next to it", () => {
  assert.equal(classify({ "README.md": "# Cloud Labs\n\nA company that builds storage.\n" }).purpose, "product");
  assert.equal(classify({ "README.md": "# Injection Labs\n\nHands-on injection and XSS labs.\n" }).purpose, "lab");
});

test("UTF-16 / BOM README text is read (null bytes and replacement chars are stripped)", () => {
  const utf16 = "﻿#\u0000 \u0000 \u0000C\u0000o\u0000u\u0000r\u0000s\u0000e\u0000";
  assert.equal(readmeHead(utf16).title.replace(/\s+/g, ""), "Course");
});

test("badges, images, HTML and code fences do not make the title", () => {
  const h = readmeHead("[![build](https://x/y.svg)](https://x)\n<p align=\"center\"><img src=\"a.png\"></p>\n\n# Real Title\n\n```\n# not a title\n```\nbody text\n");
  assert.equal(h.title, "Real Title");
});

// ── flag, override, base branch ─────────────────────────────────────────────────────────────────────────────────────
test("SLOPGRADE_PURPOSE_CLASSIFIER : default off, on / 1 / true / yes enable", () => {
  assert.equal(purposeEnabled({}), false);
  assert.equal(purposeEnabled(undefined), false);
  for (const v of ["on", "ON", "1", "true", "yes"]) assert.equal(purposeEnabled({ SLOPGRADE_PURPOSE_CLASSIFIER: v }), true, v);
  for (const v of ["off", "0", "false", "no", "maybe"]) assert.equal(purposeEnabled({ SLOPGRADE_PURPOSE_CLASSIFIER: v }), false, v);
});

test("flag off → decidePurpose never reads a file and answers product", () => {
  const d = decidePurpose({ SLOPGRADE_PURPOSE_CLASSIFIER: "off" }, () => { throw new Error("no git"); }, () => { throw new Error("no fs"); }, () => { throw new Error("no dirs"); });
  assert.equal(d.purpose, "product");
  assert.equal(d.enabled, false);
});

test("`purpose: product` override : accepted forms and refused forms", () => {
  for (const ok of ["purpose: product", "purpose: product # we ship this", "  # c\npurpose: \"product\"\r\n", "other: 1\npurpose: 'product'"]) assert.equal(parsePurposeOverride(ok), true, ok);
  for (const bad of ["purpose: teaching", "# purpose: product", "purpose: products", "xpurpose: product", "", null]) assert.equal(parsePurposeOverride(bad), false, String(bad));
});

// The classifier is opt-in (default off) ; the tests below exercise it switched on.
const ON = { SLOPGRADE_PURPOSE_CLASSIFIER: "on" };

test("the override flips a non-product repo back to product and says so", () => {
  const readme = "# Acme CTF 2024 writeups\n\ncapture the flag solutions\n";
  const without = decidePurpose(ON, null, (p) => { if (p === "README.md") return readme; throw new Error("missing"); }, () => []);
  assert.equal(without.purpose, "lab"); // failure pre-condition : the detector alone says non-product
  const withIt = decidePurpose(ON, null, (p) => { if (p === "README.md") return readme; if (p === PURPOSE_FILE) return "purpose: product\n"; throw new Error("missing"); }, () => []);
  assert.equal(withIt.purpose, "product");
  assert.equal(withIt.override, true);
  assert.match(withIt.why, /detector said lab/);
});

test("on a pull request every input comes from the BASE branch via git, never the checkout", () => {
  const calls = [];
  const git = (args) => { calls.push(args.join(" ")); if (args[0] === "ls-tree") return "lesson-01\0lesson-02\0lesson-03\0"; if (args[1] === "origin/main:README.md") return "# Python Course\n"; throw new Error("absent"); };
  const fs = () => { throw new Error("the checkout must not be read on a PR"); };
  const d = decidePurpose({ ...ON, GITHUB_BASE_REF: "main", GITHUB_REPOSITORY: "o/r" }, git, fs, fs);
  assert.equal(d.purpose, "teaching");
  assert.equal(d.source, "base");
  assert.ok(calls.some((c) => c === "show origin/main:README.md"));
  assert.ok(calls.some((c) => c === "ls-tree -d --name-only -z origin/main"));
  assert.ok(calls.some((c) => c === `show origin/main:${PURPOSE_FILE}`), "the override file is read from the base too");
});

test("an odd base ref or an unreadable base reads nothing → product (blocking unchanged)", () => {
  for (const ref of ["--output=x", "a..b", "main;rm"]) {
    let called = false;
    const i = readPurposeInputs({ GITHUB_BASE_REF: ref }, () => { called = true; return "x"; }, () => "x", () => ["lesson-01"]);
    assert.equal(i.read("README.md"), null, ref);
    assert.deepEqual(i.dirs(), [], ref);
    assert.equal(called, false, ref);
  }
  const d = decidePurpose({ ...ON, GITHUB_BASE_REF: "main" }, () => { throw new Error("shallow clone"); }, () => "# Course\n", () => []);
  assert.equal(d.purpose, "product");
});

test("the advisory log line has the documented wording", () => {
  assert.equal(purposeAdvisoryLine({ purpose: "lab", why: "README title mentions CTF" }),
    "slopGrade Firewall: this repo reads as a lab repository (README title mentions CTF) — findings are advisory. Set `purpose: product` in .slopgrade.yml to block.");
});

// ── end to end through main() : the gate turns a pack block into an advisory annotation ─────────────────────────────
const CI = (ws, extra = {}) => ({
  GITHUB_ACTIONS: "true", ACTIONS_ID_TOKEN_REQUEST_URL: "https://oidc.example/token?api-version=2", ACTIONS_ID_TOKEN_REQUEST_TOKEN: "t",
  GITHUB_SHA: "0123456789abcdef0123456789abcdef01234567", GITHUB_WORKSPACE: ws, FW_UPLOAD_SARIF: "false", ...extra,
});
const BLOCKING = {
  ok: true, pattern: "none", tenantKey: null, conformancePct: null, hardLeaks: 0, byId: 0, reliable: false, gateEntitled: true, leaks: [],
  gateLevel: "paid", fixableCount: 0, packBlocking: 1,
  sqli: { count: 1, hidden: 0, blocking: 1, findings: [{ rule: "concat-sql", table: "api.ts:3", detail: "request data concatenated into a SQL string", severity: "high" }] },
};
async function run(ws, env, verdict = BLOCKING, argv = ["--gate"], heisen = null) {
  const realFetch = globalThis.fetch, realLog = console.log, out = [];
  globalThis.fetch = async (url) => {
    if (String(url).startsWith("https://oidc.example/")) return { ok: true, status: 200, json: async () => ({ value: "eyJ.t" }) };
    if (String(url).endsWith("/api/ci/pro-extractors")) return { ok: false, status: 402, json: async () => ({}) };
    if (heisen && String(url).endsWith("/api/ci/heisen")) return { ok: true, status: 200, json: async () => heisen };
    return { ok: true, status: 200, json: async () => verdict };
  };
  console.log = (...a) => out.push(a.join(" "));
  try { const code = await main(argv, env); return { code, text: out.join("\n") }; } finally { globalThis.fetch = realFetch; console.log = realLog; }
}
const workspace = (readme, extra = {}) => {
  const ws = mkdtempSync(join(tmpdir(), "sg-fw-purpose-"));
  writeFileSync(join(ws, "api.ts"), "export const x = 1;\n");
  if (readme !== null) writeFileSync(join(ws, "README.md"), readme);
  for (const [k, v] of Object.entries(extra)) writeFileSync(join(ws, k), v);
  return ws;
};
const COURSE = "# Node.js Bootcamp Course\n\nThe code for my video course.\n";
const PRODUCT = "# Acme Billing\n\nBilling API for SaaS teams.\n";

test("e2e : a product repo with a blocking pack finding is blocked (control)", async () => {
  const r = await run(workspace(PRODUCT), CI(workspace(PRODUCT)));
  assert.equal(r.code, 1);
  assert.match(r.text, /build blocked/);
  assert.doesNotMatch(r.text, /findings are advisory/);
});

test("e2e : a course repo gets the same finding as an advisory warning and exit 0", async () => {
  const ws = workspace(COURSE);
  const r = await run(ws, CI(ws, { SLOPGRADE_PURPOSE_CLASSIFIER: "on" }));
  assert.equal(r.code, 0);
  assert.match(r.text, /::warning file=api\.ts,line=3 title=slopGrade Firewall::\[concat-sql\]/);
  assert.doesNotMatch(r.text, /::error file=/);
  assert.match(r.text, /this repo reads as a teaching repository \(README title "Node\.js Bootcamp Course" mentions [^)]*\) — findings are advisory\. Set `purpose: product` in \.slopgrade\.yml to block\./);
});

const DEEP_VERDICT = { ...BLOCKING, packBlocking: 0, sqli: { count: 0, hidden: 0, blocking: 0, findings: [] } };
const DEEP_ANSWER = { ok: true, scanned: 1, unanswered: 0, findings: [{ path: "app.py", cwe: "CWE-78", p: 0.99, evidence: "request value reaches a shell call at line 5" }] };
const deepWs = (readme) => workspace(readme, { "app.py": ["import subprocess", "from flask import request", "", "def ping():", "    return subprocess.check_output('ping ' + request.args['h'], shell=True)", ""].join(String.fromCharCode(10)) });

test("e2e : a Deep Scan block in a product repo blocks (control) and in a course repo is an advisory warning", async () => {
  const product = deepWs(PRODUCT);
  const a = await run(product, CI(product), DEEP_VERDICT, ["--gate", "--deep-scan", "--deep-scan-block"], DEEP_ANSWER);
  assert.equal(a.code, 1, "control : the product repo must block, or this test proves nothing");
  assert.match(a.text, /::error file=app.py,line=5 title=slopGrade Firewall deep scan::/);
  const course = deepWs(COURSE);
  const b = await run(course, CI(course, { SLOPGRADE_PURPOSE_CLASSIFIER: "on" }), DEEP_VERDICT, ["--gate", "--deep-scan", "--deep-scan-block"], DEEP_ANSWER);
  assert.equal(b.code, 0);
  assert.match(b.text, /::warning file=app.py,line=5 title=slopGrade Firewall deep scan::/);
  assert.match(b.text, /findings are advisory/);
});

test("e2e : `purpose: product` in .slopgrade.yml keeps blocking on", async () => {
  const ws = workspace(COURSE, { [PURPOSE_FILE]: "purpose: product\n" });
  const r = await run(ws, CI(ws, { SLOPGRADE_PURPOSE_CLASSIFIER: "on" }));
  assert.equal(r.code, 1);
  assert.match(r.text, /\.slopgrade\.yml sets purpose: product/);
});

test("e2e : SLOPGRADE_PURPOSE_CLASSIFIER=off keeps blocking on", async () => {
  const ws = workspace(COURSE);
  const r = await run(ws, CI(ws, { SLOPGRADE_PURPOSE_CLASSIFIER: "off" }));
  assert.equal(r.code, 1);
});

// Default OFF (2026-10-24 held-out benchmark below the DoD) : with no env, a course repo still blocks, silently.
test("e2e : no SLOPGRADE_PURPOSE_CLASSIFIER → classifier off, a course repo keeps blocking", async () => {
  const ws = workspace(COURSE);
  const r = await run(ws, CI(ws));
  assert.equal(r.code, 1);
  assert.match(r.text, /::error file=api\.ts,line=3/);
  assert.doesNotMatch(r.text, /findings are advisory/);
});

test("e2e : cross-tenant hard leaks still block in a course repo", async () => {
  const ws = workspace(COURSE);
  const hard = { ...BLOCKING, packBlocking: 0, sqli: { count: 0, hidden: 0, blocking: 0, findings: [] }, hardLeaks: 2, reliable: true, leaks: [] };
  const r = await run(ws, CI(ws, { SLOPGRADE_PURPOSE_CLASSIFIER: "on" }), hard);
  assert.equal(r.code, 1);
});

test("e2e (real git) : a PR cannot reclassify its own repo, and a non-product BASE stays advisory", async () => {
  const gitEnv = Object.fromEntries(Object.entries(process.env).filter(([k]) => !k.startsWith("GIT_")));
  const git = (ws, ...a) => execFileSync("git", ["-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false", ...a], { cwd: ws, env: gitEnv, stdio: "ignore" });
  const repoWith = (baseReadme, headReadme) => {
    const ws = workspace(baseReadme);
    git(ws, "init", "-q"); git(ws, "add", "."); git(ws, "commit", "-qm", "base");
    git(ws, "update-ref", "refs/remotes/origin/main", "HEAD");
    writeFileSync(join(ws, "README.md"), headReadme); // the PR head rewrites its README
    return ws;
  };
  // PR head says « course », base says product → still a product : the finding blocks.
  const evade = repoWith(PRODUCT, COURSE);
  const a = await run(evade, CI(evade, { ...ON, GITHUB_BASE_REF: "main" }));
  assert.equal(a.code, 1);
  // Base says course, head rewrites to a product README → the base wins : advisory.
  const honest = repoWith(COURSE, PRODUCT);
  const b = await run(honest, CI(honest, { ...ON, GITHUB_BASE_REF: "main" }));
  assert.equal(b.code, 0);
  assert.match(b.text, /findings are advisory/);
});

