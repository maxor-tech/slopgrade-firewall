// `.slopgradeignore` (0.10.8) — pattern semantics, the match-everything refusal, the base-branch read on a pull request
// (a PR cannot exempt its own files), and end-to-end: an ignored file's finding leaves the payload.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parseIgnore, ignoreMatcher, readIgnoreText, IGNORE_FILE, MAX_IGNORE_PATTERNS } from "../ignore.mjs";
import { main } from "../../isolation-gate.mjs";

const match = (text) => ignoreMatcher(parseIgnore(text).patterns);

test("a bare name matches that file or directory at any depth", () => {
  const m = match("messages/\ngenerated.ts\n");
  assert.equal(m("messages/en.json"), true);
  assert.equal(m("app/messages/fr.json"), true);
  assert.equal(m("lib/generated.ts"), true);
  assert.equal(m("lib/messages.ts"), false);
  assert.equal(m("lib/generated.tsx"), false);
});

test("a pattern with a slash is anchored at the repo root", () => {
  const m = match("lib/gate-pages.ts\n/docs/");
  assert.equal(m("lib/gate-pages.ts"), true);
  assert.equal(m("pkg/lib/gate-pages.ts"), false);
  assert.equal(m("docs/a.md"), true);
  assert.equal(m("site/docs/a.md"), false);
});

test("* stays inside a segment, ** crosses them, **/ may be empty", () => {
  const m = match("*.snap\nsrc/**/fixtures-*.ts\n**/examples/");
  assert.equal(m("a/b/c.snap"), true);
  assert.equal(m("src/x/y/fixtures-sql.ts"), true);
  assert.equal(m("src/fixtures-sql.ts"), true);
  assert.equal(m("src/x/fixtures/sql.ts"), false);
  assert.equal(m("examples/a.ts"), true);
  assert.equal(m("deep/examples/a.ts"), true);
});

test("comments, blanks, CRLF are skipped ; regex characters are literal", () => {
  const m = match("# a comment\r\n\r\n  lib/a+b.ts  \r\n");
  assert.equal(m("lib/a+b.ts"), true);
  assert.equal(m("lib/aab.ts"), false);
});

test("match-everything, negation and over-long patterns are refused", () => {
  const r = parseIgnore(["*", "**", "/", "**/*", "./", "/**/", "!src/keep.ts", "x".repeat(201), "ok/"].join("\n"));
  assert.deepEqual(r.kept, ["ok/"]);
  assert.equal(r.refused.length, 8);
  assert.equal(ignoreMatcher(r.patterns)("src/app.ts"), false);
});

test("the pattern count is capped", () => {
  const r = parseIgnore(Array.from({ length: MAX_IGNORE_PATTERNS + 5 }, (_, i) => `dir${i}/`).join("\n"));
  assert.equal(r.kept.length, MAX_IGNORE_PATTERNS);
  assert.equal(r.refused.length, 5);
});

test("a long run of stars is refused in linear time (no ReDoS)", () => {
  const t = Date.now();
  parseIgnore("*".repeat(200) + "x\n" + "*/".repeat(100));
  assert.ok(Date.now() - t < 200);
});

test("on a pull request the file comes from the BASE branch, never the PR head", () => {
  const calls = [];
  const git = (args) => { calls.push(args); return "docs/\n"; };
  const readFile = () => { throw new Error("the checkout copy must not be read on a PR"); };
  const r = readIgnoreText({ GITHUB_BASE_REF: "main" }, git, readFile);
  assert.deepEqual(calls, [["show", `origin/main:${IGNORE_FILE}`]]);
  assert.equal(r.source, "base");
  assert.equal(r.text, "docs/\n");
});

test("base branch without the file, or an odd base ref, means no ignore", () => {
  const missing = readIgnoreText({ GITHUB_BASE_REF: "main" }, () => { throw new Error("no such path"); }, () => "src/\n");
  assert.equal(missing.text, null);
  for (const ref of ["--output=x", "a..b", "main;rm"]) {
    let called = false;
    const r = readIgnoreText({ GITHUB_BASE_REF: ref }, () => { called = true; return "src/\n"; }, () => "src/\n");
    assert.equal(r.text, null, ref);
    assert.equal(called, false, ref);
  }
});

test("on a push the file comes from the checkout", () => {
  const r = readIgnoreText({}, () => { throw new Error("git must not be used on a push"); }, (p) => (p === IGNORE_FILE ? "docs/\n" : ""));
  assert.equal(r.source, "checkout");
  assert.equal(r.text, "docs/\n");
});

test("end to end: an ignored file's finding leaves the payload, the others stay", async () => {
  const ws = mkdtempSync(join(tmpdir(), "sg-fw-ignore-"));
  const vuln = "export async function h(req, db) { return db.query('SELECT * FROM users WHERE id = ' + req.params.id); }\n";
  mkdirSync(join(ws, "content"));
  writeFileSync(join(ws, "content", "examples-data.ts"), vuln);
  writeFileSync(join(ws, "api.ts"), vuln);
  const run = async () => {
    const out = [];
    const log = console.log;
    console.log = (s) => out.push(String(s));
    try { assert.equal(await main(["--print-payload"], { GITHUB_WORKSPACE: ws }), 0); } finally { console.log = log; }
    return JSON.parse(out.find((s) => s.trim().startsWith("{")));
  };
  const before = (await run()).sqliFingerprint.files.map((f) => f.file).sort();
  assert.deepEqual(before, ["api.ts", "content/examples-data.ts"]);
  writeFileSync(join(ws, IGNORE_FILE), "# marketing copy that SHOWS vulnerable code\ncontent/\n");
  const after = (await run()).sqliFingerprint.files.map((f) => f.file);
  assert.deepEqual(after, ["api.ts"]);
});
