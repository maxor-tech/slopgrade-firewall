// One-click fixes (0.10.1) — each kind's verified rewrite, the refusals that keep a suggestion from ever guessing, and the
// wiring into the finding comment. The /ci « N have a verified fix » count (slopgrade lib/tenant-isolation/fixable.ts)
// must mirror FIXABLE_KINDS — the list is pinned here.
import { test } from "node:test";
import assert from "node:assert/strict";
import { FIXABLE_KINDS, fixLine, fixableHitIndex, attachFixes } from "../autofix.mjs";
import { findingCommentBody } from "../pr-suggest.mjs";

test("FIXABLE_KINDS is exactly the deterministic set (mirror of slopgrade fixable.ts minus llm-dangerous-code, which has no safe rewrite)", () => {
  assert.deepEqual([...FIXABLE_KINDS].sort(), [
    "aspnet-debug-compilation", "flask-run-debug", "go-insecure-skip-verify", "node-reject-unauthorized",
    "node-tls-env", "py-yaml-unsafe", "python-verify-false", "rust-danger-accept-invalid",
  ]);
});

const CASES = [
  ["python-verify-false", "    r = requests.get(url, verify=False, timeout=5)", "    r = requests.get(url, verify=True, timeout=5)"],
  ["node-reject-unauthorized", "const agent = new https.Agent({ rejectUnauthorized: false });", "const agent = new https.Agent({ rejectUnauthorized: true });"],
  ["node-tls-env", "process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';", "process.env.NODE_TLS_REJECT_UNAUTHORIZED = '1';"],
  ["node-tls-env", "  NODE_TLS_REJECT_UNAUTHORIZED: 0", "  NODE_TLS_REJECT_UNAUTHORIZED: 1"],
  ["go-insecure-skip-verify", "\tTLSClientConfig: &tls.Config{InsecureSkipVerify: true},", "\tTLSClientConfig: &tls.Config{InsecureSkipVerify: false},"],
  ["rust-danger-accept-invalid", "    .danger_accept_invalid_certs(true)", "    .danger_accept_invalid_certs(false)"],
  ["aspnet-debug-compilation", '    <compilation debug="true" targetFramework="4.8" />', '    <compilation debug="false" targetFramework="4.8" />'],
  ["flask-run-debug", "    app.run(host='0.0.0.0', debug=True)", "    app.run(host='0.0.0.0', debug=False)"],
  ["py-yaml-unsafe", "cfg = yaml.load(fh)", "cfg = yaml.safe_load(fh)"],
  ["py-yaml-unsafe", "cfg = yaml.unsafe_load(fh)", "cfg = yaml.safe_load(fh)"],
];

test("each kind : the rewrite is the minimal secure flip, and indentation / the rest of the line are untouched", () => {
  for (const [kind, before, after] of CASES) {
    const fx = fixLine(kind, before);
    assert.ok(fx, `${kind} should fix: ${before}`);
    assert.equal(fx.after, after, kind);
    assert.ok(fx.note.length > 5);
  }
});

test("never guesses : wrong line, already safe, explicit Loader=, unknown kind, multi-line, oversized → no suggestion", () => {
  assert.equal(fixLine("python-verify-false", "r = requests.get(url)"), null, "finding not on this line");
  assert.equal(fixLine("python-verify-false", "r = requests.get(url, verify=True)"), null, "already safe");
  assert.equal(fixLine("py-yaml-unsafe", "cfg = yaml.load(fh, Loader=yaml.SafeLoader)"), null, "already a safe loader — detector does not fire");
  assert.equal(fixLine("py-yaml-unsafe", "cfg = yaml.load(fh, Loader=yaml.UnsafeLoader)"), null, "explicit Loader= is never rewritten (safe_load takes none)");
  assert.equal(fixLine("llm-dangerous-code", "eval(completion)"), null, "no deterministic fix for LLM code execution");
  assert.equal(fixLine("nope", "verify=False"), null);
  assert.equal(fixLine("python-verify-false", "a(verify=False)\nb()"), null);
  assert.equal(fixLine("python-verify-false", "x".repeat(2001) + "verify=False"), null);
});

test("fixableHitIndex keeps only fixable kinds, keyed by file:line, from any sanitized pack shape", () => {
  const idx = fixableHitIndex({
    transportFingerprint: { files: [{ file: "api/http.py", hits: [{ line: 12, kind: "python-verify-false" }, { line: 13, kind: "weak-tls" }] }] },
    deserFingerprint: { files: [{ file: "cfg.py", hits: [{ line: 3, kind: "py-yaml-unsafe" }] }] },
    junk: null, other: { deps: [] },
  });
  assert.deepEqual([...idx.entries()], [["api/http.py:12", ["python-verify-false"]], ["cfg.py:3", ["py-yaml-unsafe"]]]);
});

test("attachFixes : fixes only rows the runner can prove, reads the real line, survives a throwing reader", () => {
  const feed = [
    { file: "api/http.py", line: 12, rule: "tls-verification-disabled", severity: "high" },
    { file: "api/http.py", line: 40, rule: "sqli", severity: "high" },            // not a fixable hit
    { file: "cfg.py", line: 3, rule: "unsafe-deser", severity: "high" },         // line text no longer matches → skipped
    { file: "gone.py", line: 1, rule: "x", severity: "high" },                    // reader throws → skipped
  ];
  const idx = fixableHitIndex({ t: { files: [{ file: "api/http.py", hits: [{ line: 12, kind: "python-verify-false" }] }, { file: "cfg.py", hits: [{ line: 3, kind: "py-yaml-unsafe" }] }, { file: "gone.py", hits: [{ line: 1, kind: "python-verify-false" }] }] } });
  const lines = { "api/http.py:12": "r = s.get(u, verify=False)", "cfg.py:3": "cfg = json.load(fh)" };
  const n = attachFixes(feed, idx, (f, l) => { if (f === "gone.py") throw new Error("ENOENT"); return lines[`${f}:${l}`] ?? null; });
  assert.equal(n, 1);
  assert.deepEqual(feed[0].fix, { after: "r = s.get(u, verify=True)", note: "verify=False → True (verify TLS certificates)" });
  assert.equal(feed[1].fix, undefined);
  assert.equal(feed[2].fix, undefined);
  assert.equal(feed[3].fix, undefined);
});

test("the finding's inline comment carries the suggestion block (GitHub « Commit suggestion »), and none without a fix", () => {
  const withFix = findingCommentBody({ rule: "tls-verification-disabled", detail: "TLS off", severity: "high", fix: { after: "r = s.get(u, verify=True)", note: "verify=False → True" } });
  assert.match(withFix, /```suggestion\nr = s\.get\(u, verify=True\)\n```/);
  assert.match(withFix, /One-click fix/);
  assert.ok(!findingCommentBody({ rule: "x", detail: "d", severity: "high" }).includes("```suggestion"));
});
