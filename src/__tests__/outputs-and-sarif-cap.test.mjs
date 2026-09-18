// Action outputs (emitOutputs) + the SARIF result cap. emitOutputs writes `key=value` lines to $GITHUB_OUTPUT via an
// injected writer (no-op off CI, fail-soft); buildSarif caps its results so a huge repo's Code Scanning upload never
// exceeds GitHub's per-run limit — the truncated findings still live in the log + PR feed.
import { test } from "node:test";
import assert from "node:assert/strict";
import { emitOutputs, buildSarif, MAX_SARIF_RESULTS } from "../client-lib.mjs";

test("emitOutputs — writes key=value lines to GITHUB_OUTPUT via the injected writer", () => {
  let wrote = null;
  const w = (p, body) => { wrote = { p, body }; };
  const ok = emitOutputs({ GITHUB_OUTPUT: "/tmp/out" }, { verdict: "gate-pass", blocked: false, "hard-leaks": 0, conformance: "" }, w);
  assert.equal(ok, true);
  assert.equal(wrote.p, "/tmp/out");
  assert.match(wrote.body, /verdict=gate-pass/);
  assert.match(wrote.body, /blocked=false/);
  assert.match(wrote.body, /hard-leaks=0/);
  assert.match(wrote.body, /conformance=\n/);          // empty value renders as key= (single line)
  assert.ok(wrote.body.endsWith("\n"));
});

test("emitOutputs — no GITHUB_OUTPUT (off CI): no-op, returns false, never calls the writer", () => {
  let called = false;
  assert.equal(emitOutputs({}, { a: 1 }, () => { called = true; }), false);
  assert.equal(called, false);
});

test("emitOutputs — a write error is swallowed (never breaks the gate)", () => {
  assert.equal(emitOutputs({ GITHUB_OUTPUT: "/tmp/out" }, { a: 1 }, () => { throw new Error("EACCES"); }), false);
});

test("emitOutputs — booleans, numbers and null coerce to single-line strings", () => {
  let body = "";
  emitOutputs({ GITHUB_OUTPUT: "/tmp/out" }, { b: true, n: 42, z: null }, (_p, s) => { body = s; });
  assert.match(body, /b=true/);
  assert.match(body, /n=42/);
  assert.match(body, /z=\n/); // null → empty string, still one line (no delimiter needed)
});

test("buildSarif — caps results at MAX_SARIF_RESULTS so a huge repo never 413s the upload", () => {
  const many = Array.from({ length: MAX_SARIF_RESULTS + 5000 }, (_, i) => `src/f${i}.ts:${i + 1}  unscoped read`);
  const sarif = buildSarif(many);
  assert.equal(sarif.runs[0].results.length, MAX_SARIF_RESULTS);
});

test("buildSarif — a custom maxResults is honored; an under-cap set is unchanged", () => {
  const leaks = Array.from({ length: 10 }, (_, i) => `a${i}.ts:${i + 1}  x`);
  assert.equal(buildSarif(leaks, { maxResults: 3 }).runs[0].results.length, 3);
  assert.equal(buildSarif(leaks).runs[0].results.length, 10); // under the default cap → all kept
});
