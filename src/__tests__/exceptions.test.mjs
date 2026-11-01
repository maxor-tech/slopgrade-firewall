// `.slopgrade-exceptions` (src/exceptions.mjs, expert panel P1-6) : one finding accepted for a time with a named owner ;
// past its date it stops applying ; malformed, open-ended, glob or cross-tenant entries are refused ; on a pull request
// the file is read from the base branch.
import { test } from "node:test";
import assert from "node:assert/strict";
import { parseExceptions, exceptionFor, readExceptionsText } from "../exceptions.mjs";

const NOW = Date.parse("2026-11-01T12:00:00Z");

test("a well-formed entry is active and covers exactly its pack/rule, file and line", () => {
  const { active, refused } = parseExceptions("weakCrypto src/legacy/ntlm.ts:88 until=2026-12-31 owner=@sec-team reason=NTLM interop, removed with v2 auth", NOW);
  assert.deepEqual(refused, []);
  assert.deepEqual(active, [{ target: "weakCrypto", path: "src/legacy/ntlm.ts", line: 88, until: "2026-12-31", owner: "@sec-team", reason: "NTLM interop, removed with v2 auth" }]);
  assert.equal(exceptionFor(active, { pack: "weakCrypto", rule: "weak-crypto", file: "src/legacy/ntlm.ts", line: 88 })?.owner, "@sec-team");
  assert.equal(exceptionFor(active, { pack: "weakCrypto", rule: "weak-crypto", file: "src/legacy/ntlm.ts", line: 90 }), null, "another line");
  assert.equal(exceptionFor(active, { pack: "xss", rule: "taint-xss", file: "src/legacy/ntlm.ts", line: 88 }), null, "another pack");
});

test("an entry without a line covers the file ; the rule name works as a target too", () => {
  const { active } = parseExceptions('taint-sql db/report.py until=2026-11-30 owner=dana reason="read-only reporting replica"', NOW);
  assert.equal(exceptionFor(active, { pack: "sqli", rule: "taint-sql", file: "db/report.py", line: 412 })?.reason, "read-only reporting replica");
});

test("an entry past its date stops applying and is reported as expired", () => {
  const { active, expired } = parseExceptions("xss web/a.php:3 until=2026-10-01 owner=@x reason=legacy page, removed soon", NOW);
  assert.deepEqual(active, []);
  assert.equal(expired.length, 1);
});

test("open-ended, too-far, unowned, unexplained, glob and cross-tenant entries are refused", () => {
  const { active, refused } = parseExceptions([
    "xss web/a.php:3 owner=@x reason=no date given here",
    "xss web/a.php:3 until=2028-01-01 owner=@x reason=too far in the future",
    "xss web/a.php:3 until=2026-12-01 reason=nobody owns this one",
    "xss web/a.php:3 until=2026-12-01 owner=@x reason=short",
    "xss web/*.php until=2026-12-01 owner=@x reason=glob covers too much",
    "cross-tenant app/api/x.ts:9 until=2026-12-01 owner=@x reason=never acceptable here",
    "garbage",
  ].join("\n"), NOW);
  assert.deepEqual(active, []);
  assert.equal(refused.length, 7);
});

test("on a pull request the file comes from the base branch, never the PR head", () => {
  const calls = [];
  const r = readExceptionsText({ GITHUB_BASE_REF: "main" }, (args) => { calls.push(args); return "x"; }, () => { throw new Error("head read"); });
  assert.deepEqual(r, { text: "x", source: "base" });
  assert.deepEqual(calls, [["show", "origin/main:.slopgrade-exceptions"]]);
  assert.deepEqual(readExceptionsText({ GITHUB_BASE_REF: "--evil" }, () => "x", () => "y"), { text: null, source: "base" });
});
