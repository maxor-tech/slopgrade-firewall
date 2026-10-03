// When the server refuses a run (e.g. 402 account-locked: the owner's Team trial ended unpaid), the CI log must say WHY,
// not only "server refused (HTTP 402)". refusalLine is pure; ghWarn then passes it through sanitizeLogLine, so a hostile
// or broken body can never inject a workflow command or flood the log.
import { test } from "node:test";
import assert from "node:assert/strict";
import { refusalLine, sanitizeLogLine } from "../client-lib.mjs";

test("402 account-locked: the code and the server's message are printed", () => {
  const line = refusalLine(402, { error: "account-locked", message: "Essai Team terminé : ajoutez une carte sur slopgrade.ai pour réactiver le compte." });
  assert.equal(line, "server refused (HTTP 402: account-locked) — Essai Team terminé : ajoutez une carte sur slopgrade.ai pour réactiver le compte. — no verdict.");
});

test("no JSON body (or null) keeps the previous generic line", () => {
  assert.equal(refusalLine(429, null), "server refused (HTTP 429) — no verdict.");
  assert.equal(refusalLine(403, "not an object"), "server refused (HTTP 403) — no verdict.");
});

test("an error value that is not a plain code is not echoed", () => {
  assert.equal(refusalLine(400, { error: "::error::spoof\nX" }), "server refused (HTTP 400) — no verdict.");
});

test("the message is capped at 160 characters", () => {
  const line = refusalLine(402, { error: "account-locked", message: "x".repeat(500) });
  assert.ok(line.includes("x".repeat(160)));
  assert.ok(!line.includes("x".repeat(161)));
});

test("after sanitizeLogLine, control characters in the message cannot break out of the warning line", () => {
  const out = sanitizeLogLine(refusalLine(402, { error: "account-locked", message: "a\n::error::forged\r\u001b[31m" }));
  assert.ok(!/[\n\r\u001b]/.test(out));
});
