// The verdict receipt line (src/receipt.mjs, expert panel P1-6) : printed in the CI log so a contested block names what
// judged it. Fields are shape-checked ; an older server (no receipt) prints nothing ; a hostile field is dropped.
import { test } from "node:test";
import assert from "node:assert/strict";
import { receiptLine } from "../receipt.mjs";

test("a receipt prints app, bundle, ledger and policy", () => {
  assert.equal(
    receiptLine({ receipt: { app: "815ffef562b6", proBundle: "b426d8c0a24c", ledger: "ledger1 (2026-10-25, 347 labeled repos)", policy: "0a1b2c3d4e5f" } }),
    "slopGrade verdict receipt: app 815ffef562b6 · bundle b426d8c0a24c · ledger ledger1 (2026-10-25, 347 labeled repos) · policy 0a1b2c3d4e5f",
  );
});

test("no receipt prints nothing ; a malformed or hostile field is dropped", () => {
  assert.equal(receiptLine({}), null);
  assert.equal(receiptLine({ receipt: null }), null);
  assert.equal(receiptLine({ receipt: { app: "::error::forged", policy: "0a1b2c3d4e5f" } }), "slopGrade verdict receipt: policy 0a1b2c3d4e5f");
  assert.equal(receiptLine({ receipt: { app: null, proBundle: null, ledger: "x".repeat(200), policy: 42 } }), null);
});
