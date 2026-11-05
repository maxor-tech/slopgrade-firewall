// An advisory row never reads as blocking, and a low row stays low. The server's value is untrusted text, so its shape varies.
import { test } from "node:test";
import assert from "node:assert/strict";
import { advisoryLevel, advisoryOrder, advisorySeverity } from "../client-lib.mjs";

test("low stays low in any case ; anything else, or nothing, reads as medium", () => {
  for (const s of ["low", "LOW", "Low"]) {
    assert.equal(advisorySeverity(s), "low");
    assert.equal(advisoryLevel(s), "notice");
  }
  for (const s of ["medium", "high", "critical", "", undefined, null, 7]) {
    assert.equal(advisorySeverity(s), "medium");
    assert.equal(advisoryLevel(s), "warning");
  }
});

test("order : stronger rows first, stable inside each severity, nothing lost, input untouched", () => {
  const rows = [{ id: 1, severity: "low" }, { id: 2, severity: "medium" }, { id: 3, severity: "LOW" }, { id: 4 }, { id: 5, severity: "high" }];
  const copy = structuredClone(rows);
  assert.deepEqual(advisoryOrder(rows).map((r) => r.id), [2, 4, 5, 1, 3]);
  assert.deepEqual(rows, copy);
  assert.deepEqual(advisoryOrder([]), []);
});
