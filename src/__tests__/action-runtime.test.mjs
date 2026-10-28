// The Action's own dependencies run on node24 : a node20 pin made every consumer run print GitHub's « Node.js 20 is
// deprecated » warning naming OUR action (e2e 2026-10-27, slopgrade-gate-e2e#13).
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const action = readFileSync(new URL("../../action.yml", import.meta.url), "utf8");

test("action.yml pins actions/setup-node by SHA to v7.1.0 (runs: node24), never a mutable tag", () => {
  const uses = action.match(/uses: actions\/setup-node@(\S+)/g) ?? [];
  assert.deepEqual(uses, ["uses: actions/setup-node@949feb2413d6458794dcd2491c4babbbce0c15c1"]);
  assert.match(action, /actions\/setup-node\n\s+# v7\.1\.0, runs on node24/);
});

test("the README install snippet uses a node24 checkout (@v7), not @v4", () => {
  const readme = readFileSync(new URL("../../README.md", import.meta.url), "utf8");
  assert.deepEqual([...new Set(readme.match(/actions\/checkout@v\d+/g))], ["actions/checkout@v7"]);
});
