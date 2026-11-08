// What blocks is copy the prospect reads before installing. README.md and action.yml must state the blocking lists
// of benchmark-figures.json (copied from the live catalog) and never the withdrawn « 22 OSS classes block » claim.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  BLOCKING_SURFACES, STALE_BLOCKING_RE, blockingFromCatalog, blockingPhrase, blockingProblems, loadFigures,
} from "../../scripts/sync-pr-figures.mjs";

const read = (p) => readFileSync(new URL(`../../${p}`, import.meta.url), "utf8");

test("blockingPhrase names each class in catalog order", () => {
  assert.equal(blockingPhrase([{ key: "accessControl" }, { key: "xss", kinds: ["php-echo"] }]), "cross-tenant + XSS in PHP output");
  assert.equal(
    blockingPhrase([{ key: "accessControl" }, { key: "xss", kinds: ["php-echo"] }, { key: "timingUnsafeCompare" }]),
    "cross-tenant + XSS in PHP output + timing-unsafe signature checks",
  );
});

test("blockingPhrase throws on a class or kind it has no copy for (a catalog change forces a copy decision)", () => {
  assert.throws(() => blockingPhrase([{ key: "sqli" }]), /no copy for blocking class sqli/);
  assert.throws(() => blockingPhrase([{ key: "xss", kinds: ["dom"] }]), /no copy for xss kinds dom/);
  assert.throws(() => blockingPhrase([]), /empty blocking list/);
});

test("blockingFromCatalog keeps blocking classes only, free ones in the free list", () => {
  const cat = { classes: [
    { key: "accessControl", free: true, blocks: true },
    { key: "dbSafety", free: false, blocks: false },
    { key: "xss", free: true, blocks: true, kinds: ["php-echo"] },
    { key: "sqli", free: true, blocks: false },
    { key: "timingUnsafeCompare", free: false, blocks: true },
  ] };
  assert.deepEqual(blockingFromCatalog(cat), {
    free: [{ key: "accessControl" }, { key: "xss", kinds: ["php-echo"] }],
    paid: [{ key: "accessControl" }, { key: "xss", kinds: ["php-echo"] }, { key: "timingUnsafeCompare" }],
  });
});

test("the withdrawn claims are refused (the copy shipped in v0.13.10)", () => {
  const f = loadFigures();
  const old = "public repos and your first private repo block free on cross-tenant + the 22 OSS classes, a paid slot unlocks every calibrated class";
  const problems = blockingProblems(old, f);
  assert.equal(problems.length, 3, problems.join(" | "));
  assert.match(problems.join(" "), /withdrawn claim « block free on cross-tenant \+ the 22 OSS classes »/);
  assert.match("| cross-tenant gate + the 22 OSS classes **block, free** |", STALE_BLOCKING_RE);
  assert.match("blocking gate on every calibrated class", STALE_BLOCKING_RE);
});

test("README.md and action.yml state the free and paid blocking lists, with no withdrawn claim", () => {
  const f = loadFigures();
  assert.equal(blockingPhrase(f.blocking.free), "cross-tenant + XSS in PHP output");
  for (const p of BLOCKING_SURFACES) assert.deepEqual(blockingProblems(read(p), f), [], p);
});
