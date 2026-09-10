// firewallVerdict — the FREE/paid exit-decision boundary. Two independent block sources (both gate-only):
// a reliable cross-tenant leak on an entitled repo, and a server-paywalled blocking detector finding.
import { test } from "node:test";
import assert from "node:assert/strict";
import { firewallVerdict } from "../gate-verdict.mjs";

test("advisory mode never blocks — whatever the verdict", () => {
  // even with a hard leak AND a blocking pack finding, advisory is exit 0.
  const v = firewallVerdict({ gateMode: false, reliable: true, hardLeaks: 3, gateEntitled: true, packBlocking: 5 });
  assert.equal(v.block, false);
  assert.equal(v.kind, "advisory");
});

test("gate + blocking pack finding (packBlocking>0) → blocks", () => {
  // packBlocking is ALREADY server-paywalled to 0 unless entitled, so >0 means entitled → block.
  const v = firewallVerdict({ gateMode: true, reliable: false, hardLeaks: 0, gateEntitled: false, packBlocking: 1 });
  assert.equal(v.block, true);
  assert.equal(v.kind, "gate-blocked");
});

test("gate + packBlocking absent defaults to 0 → pack never blocks (old server response)", () => {
  const v = firewallVerdict({ gateMode: true, reliable: false, hardLeaks: 0, gateEntitled: true });
  assert.equal(v.block, false);
  assert.equal(v.kind, "gate-pass");
});

test("gate + reliable cross-tenant leak + entitled → blocks", () => {
  const v = firewallVerdict({ gateMode: true, reliable: true, hardLeaks: 2, gateEntitled: true, packBlocking: 0 });
  assert.equal(v.block, true);
  assert.equal(v.kind, "gate-blocked");
});

test("gate + reliable cross-tenant leak + NOT entitled → advisory (free never blocked)", () => {
  const v = firewallVerdict({ gateMode: true, reliable: true, hardLeaks: 2, gateEntitled: false, packBlocking: 0 });
  assert.equal(v.block, false);
  assert.equal(v.kind, "gate-unpaid");
});

test("gate + clean / non-reliable → pass", () => {
  const v = firewallVerdict({ gateMode: true, reliable: false, hardLeaks: 0, gateEntitled: true, packBlocking: 0 });
  assert.equal(v.block, false);
  assert.equal(v.kind, "gate-pass");
});

test("packBlocking accepts a string count (env/JSON passthrough) → blocks", () => {
  const v = firewallVerdict({ gateMode: true, reliable: false, hardLeaks: 0, gateEntitled: false, packBlocking: "2" });
  assert.equal(v.block, true);
  assert.equal(v.kind, "gate-blocked");
});
