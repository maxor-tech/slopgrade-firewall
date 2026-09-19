// Pro-bundle Ed25519 signature verification — the AUTHENTICITY control (the sha256 only proves integrity, and the
// server supplies both bundle + hash, so a compromised server / MITM matches its own hash). A signature verified
// against a key the client SHIPS cannot be forged. Real keypair, real sign, then every accept/reject path.
import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, sign as edSign } from "node:crypto";
import { verifyBundleSig, PRO_BUNDLE_PUBKEY } from "../client-lib.mjs";

const { publicKey, privateKey } = generateKeyPairSync("ed25519");
const PUB = publicKey.export({ type: "spki", format: "pem" });
const BUNDLE = 'export const PRO_PACKS = [];\nexport const PRO_VERSION = "x";';
const sign = (s) => edSign(null, Buffer.from(s, "utf8"), privateKey).toString("base64");

test("verifyBundleSig — a real Ed25519 signature over the bundle verifies", () => {
  assert.deepEqual(verifyBundleSig(BUNDLE, sign(BUNDLE), PUB), { ok: true });
});

test("verifyBundleSig — a tampered bundle fails (the signature no longer matches the bytes)", () => {
  const sig = sign(BUNDLE);
  const r = verifyBundleSig(BUNDLE + "\n// injected", sig, PUB);
  assert.equal(r.ok, false);
  assert.equal(r.reason, "bad signature");
});

test("verifyBundleSig — a signature from a DIFFERENT key fails (can't forge against the pinned key)", () => {
  const other = generateKeyPairSync("ed25519").privateKey;
  const forged = edSign(null, Buffer.from(BUNDLE, "utf8"), other).toString("base64");
  assert.equal(verifyBundleSig(BUNDLE, forged, PUB).ok, false);
});

test("verifyBundleSig — empty pinned key → no trust anchor, never accepts", () => {
  const r = verifyBundleSig(BUNDLE, sign(BUNDLE), "");
  assert.deepEqual(r, { ok: false, reason: "no pinned key" });
});

test("verifyBundleSig — missing/blank signature → rejected", () => {
  assert.equal(verifyBundleSig(BUNDLE, "", PUB).reason, "missing signature");
  assert.equal(verifyBundleSig(BUNDLE, undefined, PUB).reason, "missing signature");
});

test("verifyBundleSig — a garbage public key is caught, never throws", () => {
  assert.equal(verifyBundleSig(BUNDLE, sign(BUNDLE), "-----BEGIN PUBLIC KEY-----\nnope\n-----END PUBLIC KEY-----").reason, "verify error");
});

test("verifyBundleSig — malformed base64 signature is caught, never throws", () => {
  const r = verifyBundleSig(BUNDLE, "!!!not-base64!!!", PUB);
  assert.equal(r.ok, false); // decodes to garbage bytes → bad signature, not a throw
});

test("PRO_BUNDLE_PUBKEY — ships empty until a real key is pinned (signing not yet activated)", () => {
  assert.equal(typeof PRO_BUNDLE_PUBKEY, "string");
  // when empty, loadProPacks skips the check (unchanged behavior) ; pinning a real SPKI PEM here enforces it.
});
