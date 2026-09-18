// Code Scanning SARIF upload — the encoding is asserted byte-exact (base64 of gzip of the JSON) and every upload path
// is checked against an injected fetch: the accepted 202, the quiet 403/no-token skips, the loud 5xx/network/encode
// failures, and the never-throws contract. The uploader posts to the consumer's OWN repo with their OWN token — no
// slopGrade egress — so the test only ever exercises the injected fetch, never the network.
import { test } from "node:test";
import assert from "node:assert/strict";
import { gunzipSync } from "node:zlib";
import { encodeSarifForUpload, uploadSarifToCodeScanning } from "../client-lib.mjs";

const SARIF = { version: "2.1.0", runs: [{ results: [{ ruleId: "x" }] }] };
const CI = { GITHUB_TOKEN: "tok", GITHUB_REPOSITORY: "acme/app", GITHUB_SHA: "deadbeef", GITHUB_REF: "refs/pull/7/merge" };
const okRes = (status = 202) => ({ ok: status >= 200 && status < 300, status });

test("encodeSarifForUpload — base64(gzip(JSON)) round-trips back to the SARIF", () => {
  const enc = encodeSarifForUpload(SARIF);
  assert.equal(typeof enc, "string");
  const back = JSON.parse(gunzipSync(Buffer.from(enc, "base64")).toString("utf8"));
  assert.deepEqual(back, SARIF);
});

test("encodeSarifForUpload — honors an injected gzip impl", () => {
  let called = false;
  const enc = encodeSarifForUpload(SARIF, (buf) => { called = true; return Buffer.from("Z" + buf.toString("utf8")); });
  assert.ok(called);
  assert.equal(Buffer.from(enc, "base64").toString("utf8"), "Z" + JSON.stringify(SARIF));
});

test("upload — 202 accepted: posts to the code-scanning/sarifs endpoint with commit_sha+ref+base64 sarif", async () => {
  let seen = null;
  const fetchImpl = async (url, opts) => { seen = { url, body: JSON.parse(opts.body), method: opts.method, headers: opts.headers }; return okRes(202); };
  const logs = [];
  const r = await uploadSarifToCodeScanning(CI, SARIF, { fetchImpl, log: (m) => logs.push(m) });
  assert.equal(r, "uploaded");
  assert.equal(seen.url, "https://api.github.com/repos/acme/app/code-scanning/sarifs");
  assert.equal(seen.method, "POST");
  assert.equal(seen.headers.Authorization, "Bearer tok");
  assert.equal(seen.body.commit_sha, "deadbeef");
  assert.equal(seen.body.ref, "refs/pull/7/merge");
  // the sarif field is the base64(gzip(JSON)) payload, decodable back to the report
  assert.deepEqual(JSON.parse(gunzipSync(Buffer.from(seen.body.sarif, "base64")).toString("utf8")), SARIF);
  assert.ok(logs.some((m) => /uploaded/i.test(m)));
});

test("upload — no token: quiet skip (info line with the permission hint), no fetch", async () => {
  let called = false;
  const logs = [], warns = [];
  const r = await uploadSarifToCodeScanning({ ...CI, GITHUB_TOKEN: "", FW_GH_TOKEN: "" }, SARIF,
    { fetchImpl: async () => { called = true; return okRes(); }, log: (m) => logs.push(m), warn: (m) => warns.push(m) });
  assert.equal(r, "skipped");
  assert.equal(called, false);
  assert.equal(warns.length, 0); // never a scary warning for a missing permission
  assert.ok(logs.some((m) => /security-events: write/.test(m)));
});

test("upload — missing repo/sha/ref: skipped, no fetch", async () => {
  let called = false;
  for (const env of [{ ...CI, GITHUB_REPOSITORY: "" }, { ...CI, GITHUB_SHA: "" }, { ...CI, GITHUB_REF: "" }, { ...CI, GITHUB_REPOSITORY: "noslash" }]) {
    const r = await uploadSarifToCodeScanning(env, SARIF, { fetchImpl: async () => { called = true; return okRes(); } });
    assert.equal(r, "skipped");
  }
  assert.equal(called, false);
});

test("upload — 403 (missing scope / GHAS off): QUIET skip via log, never a warning", async () => {
  const logs = [], warns = [];
  const r = await uploadSarifToCodeScanning(CI, SARIF,
    { fetchImpl: async () => okRes(403), log: (m) => logs.push(m), warn: (m) => warns.push(m) });
  assert.equal(r, "skipped");
  assert.equal(warns.length, 0);
  assert.ok(logs.some((m) => /security-events: write/.test(m)));
});

test("upload — 5xx: loud failure (warn), returns failed, never throws", async () => {
  const warns = [];
  const r = await uploadSarifToCodeScanning(CI, SARIF, { fetchImpl: async () => okRes(500), warn: (m) => warns.push(m) });
  assert.equal(r, "failed");
  assert.ok(warns.some((m) => /500/.test(m)));
});

test("upload — network throw: caught, returns failed (never breaks the gate)", async () => {
  const warns = [];
  const r = await uploadSarifToCodeScanning(CI, SARIF, { fetchImpl: async () => { throw new Error("ENETDOWN"); }, warn: (m) => warns.push(m) });
  assert.equal(r, "failed");
  assert.ok(warns.some((m) => /ENETDOWN/.test(m)));
});

test("upload — encode error (gzip throws): caught before the fetch, returns failed", async () => {
  let called = false;
  const r = await uploadSarifToCodeScanning(CI, SARIF, {
    fetchImpl: async () => { called = true; return okRes(); },
    gzipImpl: () => { throw new Error("gzip boom"); },
    warn: () => {},
  });
  assert.equal(r, "failed");
  assert.equal(called, false);
});
