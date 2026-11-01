// Precision round 2 (independent set v3, 2026-11-01) in the client's own extractors : a fixed SSRF origin and a cipher
// name inside a multi-line string are not findings ; the controls keep firing. Mirror of maxor-tech/slopgrade fp-classes-v3.
import { test } from "node:test";
import assert from "node:assert/strict";
import { extractSsrf } from "../ssrf-extract.mjs";
import { extractCrypto } from "../crypto-extract.mjs";

const ssrf = (code, file) => extractSsrf(code, new Map(), file).map((h) => h.line);

test("SSRF : a fixed origin before the user value is not an SSRF ; a user-chosen host still is", () => {
  assert.deepEqual(ssrf("app.get('/x', async (req, res) => {\n  const id = req.params.jobId;\n  await fetch(`${config.AGENT_URL}/v2/agent/${id}`);\n});\n", "agent.ts"), []);
  assert.deepEqual(ssrf("app.get('/a', (req, res) => fetch('https://api.example.com/users/' + req.query.id));\n", "a.js"), []);
  assert.deepEqual(ssrf("app.get('/a', (req, res) => {\n  const h = req.query.h;\n  fetch(`${proto}://${h}/x`);\n});\n", "a.js"), [3]);
  assert.deepEqual(ssrf("app.get('/a', (req, res) => fetch('https://' + req.query.host));\n", "a.js"), [1]);
});

test("weakCrypto : a cipher name in a Go raw-string help table is text ; a real call fires", () => {
  const go = "package help\n\nconst hashes = `\n  1500 | descrypt, DES (Unix), Traditional DES | Operating System\n`\n";
  assert.deepEqual(extractCrypto(go, "client/command/help/long-help.go"), []);
  assert.equal(extractCrypto(go + "func f() { c, _ := des.NewCipher(k) }\n", "client/x.go").length, 1);
});
