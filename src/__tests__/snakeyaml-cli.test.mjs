// End to end (main() against a stubbed network) : the client reads the repo's SnakeYAML major from its build files and
// sends a SnakeYAML load as gated (not high) when the repo builds with 2.x. No build file, or 1.x → high, as before.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { main } from "../../isolation-gate.mjs";

const JAVA = `package app;\npublic class Config {\n  public Object parse(String body) {\n    Yaml yaml = new Yaml();\n    return yaml.load(body);\n  }\n}\n`;
const pom = (v) => `<project><dependencies><dependency>\n<groupId>org.yaml</groupId>\n<artifactId>snakeyaml</artifactId>\n<version>${v}</version>\n</dependency></dependencies></project>\n`;

async function sentDeserHits(pomText) {
  const ws = mkdtempSync(join(tmpdir(), "sg-snake-"));
  mkdirSync(join(ws, "src", "main", "java", "app"), { recursive: true });
  writeFileSync(join(ws, "src", "main", "java", "app", "Config.java"), JAVA);
  if (pomText !== null) writeFileSync(join(ws, "pom.xml"), pomText);
  const env = { GITHUB_ACTIONS: "true", GITHUB_SHA: "0123456789abcdef0123456789abcdef01234567", GITHUB_WORKSPACE: ws, FW_UPLOAD_SARIF: "false",
    ACTIONS_ID_TOKEN_REQUEST_URL: "https://oidc.example/token?api-version=2", ACTIONS_ID_TOKEN_REQUEST_TOKEN: "runner-token" };
  const realFetch = globalThis.fetch, realLog = console.log;
  let body = null;
  globalThis.fetch = async (url, init) => {
    if (String(url).startsWith("https://oidc.example/")) return { ok: true, status: 200, json: async () => ({ value: "eyJ.oidc.token" }) };
    if (String(url).endsWith("/api/ci/pro-extractors")) return { ok: false, status: 402, json: async () => ({ error: "plan-required", gateLevel: "none" }) };
    if (init?.body) body = JSON.parse(init.body);
    return { ok: true, status: 200, json: async () => ({ ok: true, pattern: "none", hardLeaks: 0, leaks: [], gateLevel: "free", packBlocking: 0 }) };
  };
  console.log = () => {};
  try { await main([], env); } finally { globalThis.fetch = realFetch; console.log = realLog; rmSync(ws, { recursive: true, force: true }); }
  assert.ok(body, "the client posted a fingerprint");
  return (body.deserFingerprint?.files ?? []).flatMap((f) => f.hits);
}

test("SnakeYAML 2.x in pom.xml : the load is sent gated, with no request source on the line", async () => {
  const hits = await sentDeserHits(pom("2.2"));
  assert.equal(hits.length, 1);
  assert.equal(hits[0].kind, "java-readobject");
  assert.equal(hits[0].high, false);
  assert.equal(hits[0].srcCtx, false);
});

test("CONTROL : SnakeYAML 1.x, or no build file, sends the load high", async () => {
  for (const p of [pom("1.33"), null]) {
    const hits = await sentDeserHits(p);
    assert.equal(hits.length, 1);
    assert.equal(hits[0].high, true);
  }
});
