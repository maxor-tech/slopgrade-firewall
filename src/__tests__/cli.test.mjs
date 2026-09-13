// End-to-end tests of the CLI `main()` against a STUBBED network (globalThis.fetch) — the release-audit 2026-09-13
// probe on an independent repo showed the server's sqli/cmdi/xss/… blocks were silently dropped by a hardcoded key
// list (B-P0-2), and that `--strict` did not fail closed on a blocked custom origin (B-P2-5). These pin both.
import { test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { main } from "../../isolation-gate.mjs";

const CI_ENV = {
  GITHUB_ACTIONS: "true",
  ACTIONS_ID_TOKEN_REQUEST_URL: "https://oidc.example/token?api-version=2",
  ACTIONS_ID_TOKEN_REQUEST_TOKEN: "runner-token",
  GITHUB_SHA: "0123456789abcdef0123456789abcdef01234567",
  GITHUB_WORKSPACE: fileURLToPath(new URL("./", import.meta.url)), // scan only this tests dir (fast, deterministic)
};

function withStubbedNetwork(verdict, fn) {
  const realFetch = globalThis.fetch;
  const realLog = console.log;
  const calls = [];
  const out = [];
  globalThis.fetch = async (url, opts) => {
    calls.push({ url: String(url), opts });
    if (String(url).startsWith("https://oidc.example/")) return { ok: true, status: 200, json: async () => ({ value: "eyJ.oidc.token" }) };
    return { ok: true, status: 200, json: async () => verdict };
  };
  console.log = (...a) => out.push(a.join(" "));
  return fn({ calls, out }).finally(() => { globalThis.fetch = realFetch; console.log = realLog; });
}

const VERDICT = {
  ok: true, pattern: "none", tenantKey: null, conformancePct: null, hardLeaks: 0, byId: 0, reliable: false,
  gateEntitled: false, leaks: [], gateLevel: "none", fixableCount: 0, packBlocking: 0,
  // the shape the server persisted for the probe repo (pack_verdicts) — free tier : count + 1 redacted sample
  sqli: { count: 2, hidden: 1, blocking: 0, findings: [{ rule: "gated", table: "src/app.js:10", detail: "", severity: "high" }] },
  cmdi: { count: 1, hidden: 0, blocking: 0, findings: [{ rule: "gated", table: "src/ping.py:9", detail: "", severity: "high" }] },
  weakCrypto: { count: 1, hidden: 0, blocking: 0, findings: [{ rule: "gated", table: "src/app.js:20", detail: "", severity: "medium" }] },
  secrets: { count: 1, hidden: 0, blocking: 0, findings: [{ rule: "gated", table: "src/app.js:19", detail: "", severity: "high" }] },
  xss: { count: 0, hidden: 0, blocking: 0, findings: [] },
};

test("renders EVERY pack the server returns (sqli/cmdi/weakCrypto/secrets), not only the legacy six", async () => {
  await withStubbedNetwork(VERDICT, async ({ calls, out }) => {
    const code = await main(["--gate"], CI_ENV);
    assert.equal(code, 0); // non-entitled → advisory, never blocked
    const text = out.join("\n");
    assert.match(text, /SQL injection: 2 finding\(s\)/);
    assert.match(text, /command injection: 1 finding\(s\)/);
    assert.match(text, /weak crypto: 1 finding\(s\)/);
    assert.match(text, /hardcoded secrets: 1 finding\(s\)/);
    assert.doesNotMatch(text, /cross-site scripting: 0/);                 // count 0 → not rendered
    // one ::error annotation per located finding, on the right file:line, never an empty message
    assert.match(text, /::error file=src\/app\.js,line=10 title=slopGrade Firewall::\[gated\] SQL injection finding here/);
    assert.match(text, /::error file=src\/ping\.py,line=9 title=slopGrade Firewall::\[gated\] command injection finding here/);
    assert.doesNotMatch(text, /::error file=[^\n]*::\[gated\] $/m);        // the B-P1-5 empty annotation is gone
    assert.match(text, /\+1 more hidden/);
    assert.equal(calls.length, 2);                                           // 1 OIDC mint + 1 POST, nothing else
    assert.match(calls[1].url, /^https:\/\/app\.slopgrade\.ai\/api\/ci\/isolation$/);
  });
});

test("--gate --strict fails CLOSED on a blocked custom origin (a no-verdict path)", async () => {
  await withStubbedNetwork(VERDICT, async ({ calls, out }) => {
    const code = await main(["--gate", "--strict"], { ...CI_ENV, SLOPGRADE_ORIGIN: "https://evil.example" });
    assert.equal(code, 1);
    assert.equal(calls.length, 0);                                           // dry : nothing minted, nothing posted
    assert.match(out.join("\n"), /running DRY/);
  });
});

test("blocked custom origin without --strict still fails OPEN (exit 0, nothing posted)", async () => {
  await withStubbedNetwork(VERDICT, async ({ calls }) => {
    const code = await main(["--gate"], { ...CI_ENV, SLOPGRADE_ORIGIN: "https://evil.example" });
    assert.equal(code, 0);
    assert.equal(calls.length, 0);
  });
});

test("a paid verdict with packBlocking>0 exits 1 AND names the located findings", async () => {
  const paid = { ...VERDICT, gateEntitled: true, gateLevel: "paid", packBlocking: 2,
    sqli: { count: 2, hidden: 0, blocking: 2, findings: [
      { rule: "concat-sql", table: "src/app.js:10", detail: "user input concatenated into a SQL string", severity: "high" },
      { rule: "interp-sql", table: "src/app.js:14", detail: "template literal query with request data", severity: "high" },
    ] } };
  await withStubbedNetwork(paid, async ({ out }) => {
    const code = await main(["--gate"], CI_ENV);
    assert.equal(code, 1);
    const text = out.join("\n");
    assert.match(text, /::error file=src\/app\.js,line=14 title=slopGrade Firewall::\[interp-sql\] template literal query/);
    assert.match(text, /2 blocking security finding\(s\)[^\n]*build blocked/);
  });
});
