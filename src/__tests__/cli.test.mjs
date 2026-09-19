// End-to-end tests of the CLI `main()` against a STUBBED network (globalThis.fetch) — the release-audit 2026-09-13
// probe on an independent repo showed the server's sqli/cmdi/xss/… blocks were silently dropped by a hardcoded key
// list (B-P0-2), and that `--strict` did not fail closed on a blocked custom origin (B-P2-5). These pin both.
import { test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { main } from "../../isolation-gate.mjs";

// The walk excludes `__tests__/` (so CI_ENV's workspace scans nothing — fast, deterministic). The pro tests need a
// workspace with real files to extract from : a throwaway dir with one code file and one non-code file.
function proWorkspace() {
  const ws = mkdtempSync(join(tmpdir(), "sg-fw-pro-"));
  writeFileSync(join(ws, "app.mjs"), "export const x = 1;\n", "utf8");
  writeFileSync(join(ws, "NOTES.md"), "# notes\n", "utf8");
  return ws;
}

const CI_ENV = {
  GITHUB_ACTIONS: "true",
  ACTIONS_ID_TOKEN_REQUEST_URL: "https://oidc.example/token?api-version=2",
  ACTIONS_ID_TOKEN_REQUEST_TOKEN: "runner-token",
  GITHUB_SHA: "0123456789abcdef0123456789abcdef01234567",
  GITHUB_WORKSPACE: fileURLToPath(new URL("./", import.meta.url)), // scan only this tests dir (fast, deterministic)
};

// Default : the pro-extractors call answers 402 (a FREE repo) — the shape every non-paying run sees.
const PRO_FREE = { ok: false, status: 402, json: async () => ({ error: "plan-required", gateLevel: "none" }) };

function withStubbedNetwork(verdict, fn, pro = PRO_FREE) {
  const realFetch = globalThis.fetch;
  const realLog = console.log;
  const calls = [];
  const out = [];
  globalThis.fetch = async (url, opts) => {
    calls.push({ url: String(url), opts });
    if (String(url).startsWith("https://oidc.example/")) return { ok: true, status: 200, json: async () => ({ value: "eyJ.oidc.token" }) };
    if (String(url).endsWith("/api/ci/pro-extractors")) return pro;
    return { ok: true, status: 200, json: async () => verdict };
  };
  console.log = (...a) => out.push(a.join(" "));
  return fn({ calls, out }).finally(() => { globalThis.fetch = realFetch; console.log = realLog; });
}

// A tiny PRO bundle, the exact module shape the server ships (PRO_VERSION / PRO_WALK_EXTS / PRO_PACKS). Its file pack
// deliberately emits a source-bearing `snippet` : the egress boundary must drop it before the POST.
const PRO_BUNDLE = [
  'export const PRO_VERSION = "test-1";',
  "export const PRO_WALK_EXTS = /\\.(mjs|md|sql)$/i;",
  "export const PRO_PACKS = [",
  '  { fpField: "demoProFingerprint", mode: "file", match: /\\.mjs$/i, run: (t, f) => ({ file: f, hits: [{ line: 1, kind: "demo", snippet: "SHOULD-NEVER-LEAVE" }] }) },',
  '  { fpField: "demoSqlFingerprint", mode: "sql", match: /\\.sql$/i, run: (sql) => ({ tableCols: { "public.t": ["id"] }, policies: [], grants: [], rlsOn: [] }) },',
  "];",
].join("\n");
const sha = (s) => createHash("sha256").update(s).digest("hex");
const proResponse = (overrides = {}) => {
  // Model a real Response: the client reads the body with a bounded stream/text() reader (not res.json()), so the mock
  // must expose text() + a content-length header, exactly like fetch's Response.
  const body = { ok: true, gateLevel: "paid", version: "test-1", sha256: sha(PRO_BUNDLE), packs: ["demoProFingerprint", "demoSqlFingerprint"], bundle: PRO_BUNDLE, ...overrides };
  const text = JSON.stringify(body);
  return {
    ok: true, status: 200,
    headers: { get: (k) => (String(k).toLowerCase() === "content-length" ? String(Buffer.byteLength(text, "utf8")) : null) },
    json: async () => body,
    text: async () => text,
  };
};

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
    assert.equal(calls.length, 3);                                           // 1 OIDC mint + 1 pro ask (402) + 1 POST, nothing else
    assert.match(calls[1].url, /^https:\/\/app\.slopgrade\.ai\/api\/ci\/pro-extractors$/);
    assert.match(calls[2].url, /^https:\/\/app\.slopgrade\.ai\/api\/ci\/isolation$/);
    // the coverage line prints on every run : a free repo names its 22 packs and the files it walked (B-P1-7)
    assert.match(text, /slopGrade Firewall: 22 detector packs \(free tier\) · \d+ files scanned\./);
    const body = JSON.parse(calls[2].opts.body);
    assert.equal(body.demoProFingerprint, undefined);
    assert.equal(body.proVersion, undefined);
  });
});

// ── release-audit B-P1-7 : a PAID repo runs the closed-source extractors in the runner ──
test("PAID repo : the pro bundle is fetched, verified, run locally, sanitized, and its fingerprints ride in the POST", async () => {
  await withStubbedNetwork(VERDICT, async ({ calls, out }) => {
    const code = await main(["--gate"], { ...CI_ENV, GITHUB_WORKSPACE: proWorkspace() });
    assert.equal(code, 0);
    assert.equal(calls.length, 3);
    const body = JSON.parse(calls[2].opts.body);
    // `snippet` dropped at the egress boundary ; NOTES.md walked by the pro set but not matched by the pack
    assert.deepEqual(body.demoProFingerprint, { files: [{ file: "app.mjs", hits: [{ line: 1, kind: "demo" }] }] });
    assert.equal(body.demoSqlFingerprint, undefined);                          // no .sql in the walked dir → the sql pack emits nothing
    assert.equal(body.proVersion, "test-1");
    assert.doesNotMatch(calls[2].opts.body, /SHOULD-NEVER-LEAVE/);
    assert.equal(body.sqliFingerprint !== undefined, true);                     // the free packs are still there
    assert.match(out.join("\n"), /slopGrade Firewall: 24 detector packs \(paid · pro extractors test-1\) · 1 files scanned\./);
  }, proResponse());
});

test("a pro bundle whose sha256 does not match is REJECTED : nothing evaluated, the run keeps its free packs", async () => {
  await withStubbedNetwork(VERDICT, async ({ calls, out }) => {
    const code = await main(["--gate"], CI_ENV);
    assert.equal(code, 0);
    const text = out.join("\n");
    assert.match(text, /pro extractors rejected \(hash mismatch\)/);
    assert.match(text, /22 detector packs \(free tier — pro extractors rejected\)/);
    assert.equal(JSON.parse(calls[2].opts.body).demoProFingerprint, undefined);
  }, proResponse({ sha256: sha("something else") }));
});

test("an OVERSIZED pro response is rejected BEFORE parse (size cap) — free packs, the runner never OOMs", async () => {
  const huge = {
    ok: true, status: 200,
    headers: { get: (k) => (String(k).toLowerCase() === "content-length" ? String(50 * 1024 * 1024) : null) },
    json: async () => ({}), text: async () => "{}",
  };
  await withStubbedNetwork(VERDICT, async ({ calls, out }) => {
    const code = await main(["--gate"], CI_ENV);
    assert.equal(code, 0);
    assert.match(out.join("\n"), /oversized or malformed response/);
    assert.equal(JSON.parse(calls[2].opts.body).demoProFingerprint, undefined); // pro bundle never evaluated
  }, huge);
});

test("the pro bundle is fetched ONLY from the canonical origin — a custom origin gets free packs, never runs fetched code", async () => {
  await withStubbedNetwork(VERDICT, async ({ calls, out }) => {
    const code = await main(["--gate"], { ...CI_ENV, SLOPGRADE_ORIGIN: "https://evil.example", SLOPGRADE_ALLOW_CUSTOM_ORIGIN: "1" });
    assert.equal(code, 0);
    assert.ok(calls.every((c) => !c.url.endsWith("/api/ci/pro-extractors")), "a custom origin must never be asked for the closed-source pro bundle");
    assert.match(out.join("\n"), /only from the canonical origin/);
  }, proResponse());
});

test("a 5xx / unreachable pro endpoint never costs the verdict (fail-open to the free packs)", async () => {
  await withStubbedNetwork(VERDICT, async ({ calls, out }) => {
    const code = await main(["--gate"], CI_ENV);
    assert.equal(code, 0);
    assert.match(out.join("\n"), /pro extractors refused \(HTTP 503\)/);
    assert.equal(calls.length, 3);                                             // the isolation POST still happened
  }, { ok: false, status: 503, json: async () => ({ error: "bundle-unavailable" }) });
});

test("--print-payload inside CI prints EXACTLY the wire payload, pro packs included, and never POSTs", async () => {
  await withStubbedNetwork(VERDICT, async ({ calls, out }) => {
    const code = await main(["--print-payload"], { ...CI_ENV, GITHUB_WORKSPACE: proWorkspace() });
    assert.equal(code, 0);
    assert.equal(calls.length, 2);                                             // OIDC + pro ask ; NO isolation POST
    const payload = JSON.parse(out[out.length - 1]);
    assert.ok(payload.fingerprint && payload.sqliFingerprint, "free payload present");
    assert.deepEqual(payload.demoProFingerprint, { files: [{ file: "app.mjs", hits: [{ line: 1, kind: "demo" }] }] }, "pro packs in the printed payload, sanitized");
    assert.doesNotMatch(out[out.length - 1], /SHOULD-NEVER-LEAVE/);
  }, proResponse());
});

test("--print-payload outside CI prints the free payload and contacts nothing (unchanged)", async () => {
  await withStubbedNetwork(VERDICT, async ({ calls, out }) => {
    const code = await main(["--print-payload"], { GITHUB_WORKSPACE: CI_ENV.GITHUB_WORKSPACE });
    assert.equal(code, 0);
    assert.equal(calls.length, 0);
    const payload = JSON.parse(out[out.length - 1]);
    assert.ok(payload.fingerprint && payload.sqliFingerprint);
    assert.equal(payload.demoProFingerprint, undefined);
  }, proResponse());
});

test("a pack in the server's calibration window (advisory:true) annotates as a WARNING and never counts as blocking in the feed", async () => {
  const paid = { ...VERDICT, gateEntitled: true, gateLevel: "paid", packBlocking: 0,
    iac: { count: 2, hidden: 0, blocking: 0, advisory: true, findings: [
      { rule: "aws-sg-open-world", table: "infra/main.tf:3", detail: "security group open to 0.0.0.0/0 on all ports", severity: "high" },
      { rule: "aws-sg-open-world", table: "infra/db.tf:9", detail: "security group open to 0.0.0.0/0 on all ports", severity: "high" },
    ] } };
  await withStubbedNetwork(paid, async ({ out }) => {
    const code = await main(["--gate"], CI_ENV);
    assert.equal(code, 0);                                                     // reported, never blocked
    const text = out.join("\n");
    assert.match(text, /iac: 2 finding\(s\) \(advisory — calibration window\)/);
    assert.match(text, /::warning file=infra\/main\.tf,line=3 title=slopGrade Firewall::\[aws-sg-open-world\]/);
    assert.doesNotMatch(text, /::error file=infra\//);
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
