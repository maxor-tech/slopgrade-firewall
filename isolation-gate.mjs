#!/usr/bin/env node
// slopGrade Firewall — the LOCAL CLIENT (open source, FREE tier: 10 flagship classes).
//   node isolation-gate.mjs [--gate] [--strict] [--print-payload] [--sarif <path>] [--help]
//   • Runs the extractors IN PLACE — file CONTENTS never leave the runner. What leaves, by design, is the
//     structural fingerprint (file paths, abstract shapes, {file,line,kind}); `--print-payload` prints exactly
//     that and exits, so you can audit it before enabling uploads.
//   • Mints a zero-secret GitHub OIDC token and POSTs the fingerprint to /api/ci/isolation; the server brain
//     classifies + measures and returns the verdict (the calibrated suppression lives server-side, never shipped).
//   • Exit 1 ONLY in --gate mode on a `reliable` verdict WITH hard leaks AND an entitled repo. Every failure path
//     fails OPEN (exit 0) so a network/DNS incident never breaks a build — unless --strict (fail CLOSED).
//
// FREE-tier scope: the 10 highest-severity classes (SQLi, command injection, XSS, SSRF, XXE, insecure
// deserialization, path traversal, hardcoded secrets, broken crypto, CORS reflected-origin) across JS/TS/Python
// plus Go/.NET. The interprocedural taint engine + the rest of the detector-class catalog + the calibrated suppression + the
// cross-repo intelligence are the hosted product (slopgrade.ai). This client extracts locally; only the
// structural fingerprint (no code) is posted for classification — your source never leaves the runner.
import { pathToFileURL } from "node:url";
import { writeFileSync, readFileSync, appendFileSync } from "node:fs";
import { walk } from "./src/extract.mjs";
import { buildFingerprint } from "./src/fingerprint.mjs";
// The 10 flagship classes (base + go/dotnet variants where they exist).
import { extractSqliFingerprint, sqliWrapperCfg } from "./src/sqli-extract.mjs";
import { extractGoSqliFingerprint } from "./src/gosqli-extract.mjs";
import { extractDotnetSqliFingerprint } from "./src/dotnetsqli-extract.mjs";
import { extractCmdiFingerprint, cmdiWrapperCfg } from "./src/cmdi-extract.mjs";
import { extractGoCmdiFingerprint } from "./src/gocmdi-extract.mjs";
import { extractDotnetCmdiFingerprint } from "./src/dotnetcmdi-extract.mjs";
import { extractXssFingerprint, xssWrapperCfg } from "./src/xss-extract.mjs";
import { extractGoXssFingerprint } from "./src/goxss-extract.mjs";
import { extractDotnetXssFingerprint } from "./src/dotnetxss-extract.mjs";
import { extractSsrfFingerprint, ssrfWrapperCfg } from "./src/ssrf-extract.mjs";
import { extractGoSsrfFingerprint } from "./src/gossrf-extract.mjs";
import { extractDotnetSsrfFingerprint } from "./src/dotnetssrf-extract.mjs";
import { extractPathTraversalFingerprint, pathTraversalWrapperCfg } from "./src/pathtraversal-extract.mjs";
import { extractGoPathTraversalFingerprint } from "./src/gopathtraversal-extract.mjs";
import { extractDotnetPathTraversalFingerprint } from "./src/dotnetpathtraversal-extract.mjs";
import { extractCorsFingerprint } from "./src/cors-extract.mjs";
import { extractGoCorsFingerprint } from "./src/gocors-extract.mjs";
import { extractDotnetCorsFingerprint } from "./src/dotnetcors-extract.mjs";
import { extractXxeFingerprint } from "./src/xxe-extract.mjs";
import { extractDeserFingerprint } from "./src/deser-extract.mjs";
import { extractSecretFingerprint } from "./src/secret-extract.mjs";
import { extractCryptoFingerprint } from "./src/crypto-extract.mjs";
// OSS shim: the interprocedural pass is stubbed (returns empty) → the taint detectors run INTRA-function only.
import { buildWrapperRegistries, resolveImportedWrappers } from "./src/taint-interproc.mjs";
import { firewallVerdict } from "./src/gate-verdict.mjs";
import { postFindingComments, postSummaryComment, resolvePrContext } from "./src/pr-suggest.mjs";
import {
  resolveOrigin, classifyEnv, validVerdict, sanitizeLogLine, sanitizeFingerprint, sanitizePackFingerprints,
  parseLeak, buildSarif, errMsg, CLIENT_VERSION, FINGERPRINT_VERSION, MAX_PAYLOAD_BYTES,
  githubBlobBase, stepSummaryMarkdown, emitStepSummary,
} from "./src/client-lib.mjs";

const CODE_EXTS = /\.(py|ts|tsx|js|jsx|mjs|cjs|sql|rb|go|php|prisma|java|cs|rs|c|cc|cpp|h|hpp|kt|scala|ex|exs)$/;
const TIMEOUT_MS = 20_000;

const ghWarn = (msg) => console.log(`::warning title=slopGrade Firewall::${sanitizeLogLine(msg)}`);
const line = (msg) => console.log(sanitizeLogLine(msg));

async function timedFetch(url, opts) {
  return fetch(url, { ...opts, signal: AbortSignal.timeout(TIMEOUT_MS) });
}

/** Mint the zero-secret OIDC token for `origin` as audience. Returns null on any failure (caller fails open). */
async function mintOidc(env, origin) {
  const url = env.ACTIONS_ID_TOKEN_REQUEST_URL;
  const tok = env.ACTIONS_ID_TOKEN_REQUEST_TOKEN;
  const r = await timedFetch(`${url}&audience=${encodeURIComponent(origin)}`, { headers: { authorization: `Bearer ${tok}` } });
  if (!r.ok) { ghWarn(`OIDC token refused (HTTP ${r.status}).`); return null; }
  return (await r.json()).value ?? null;
}

/** POST the payload with one backoff retry on a transient 5xx / network error. Returns the parsed body or null. */
async function postVerdict(origin, body) {
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      const res = await timedFetch(`${origin}/api/ci/isolation`, {
        method: "POST", headers: { "content-type": "application/json" }, body,
      });
      if (res.ok) return await res.json();
      if (res.status >= 500 && attempt === 0) { await new Promise((r) => setTimeout(r, 750)); continue; }
      ghWarn(`server refused (HTTP ${res.status}) — no verdict.`);
      return null;
    } catch (e) {
      if (attempt === 0) { await new Promise((r) => setTimeout(r, 750)); continue; }
      ghWarn(`server call failed (${errMsg(e)}) — no verdict.`);
      return null;
    }
  }
  return null;
}

const HELP = `slopGrade Firewall — CI leak detection (free tier: 10 flagship classes)
Usage: node isolation-gate.mjs [--gate] [--strict] [--print-payload] [--sarif <path>] [--help]
  --gate           block (exit 1) on a reliable hard leak in an entitled repo (default: advisory, never blocks)
  --strict         with --gate, fail CLOSED (exit 1) when no server verdict is available (default: fail open)
  --print-payload  print the exact structural fingerprint that would be sent, then exit (audit what leaves the runner)
  --sarif <path>   also write a SARIF report of the leaks (upload with github/codeql-action/upload-sarif)
  --help           show this help
Exit codes: 1 only on a gate-blocked verdict (or --strict with no verdict); 0 otherwise (fail open).`;
const KNOWN_FLAGS = new Set(["--gate", "--strict", "--print-payload", "--help", "--sarif"]);

export async function main(argv = [], env = process.env) {
  if (argv.includes("--help")) { console.log(HELP); return 0; }
  const sarifIdx = argv.indexOf("--sarif");
  const sarifPath = sarifIdx >= 0 ? argv[sarifIdx + 1] : null;
  for (const a of argv) if (a.startsWith("-") && !KNOWN_FLAGS.has(a)) console.log(`::warning title=slopGrade Firewall::unknown flag ${sanitizeLogLine(a)} ignored (see --help).`);
  const gateMode = argv.includes("--gate");
  const strict = argv.includes("--strict");
  const printPayload = argv.includes("--print-payload");
  const root = env.GITHUB_WORKSPACE || process.cwd();
  const noVerdict = () => (strict && gateMode ? 1 : 0);

  // 1. LOCAL — the structural fingerprint (file contents never leave). Wrapped so a crafted repo (symlink cycle)
  //    that makes extraction throw routes through noVerdict(), NOT the entrypoint catch (which fails OPEN).
  let fingerprint;
  let sqliFingerprint, goSqliFingerprint, dotnetSqliFingerprint;
  let cmdiFingerprint, goCmdiFingerprint, dotnetCmdiFingerprint;
  let xssFingerprint, goXssFingerprint, dotnetXssFingerprint;
  let ssrfFingerprint, goSsrfFingerprint, dotnetSsrfFingerprint;
  let pathTraversalFingerprint, goPathTraversalFingerprint, dotnetPathTraversalFingerprint;
  let corsFingerprint, goCorsFingerprint, dotnetCorsFingerprint;
  let xxeFingerprint, deserFingerprint, secretFingerprint, cryptoFingerprint;
  const rel = (f) => { const nf = f.replace(/\\/g, "/"), nr = root.replace(/\\/g, "/").replace(/\/+$/, ""); return nf.startsWith(nr + "/") ? nf.slice(nr.length + 1) : nf.split("/").slice(-2).join("/"); };
  try {
    const files = walk(root, CODE_EXTS);
    fingerprint = sanitizeFingerprint(buildFingerprint(files, root));
    sqliFingerprint = { files: [] }; goSqliFingerprint = { files: [] }; dotnetSqliFingerprint = { files: [] };
    cmdiFingerprint = { files: [] }; goCmdiFingerprint = { files: [] }; dotnetCmdiFingerprint = { files: [] };
    xssFingerprint = { files: [] }; goXssFingerprint = { files: [] }; dotnetXssFingerprint = { files: [] };
    ssrfFingerprint = { files: [] }; goSsrfFingerprint = { files: [] }; dotnetSsrfFingerprint = { files: [] };
    pathTraversalFingerprint = { files: [] }; goPathTraversalFingerprint = { files: [] }; dotnetPathTraversalFingerprint = { files: [] };
    corsFingerprint = { files: [] }; goCorsFingerprint = { files: [] }; dotnetCorsFingerprint = { files: [] };
    xxeFingerprint = { files: [] }; deserFingerprint = { files: [] }; secretFingerprint = { files: [] }; cryptoFingerprint = { files: [] };
    // Cross-file taint registries — OSS shim returns {} so every resolveImportedWrappers() below is an empty Map
    // (the taint detectors degrade to intra-function; the interprocedural pass is the hosted product).
    const xfileRegs = buildWrapperRegistries((function* () {
      for (const f of files) { let t; try { t = readFileSync(f, "utf8"); } catch { continue; } yield { path: rel(f), text: t }; }
    })(), { ssrf: ssrfWrapperCfg, sqli: sqliWrapperCfg, cmdi: cmdiWrapperCfg, pt: pathTraversalWrapperCfg, xss: xssWrapperCfg });
    for (const f of files) {
      let t; try { t = readFileSync(f, "utf8"); } catch { continue; }
      const r = rel(f);
      const sqf = extractSqliFingerprint(t, r, resolveImportedWrappers(t, r, xfileRegs.sqli)); if (sqf.hits.length) sqliFingerprint.files.push(sqf);
      const gqf = extractGoSqliFingerprint(t, r); if (gqf.hits.length) goSqliFingerprint.files.push(gqf);
      const dqf = extractDotnetSqliFingerprint(t, r); if (dqf.hits.length) dotnetSqliFingerprint.files.push(dqf);
      const mf = extractCmdiFingerprint(t, r, resolveImportedWrappers(t, r, xfileRegs.cmdi)); if (mf.hits.length) cmdiFingerprint.files.push(mf);
      const gxf = extractGoCmdiFingerprint(t, r); if (gxf.hits.length) goCmdiFingerprint.files.push(gxf);
      const ncf = extractDotnetCmdiFingerprint(t, r); if (ncf.hits.length) dotnetCmdiFingerprint.files.push(ncf);
      const xsf = extractXssFingerprint(t, r, resolveImportedWrappers(t, r, xfileRegs.xss)); if (xsf.hits.length) xssFingerprint.files.push(xsf);
      const gxsf = extractGoXssFingerprint(t, r); if (gxsf.hits.length) goXssFingerprint.files.push(gxsf);
      const dxsf = extractDotnetXssFingerprint(t, r); if (dxsf.hits.length) dotnetXssFingerprint.files.push(dxsf);
      const srf = extractSsrfFingerprint(t, r, resolveImportedWrappers(t, r, xfileRegs.ssrf)); if (srf.hits.length) ssrfFingerprint.files.push(srf);
      const gsf = extractGoSsrfFingerprint(t, r); if (gsf.hits.length) goSsrfFingerprint.files.push(gsf);
      const nsf = extractDotnetSsrfFingerprint(t, r); if (nsf.hits.length) dotnetSsrfFingerprint.files.push(nsf);
      const pf = extractPathTraversalFingerprint(t, r, resolveImportedWrappers(t, r, xfileRegs.pt)); if (pf.hits.length) pathTraversalFingerprint.files.push(pf);
      const gpf = extractGoPathTraversalFingerprint(t, r); if (gpf.hits.length) goPathTraversalFingerprint.files.push(gpf);
      const dpf = extractDotnetPathTraversalFingerprint(t, r); if (dpf.hits.length) dotnetPathTraversalFingerprint.files.push(dpf);
      const cof = extractCorsFingerprint(t, r); if (cof.hits.length) corsFingerprint.files.push(cof);
      const gcof = extractGoCorsFingerprint(t, r); if (gcof.hits.length) goCorsFingerprint.files.push(gcof);
      const dcof = extractDotnetCorsFingerprint(t, r); if (dcof.hits.length) dotnetCorsFingerprint.files.push(dcof);
      const xf = extractXxeFingerprint(t, r); if (xf.hits.length) xxeFingerprint.files.push(xf);
      const df = extractDeserFingerprint(t, r); if (df.hits.length) deserFingerprint.files.push(df);
      const sf = extractSecretFingerprint(t, r); if (sf.hits.length) secretFingerprint.files.push(sf);
      const cf = extractCryptoFingerprint(t, r); if (cf.hits.length) cryptoFingerprint.files.push(cf);
    }
  } catch (e) {
    ghWarn(`could not scan the repo (${errMsg(e)}) — no verdict.`);
    return noVerdict();
  }

  const packFingerprints = {
    sqliFingerprint, goSqliFingerprint, dotnetSqliFingerprint,
    cmdiFingerprint, goCmdiFingerprint, dotnetCmdiFingerprint,
    xssFingerprint, goXssFingerprint, dotnetXssFingerprint,
    ssrfFingerprint, goSsrfFingerprint, dotnetSsrfFingerprint,
    pathTraversalFingerprint, goPathTraversalFingerprint, dotnetPathTraversalFingerprint,
    corsFingerprint, goCorsFingerprint, dotnetCorsFingerprint,
    xxeFingerprint, deserFingerprint, secretFingerprint, cryptoFingerprint,
  };
  // Egress boundary: rebuild the pack fingerprints by whitelist (the twin of sanitizeFingerprint above), so what
  // leaves the runner is PROVABLE — a future extractor bug can't grow a source-bearing hit field. This is exactly
  // what --print-payload shows AND what is POSTed, so the audit and the wire agree byte-for-byte.
  const wirePacks = sanitizePackFingerprints(packFingerprints);

  if (printPayload) { console.log(JSON.stringify({ fingerprint, ...wirePacks }, null, 2)); return 0; }

  // 2. EXFILTRATION guard — a custom origin would mint a token for an attacker audience. Run DRY unless opted in.
  const { origin, blocked } = resolveOrigin(env);
  if (blocked) {
    ghWarn(`custom SLOPGRADE_ORIGIN (${origin}) — running DRY: no token minted, nothing uploaded. Set SLOPGRADE_ALLOW_CUSTOM_ORIGIN=1 to allow.`);
    return 0;
  }

  // 3. Environment — distinguish the three cases (the #1 support ticket is a forgotten id-token permission).
  const envState = classifyEnv(env);
  if (envState === "no-ci") {
    line(`slopGrade Firewall: outside GitHub CI — local fingerprint only (${fingerprint.queries.length} queries), no server verdict.`);
    return 0;
  }
  if (envState === "missing-permission") {
    ghWarn("no OIDC token — the workflow is missing `id-token: write`. Add the permissions block printed below.");
    line("");
    line("  permissions:");
    line("    id-token: write");
    line("    contents: read");
    line("");
    return noVerdict();
  }
  const sha = env.GITHUB_SHA || "";
  if (!sha) { ghWarn("GITHUB_SHA missing — cannot request a verdict."); return noVerdict(); }

  // 4. Mint OIDC + POST (both time-bounded; body size-capped).
  let oidcToken;
  try { oidcToken = await mintOidc(env, origin); }
  catch (e) { ghWarn(`OIDC unavailable (${errMsg(e)}).`); return noVerdict(); }
  if (!oidcToken) return noVerdict();

  const body = JSON.stringify({ oidcToken, sha, fingerprint, ...wirePacks, clientVersion: CLIENT_VERSION, fingerprintVersion: FINGERPRINT_VERSION });
  if (Buffer.byteLength(body, "utf8") > MAX_PAYLOAD_BYTES) {
    ghWarn(`fingerprint exceeds ${Math.round(MAX_PAYLOAD_BYTES / 1024 / 1024)}MB — skipping upload for this run.`);
    return noVerdict();
  }
  const v = await postVerdict(origin, body);
  if (v === null) return noVerdict();
  if (!validVerdict(v)) { ghWarn("malformed verdict from server — treating as no verdict."); return noVerdict(); }

  // 5. Human-readable report (server strings sanitized before hitting the log).
  line(`\nslopGrade Firewall — tenant isolation`);
  line(`  pattern       : ${v.pattern}${v.tenantKey ? ` (key: ${v.tenantKey})` : ""}`);
  line(`  conformance   : ${v.conformancePct == null ? "n/a" : v.conformancePct.toFixed(1) + "%"}`);
  line(`  hard leaks    : ${v.hardLeaks}${v.byId ? `  (+${v.byId} by-id conditional)` : ""}`);
  line(`  mode          : ${v.reliable ? "GATE-able (explicit scoping)" : "ADVISORY (ORM — dataflow ceiling)"}`);
  for (const l of (Array.isArray(v.leaks) ? v.leaks : []).slice(0, 10)) line(`    - ${l}`);
  if (v.hiddenLeaks > 0) line(`    ... +${v.hiddenLeaks} more leak(s) hidden — see them all and block them in CI: ${origin}/ci`);

  // A leak/finding location is "file:line" — parse once for annotations + the inline feed.
  const parseLoc = (t) => { const m = /^(.*):(\d+)$/.exec(String(t ?? "")); return m ? { file: m[1], line: Number(m[2]) } : { file: null, line: 1 }; };
  const feed = []; // normalized {file,line,rule,detail,severity} for the inline PR comment feed (CodeRabbit-style)

  for (const p of (Array.isArray(v.leaks) ? v.leaks : []).map(parseLeak)) {
    if (p.file) { console.log(`::error file=${p.file},line=${p.line} title=slopGrade Firewall::${p.message}`); feed.push({ file: p.file, line: p.line, rule: "cross-tenant", detail: p.message, severity: "high" }); }
  }
  for (const [labelName, block] of [["access control", v.accessControl], ["db safety", v.dbSafety], ["supply chain", v.supplyChain], ["secrets", v.secrets], ["container", v.container], ["ci/cd", v.cicd]]) {
    if (block && block.count > 0) {
      line(`\nslopGrade Firewall — ${labelName}: ${block.count} finding(s)`);
      // `table` is "file:line" for the file-based packs → parse it so annotations + the feed land on the RIGHT line.
      for (const f of (Array.isArray(block.findings) ? block.findings : [])) {
        const loc = parseLoc(f.table);
        if (loc.file) { console.log(`::error file=${loc.file},line=${loc.line} title=slopGrade Firewall::[${sanitizeLogLine(f.rule)}] ${sanitizeLogLine(f.detail)}`); feed.push({ file: loc.file, line: loc.line, rule: f.rule, detail: f.detail, severity: f.severity }); }
      }
      for (const f of (Array.isArray(block.findings) ? block.findings : []).slice(0, 10)) line(`    - [${sanitizeLogLine(f.rule)}] ${sanitizeLogLine(f.detail)}`);
      if (block.hidden > 0) line(`    ... +${block.hidden} more hidden — enable the gate to see them all: ${origin}/ci`);
    }
  }

  // The inline finding FEED (CodeRabbit-style) — one review comment per finding at its file:line + a deduped summary,
  // when this is a PR with a writable token. Fail-open + dedup so a re-run updates instead of spamming (pr-suggest.mjs).
  if (feed.length) {
    const deps = { readEvent: () => { try { return JSON.parse(readFileSync(env.GITHUB_EVENT_PATH, "utf8")); } catch { return null; } }, log: (m) => line(m), warn: (m) => ghWarn(m) };
    const blocking = feed.filter((f) => f.severity === "high" || f.severity === "critical").length;
    const summary = `## 🛡 slopGrade Firewall\n\n**${blocking}** blocking (critical/high) · ${feed.length - blocking} advisory · ${feed.length} finding(s) located.\n\nBlocking findings fail the check when the gate is enabled on this repo. See all findings + enable the gate: ${origin}/ci`;
    const postedFeed = await postFindingComments(env, feed, deps);
    const summaryState = await postSummaryComment(env, summary, deps);
    if (postedFeed || summaryState !== "skipped") line(`\nslopGrade Firewall — feed: ${postedFeed} inline comment(s) posted, summary ${summaryState}.`);
  }

  if (sarifPath) {
    const acLeaks = [
      ...(v.accessControl?.findings ?? []), ...(v.dbSafety?.findings ?? []),
      ...(v.supplyChain?.findings ?? []), ...(v.secrets?.findings ?? []), ...(v.container?.findings ?? []),
      ...(v.cicd?.findings ?? []),
    ].map((f) => `${f.table}:1  ${f.detail}`);
    try { writeFileSync(sarifPath, JSON.stringify(buildSarif([...(v.leaks ?? []), ...acLeaks], { version: CLIENT_VERSION }), null, 2)); line(`  SARIF written: ${sarifPath}`); }
    catch (e) { ghWarn(`could not write SARIF to ${sanitizeLogLine(String(sarifPath))} (${errMsg(e)}).`); }
  }

  // 6. Exit decision — the PURE, tested free/paid boundary. Blocks on --gate + EITHER a reliable+entitled cross-tenant
  // hard leak OR >=1 blocking detector finding (packBlocking, critical|high — already server-paywalled to 0 unless
  // entitled). The build-block message NAMES the real reason(s).
  const decision = firewallVerdict({ gateMode, reliable: v.reliable, hardLeaks: v.hardLeaks, gateEntitled: v.gateEntitled, packBlocking: v.packBlocking });
  // Rendered run-page report (GitHub Step Summary) — a scannable, clickable verdict at the top of the run. Unlike the
  // PR feed it also shows on push runs (no PR to comment on). Clickable file:line via the PR head sha (blob base).
  // Fail-soft: it never changes the verdict or breaks the build (no summary file / write error → silently skipped).
  try {
    const prCtx = resolvePrContext(env, () => { try { return JSON.parse(readFileSync(env.GITHUB_EVENT_PATH, "utf8")); } catch { return null; } });
    const blobBase = githubBlobBase(env, (prCtx && prCtx.headSha) || env.GITHUB_SHA || null);
    emitStepSummary(env, stepSummaryMarkdown(v, { origin, blobBase, decision: decision.kind }), appendFileSync);
  } catch (e) { ghWarn(`step summary skipped (${errMsg(e)}).`); }
  if (decision.kind === "gate-blocked") {
    const reasons = [];
    if (v.reliable && v.hardLeaks > 0 && v.gateEntitled) reasons.push(`${v.hardLeaks} hard cross-tenant leak(s)`);
    if (Number(v.packBlocking) > 0) reasons.push(`${v.packBlocking} blocking security finding(s) (injection/crypto/secrets…)`);
    console.log(`::error title=slopGrade Firewall::${reasons.join(" + ") || `${v.hardLeaks} hard cross-tenant leak(s)`} — build blocked.`);
    return 1;
  }
  if (decision.kind === "gate-unpaid") {
    line(`\nslopGrade Firewall: ${v.hardLeaks} hard leak(s) found, but this repo is ADVISORY (no paid gate) — non-blocking. Enable the gate to block ($8–29/repo/mo · 14-day free trial, no card): ${origin}/ci`);
    return 0;
  }
  line(`\nslopGrade Firewall: ${gateMode ? "no blocking hard leaks." : "advisory (non-blocking)."}`);
  return 0;
}

// Entrypoint only when run directly — imported (tests) it runs nothing, so the logic is unit-testable.
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const argv = process.argv.slice(2);
  main(argv, process.env).then((code) => { process.exitCode = code; }).catch((e) => {
    const strictClosed = argv.includes("--strict") && argv.includes("--gate");
    console.log(`::warning title=slopGrade Firewall::client error (${sanitizeLogLine(errMsg(e))}) — ${strictClosed ? "failing CLOSED (--strict)" : "failing open"}.`);
    process.exitCode = strictClosed ? 1 : 0;
  });
}
