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
//   • PAID repos (client ≥ 0.7.0): the closed-source extractors for the rest of the catalogue are fetched from
//     /api/ci/pro-extractors (OIDC-proved entitlement), sha256-verified, and run HERE — same zero-egress contract,
//     a second egress boundary (sanitizeProFingerprints), fail-open to the free packs (loadProPacks below).
import { pathToFileURL } from "node:url";
import { writeFileSync, readFileSync, appendFileSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
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
import { postFindingReview, resolvePrContext } from "./src/pr-suggest.mjs";
import {
  resolveOrigin, DEFAULT_ORIGIN, classifyEnv, validVerdict, sanitizeLogLine, sanitizeFingerprint, sanitizePackFingerprints,
  parseLeak, findingLocation, buildSarif, collectPackBlocks, errMsg, CLIENT_VERSION, FINGERPRINT_VERSION, MAX_PAYLOAD_BYTES,
  validProBundleResponse, verifyBundleSig, PRO_BUNDLE_PUBKEY, runProPacks, sanitizeProFingerprints, FREE_PACK_COUNT, MAX_SARIF_RESULTS, MAX_PRO_BUNDLE_BYTES,
  githubBlobBase, stepSummaryMarkdown, emitStepSummary, uploadSarifToCodeScanning, emitOutputs,
} from "./src/client-lib.mjs";

const CODE_EXTS = /\.(py|ts|tsx|js|jsx|mjs|cjs|sql|rb|go|php|prisma|java|cs|rs|c|cc|cpp|h|hpp|kt|scala|ex|exs)$/;
const TIMEOUT_MS = 20_000;

const ghWarn = (msg) => console.log(`::warning title=slopGrade Firewall::${sanitizeLogLine(msg)}`);
const line = (msg) => console.log(sanitizeLogLine(msg));

async function timedFetch(url, opts) {
  return fetch(url, { ...opts, signal: AbortSignal.timeout(TIMEOUT_MS) });
}

/** Read a response body to a string with a HARD byte cap — a compromised/oversized pro-bundle response must not OOM the
 *  runner (res.json() buffers unbounded). Streams the body and aborts past `maxBytes`; falls back to text() if no stream. */
async function readCappedText(res, maxBytes) {
  const reader = res.body && typeof res.body.getReader === "function" ? res.body.getReader() : null;
  if (!reader) { const t = await res.text(); if (Buffer.byteLength(t, "utf8") > maxBytes) throw new Error("response exceeds size cap"); return t; }
  const chunks = []; let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.length;
    if (total > maxBytes) { try { await reader.cancel(); } catch { /* ignore */ } throw new Error("response exceeds size cap"); }
    chunks.push(value);
  }
  return Buffer.concat(chunks).toString("utf8");
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

/**
 * PRO extractors — the paid half of the catalogue (client ≥ 0.7.0). The server judges ~120 detector packs ; this
 * client ships the extractors for 22. A repo that proves (OIDC) it is paid-entitled receives the closed-source
 * extractors for the rest from /api/ci/pro-extractors and runs them HERE, in the runner — the source still never
 * leaves, only fingerprints do (sanitizeProFingerprints is the egress boundary, `--print-payload` shows exactly it).
 * fetch → verify (bounded, sha256) → load from a temp file → run over the pro walk set → sanitize. Every failure path
 * degrades to the free packs with a warning — a pro hiccup never costs the verdict. A free repo gets 402, silently.
 */
async function loadProPacks(origin, oidcToken, root, rel) {
  const none = (note) => ({ wire: {}, packCount: 0, version: null, note });
  // The pro bundle is closed-source code EXECUTED in the runner (import). Fetch it ONLY from the canonical origin — a
  // custom origin (staging, or an attacker who set SLOPGRADE_ALLOW_CUSTOM_ORIGIN) must never hand us code to run.
  if (origin !== DEFAULT_ORIGIN) return none(" (free tier — pro extractors only from the canonical origin)");
  let res;
  try {
    res = await timedFetch(`${origin}/api/ci/pro-extractors`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ oidcToken }) });
  } catch (e) { ghWarn(`pro extractors unreachable (${errMsg(e)}) — running the ${FREE_PACK_COUNT} free packs.`); return none(" (free tier — pro extractors unreachable)"); }
  if (res.status === 402) return none(" (free tier)");
  if (!res.ok) { ghWarn(`pro extractors refused (HTTP ${res.status}) — running the ${FREE_PACK_COUNT} free packs.`); return none(" (free tier — pro extractors refused)"); }
  // Bound the RAW body BEFORE parsing (res.json() is unbounded → an oversized/compromised response could OOM the runner).
  let j;
  try {
    const cap = MAX_PRO_BUNDLE_BYTES + 65_536; // the bundle cap + a little JSON-envelope slack
    const cl = Number(res.headers && typeof res.headers.get === "function" ? res.headers.get("content-length") : NaN);
    if (Number.isFinite(cl) && cl > cap) throw new Error(`content-length ${cl} exceeds cap`);
    j = JSON.parse(await readCappedText(res, cap));
  } catch (e) { ghWarn(`pro extractors: oversized or malformed response (${errMsg(e)}) — running the free packs.`); return none(" (free tier — pro extractors malformed)"); }
  const check = validProBundleResponse(j, (s) => createHash("sha256").update(s).digest("hex"));
  if (!check.ok) { ghWarn(`pro extractors rejected (${check.reason}) — running the ${FREE_PACK_COUNT} free packs.`); return none(" (free tier — pro extractors rejected)"); }
  // AUTHENTICITY (not just integrity) : when a pinned public key is configured, the bundle MUST carry a valid Ed25519
  // signature over its bytes — a compromised server / CA-valid MITM can match its own sha256 but cannot forge this.
  // An unsigned/invalid bundle is NEVER written or imported ; we degrade to the free packs. Empty pinned key = signing
  // not yet activated → skipped (unchanged behavior) until the public key is pinned in client-lib.
  if (PRO_BUNDLE_PUBKEY) {
    const sig = verifyBundleSig(j.bundle, j.sig, PRO_BUNDLE_PUBKEY);
    if (!sig.ok) { ghWarn(`pro extractors signature ${sig.reason} — NOT executing the untrusted bundle ; running the ${FREE_PACK_COUNT} free packs.`); return none(" (free tier — pro extractors unsigned/untrusted)"); }
  }
  // Write to a PRIVATE (0700) unique temp dir with the EXCLUSIVE flag (no symlink-follow, no clobber), import, then
  // remove the dir — closes the predictable-name symlink/TOCTOU race on shared self-hosted runners.
  let mod, dir;
  try {
    dir = mkdtempSync(join(tmpdir(), "slopgrade-pro-"));
    const file = join(dir, "bundle.mjs");
    writeFileSync(file, j.bundle, { encoding: "utf8", flag: "wx" });
    mod = await import(pathToFileURL(file).href);
  } catch (e) { ghWarn(`pro extractors failed to load (${errMsg(e)}) — running the free packs.`); return none(" (free tier — pro extractors failed to load)"); }
  finally { if (dir) { try { rmSync(dir, { recursive: true, force: true }); } catch { /* best-effort cleanup */ } } }
  const packs = Array.isArray(mod?.PRO_PACKS) ? mod.PRO_PACKS : [];
  // The pro walk set adds the infra formats (yaml/tf/json/Dockerfile…) the free CODE_EXTS walk never reads.
  const proFiles = mod?.PRO_WALK_EXTS instanceof RegExp ? walk(root, mod.PRO_WALK_EXTS) : walk(root, CODE_EXTS);
  const { wire, errors } = runProPacks(packs, proFiles, { read: (f) => readFileSync(f, "utf8"), rel });
  if (errors > 0) ghWarn(`${errors} pro extractor call(s) threw and were skipped.`);
  return { wire: sanitizeProFingerprints(wire), packCount: packs.length, version: String(j.version), note: ` (paid · pro extractors ${sanitizeLogLine(String(j.version), 40)})` };
}

const HELP = `slopGrade Firewall — CI leak detection (free tier: 10 flagship classes · paid repos: the full catalogue, extracted in your runner)
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

  // Fail-safe outputs sentinel — emitted BEFORE any no-verdict early return, so a downstream step reading
  // `steps.firewall.outputs.blocked` never sees an EMPTY string (which `!= 'true'` would treat as "not blocked" even
  // when the gate failed CLOSED under --strict and exited 1). `blocked` here mirrors the no-verdict exit code
  // (strict+gate ⇒ 1 ⇒ true). The happy path re-emits the REAL values at the decision — GITHUB_OUTPUT: last write wins.
  emitOutputs(env, {
    verdict: "no-verdict", blocked: strict && gateMode,
    "hard-leaks": "", "blocking-findings": "", conformance: "", entitled: "", "sarif-uploaded": false,
  }, appendFileSync);

  // 1. LOCAL — the structural fingerprint (file contents never leave). Wrapped so a crafted repo (symlink cycle)
  //    that makes extraction throw routes through noVerdict(), NOT the entrypoint catch (which fails OPEN).
  let fingerprint;
  let files = [];
  let sqliFingerprint, goSqliFingerprint, dotnetSqliFingerprint;
  let cmdiFingerprint, goCmdiFingerprint, dotnetCmdiFingerprint;
  let xssFingerprint, goXssFingerprint, dotnetXssFingerprint;
  let ssrfFingerprint, goSsrfFingerprint, dotnetSsrfFingerprint;
  let pathTraversalFingerprint, goPathTraversalFingerprint, dotnetPathTraversalFingerprint;
  let corsFingerprint, goCorsFingerprint, dotnetCorsFingerprint;
  let xxeFingerprint, deserFingerprint, secretFingerprint, cryptoFingerprint;
  const rel = (f) => { const nf = f.replace(/\\/g, "/"), nr = root.replace(/\\/g, "/").replace(/\/+$/, ""); return nf.startsWith(nr + "/") ? nf.slice(nr.length + 1) : nf.split("/").slice(-2).join("/"); };
  try {
    files = walk(root, CODE_EXTS);
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

  // 2. EXFILTRATION guard — a custom origin would mint a token for an attacker audience. Run DRY unless opted in.
  const { origin, blocked } = resolveOrigin(env);
  // 3. Environment — distinguish the three cases (the #1 support ticket is a forgotten id-token permission).
  const envState = classifyEnv(env);
  const sha = env.GITHUB_SHA || "";
  // --print-payload : outside a server-reachable context it prints the free payload and exits WITHOUT contacting the
  // server (as always). Inside CI it also asks for the pro extractors first (a paid repo runs ~100 more packs), so the
  // printed payload stays byte-for-byte what the POST would carry — the audit promise holds on the paid tier too.
  const serverReachable = !blocked && envState === "ci-ready" && !!sha;
  if (printPayload && !serverReachable) { console.log(JSON.stringify({ fingerprint, ...wirePacks }, null, 2)); return 0; }
  if (blocked) {
    // A dry run is a NO-VERDICT path: --strict must fail closed here too (it promised "exit 1 when no verdict").
    ghWarn(`custom SLOPGRADE_ORIGIN (${origin}) — running DRY: no token minted, nothing uploaded. Set SLOPGRADE_ALLOW_CUSTOM_ORIGIN=1 to allow.`);
    return noVerdict();
  }
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
  if (!sha) { ghWarn("GITHUB_SHA missing — cannot request a verdict."); return noVerdict(); }

  // 4. Mint OIDC (time-bounded).
  let oidcToken;
  try { oidcToken = await mintOidc(env, origin); }
  catch (e) { ghWarn(`OIDC unavailable (${errMsg(e)}).`); return noVerdict(); }
  if (!oidcToken) return noVerdict();

  // 4b. PRO extractors — a PAID repo receives the closed-source extractors for the rest of the catalogue and runs them
  //     here (the source still never leaves) ; a free repo gets 402 and keeps its free packs. Fail-open, always.
  const pro = await loadProPacks(origin, oidcToken, root, rel);
  const wireAll = { ...pro.wire, ...wirePacks }; // the public extractors win on a key collision (never expected)
  // The coverage line — printed on EVERY run, clean or not : a run that scanned N files with P packs and found nothing
  // must be distinguishable from a run that scanned nothing (release-audit B-P1-7).
  line(`slopGrade Firewall: ${FREE_PACK_COUNT + pro.packCount} detector packs${pro.note} · ${files.length} files scanned.`);
  if (printPayload) { console.log(JSON.stringify({ fingerprint, ...wireAll }, null, 2)); return 0; }

  // 5. POST (time-bounded; body size-capped).
  const body = JSON.stringify({ oidcToken, sha, fingerprint, ...wireAll, clientVersion: CLIENT_VERSION, fingerprintVersion: FINGERPRINT_VERSION, ...(pro.version ? { proVersion: pro.version } : {}) });
  if (Buffer.byteLength(body, "utf8") > MAX_PAYLOAD_BYTES) {
    ghWarn(`fingerprint exceeds ${Math.round(MAX_PAYLOAD_BYTES / 1024 / 1024)}MB — skipping upload for this run.`);
    return noVerdict();
  }
  const v = await postVerdict(origin, body);
  if (v === null) return noVerdict();
  if (!validVerdict(v)) { ghWarn("malformed verdict from server — treating as no verdict."); return noVerdict(); }

  // F1 (2026-09-14) — SILENT DOWNGRADE guard. loadProPacks returns silently (" (free tier)") on a 402, which is correct
  // for a genuinely-free repo. But if the server's verdict says this repo IS entitled (`gateEntitled`) while the pro
  // bundle did NOT load (pro.packCount === 0), the entitlement chain broke (livemode drift / unassigned slot / unlinked
  // repo) and a PAYING customer is silently getting only the free packs. We KNOW it's paid here, so say so LOUDLY.
  if (v.gateEntitled === true && pro.packCount === 0) {
    ghWarn(`this repo is PAID (entitled) but the pro extractors did not load — you are getting only the ${FREE_PACK_COUNT} free packs, not the full catalogue. Check the repo's slot assignment + plan at ${origin}/ci (or re-run — a transient server error also lands here).`);
  }

  // 6. Human-readable report (server strings sanitized before hitting the log).
  line(`\nslopGrade Firewall — tenant isolation`);
  line(`  pattern       : ${v.pattern}${v.tenantKey ? ` (key: ${v.tenantKey})` : ""}`);
  line(`  conformance   : ${v.conformancePct == null ? "n/a" : v.conformancePct.toFixed(1) + "%"}`);
  line(`  hard leaks    : ${v.hardLeaks}${v.byId ? `  (+${v.byId} by-id conditional)` : ""}`);
  line(`  mode          : ${v.reliable ? "GATE-able (explicit scoping)" : "ADVISORY (ORM — dataflow ceiling)"}`);
  for (const l of (Array.isArray(v.leaks) ? v.leaks : []).slice(0, 10)) line(`    - ${l}`);
  if (v.hiddenLeaks > 0) line(`    ... +${v.hiddenLeaks} more leak(s) hidden — see them all and block them in CI: ${origin}/ci`);

  const feed = []; // normalized {file,line,rule,detail,severity} for the inline PR comment feed (CodeRabbit-style)

  // `file=` is a workflow-command argument: sanitize it like every other server string (no `,`/`::` spoof).
  const wfFile = (f) => sanitizeLogLine(f).replace(/[,:]/g, "_");
  for (const p of (Array.isArray(v.leaks) ? v.leaks : []).map(parseLeak)) {
    if (p.file) { console.log(`::error file=${wfFile(p.file)},line=${p.line} title=slopGrade Firewall::${p.message}`); feed.push({ file: p.file, line: p.line, pack: "cross-tenant", rule: "cross-tenant", detail: p.message, severity: "high" }); }
  }
  // Every detector pack the server returned — DATA-DRIVEN (collectPackBlocks), never a hardcoded key list: a pack
  // missing from a static list would be silently dropped from the log, the feed and the SARIF (release-audit B-P0-2).
  for (const { key, label, block } of collectPackBlocks(v)) {
    // A pack in the server's CALIBRATION WINDOW (pro packs not yet swept on the corpus) reports everything but never
    // blocks : its findings annotate as warnings and count as advisory in the feed, so the summary never claims a
    // « blocking » finding the check did not block on.
    const advisory = block.advisory === true;
    line(`\nslopGrade Firewall — ${label}: ${block.count} finding(s)${advisory ? " (advisory — calibration window)" : ""}`);
    const findings = Array.isArray(block.findings) ? block.findings : [];
    // Location: most packs put "file:line" in `table`; the AC family (accessControl/dbSafety) puts a DB TABLE NAME
    // there + the real path in `file` — findingLocation resolves both, so annotations/feed/SARIF land on the RIGHT file.
    for (const f of findings) {
      const loc = findingLocation(f);
      // The free tier withholds the rule name + detail (rule "gated", empty detail): say so, and say where to unlock,
      // instead of printing an empty annotation.
      const detail = f.detail && String(f.detail).trim()
        ? String(f.detail)
        : `${label} finding here — the exact rule and the remaining findings are unlocked with the gate: ${origin}/ci`;
      if (loc.file) {
        console.log(`::${advisory ? "warning" : "error"} file=${wfFile(loc.file)},line=${loc.line} title=slopGrade Firewall::[${sanitizeLogLine(f.rule)}] ${sanitizeLogLine(detail)}`);
        feed.push({ file: loc.file, line: loc.line, pack: key, rule: f.rule, detail, severity: advisory ? "medium" : f.severity });
      }
    }
    for (const f of findings.slice(0, 10)) line(`    - ${sanitizeLogLine(f.table ?? "")}  [${sanitizeLogLine(f.rule)}] ${sanitizeLogLine(f.detail && String(f.detail).trim() ? f.detail : "(detail withheld on the free tier)")}`);
    if (block.hidden > 0) line(`    ... +${block.hidden} more hidden — enable the gate to see them all: ${origin}/ci`);
  }

  // The finding feed — posted as ONE PR review (the summary in its body + every on-diff finding inline), so the PR
  // author gets ONE notification, not one email per finding (F8 2026-09-14 : a findings-heavy PR emailed ~40 times).
  // Fail-open + dedup so a re-run adds only new findings, never a wall of comments (pr-suggest.mjs).
  if (feed.length) {
    const deps = { readEvent: () => { try { return JSON.parse(readFileSync(env.GITHUB_EVENT_PATH, "utf8")); } catch { return null; } }, log: (m) => line(m), warn: (m) => ghWarn(m) };
    const blocking = feed.filter((f) => f.severity === "high" || f.severity === "critical").length;
    const summary = `## 🛡 slopGrade Firewall\n\n**${blocking}** blocking (critical/high) · ${feed.length - blocking} advisory · ${feed.length} finding(s) located.\n\nBlocking findings fail the check when the gate is enabled on this repo. See all findings + enable the gate: ${origin}/ci`;
    const review = await postFindingReview(env, feed, summary, deps);
    if (review.review !== "skipped" || review.comments) line(`\nslopGrade Firewall — ${review.comments} finding(s) inline in ONE PR review (${review.review}) — one notification, not one per finding.`);
  }

  // SARIF — built from the SAME normalized feed the log + PR review use, so all three channels agree: cross-tenant
  // leaks via v.leaks (rule cross-tenant-isolation-leak), and EVERY detector pack via the feed, EACH carrying its own
  // pack rule id. The AC family (accessControl/dbSafety) now flows through the feed too — findingLocation resolves it to
  // its real `file` — so it is no longer lumped under the cross-tenant rule nor dropped (B#2). `feed` cross-tenant rows
  // are excluded here because v.leaks already carries them (no double alert).
  const sarifFindings = feed.filter((f) => f.pack !== "cross-tenant");
  const sarif = buildSarif(v.leaks ?? [], { version: CLIENT_VERSION, findings: sarifFindings });
  // Make a cap VISIBLE, never silent — but only when it ACTUALLY truncates. Count the real mappable candidates (the
  // same predicates buildSarif applies) so the warning fires on genuine overflow, not at exactly the cap, and names the
  // true count. buildSarif keeps the HIGHEST-severity results, so the dropped ones are the lowest-severity.
  const sarifCandidates = (Array.isArray(v.leaks) ? v.leaks : []).reduce((n, l) => n + (parseLeak(l).file ? 1 : 0), 0)
    + sarifFindings.filter((f) => typeof f.file === "string" && f.file).length;
  if (sarifCandidates > MAX_SARIF_RESULTS) {
    ghWarn(`SARIF capped: ${sarifCandidates} findings exceed GitHub's ${MAX_SARIF_RESULTS}-result Code Scanning limit — the highest-severity ${MAX_SARIF_RESULTS} are uploaded; the rest are in the log and the PR feed.`);
  }
  // Back-compat: --sarif <path> still writes the file (for an artifact or a manual codeql-action/upload-sarif step).
  if (sarifPath) {
    try { writeFileSync(sarifPath, JSON.stringify(sarif, null, 2)); line(`  SARIF written: ${sarifPath}`); }
    catch (e) { ghWarn(`could not write SARIF to ${sanitizeLogLine(String(sarifPath))} (${errMsg(e)}).`); }
  }
  // Upload to Code Scanning ourselves — the Security tab + inline PR annotations (tracked across commits, dismissible),
  // with NO extra workflow step to wire and no SHA to pin. Default on; FW_UPLOAD_SARIF=false opts out. Fail-soft: it
  // never throws, never changes the verdict, and stays quiet (an info line, not a warning) when the permission is absent.
  let sarifUploaded = "skipped";
  if (env.FW_UPLOAD_SARIF !== "false") {
    sarifUploaded = await uploadSarifToCodeScanning(env, sarif, { log: (m) => line(m), warn: (m) => ghWarn(m) });
  }

  // 7. Exit decision — the PURE, tested free/paid boundary. Blocks on --gate + EITHER a reliable+entitled cross-tenant
  // hard leak OR >=1 blocking detector finding (packBlocking, critical|high — already server-paywalled to 0 unless
  // entitled). The build-block message NAMES the real reason(s).
  const decision = firewallVerdict({ gateMode, reliable: v.reliable, hardLeaks: v.hardLeaks, gateEntitled: v.gateEntitled, packBlocking: v.packBlocking });
  // Action outputs — surface the verdict + counts to downstream steps (a Slack alert, gating another job, a badge).
  // Fail-soft, no-op off CI. Emitted here (once the verdict is known) — the no-verdict early returns above set none.
  emitOutputs(env, {
    verdict: decision.kind,                    // advisory | gate-blocked | gate-unpaid | gate-pass
    blocked: decision.block === true,          // did the gate fail the build?
    "hard-leaks": Number(v.hardLeaks) || 0,
    "blocking-findings": Number(v.packBlocking) || 0,
    conformance: v.conformancePct == null ? "" : Number(v.conformancePct).toFixed(1),
    entitled: v.gateEntitled === true,
    "sarif-uploaded": sarifUploaded === "uploaded",
  }, appendFileSync);
  // Rendered run-page report (GitHub Step Summary) — a scannable, clickable verdict at the top of the run. Unlike the
  // PR review it also shows on push runs (no PR to comment on). Clickable file:line via the PR head sha (blob base).
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
