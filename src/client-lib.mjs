// PURE, testable client helpers — the security- and correctness-critical logic, isolated from I/O so it can be
// unit-tested (the CLI in isolation-gate.mjs is a thin adapter around these + the network). Zero dependencies.

export const DEFAULT_ORIGIN = "https://app.slopgrade.ai";
export const CLIENT_VERSION = "0.7.2"; // keep in lock-step with package.json (pinned by client-lib.test.mjs)
export const FINGERPRINT_VERSION = 1;
export const MAX_PAYLOAD_BYTES = 8 * 1024 * 1024; // 8MB hard cap on the POST body (clear error, not an opaque 413)
/** The pro-extractor bundle a PAID repo receives from /api/ci/pro-extractors — bounded like every other input. */
export const MAX_PRO_BUNDLE_BYTES = 4 * 1024 * 1024;
/** A file larger than this is skipped by the pro pass (a minified bundle / a data dump is never product code). */
export const MAX_PRO_FILE_CHARS = 1_000_000;
/** How many detector packs the free client extracts on its own (the 22 `src/*-extract.mjs`). */
export const FREE_PACK_COUNT = 22;

/**
 * Origin resolution + the origin-override guard. The OIDC audience is derived from the origin and the fingerprint is
 * POSTed to it, so an ACCIDENTAL origin override (a stray env var, a mis-set staging value) should not silently ship
 * a private repo's fingerprint elsewhere. A non-default origin therefore runs DRY (compute locally, mint nothing,
 * POST nothing) unless the owner explicitly opts in with SLOPGRADE_ALLOW_CUSTOM_ORIGIN=1, and an opted-in origin
 * must be https. NOTE: this guards ACCIDENTS, not an active attacker who controls the runner env (they can set the
 * opt-in too) — the real defense against a stolen token is the SERVER's audience verification, which rejects a token
 * whose audience is not the server's own origin. This client-side guard is defense-in-depth, not the primary control.
 * @returns {{ origin: string, custom: boolean, blocked: boolean }} blocked = dry-run (custom w/o opt-in, or non-https).
 */
export function resolveOrigin(env) {
  const raw = (env.SLOPGRADE_ORIGIN || "").trim().replace(/\/+$/, ""); // normalize trailing slash before comparing
  if (!raw) return { origin: DEFAULT_ORIGIN, custom: false, blocked: false };
  const custom = raw !== DEFAULT_ORIGIN;
  const allowed = env.SLOPGRADE_ALLOW_CUSTOM_ORIGIN === "1";
  // An opted-in custom origin must still be https — never send the OIDC token + fingerprint in cleartext.
  if (custom && allowed && !/^https:\/\//i.test(raw)) return { origin: raw, custom: true, blocked: true };
  if (custom && !allowed) return { origin: raw, custom: true, blocked: true };
  return { origin: raw, custom, blocked: false };
}

/**
 * The three CI states, distinguished for a correct diagnostic (the #1 support case is a forgotten
 * `permissions: id-token: write`, NOT "outside CI"). Only 'ci-ready' should attempt a server call.
 * @returns {"no-ci"|"missing-permission"|"ci-ready"}
 */
export function classifyEnv(env) {
  if (!env.GITHUB_ACTIONS) return "no-ci";
  if (!env.ACTIONS_ID_TOKEN_REQUEST_URL || !env.ACTIONS_ID_TOKEN_REQUEST_TOKEN) return "missing-permission";
  return "ci-ready";
}

/**
 * Server-response schema guard. v.reliable / v.hardLeaks / v.gateEntitled arrive from the network and drive the
 * exit code — a malformed verdict must be distinguished from a failed call (else `conformancePct` as a string throws
 * inside toFixed and is mis-reported as "call failed"). Returns true only for a well-formed verdict.
 */
export function validVerdict(v) {
  if (!v || typeof v !== "object") return false;
  if (typeof v.pattern !== "string") return false;
  if (typeof v.hardLeaks !== "number" || !Number.isFinite(v.hardLeaks)) return false;
  if (typeof v.reliable !== "boolean") return false;
  if (typeof v.gateEntitled !== "boolean") return false;
  if (v.conformancePct != null && !Number.isFinite(v.conformancePct)) return false; // rejects NaN (renders "NaN%")
  if (v.leaks != null && !Array.isArray(v.leaks)) return false;
  return true;
}

/**
 * Human labels for the detector packs the server can return. The verdict carries one object per pack, keyed by the
 * server's pack id; a key missing here still renders (see packLabel) — the label map is cosmetic, the ITERATION is
 * data-driven (collectPackBlocks). Release-audit 2026-09-13 : the previous client iterated a hardcoded list of six
 * legacy keys and silently dropped 9 of the 10 free-tier classes (sqli/cmdi/xss/ssrf/xxe/deser/pathTraversal/
 * crypto/cors) from the log, the PR feed and the SARIF — a paying repo was blocked without being shown where.
 */
export const PACK_LABELS = Object.freeze({
  accessControl: "access control", dbSafety: "db safety", supplyChain: "supply chain", secrets: "hardcoded secrets",
  container: "container", cicd: "ci/cd", transport: "transport security",
  sqli: "SQL injection", goSqli: "SQL injection (Go)", dotnetSqli: "SQL injection (.NET)",
  cmdi: "command injection", goCmdi: "command injection (Go)", dotnetCmdi: "command injection (.NET)",
  xss: "cross-site scripting", goXss: "cross-site scripting (Go)", dotnetXss: "cross-site scripting (.NET)",
  ssrf: "server-side request forgery", goSsrf: "server-side request forgery (Go)", dotnetSsrf: "server-side request forgery (.NET)",
  pathTraversal: "path traversal", goPathTraversal: "path traversal (Go)", dotnetPathTraversal: "path traversal (.NET)",
  cors: "CORS reflected origin", goCors: "CORS reflected origin (Go)", dotnetCors: "CORS reflected origin (.NET)",
  xxe: "XML external entity", insecureDeser: "insecure deserialization", weakCrypto: "weak crypto",
});

/** Label for a pack key — the map above, else the camelCase key split into words (never throws, never empty). */
export function packLabel(key) {
  const k = String(key ?? "");
  return PACK_LABELS[k] ?? (k.replace(/([A-Z])/g, " $1").trim().toLowerCase() || "finding");
}

/**
 * Every detector-pack block in a server verdict — data-driven, so a pack the server adds tomorrow renders today.
 * A pack block is an object carrying a numeric `count` (+ optional findings[] / hidden / blocking). Scalars, arrays
 * and the tenant-verdict fields are skipped. Only blocks with count > 0 are returned (nothing to show otherwise).
 * @returns {Array<{ key: string, label: string, block: { count: number, findings?: any[], hidden?: number } }>}
 */
export function collectPackBlocks(v) {
  const out = [];
  if (!v || typeof v !== "object") return out;
  for (const [key, block] of Object.entries(v)) {
    if (!block || typeof block !== "object" || Array.isArray(block)) continue;
    if (typeof block.count !== "number" || !Number.isFinite(block.count) || block.count <= 0) continue;
    out.push({ key, label: packLabel(key), block });
  }
  return out;
}

/**
 * Sanitize a server-controlled string before writing it to the CI log: strip ANSI/control characters (log spoofing,
 * fake `::error::` workflow-command injection) and cap the length. The server is ours, but a log sink must never
 * trust its input — defense in depth.
 */
export function sanitizeLogLine(s, max = 240) {
  const str = String(s);
  // strip C0 (incl. ESC/CR/LF) + C1 control ranges — the chars ANSI escapes and `::workflow::` spoofs ride on.
  const stripped = str.replace(/[\u0000-\u001f\u007f-\u009f]/g, " ");
  return stripped.length > max ? stripped.slice(0, Math.max(0, max - 3)) + "..." : stripped;
}

/**
 * The EXACT wire payload, built by whitelisting known fields — applied at the POST boundary (not only inside
 * buildFingerprint) so what leaves the runner is provable and cannot grow a source-bearing field by accident.
 * This is the whole contract: structural signals + names + abstract query shapes. Never file contents.
 */
// Coerce to a bounded identifier string — the boundary must not trust the shape of names/paths coming from the
// extractor, so a future extractor bug can never let a source-bearing value ride through tableCols/rls untouched.
const ident = (x) => String(x).slice(0, 200);

export function sanitizeFingerprint(fp) {
  const s = fp?.signals ?? {};
  const q = Array.isArray(fp?.queries) ? fp.queries : [];
  // Rebuild tableCols: coerce every key and every column value to a bounded string (never pass the subtree through).
  const rawCols = fp?.tableCols && typeof fp.tableCols === "object" ? fp.tableCols : {};
  const tableCols = {};
  for (const [k, v] of Object.entries(rawCols)) tableCols[ident(k)] = (Array.isArray(v) ? v : []).map(ident);
  return {
    signals: {
      schemaPath: Number(s.schemaPath) || 0,
      rlsPolicy: Number(s.rlsPolicy) || 0,
      rlsSupabase: Number(s.rlsSupabase) || 0,
    },
    tableCols,
    rls: {
      on: (Array.isArray(fp?.rls?.on) ? fp.rls.on : []).map(ident),
      policy: (Array.isArray(fp?.rls?.policy) ? fp.rls.policy : []).map(ident),
    },
    queries: q.map((x) => ({
      kind: x.kind, table: x.table, verb: x.verb, method: x.method,
      whereIdCols: Array.isArray(x.whereIdCols) ? x.whereIdCols : [],
      hasIdConstraint: !!x.hasIdConstraint, isBulk: !!x.isBulk, isAdmin: !!x.isAdmin,
      spState: x.spState, file: x.file, line: x.line,
    })),
  };
}

/**
 * The pack-fingerprint egress boundary — the twin of sanitizeFingerprint for the 22 detector packs. Each extractor
 * already emits only {file} + hits of {line, kind} (+ the scalar tags entropy/placeholder/high/secCtx/srcCtx), never
 * source. But that guarantee lived in each extractor; this rebuilds every pack by WHITELIST at the POST boundary, so
 * a future extractor bug can never grow a source-bearing hit field that rides to the server untouched. Any key not in
 * the allowlist is dropped; identifiers are bounded; scalars are coerced. Same posture as sanitizeFingerprint: what
 * leaves the runner is provable, not merely trusted.
 */
const packHit = (h) => {
  const o = { line: Number(h?.line) || 0, kind: ident(h?.kind) };
  if (h?.entropy != null) o.entropy = Number(h.entropy) || 0;      // secrets: Shannon bits/char (a scalar, not a value)
  if (h?.placeholder != null) o.placeholder = !!h.placeholder;
  if (h?.high != null) o.high = !!h.high;                          // deser/crypto: severity + context booleans
  if (h?.secCtx != null) o.secCtx = !!h.secCtx;
  if (h?.srcCtx != null) o.srcCtx = !!h.srcCtx;
  return o;
};
export function sanitizePackFingerprints(packs) {
  const clean = {};
  for (const [name, pack] of Object.entries(packs && typeof packs === "object" ? packs : {})) {
    const files = Array.isArray(pack?.files) ? pack.files : [];
    clean[ident(name)] = { files: files.map((f) => ({ file: ident(f?.file), hits: (Array.isArray(f?.hits) ? f.hits : []).map(packHit) })) };
  }
  return clean;
}

/**
 * PRO extractors (paid repos, client ≥ 0.7.0). The hosted product judges ~120 detector packs, this client extracts 22.
 * A repo that proves (OIDC) it is paid-entitled receives the closed-source extractors for the other ~100 packs from
 * /api/ci/pro-extractors and runs them HERE, in the runner — the source still never leaves, only fingerprints do.
 * Three pure pieces, all tested :
 *   · validProBundleResponse — the server response is bounded and integrity-checked (sha256) before one byte is
 *     evaluated ; a mismatch, an oversize or a malformed manifest means « no pro pass », never a half-trusted module.
 *   · runProPacks — drives PRO_PACKS over the walked files (mode file / sql / manifest) ; a throwing extractor is
 *     counted, never fatal.
 *   · sanitizeProFingerprints — the egress boundary for shapes this client cannot know in advance : a recursive,
 *     bounded scrub that keeps numbers, booleans and short strings under identifier-like keys, DROPS every key that
 *     could name source (text/snippet/content/raw/value/secret/…), caps depth, array length and string length. Same
 *     posture as sanitizePackFingerprints : what leaves is provable, `--print-payload` shows exactly it.
 */
export function validProBundleResponse(j, sha256Of) {
  if (!j || typeof j !== "object" || j.ok !== true) return { ok: false, reason: "not an ok response" };
  if (typeof j.bundle !== "string" || j.bundle.length === 0) return { ok: false, reason: "empty bundle" };
  if (Buffer.byteLength(j.bundle, "utf8") > MAX_PRO_BUNDLE_BYTES) return { ok: false, reason: "bundle too large" };
  if (typeof j.sha256 !== "string" || !/^[0-9a-f]{64}$/.test(j.sha256)) return { ok: false, reason: "missing hash" };
  if (typeof sha256Of === "function" && sha256Of(j.bundle) !== j.sha256) return { ok: false, reason: "hash mismatch" };
  if (!Array.isArray(j.packs) || j.packs.length === 0 || !j.packs.every((p) => typeof p === "string" && /^[a-zA-Z0-9]{1,64}$/.test(p))) return { ok: false, reason: "bad pack list" };
  if (typeof j.version !== "string" || j.version.length === 0 || j.version.length > 64) return { ok: false, reason: "missing version" };
  return { ok: true };
}

/**
 * Run the pro packs over `files` (absolute paths ; `rel` maps to the repo-relative posix path the server sees).
 * mode "file" : per matching file, keep a result that carries at least one non-empty list ; mode "manifest" : per
 * matching dependency manifest, merge `deps` ; mode "sql" : once, over every *.sql concatenated (whole-schema shape).
 * @returns {{ wire: Record<string, object>, errors: number, ran: number }}
 */
const PRO_SKIP_FILE = /(^|\/)(package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml|Cargo\.lock|poetry\.lock|Pipfile\.lock|composer\.lock|Gemfile\.lock|go\.sum|flake\.lock)$/i;
export function runProPacks(packs, files, { read, rel }) {
  const wire = {};
  let errors = 0, ran = 0, sqlAll = "";
  const list = Array.isArray(packs) ? packs.filter((p) => p && typeof p.fpField === "string" && typeof p.run === "function") : [];
  const sqlPacks = list.filter((p) => p.mode === "sql");
  const filePacks = list.filter((p) => p.mode !== "sql" && p.match instanceof RegExp);
  for (const f of files) {
    const r = rel(f);
    if (PRO_SKIP_FILE.test(r)) continue; // lockfiles / generated manifests : never product code, often huge
    let t; try { t = read(f); } catch { continue; }
    if (typeof t !== "string" || t.length > MAX_PRO_FILE_CHARS) continue;
    if (sqlPacks.length && /\.sql$/i.test(r)) sqlAll += t + "\n";
    for (const p of filePacks) {
      if (!p.match.test(r)) continue;
      let o; try { o = p.run(t, r); ran++; } catch { errors++; continue; }
      if (!o || typeof o !== "object") continue;
      if (p.mode === "manifest") {
        const deps = Array.isArray(o.deps) ? o.deps : [];
        if (deps.length) (wire[p.fpField] ??= { deps: [] }).deps.push(...deps);
        continue;
      }
      const carries = Object.entries(o).some(([k, v]) => k !== "file" && Array.isArray(v) && v.length > 0);
      if (carries) (wire[p.fpField] ??= { files: [] }).files.push({ ...o, file: r });
    }
  }
  for (const p of sqlPacks) {
    if (!sqlAll) continue;
    try { const o = p.run(sqlAll); ran++; if (o && typeof o === "object") wire[p.fpField] = o; } catch { errors++; }
  }
  return { wire, errors, ran };
}

const PRO_DENY_KEY = /^(text|source|src|snippet|snippets|content|contents|code|raw|body|value|values|secret|secrets|token|password|match|matched|matches|line_?text|excerpt|sql|query|statement)$/i;
const PRO_IDENT_KEY = /^[A-Za-z_$][\w.\-$]{0,127}$/;
export function sanitizeProFingerprints(packs, { maxDepth = 6, maxItems = 200000, maxString = 200 } = {}) {
  const scrub = (v, depth) => {
    if (typeof v === "number") return Number.isFinite(v) ? v : undefined;
    if (typeof v === "boolean") return v;
    if (typeof v === "string") return v.slice(0, maxString);
    if (v == null || depth >= maxDepth) return undefined;
    if (Array.isArray(v)) {
      const out = [];
      for (const x of v.slice(0, maxItems)) { const s = scrub(x, depth + 1); if (s !== undefined) out.push(s); }
      return out;
    }
    if (typeof v === "object") {
      const out = {};
      for (const [k, x] of Object.entries(v)) {
        if (!PRO_IDENT_KEY.test(k) || PRO_DENY_KEY.test(k)) continue;
        const s = scrub(x, depth + 1);
        if (s !== undefined) out[k] = s;
      }
      return out;
    }
    return undefined; // functions, symbols, bigints — never on the wire
  };
  const clean = {};
  for (const [name, pack] of Object.entries(packs && typeof packs === "object" ? packs : {})) {
    if (!/^[a-zA-Z0-9]{1,64}$/.test(name)) continue;
    const s = scrub(pack, 0);
    if (s && typeof s === "object" && !Array.isArray(s)) clean[name] = s;
  }
  return clean;
}

/** Parse a verdict leak line ("path:line  [table]  reason") into {file, line, message}; {file:null} if unparseable. */
export function parseLeak(s) {
  const m = /^(.+?):(\d+)\s+(.*)$/.exec(String(s).trim());
  if (!m) return { file: null, line: 0, message: sanitizeLogLine(String(s)) };
  return { file: m[1], line: Number(m[2]), message: sanitizeLogLine(m[3] || "cross-tenant isolation leak") };
}

/** SARIF level for a detector severity: critical/high → error, medium → warning, anything else → note. */
export function sarifLevel(severity) {
  const s = String(severity ?? "").toLowerCase();
  if (s === "critical" || s === "high") return "error";
  if (s === "medium") return "warning";
  return "note";
}

/**
 * Build a SARIF 2.1.0 report so findings land in the PR "Files changed" diff and the code-scanning tab (upload with
 * github/codeql-action/upload-sarif). Two sources: the cross-tenant `leaks` (strings "path:line  reason") and the
 * detector-pack `findings` (the normalized feed rows {file, line, pack, rule, detail, severity}) — one SARIF rule per
 * pack key, so every free-tier class is visible in code scanning, not only the cross-tenant rule. Only entries with
 * a parseable path become results; an unmappable path is skipped (a wrong-path annotation is worse than none).
 */
export function buildSarif(leaks, { version = CLIENT_VERSION, findings = [] } = {}) {
  const results = (Array.isArray(leaks) ? leaks : [])
    .map(parseLeak)
    .filter((l) => l.file)
    .map((l) => ({
      ruleId: "cross-tenant-isolation-leak",
      level: "error",
      message: { text: l.message },
      locations: [{ physicalLocation: { artifactLocation: { uri: l.file }, region: { startLine: Math.max(1, l.line) } } }],
    }));
  const rules = [{
    id: "cross-tenant-isolation-leak",
    name: "CrossTenantIsolationLeak",
    shortDescription: { text: "Unscoped read/write on a tenant-scoped table (cross-tenant data exposure)." },
  }];
  const seenPacks = new Set();
  for (const f of Array.isArray(findings) ? findings : []) {
    if (!f || typeof f.file !== "string" || !f.file) continue;
    const pack = ident(f.pack || f.rule || "finding");
    if (!seenPacks.has(pack)) {
      seenPacks.add(pack);
      rules.push({
        id: pack,
        name: pack.replace(/(^|[^a-zA-Z0-9])([a-z])/g, (_, __, c) => c.toUpperCase()).replace(/[^a-zA-Z0-9]/g, "") || "Finding",
        shortDescription: { text: `${packLabel(pack)} — slopGrade Firewall detector pack.` },
      });
    }
    results.push({
      ruleId: pack,
      level: sarifLevel(f.severity),
      message: { text: sanitizeLogLine(f.detail || `${packLabel(pack)} finding`) },
      locations: [{ physicalLocation: { artifactLocation: { uri: f.file }, region: { startLine: Math.max(1, Number(f.line) || 1) } } }],
    });
  }
  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [{
      tool: { driver: {
        name: "slopGrade Firewall",
        informationUri: "https://www.slopgrade.ai",
        version,
        rules,
      } },
      results,
    }],
  };
}

/** Uniform error-to-message (dedup of the `e instanceof Error ? e.message : String(e)` pattern). */
export const errMsg = (e) => (e instanceof Error ? e.message : String(e));

// ── GitHub Step Summary — the RENDERED report on the run page (unlike the PR review, it also shows on push runs). ──
/** Blob base for a clickable line link: `${server}/${owner}/repo/blob/${sha}`. null when repo/sha are missing
 *  (off CI) → locations stay plain code, never a broken link. Pure. */
export function githubBlobBase(env, sha) {
  const repo = env && env.GITHUB_REPOSITORY;
  const server = (env && env.GITHUB_SERVER_URL) || "https://github.com";
  return repo && sha ? `${server}/${repo}/blob/${sha}` : null;
}

/** A `file:line` as a clickable GitHub link when blobBase is set, else plain inline code. Pure. */
function fileLink(blobBase, file, lineNo) {
  if (!file) return "";
  const n = Math.max(1, Number(lineNo) || 1);
  const disp = `${file}:${n}`;
  return blobBase ? `[\`${disp}\`](${blobBase}/${file}#L${n})` : `\`${disp}\``;
}

/**
 * The GitHub Step Summary markdown for a firewall verdict `v` — a scannable, clickable report on the run page:
 * verdict banner + pattern/conformance + cross-tenant leaks (clickable file:line) + per-pack finding counts
 * (data-driven via collectPackBlocks, so a pack the server adds tomorrow renders today) + the "see all / enable"
 * CTA. Pure. `decision` is the firewallVerdict kind (gate-blocked | gate-unpaid | pass).
 */
export function stepSummaryMarkdown(v, { origin = DEFAULT_ORIGIN, blobBase = null, decision = "pass" } = {}) {
  const hard = Number(v && v.hardLeaks) || 0;
  const packBlocking = Number(v && v.packBlocking) || 0;
  const head = "## 🛡️ slopGrade Firewall — tenant isolation";
  const verdict = decision === "gate-blocked"
    ? `### ❌ Blocked — ${hard} hard cross-tenant leak${hard === 1 ? "" : "s"}${packBlocking > 0 ? ` · ${packBlocking} blocking finding${packBlocking === 1 ? "" : "s"}` : ""}`
    : decision === "gate-unpaid"
      ? `### ⚠️ Advisory — ${hard} hard leak${hard === 1 ? "" : "s"} found, not blocking on the free tier`
      : hard > 0
        ? `### ⚠️ Advisory — ${hard} leak${hard === 1 ? "" : "s"} (this pattern can't be gated reliably)`
        : "### ✅ Clean — no blocking cross-tenant leaks";
  const facts = `- **Pattern** \`${(v && v.pattern) || "n/a"}\`${v && v.tenantKey ? ` · **Tenant key** \`${v.tenantKey}\`` : ""}\n`
    + `- **Conformance** ${v && v.conformancePct == null ? "n/a" : Number(v.conformancePct).toFixed(1) + "%"}`
    + (Number(v && v.byId) > 0 ? `\n- **+${v.byId}** conditional by-id access${Number(v.byId) === 1 ? "" : "es"} (review)` : "");
  const leaks = (Array.isArray(v && v.leaks) ? v.leaks : []).slice(0, 20).map(parseLeak).filter((p) => p.file);
  const leakTable = leaks.length
    ? "\n\n| Cross-tenant leak |\n|:--|\n" + leaks.map((p) => `| ${fileLink(blobBase, p.file, p.line)} |`).join("\n")
      + (((v && Array.isArray(v.leaks) ? v.leaks.length : 0) > 20) ? `\n| _…and ${v.leaks.length - 20} more_ |` : "")
    : "";
  const packLines = collectPackBlocks(v)
    .map(({ label, block }) => `- **${label}** — ${block.count} finding${Number(block.count) === 1 ? "" : "s"}${Number(block.hidden) > 0 ? ` (+${block.hidden} hidden)` : ""}`);
  const packs = packLines.length ? "\n\n" + packLines.join("\n") : "";
  const cta = decision === "gate-unpaid"
    ? `\n\n> **[Enable the gate on this repo →](${origin}/ci)** to block these before they merge.`
    : `\n\n<sub><a href="${origin}/ci">See all findings · manage the gate</a></sub>`;
  return `${head}\n\n${verdict}\n\n${facts}${leakTable}${packs}${cta}\n`;
}

/** Append markdown to the GitHub Step Summary file. No-op off CI (var absent) ; fail-soft (never breaks the gate).
 *  `writeImpl` (fs.appendFileSync) is injected for testability. */
export function emitStepSummary(env, markdown, writeImpl) {
  const path = env && env.GITHUB_STEP_SUMMARY;
  if (!path || !markdown) return false;
  try { writeImpl(path, markdown.endsWith("\n") ? markdown : markdown + "\n"); return true; }
  catch { return false; }
}
