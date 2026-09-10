// PURE, testable client helpers — the security- and correctness-critical logic, isolated from I/O so it can be
// unit-tested (the CLI in isolation-gate.mjs is a thin adapter around these + the network). Zero dependencies.

export const DEFAULT_ORIGIN = "https://app.slopgrade.ai";
export const CLIENT_VERSION = "0.6.0";
export const FINGERPRINT_VERSION = 1;
export const MAX_PAYLOAD_BYTES = 8 * 1024 * 1024; // 8MB hard cap on the POST body (clear error, not an opaque 413)

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

/** Parse a verdict leak line ("path:line  [table]  reason") into {file, line, message}; {file:null} if unparseable. */
export function parseLeak(s) {
  const m = /^(.+?):(\d+)\s+(.*)$/.exec(String(s).trim());
  if (!m) return { file: null, line: 0, message: sanitizeLogLine(String(s)) };
  return { file: m[1], line: Number(m[2]), message: sanitizeLogLine(m[3] || "cross-tenant isolation leak") };
}

/**
 * Build a SARIF 2.1.0 report from the verdict's leaks so findings land in the PR "Files changed" diff and the
 * code-scanning tab (upload with github/codeql-action/upload-sarif). Only leaks with a parseable path:line become
 * results; a leak with an unmappable path is skipped (a wrong-path annotation is worse than none).
 */
export function buildSarif(leaks, { version = CLIENT_VERSION } = {}) {
  const results = (Array.isArray(leaks) ? leaks : [])
    .map(parseLeak)
    .filter((l) => l.file)
    .map((l) => ({
      ruleId: "cross-tenant-isolation-leak",
      level: "error",
      message: { text: l.message },
      locations: [{ physicalLocation: { artifactLocation: { uri: l.file }, region: { startLine: Math.max(1, l.line) } } }],
    }));
  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [{
      tool: { driver: {
        name: "slopGrade Firewall",
        informationUri: "https://www.slopgrade.ai",
        version,
        rules: [{
          id: "cross-tenant-isolation-leak",
          name: "CrossTenantIsolationLeak",
          shortDescription: { text: "Unscoped read/write on a tenant-scoped table (cross-tenant data exposure)." },
        }],
      } },
      results,
    }],
  };
}

/** Uniform error-to-message (dedup of the `e instanceof Error ? e.message : String(e)` pattern). */
export const errMsg = (e) => (e instanceof Error ? e.message : String(e));
