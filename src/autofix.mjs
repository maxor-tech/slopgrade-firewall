// One-click fixes (0.10.1) — a GitHub « Commit suggestion » on the PR line, for the findings that have a deterministic,
// line-local secure rewrite (a secure-default flip or a drop-in safe call). Computed HERE, in the runner, from the file
// the runner already has : nothing leaves, slopGrade's server never sees the code nor the fix.
//
// VERIFIED, not guessed : a fix is kept only if (1) the finding's OWN detector regex (the same one the extractor uses)
// no longer matches the rewritten line, (2) the line actually changed, and (3) the change is a short single span — so a
// suggestion can never rewrite more than the insecure token. Anything else → no suggestion (the finding still posts).
//
// The server's FIXABLE_KINDS (slopgrade lib/tenant-isolation/fixable.ts, the /ci « N have a verified fix » count) must
// mirror this set — pinned by src/__tests__/autofix.test.mjs.

// kind → [detector (same regex as the extractor), rewrite, human note]
const RULES = {
  "python-verify-false": [/\bverify\s*=\s*False\b/, (l) => l.replace(/\b(verify\s*=\s*)False\b/, (_, a) => `${a}True`), "verify=False → True (verify TLS certificates)"],
  "node-reject-unauthorized": [/\brejectUnauthorized\s*:\s*false\b/, (l) => l.replace(/\b(rejectUnauthorized\s*:\s*)false\b/, (_, a) => `${a}true`), "rejectUnauthorized: false → true (verify TLS certificates)"],
  "node-tls-env": [/NODE_TLS_REJECT_UNAUTHORIZED\s*[=:]\s*['"`]?0\b/, (l) => l.replace(/(NODE_TLS_REJECT_UNAUTHORIZED\s*[=:]\s*['"`]?)0\b/, (_, a) => `${a}1`), "NODE_TLS_REJECT_UNAUTHORIZED 0 → 1 (TLS verification back on)"],
  "go-insecure-skip-verify": [/\bInsecureSkipVerify\s*:\s*true\b/, (l) => l.replace(/\b(InsecureSkipVerify\s*:\s*)true\b/, (_, a) => `${a}false`), "InsecureSkipVerify: true → false (verify TLS certificates)"],
  "rust-danger-accept-invalid": [/\bdanger_accept_invalid_(?:certs|hostnames)\s*\(\s*true\s*\)/, (l) => l.replace(/\b(danger_accept_invalid_(?:certs|hostnames)\s*\(\s*)true(\s*\))/, (_, a, b) => `${a}false${b}`), "danger_accept_invalid_…(true) → (false)"],
  "aspnet-debug-compilation": [/<compilation\b[^>]*\bdebug\s*=\s*["']true["']/i, (l) => l.replace(/(<compilation\b[^>]*\bdebug\s*=\s*["'])true(["'])/i, (_, a, b) => `${a}false${b}`), "<compilation debug=\"true\"> → \"false\" (no debug build in production)"],
  "flask-run-debug": [/\.run\s*\([^)\n]*\bdebug\s*=\s*True\b/, (l) => l.replace(/(\.run\s*\([^)\n]*\bdebug\s*=\s*)True\b/, (_, a) => `${a}False`), "app.run(debug=True) → False (no interactive debugger in production)"],
  // yaml.load with an explicit Loader= is not rewritten (safe_load takes no Loader) — only the bare / unsafe_load forms.
  "py-yaml-unsafe": [/\byaml\.unsafe_load\s*\(\s*[^\s)]|\byaml\.load\s*\(\s*(?![^\n]*(?:Safe|CSafe|Base|Full)?Loader)[^\s)]/,
    (l) => (/\bLoader\s*=/.test(l) ? l : l.replace(/\byaml\.(?:unsafe_)?load\s*\(/, "yaml.safe_load(")), "yaml.load → yaml.safe_load (no arbitrary object construction)"],
};

export const FIXABLE_KINDS = new Set(Object.keys(RULES));
const MAX_SPAN = 24; // the changed region of a fixed line — a flip / a call rename, never a rewrite

/** PURE — the verified secure rewrite of `line` for `kind`, or null. */
export function fixLine(kind, line) {
  const rule = RULES[kind];
  if (!rule || typeof line !== "string" || line.length > 2000 || line.includes("\n")) return null;
  const [detect, rewrite, note] = rule;
  if (!detect.test(line)) return null;           // the finding isn't on this line as reported → never guess
  const after = rewrite(line);
  if (after === line || detect.test(after)) return null; // (1)+(2) : changed AND the detector no longer fires
  let p = 0; while (p < line.length && line[p] === after[p]) p++;
  let s = 0; while (s < line.length - p && s < after.length - p && line[line.length - 1 - s] === after[after.length - 1 - s]) s++;
  if (Math.max(line.length - p - s, after.length - p - s) > MAX_SPAN) return null; // (3) single short span
  return { after, note };
}

/**
 * Index the runner's LOCAL hits (free packs + the pro wire, both already egress-sanitized) by "file:line" → fixable kinds.
 * `packs` = { anyFingerprint: { files: [{ file, hits: [{ line, kind }] }] } }. PURE.
 */
export function fixableHitIndex(packs) {
  const idx = new Map();
  for (const pack of Object.values(packs && typeof packs === "object" ? packs : {})) {
    const files = pack && Array.isArray(pack.files) ? pack.files : [];
    for (const f of files) {
      if (!f || typeof f.file !== "string") continue;
      for (const h of Array.isArray(f.hits) ? f.hits : []) {
        if (!h || !FIXABLE_KINDS.has(h.kind) || !Number.isInteger(h.line)) continue;
        const k = `${f.file}:${h.line}`;
        idx.set(k, [...(idx.get(k) ?? []), h.kind]);
      }
    }
  }
  return idx;
}

/**
 * Attach a verified `fix` to each feed row that has one. `readLine(file, line)` returns the line's text (or null).
 * Rows keep their identity ; only `fix: { after, note }` is added. Returns the number of rows fixed. Never throws.
 */
export function attachFixes(feed, index, readLine) {
  let n = 0;
  for (const row of Array.isArray(feed) ? feed : []) {
    const kinds = row && index.get(`${row.file}:${row.line}`);
    if (!kinds) continue;
    let text = null;
    try { text = readLine(row.file, row.line); } catch { text = null; }
    if (typeof text !== "string") continue;
    for (const kind of kinds) {
      const fx = fixLine(kind, text);
      if (fx) { row.fix = fx; n++; break; }
    }
  }
  return n;
}
