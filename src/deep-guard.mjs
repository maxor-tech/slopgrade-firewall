// Deterministic Deep Scan guards (0.16.0). With `deep-scan-block` on, a NEW Deep Scan finding blocks the PR. These rules
// keep a finding as an advisory warning when its own evidence or file shows no external attacker can reach it.
//
// Provenance (measured, 2026-11-10) : an AI verifier read 404 blocking findings on the 61k replay and rejected 215 with a
// written reason. The reasons were grouped, each group was written as a rule below, and only the rules that remove 0
// true-positive-labeled findings on the frozen labels were kept. On the shipped view (purpose v3 + tooling rule) Deep
// Scan block precision went 24.0 % -> 30.9 % (held-out 23.3 % -> 31.6 %), 156 of 156 TP findings kept. The rules were
// mined from the same PRs, so these figures are exploratory until a fresh labeled sample confirms them.
// Rules that would have removed true positives were dropped : weak crypto, TLS verification off, CSRF off, insecure
// cookie, and « the sink only tests that a path exists ».
//
// PURE apart from `read(path)` (repo file text or null). Never throws : an unreadable file never clears a finding.

// Posture findings (a configuration choice, no taint flow) : cleartext gRPC, wildcard CORS, widened file permissions.
const POSTURE = new Set(["CWE-319", "CWE-942", "CWE-732"]);
// A command-line argument : the operator who runs the tool supplies it, not a remote attacker.
const CLI = /\bsys\.argv\b|\bprocess\.argv\b|\bos\.Args\b|\bARGV\b|\.parse_args\(\)|\bflag\.(?:Arg|Args|String|Parse)\b/;
// Third-party code committed into the repo.
const VENDOR = /(?:^|\/)(?:site-packages|dist-packages|\.?venv|node_modules|bower_components|vendor|third[_-]?party)\/|(?:^|\/)workbox-v?\d|(?:^|\/)_themes\/|\.min\.js$/i;
// Test files the tooling rule (deep-scan.mjs TOOLING_PATH) does not name.
const TESTISH = /(?:^|\/)tests?\.[cm]?[jt]sx?$|(?:^|\/)testapp\/|[-_]tests?\/|(?:^|\/)calibration\/|_lab\.php$/i;
// The page's own URL : origin fixed by the browser. Its query, hash or any '?' split is attacker-chosen.
const SELF_URL = /(?:document\.|window\.)?location\.href\b/;
const SELF_URL_BAD = /location\.(?:search|hash)|URLSearchParams|getParameter|\?/i;
// Browser-side code with no server marker : an outgoing request runs in the visitor's browser (no server position).
const BROWSER = /\bdocument\.|\bwindow\.|\buseEffect\(|\bself\.addEventListener\(/;
const SERVER = /require\(['"](?:express|http|koa|fastify)['"]\)|from ['"](?:express|next\/server)['"]|\bexport\s+async\s+function\s+(?:GET|POST)|\bapp\.(?:get|post)\(|\breq\.(?:query|body|params)\b/;
const SRC_AT = /read at (?:line (\d+)|([^\s:]+):(\d+))/;

// The evidence path comes from the server : read only a relative path inside the repo (no absolute path, no `..`).
const OUTSIDE = /^(?:[\\/]|[A-Za-z]:)|(?:^|[\\/])\.\.(?:[\\/]|$)/;
function safeRead(read, p) {
  if (typeof p !== "string" || !p || OUTSIDE.test(p)) return null;
  try { const t = read(p); return typeof t === "string" ? t : null; } catch { return null; }
}
function lineOf(text, n) {
  if (!text || !Number.isInteger(n) || n < 1) return "";
  const ls = text.split("\n");
  return n <= ls.length ? ls[n - 1] : "";
}
/** The source line the engine names in its evidence (« read at line N » or « read at path:N »). */
function sourceLine(row, read) {
  const m = SRC_AT.exec(String(row.detail ?? ""));
  if (!m) return "";
  if (m[1]) return lineOf(safeRead(read, row.file), Number(m[1]));
  return lineOf(safeRead(read, m[2]), Number(m[3]));
}

/**
 * Why this Deep Scan row must not block, or null when it keeps blocking.
 * `row` = { file, line, rule (CWE id), detail (engine evidence) } — the client's heisen feed row.
 */
export function deepGuard(row, read) {
  const file = String(row?.file ?? "");
  const rule = String(row?.rule ?? "");
  const detail = String(row?.detail ?? "");
  if (!file) return null;
  if (POSTURE.has(rule) && detail.startsWith("ast-pattern")) return "configuration finding";
  if (VENDOR.test(file)) return "vendored code";
  if (TESTISH.test(file)) return "test code";
  const src = sourceLine(row, read);
  if (CLI.test(src)) return "command-line input";
  if ((rule === "CWE-601" || rule === "CWE-79") && SELF_URL.test(src) && !SELF_URL_BAD.test(src)) return "same-page URL";
  if (rule === "CWE-79" && detail.includes("jQuery $()") && src.includes("location.hash")) return "jQuery selector";
  if ((rule === "CWE-918" || /outgoing HTTP request/.test(detail)) && /\.[cm]?[jt]sx?$/.test(file)) {
    const text = safeRead(read, file);
    if (text && BROWSER.test(text) && !SERVER.test(text)) return "browser-side request";
  }
  return null;
}
