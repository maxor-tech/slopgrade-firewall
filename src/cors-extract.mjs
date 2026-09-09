// CORS misconfiguration (CWE-942 — permissive cross-origin resource sharing) — LANGUAGE-AGNOSTIC client fingerprint.
// Emit {file, line, kind} — NEVER the source line. Two shapes take a credentialed cross-origin request from ANY site,
// which turns a logged-in victim's browser into a proxy for the attacker (read authenticated responses → account
// takeover):
//   1. REFLECTED ORIGIN — Access-Control-Allow-Origin set to the caller's own Origin header (res.setHeader('ACAO',
//      req.headers.origin)) / echoed via $_SERVER['HTTP_ORIGIN']. With credentials this is a full same-origin bypass.
//   2. WILDCARD/ANY + CREDENTIALS — the express `cors({ origin: '*' | true, credentials: true })` middleware object:
//      `origin:'*'`/`origin:true` accepts any site AND `credentials:true` sends cookies → credentialed wildcard.
// Precision over recall = ~0 FP: a constant ACAO ('https://app.example.com'), a validated-var origin, and a
// `cors({ origin: '*' })` WITHOUT credentials (a legitimate public API) all stay clean.

const PATTERNS = [
  // Reflected Origin — a response header ACAO whose value is pulled from the request headers (req.headers.origin /
  // req.get('Origin') / ctx.set(...req...)). A constant or a validated var never references req.headers inline.
  ["cors-reflect-origin", /\b(?:res|ctx|reply|response)\s*\.\s*(?:set(?:Header)?|header)\s*\(\s*["']Access-Control-Allow-Origin["']\s*,\s*[^)]*\breq(?:uest)?\s*\.\s*(?:headers?|get)\b/],
  // PHP — header('Access-Control-Allow-Origin: '.$_SERVER['HTTP_ORIGIN']) reflects the caller's origin.
  ["cors-php-reflect", /header\s*\(\s*["']Access-Control-Allow-Origin\s*:[^)]*\$_SERVER\s*\[\s*["']HTTP_ORIGIN/],
  // express `cors({ origin: '*' | true, credentials: true })` — any-origin AND credentials (either key order).
  ["cors-any-credentials", /\bcors\s*\(\s*\{[^}]*\borigin\s*:\s*(?:["']\*["']|\btrue\b)[^}]*\bcredentials\s*:\s*true\b|\bcors\s*\(\s*\{[^}]*\bcredentials\s*:\s*true\b[^}]*\borigin\s*:\s*(?:["']\*["']|\btrue\b)/],
];

const isComment = (l) => /^\s*(\/\/|\*|#|--|;|<!--)/.test(l);

/** Scan one file → [{line, kind}]. Source line NEVER leaves this function. */
export function extractCors(text) {
  const out = [];
  const lines = String(text).split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const l = lines[i];
    if (l.length > 4000) continue;   // minified blob — noise
    if (isComment(l)) continue;      // a header named in a comment is documentation, not live code
    for (const [kind, re] of PATTERNS) {
      if (re.test(l)) out.push({ line: i + 1, kind });
    }
  }
  return out;
}

/** The CORS-misconfig fingerprint for one file — locations + kinds, no source. */
export function extractCorsFingerprint(text, file) {
  return { file, hits: extractCors(text) };
}
