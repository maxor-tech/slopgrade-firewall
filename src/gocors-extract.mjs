// Go CORS misconfiguration (CWE-942 — permissive cross-origin resource sharing) — SERVER fingerprint. Emit
// {file, line, kind} — never source. Go-specific: a net/http handler that sets the Access-Control-Allow-Origin
// response header to the CALLER's own Origin request header (r.Header.Get("Origin")) reflects any site back as an
// allowed origin; combined with credentials this turns a logged-in victim's browser into a proxy for the attacker
// (read authenticated responses → account takeover). DISCRIMINATOR (mirror of cors #36 "reflected origin"): the ACAO
// header WRITE must pull its value from the request Origin header INLINE on the same line — a constant ACAO
// ("*", "https://app.example.com") or a validated-var origin never references r.Header inline, so neither fires.
// EXTENDS CORS misconfig to Go — DISTINCT from cors #36 (JS res.setHeader / express cors({}) / PHP $_SERVER). HIGH.

// The reflected Origin request accessor — net/http Request.Header.Get("Origin") or the map-index form.
const REQ_ORIGIN = "\\br(?:eq)?\\s*\\.\\s*Header\\s*\\.\\s*Get\\s*\\(\\s*[\"'`]Origin|\\br(?:eq)?\\s*\\.\\s*Header\\s*\\[\\s*[\"'`]Origin";
// The Access-Control-Allow-Origin header literal (Go double-quote or raw-string backtick).
const ACAO = "[\"'`]Access-Control-Allow-Origin[\"'`]";

const PATTERNS = [
  // A response-header write of ACAO — w.Header().Set/Add("Access-Control-Allow-Origin", …) OR the map-assign form
  // w.Header()["Access-Control-Allow-Origin"] = … — whose value references the request Origin header on the line.
  ["go-cors-reflect", new RegExp(
    `(?:\\.\\s*Header\\s*\\(\\s*\\)\\s*\\.\\s*(?:Set|Add)\\s*\\(\\s*${ACAO}\\s*,|\\.\\s*Header\\s*\\(\\s*\\)\\s*\\[\\s*${ACAO}\\s*\\]\\s*=)\\s*[^\\n]*(?:${REQ_ORIGIN})`)],
];
const isComment = (l) => /^\s*(\/\/|\*|#|--|<!--|;)/.test(l);

/** Scan one file → [{line, kind}]. */
export function extractGoCors(text) {
  const out = [];
  const lines = String(text).split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const l = lines[i];
    if (l.length > 4000) continue;
    if (isComment(l)) continue;
    for (const [kind, re] of PATTERNS) {
      if (re.test(l)) { out.push({ line: i + 1, kind }); break; }
    }
  }
  return out;
}

/** The Go-CORS-misconfig fingerprint for one file. */
export function extractGoCorsFingerprint(text, file) {
  return { file, hits: extractGoCors(text) };
}
