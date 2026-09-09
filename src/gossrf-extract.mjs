// Go SSRF (CWE-918) — a request value is the URL of an outbound HTTP call by the Go `net/http` package — SERVER
// fingerprint. Emit {file, line, kind} — never source. Go-specific: http.Get / http.Post / http.Head / http.PostForm
// and http.NewRequest(WithContext) fetch a URL; when that URL is derived from a net/http request accessor (r.FormValue
// / r.PostFormValue / r.URL / r.Header), the server fetches an attacker-chosen endpoint → cloud metadata
// (169.254.169.254), localhost admin APIs, internal services. Scoped to the stdlib `http.` package functions (never an
// ambiguous client.Get that could be redis) with a request accessor INLINE → ~0 FP. A constant/host-derived URL never
// fires. DISTINCT from ssrf #26 (Python/Node/PHP/Java/Ruby sinks — no Go).

const PATTERNS = [
  // http.Get/Post/Head/PostForm/NewRequest(WithContext) whose argument region carries a net/http request accessor —
  // the request value IS the outbound URL. `[^)]*` keeps the match on the same call.
  ["go-http-request", /\bhttp\s*\.\s*(?:Get|Post|Head|PostForm|NewRequest(?:WithContext)?)\s*\([^)]*\b(?:r|req|request)\s*\.\s*(?:FormValue|PostFormValue|URL|Header)\b/],
];
const isComment = (l) => /^\s*(\/\/|\*|#|--|<!--|;)/.test(l);

/** Scan one file → [{line, kind}]. */
export function extractGoSsrf(text) {
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

/** The Go-SSRF fingerprint for one file. */
export function extractGoSsrfFingerprint(text, file) {
  return { file, hits: extractGoSsrf(text) };
}
