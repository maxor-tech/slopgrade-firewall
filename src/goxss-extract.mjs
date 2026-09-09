// Go reflected XSS (CWE-79) — a net/http request accessor written UNESCAPED into an HTML response —
// SERVER fingerprint. Emit {file, line, kind} — never source. Go-specific: writing to the http.ResponseWriter
// (fmt.Fprintf/Fprint/Fprintln(w, …), w.Write([]byte(…)), io.WriteString(w, …)) with HTML markup ("<") on the
// line AND a request accessor (r.FormValue / r.PostFormValue / r.URL.Query().Get / r.Header.Get) → the attacker's
// markup runs in the victim's session (session theft, account takeover). Go's html/template auto-escapes, so the
// vuln is exactly this raw-write path; the same-line escaper (template.HTMLEscapeString / html.EscapeString) is
// excluded → ~0 FP. A no-markup body (no "<") never fires. EXTENDS XSS to Go — DISTINCT from xss #25
// (php/rails/django/react/DOM, no Go) and goOpenRedirect #83 (http.Redirect target, not an HTML body write).

const PATTERNS = [
  // A ResponseWriter write sink with HTML markup ("<") and a net/http request accessor on the same line. The write
  // sink comes first, then "<" (the markup), then the request accessor (their natural left-to-right order).
  ["go-xss", /\b(?:fmt\s*\.\s*Fprint(?:f|ln)?\s*\(\s*w\b|w\s*\.\s*Write\s*\(|io\s*\.\s*WriteString\s*\(\s*w\b).*<.*\b(?:r|req|request)\s*\.\s*(?:FormValue|PostFormValue|URL\s*\.\s*Query|Header\s*\.\s*Get)\b/],
];
const isComment = (l) => /^\s*(\/\/|\*|#|--|<!--|;)/.test(l);
// html/template auto-escapes, and template.HTMLEscapeString / html.EscapeString neutralise the value inline — a
// request value wrapped in either can't inject markup, so exclude the line (parity with xss #25 excluding escapeHtml).
const isSanitized = (l) => /\b(?:template\s*\.\s*HTMLEscape(?:String)?|html\s*\.\s*EscapeString)\s*\(/.test(l);

/** Scan one file → [{line, kind}]. */
export function extractGoXss(text) {
  const out = [];
  const lines = String(text).split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const l = lines[i];
    if (l.length > 4000) continue;
    if (isComment(l)) continue;
    if (isSanitized(l)) continue;
    for (const [kind, re] of PATTERNS) {
      if (re.test(l)) { out.push({ line: i + 1, kind }); break; }
    }
  }
  return out;
}

/** The Go-XSS fingerprint for one file. */
export function extractGoXssFingerprint(text, file) {
  return { file, hits: extractGoXss(text) };
}
