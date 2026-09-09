// .NET reflected XSS (CWE-79) — an ASP.NET request accessor written UNESCAPED to the response —
// SERVER fingerprint. Emit {file, line, kind} — never source. .NET-specific: Response.Write / Response.Output.Write
// (Web Forms / classic) and Response.WriteAsync (Core) emit directly into the response body, which defaults to
// text/html; when the argument is a request accessor (Request[...] / Request.QueryString / Request.Form /
// Request.Query / Request.Params / Request.Headers), the attacker's markup runs in the victim's session (session
// theft, account takeover). Scoped to the Write sink with a request accessor INLINE → ~0 FP; the same-line HTML
// encoder (Server.HtmlEncode / HttpUtility.HtmlEncode / WebUtility.HtmlEncode / HtmlEncoder…Encode) is excluded, and
// a constant/non-request write never fires. EXTENDS XSS to .NET — DISTINCT from xss #25 (no .NET), goXss #85 (Go) and
// dotnetOpenRedirect #84 (Response.Redirect target, not an HTML body write).

const PATTERNS = [
  // A .NET response-write sink whose argument region carries an ASP.NET request accessor (property or indexer). `[^)]*`
  // keeps the match on the same call; Response.Write / Response.Output.Write / Response.WriteAsync are the sinks.
  ["dotnet-xss", /Response\s*\.\s*(?:Output\s*\.\s*)?Write(?:Async)?\s*\([^)]*\bRequest\s*(?:\.\s*(?:QueryString|Form|Params|Query|Headers)\b|\[)/],
];
const isComment = (l) => /^\s*(\/\/|\*|#|--|<!--|;)/.test(l);
// An HTML encoder neutralises the value inline — a request value wrapped in one can't inject markup, so exclude the
// line (parity with xss #25 excluding htmlspecialchars / escapeHtml).
const isSanitized = (l) => /\b(?:Server\s*\.\s*HtmlEncode|HttpUtility\s*\.\s*HtmlEncode|WebUtility\s*\.\s*HtmlEncode|HtmlEncoder[\w.]*\.\s*Encode)\s*\(/.test(l);

/** Scan one file → [{line, kind}]. */
export function extractDotnetXss(text) {
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

/** The .NET-XSS fingerprint for one file. */
export function extractDotnetXssFingerprint(text, file) {
  return { file, hits: extractDotnetXss(text) };
}
