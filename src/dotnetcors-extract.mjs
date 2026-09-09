// .NET CORS misconfiguration (CWE-942 — permissive cross-origin resource sharing) — SERVER fingerprint. Emit
// {file, line, kind} — never source. Two ASP.NET shapes take a credentialed cross-origin request from ANY site
// (logged-in victim's browser → attacker proxy → account takeover):
//   1. REFLECTED ORIGIN — a Response header write of Access-Control-Allow-Origin whose value is the caller's own
//      Request.Headers["Origin"] (Response.Headers.Add / indexer / AppendHeader).
//   2. POLICY BYPASS — an ASP.NET Core CORS policy that allows EVERY origin via SetIsOriginAllowed(_ => true) AND
//      sends credentials via .AllowCredentials() on the same fluent chain (AllowAnyOrigin().AllowCredentials()
//      throws at runtime, so `_ => true` is the real shipped bypass).
// DISCRIMINATOR (mirror of cors #36): a constant ACAO ("*", "https://app.example.com"), a validated-var origin, and
// SetIsOriginAllowed(o => allowed.Contains(o)) (a real check, body ≠ `true`) all stay clean. EXTENDS CORS misconfig
// to .NET — DISTINCT from cors #36 (JS/PHP). HIGH (credentialed cross-origin → account takeover).

const ACAO = "[\"']Access-Control-Allow-Origin[\"']";
// The reflected Origin request accessor — ASP.NET Request.Headers["Origin"] or the typed Request.Headers.Origin.
const REQ_ORIGIN = "Request\\s*\\.\\s*Headers\\s*\\[\\s*[\"']Origin|Request\\s*\\.\\s*Headers\\s*\\.\\s*Origin\\b";

const PATTERNS = [
  // A Response-header WRITE of ACAO (Add / indexer / AppendHeader) whose value references the request Origin header.
  ["dotnet-cors-reflect", new RegExp(
    `(?:Response\\s*\\.\\s*Headers\\s*(?:\\.\\s*(?:Add|Append)\\s*\\(\\s*|\\[\\s*)${ACAO}|Response\\s*\\.\\s*AppendHeader\\s*\\(\\s*${ACAO})[^\\n]*(?:${REQ_ORIGIN})`)],
  // An ASP.NET Core CORS policy allowing every origin (SetIsOriginAllowed(x => true)) WITH credentials.
  ["dotnet-cors-policy", new RegExp(
    `SetIsOriginAllowed\\s*\\(\\s*[A-Za-z_]\\w*\\s*=>\\s*true\\s*\\)[^\\n]*AllowCredentials`)],
];
const isComment = (l) => /^\s*(\/\/|\*|#|--|<!--|;)/.test(l);

/** Scan one file → [{line, kind}]. */
export function extractDotnetCors(text) {
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

/** The .NET-CORS-misconfig fingerprint for one file. */
export function extractDotnetCorsFingerprint(text, file) {
  return { file, hits: extractDotnetCors(text) };
}
