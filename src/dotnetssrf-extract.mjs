// .NET SSRF (CWE-918) — a request value is the URL of an outbound HTTP call by .NET (HttpClient / WebClient /
// WebRequest) — SERVER fingerprint. Emit {file, line, kind} — never source. .NET-specific: HttpClient.GetAsync /
// GetStringAsync / GetByteArrayAsync / GetStreamAsync / PostAsync, WebClient.DownloadString / DownloadData / OpenRead,
// and WebRequest.Create fetch a URL; when that URL is derived from an ASP.NET request accessor (Request[...] /
// Request.QueryString / Request.Form / Request.Query / Request.Params / Request.Headers), the server fetches an
// attacker-chosen endpoint → cloud metadata, localhost admin APIs, internal services. Scoped to an ASP.NET request
// accessor INLINE in the outbound-HTTP call → ~0 FP. A constant/config URL never fires. DISTINCT from ssrf #26
// (Python/Node/PHP/Java/Ruby sinks — no .NET) and goSsrf #77.

const PATTERNS = [
  // An HttpClient/WebClient outbound-fetch method or WebRequest.Create whose argument region carries an ASP.NET
  // request accessor (a property Request.QueryString/Form/... or an indexer Request[...]). `[^)]*` keeps it on the call.
  ["dotnet-http-request", /(?:\.\s*(?:GetAsync|GetStringAsync|GetByteArrayAsync|GetStreamAsync|PostAsync|DownloadString|DownloadData|OpenRead)|WebRequest\s*\.\s*Create)\s*\([^)]*\bRequest\s*(?:\.\s*(?:QueryString|Form|Params|Query|Headers)\b|\[)/],
];
const isComment = (l) => /^\s*(\/\/|\*|#|--|<!--|;)/.test(l);

/** Scan one file → [{line, kind}]. */
export function extractDotnetSsrf(text) {
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

/** The .NET-SSRF fingerprint for one file. */
export function extractDotnetSsrfFingerprint(text, file) {
  return { file, hits: extractDotnetSsrf(text) };
}
