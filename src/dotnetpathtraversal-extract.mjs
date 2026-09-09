// .NET path traversal / LFI (CWE-22) — a request value is used DIRECTLY as a filesystem path by a .NET file-read sink
// — SERVER fingerprint. Emit {file, line, kind} — never source. .NET-specific: File.ReadAllText / ReadAllBytes /
// ReadAllLines / OpenRead / Open, new StreamReader, new FileStream open a file by name; when that name is derived from
// an ASP.NET request accessor (Request[...] / Request.QueryString / Request.Form / Request.Query / Request.Params /
// Request.Headers), an attacker supplies `..\..\web.config` → arbitrary file read (Path.Combine does NOT stop `..` —
// only Path.GetFileName strips the directory). Scoped to the file-read sink with a request accessor INLINE → ~0 FP; a
// constant/config path never fires. EXTENDS path traversal to .NET — DISTINCT from pathTraversal #23 (no .NET),
// dotnetSsrf #78 (HTTP sink) and dotnetSqli #80 (SQL string).

const PATTERNS = [
  // A .NET file-read sink whose argument region carries an ASP.NET request accessor (property or indexer). `[^)]*`
  // keeps the match on the same call; the request accessor as the path is the vuln.
  ["dotnet-file-read", /(?:File\s*\.\s*(?:ReadAllText|ReadAllBytes|ReadAllLines|OpenRead|OpenText|Open)|new\s+StreamReader|new\s+FileStream)\s*\([^)]*\bRequest\s*(?:\.\s*(?:QueryString|Form|Params|Query|Headers)\b|\[)/],
];
const isComment = (l) => /^\s*(\/\/|\*|#|--|<!--|;)/.test(l);
// Path.GetFileName strips the directory components, so a request value wrapped in it can't traverse — exclude it on the
// same line (the safe boundary is the arg), exactly as pathTraversal #23 excludes safe_join / path.resolve.
const isSanitized = (l) => /\bPath\s*\.\s*GetFileName\s*\(/.test(l);

/** Scan one file → [{line, kind}]. */
export function extractDotnetPathTraversal(text) {
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

/** The .NET-path-traversal fingerprint for one file. */
export function extractDotnetPathTraversalFingerprint(text, file) {
  return { file, hits: extractDotnetPathTraversal(text) };
}
