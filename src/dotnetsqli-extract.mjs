// .NET SQL injection (CWE-89) — a request value is BUILT INTO a SQL string by .NET (ADO.NET SqlCommand, EF Core raw
// SQL, or CommandText) — SERVER fingerprint. Emit {file, line, kind} — never source. .NET-specific: a SQL sink
// (new SqlCommand / MySqlCommand / NpgsqlCommand / OleDbCommand / SqliteCommand, a .CommandText assignment, or EF Core
// FromSqlRaw / ExecuteSqlRaw(Async)) receives a string assembled from an ASP.NET request accessor (Request[...] /
// Request.QueryString / Request.Form / Request.Query / Request.Params / Request.Headers) via an interpolated string
// ($"… {Request…}"), string.Format, or `"…" +` concat → the attacker rewrites the query. Scoped to the request
// accessor INSIDE the SQL string on the SAME line as the sink — a parameterized command (@id + Parameters.AddWithValue)
// keeps the accessor off the sink line → ~0 FP. DISTINCT from sqli #30 (no .NET), goSqli #79 (Go), dotnetCmdi #76.

const PATTERNS = [
  // A SQL sink (command ctor / CommandText / EF raw) followed on the same line by an interpolated string, string.Format,
  // or a "…" + concat that carries an ASP.NET Request accessor (property or indexer). `[^;]*` bridges sink→accessor
  // within the statement; the interpolation/concat token is what distinguishes it from a safe parameterized query.
  ["dotnet-sql-build", /(?:new\s+\w*Command\s*\(|\.\s*CommandText\s*=|FromSqlRaw\s*\(|ExecuteSqlRaw(?:Async)?\s*\()[^;]*(?:\$"|"\s*\+|string\s*\.\s*Format\s*\()[^;]*\bRequest\s*(?:\.\s*(?:QueryString|Form|Params|Query|Headers)\b|\[)/],
];
const isComment = (l) => /^\s*(\/\/|\*|#|--|<!--|;)/.test(l);

/** Scan one file → [{line, kind}]. */
export function extractDotnetSqli(text) {
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

/** The .NET-SQLi fingerprint for one file. */
export function extractDotnetSqliFingerprint(text, file) {
  return { file, hits: extractDotnetSqli(text) };
}
