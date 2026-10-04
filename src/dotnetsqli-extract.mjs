// .NET SQL injection (CWE-89) — a request value is BUILT INTO a SQL string by .NET (ADO.NET SqlCommand, EF Core raw
// SQL, or CommandText) — SERVER fingerprint. Emit {file, line, kind} — never source. .NET-specific: a SQL sink
// (new SqlCommand / MySqlCommand / NpgsqlCommand / OleDbCommand / SqliteCommand, a .CommandText assignment, or EF Core
// FromSqlRaw / ExecuteSqlRaw(Async)) receives a string assembled from an ASP.NET request accessor (Request[...] /
// Request.QueryString / Request.Form / Request.Query / Request.Params / Request.Headers) via an interpolated string
// ($"… {Request…}"), string.Format, or `"…" +` concat → the attacker rewrites the query. Scoped to the request
// accessor INSIDE the SQL string on the SAME line as the sink — a parameterized command (@id + Parameters.AddWithValue)
// keeps the accessor off the sink line → ~0 FP. DISTINCT from sqli #30 (no .NET), goSqli #79 (Go), dotnetCmdi #76.
//
// TWO layers (batch57/58 added the taint layer): DIRECT (below) fires when the Request accessor is INLINE in the sink
// statement. TAINT (dataflow) catches the two-step build — `var id = Request.QueryString["id"]; var sql =
// string.Format("… {0}", id); new SqlCommand(sql)` — that the direct layer misses. 0-FP discipline held: a var only
// becomes SQL-tainted when a CONCRETE Request accessor is combined with a SQL string; a dynamic SQL built from a bare
// local (no Request origin) is NOT flagged (that would need an abstract-source assumption = FP), and a parameterized /
// SqlParameter command clears the taint.

const PATTERNS = [
  // A SQL sink (command ctor / CommandText / EF raw) followed on the same line by an interpolated string, string.Format,
  // or a "…" + concat that carries an ASP.NET Request accessor (property or indexer). `[^;]*` bridges sink→accessor
  // within the statement; the interpolation/concat token is what distinguishes it from a safe parameterized query.
  ["dotnet-sql-build", /(?:new\s+\w*Command\s*\(|\.\s*CommandText\s*=|FromSqlRaw\s*\(|ExecuteSqlRaw(?:Async)?\s*\()[^;]*(?:\$"|"\s*\+|string\s*\.\s*Format\s*\()[^;]*\bRequest\s*(?:\.\s*(?:QueryString|Form|Params|Query|Headers)\b|\[)/],
];
const isComment = (l) => /^\s*(\/\/|\*|#|--|<!--|;)/.test(l);

import { runTaintPass, mentions, escapeVar } from "./taint-core.mjs";

// A CONCRETE ASP.NET request accessor (property or indexer) — the user source.
const DN_SRC = /\bRequest\s*(?:\.\s*(?:QueryString|Form|Params|Query|Headers|Cookies|RouteValues|Body)\b|\[)/;
// A string literal (plain / verbatim @"…" / interpolated $"…") carrying a SQL keyword — evidence the RHS builds a query.
const SQL_STRING = /(?:"[^"]*|@"[^"]*|\$"[^"]*)\b(?:SELECT|INSERT\s+INTO|INSERT|UPDATE|DELETE\s+FROM|DELETE|WHERE|FROM|VALUES|ORDER\s+BY|GROUP\s+BY|UNION|DROP\s+TABLE|JOIN)\b/i;
// A parameterized / safe form — clears taint (don't cry wolf).
const DN_SANITIZE = /\b(?:SqlParameter|Parameters\s*\.\s*Add|AddWithValue|FromSqlInterpolated|ExecuteSqlInterpolated|Parameteriz\w*|SqlDbType|DbParameter)\b/;
// A tainted var reaching a .NET SQL sink (ctor arg / CommandText assignment / EF raw arg).
const sink = (v) => new RegExp(`(?:new\\s+\\w*Command\\s*\\(\\s*|\\.\\s*CommandText\\s*=\\s*|FromSqlRaw\\s*\\(\\s*|ExecuteSqlRaw(?:Async)?\\s*\\(\\s*)${escapeVar(v)}\\b`);
const HAS_SINK = /new\s+\w*Command\s*\(|\.\s*CommandText\s*=|FromSqlRaw\s*\(|ExecuteSqlRaw/;
// C# method / type boundary — reset taint so a source in one method can't fire on a same-named var in another.
const DN_BOUNDARY = /=>|\bclass\s|\bnamespace\s|^\s*(?:\[[^\]]*\]\s*)*(?:public|private|protected|internal|static|async|override|virtual|sealed|void|Task)\b[^;=]*\)\s*\{?\s*$/;
// A C# typed local declaration `Type name = …` (the shared =-based ASSIGN_RE only catches `var name =`).
const DN_DECL = /^\s*(?:(?:public|private|protected|internal|static|readonly|const)\s+)*[A-Za-z_][\w.<>\[\],]*\s+([A-Za-z_]\w*)\s*=\s*(?!=)(.+)$/;

/**
 * .NET-SQLi taint pass — intra-method. `var id = Request.QueryString["id"]` tags id "user"; a SQL string built with a
 * user var (`sql = string.Format("… {0}", id)`) becomes "sql"; a "sql" var reaching a .NET SQL sink emits
 * dotnet-sql-taint. A concrete Request accessor is required to start the chain → a dynamic SQL from a bare local never
 * fires (0-FP). Note: `command.CommandText = tainted` is BOTH a sink (checked first) and a member assign (not a decl).
 */
function taintPass(lines) {
  return runTaintPass(lines, {
    boundary: DN_BOUNDARY,
    sanitizer: DN_SANITIZE,
    checkSinks(l, taint, emit) {
      for (const [v, t] of taint) if (t === "sql" && sink(v).test(l)) { emit("dotnet-sql-taint"); return; }
    },
    updateTaint(l, taint, sa) {
      // A member assignment (`x.CommandText = …`, `obj.Prop = …`) is not a local decl — never taint a dotted LHS.
      const ce = !sa && !/^\s*[A-Za-z_]\w*\s*\./.test(l) && l.match(DN_DECL);
      const eff = sa || (ce ? { name: ce[1], rhs: ce[2] } : null);
      if (!eff) return;
      const { name, rhs } = eff;
      const hasReq = DN_SRC.test(rhs);
      const hasUserVar = [...taint].some(([v, t]) => t === "user" && mentions(v, rhs));
      const hasSqlVar = [...taint].some(([v, t]) => t === "sql" && mentions(v, rhs));
      const buildsSql = SQL_STRING.test(rhs);
      if ((hasReq || hasUserVar) && buildsSql) taint.set(name, "sql");   // SQL string built with a request-derived value
      else if (hasSqlVar) taint.set(name, "sql");                        // propagate
      else if (hasReq || hasUserVar) taint.set(name, "user");           // raw request value, not SQL yet
      else taint.delete(name);                                          // reassigned to something clean
    },
  });
}

/** Scan one file → [{line, kind}]. Direct inline patterns + the two-step taint layer. */
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
  if (HAS_SINK.test(text) && DN_SRC.test(text)) for (const h of taintPass(lines)) out.push(h);
  return out;
}

/** The .NET-SQLi fingerprint for one file. */
export function extractDotnetSqliFingerprint(text, file) {
  return { file, hits: extractDotnetSqli(text) };
}
