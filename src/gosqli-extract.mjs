// Go SQL injection (CWE-89) — a request value is BUILT INTO a database/sql query string by the Go `database/sql`
// package — SERVER fingerprint. Emit {file, line, kind} — never source. Go-specific: db.Query / QueryRow /
// QueryContext / Exec / ExecContext run a SQL string; when that string is assembled from a net/http request accessor
// (r.FormValue / r.PostFormValue / r.URL / r.Header) via fmt.Sprintf or string concatenation (`"…" +`), the attacker
// rewrites the query (' OR '1'='1, UNION dump, DROP). Scoped by the discriminator that separates the vuln from a safe
// parameterized query: the request accessor must be INSIDE the SQL string (fmt.Sprintf format args OR a "…" + concat),
// NOT a separate bound parameter — so db.Query("… $1", r.FormValue("id")) / db.Query("… ?", id) never fire → ~0 FP.
// DISTINCT from sqli #30 (Python/Node/PHP/Ruby — no Go) and goCmdi #75 (exec sink) / goSsrf #77 (http sink).

const PATTERNS = [
  // A database/sql query/exec sink whose argument is fmt.Sprintf(...) carrying a net/http request accessor — every
  // Sprintf arg after the format string is interpolated, so this IS the injection. `[^)]*` keeps it on the call.
  ["go-sql-sprintf", /\.\s*(?:Query|QueryRow|QueryContext|Exec|ExecContext)\s*\(\s*(?:[A-Za-z_]\w*(?:\.\w+)?\s*,\s*)?fmt\s*\.\s*Sprintf\s*\([^)]*\b(?:r|req|request)\s*\.\s*(?:FormValue|PostFormValue|URL|Header)\b/],
  // A query/exec sink whose argument is a string literal (double-quoted or a raw backtick string) concatenated with `+`
  // and a request accessor — the request value is spliced into the SQL string. An optional leading context arg (ctx,)
  // is allowed for the *Context sinks. A comma-separated bound param never matches (no `"…" +` before the accessor).
  ["go-sql-concat", /\.\s*(?:Query|QueryRow|QueryContext|Exec|ExecContext)\s*\(\s*(?:[A-Za-z_]\w*(?:\.\w+)?\s*,\s*)?(?:"[^"]*"|`[^`]*`)\s*\+[^)]*\b(?:r|req|request)\s*\.\s*(?:FormValue|PostFormValue|URL|Header)\b/],
];
const isComment = (l) => /^\s*(\/\/|\*|#|--|<!--|;)/.test(l);

/** Scan one file → [{line, kind}]. */
export function extractGoSqli(text) {
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

/** The Go-SQLi fingerprint for one file. */
export function extractGoSqliFingerprint(text, file) {
  return { file, hits: extractGoSqli(text) };
}
