// Go SQL injection (CWE-89) — a request value is BUILT INTO a database/sql query string by the Go `database/sql`
// package — SERVER fingerprint. Emit {file, line, kind} — never source. Go-specific: db.Query / QueryRow /
// QueryContext / Exec / ExecContext run a SQL string; when that string is assembled from a net/http request accessor
// (r.FormValue / r.PostFormValue / r.URL / r.Header) via fmt.Sprintf or string concatenation (`"…" +`), the attacker
// rewrites the query (' OR '1'='1, UNION dump, DROP). Scoped by the discriminator that separates the vuln from a safe
// parameterized query: the request accessor must be INSIDE the SQL string (fmt.Sprintf format args OR a "…" + concat),
// NOT a separate bound parameter — so db.Query("… $1", r.FormValue("id")) / db.Query("… ?", id) never fire → ~0 FP.
// DISTINCT from sqli #30 (Python/Node/PHP/Ruby — no Go) and goCmdi #75 (exec sink) / goSsrf #77 (http sink).
//
// TWO layers (batch57 added the taint layer): DIRECT (below) fires when the request accessor is INLINE in the sink
// call. TAINT (dataflow) catches the two-step build — `q = "SELECT … " + req.FormValue(…)` … `db.Query(q)` — which the
// direct layer misses. The 0-FP discipline is unchanged: a var only becomes SQL-tainted when a CONCRETE request
// accessor is combined with a SQL string; a pure SQL string built with a NON-request value (fmt.Sprintf on a bare
// local) is tagged "sqlstr" and NEVER fires (that would need an abstract-source assumption = FP). A sanitizer/escape/
// parameterize call on the var clears the taint.

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

import { runTaintPass, mentions, escapeVar } from "./taint-core.mjs";

// A net/http request accessor — the CONCRETE user source (same vocab as the direct patterns, for parity).
const GO_SRC = /\b(?:r|req|request)\s*\.\s*(?:FormValue|PostFormValue|FormFile|PostForm|URL|Header)\b/;
// A string literal (double-quoted or backtick) carrying a SQL keyword — evidence the RHS is building a query.
const SQL_STRING = /(?:"[^"]*|`[^`]*)\b(?:SELECT|INSERT\s+INTO|INSERT|UPDATE|DELETE\s+FROM|DELETE|WHERE|FROM|VALUES|ORDER\s+BY|GROUP\s+BY|UNION|DROP\s+TABLE|JOIN)\b/i;
// fmt.Sprintf building a string (with a SQL string inside) is also SQL-building.
const SPRINTF = /fmt\s*\.\s*Sprintf\s*\(/;
// A parameterize/escape/quote call clears taint — the value is made safe (don't cry wolf).
const GO_SANITIZE = /\b(?:Prepare|PrepareContext|Named(?:Arg|Exec|Query)|sqlx\.In|pq\.QuoteIdentifier|pq\.QuoteLiteral|Rebind|escape\w*|quote\w*|sanitiz\w*|validate\w*)\b/i;
// A tainted var used as the query argument of a db sink (optionally after a leading ctx arg).
const sink = (v) => new RegExp(`\\.\\s*(?:Query|QueryRow|QueryContext|Exec|ExecContext)\\s*\\(\\s*(?:[A-Za-z_]\\w*(?:\\.\\w+)?\\s*,\\s*)?${escapeVar(v)}\\s*[),]`);
const HAS_SINK = /\.\s*(?:Query|QueryRow|QueryContext|Exec|ExecContext)\s*\(/;

/**
 * Go-SQLi taint pass — intra-function. A var becomes "sql" when a CONCRETE request accessor is combined with a SQL
 * string (`q = "SELECT…" + req.FormValue(…)`), OR when a SQL-string var later gets a request value appended
 * (`q := "SELECT…"; q += req.FormValue(…)`). A pure SQL string built without a request value is "sqlstr" and never
 * fires. A "sql" var reaching a db sink emits "go-sql-taint".
 */
function taintPass(lines) {
  return runTaintPass(lines, {
    sanitizer: GO_SANITIZE,
    checkSinks(l, taint, emit) {
      for (const [v, t] of taint) if (t === "sql" && sink(v).test(l)) { emit("go-sql-taint"); return; }
    },
    updateTaint(l, taint, sa) {
      // `q += <rhs>` (compound-append, not caught by the shared simple-assign regex).
      const pe = l.match(/^\s*([A-Za-z_]\w*)\s*\+=\s*(.+)$/);
      if (pe) {
        const [, name, rhs] = pe;
        const cur = taint.get(name);
        if (GO_SRC.test(rhs) && (cur === "sqlstr" || cur === "sql")) taint.set(name, "sql");           // SQL var + user append
        else if (cur === "sql") { /* stays sql */ }
        else if ((SQL_STRING.test(rhs) || SPRINTF.test(rhs)) && GO_SRC.test(rhs)) taint.set(name, "sql");
        return;
      }
      // Go's short declaration `q := …` is not the shared `=` assign form — parse it here so real Go (which uses `:=`
      // far more than `=`) taints correctly.
      const ce = !sa && l.match(/^\s*([A-Za-z_]\w*)\s*:=\s*(?!=)(.+)$/);
      const eff = sa || (ce ? { name: ce[1], rhs: ce[2] } : null);
      if (!eff) return;
      const { name, rhs } = eff;
      const hasReq = GO_SRC.test(rhs);
      const buildsSql = SQL_STRING.test(rhs) || SPRINTF.test(rhs);
      const hasSqlVar = [...taint].some(([v, t]) => t === "sql" && mentions(v, rhs));
      if (hasReq && buildsSql) taint.set(name, "sql");            // q = "SELECT…" + req.FormValue(…)
      else if (hasSqlVar) taint.set(name, "sql");                 // propagate: q2 := q + " ORDER BY …"
      else if (buildsSql) taint.set(name, "sqlstr");              // pure SQL string — may get a user value appended later
      else taint.delete(name);                                    // reassigned to something clean
    },
  });
}

/** Scan one file → [{line, kind}]. Direct inline patterns + the two-step taint layer. */
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
  if (HAS_SINK.test(text) && GO_SRC.test(text)) for (const h of taintPass(lines)) out.push(h);
  return out;
}

/** The Go-SQLi fingerprint for one file. */
export function extractGoSqliFingerprint(text, file) {
  return { file, hits: extractGoSqli(text) };
}
