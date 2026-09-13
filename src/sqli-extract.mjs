// SQL Injection (CWE-89) — LANGUAGE-AGNOSTIC client fingerprint. Emit {file, line, kind} — NEVER the source line.
// The #1 web vuln: a user value BUILT INTO the SQL string (f-string / concat / template literal / #{} / format) lets
// an attacker rewrite the query (`' OR '1'='1`, `; DROP TABLE`, UNION-based dump). The DISCRIMINATOR that separates
// the vuln from a safe parameterized query: the request value must appear INSIDE the query string, NOT as a separate
// bound parameter — so `execute("… WHERE id = ?", [id])` / `execute("… %s", (id,))` do NOT fire.
//
// TWO detection layers, both computed client-side; only the {line, kind} egresses:
//   1. DIRECT (line-regex, unchanged) — the user source is INLINE in the sink call: execute(f"…{request…}"),
//      execute("SELECT …" + request…), mysqli_query("… $_GET").
//   2. TAINT (dataflow, new)          — intra-function: `q = "SELECT … " + request.args['id']` … `cursor.execute(q)`.
//      A var becomes SQL-tainted when its RHS combines a user source (or a user-tainted intermediate) with SQL-keyword
//      string-building; a hit fires when that var reaches an execute sink. A CONSTANT query string never taints, so a
//      parameterized `q = "… %s"; execute(q, [id])` stays clean. Taint clears on a function boundary, an escaping/
//      parameterizing call on the var, or a non-tainting reassignment (precision over recall = ~0 FP).

// A request/user source token (Python request.*, Node req.*, Ruby params, PHP superglobals).
const REQ = "request\\s*\\.\\s*(?:args|form|values|GET|POST|json|data)|req(?:uest)?\\s*\\.\\s*(?:query|body|params)|\\$_(?:GET|POST|REQUEST|COOKIE)|\\bparams\\b";
// A SQL-executing sink.
const SINK = "execute|executemany|executescript|query|raw|exec|executeQuery|executeUpdate|prepareStatement|mysqli_query|mysql_query|pg_query|pg_exec|find_by_sql";

const SQL_KW = "SELECT|INSERT|UPDATE|DELETE|WHERE|FROM|VALUES|ORDER\\s+BY|UNION|--";
// A SQL string literal in EITHER quote style, matched per quote so the OTHER quote may appear inside it. Release audit
// 2026-09-13 (B-P1-6) : the textbook `db.query("SELECT … WHERE name = '" + req.query.name + "'")` never fired because
// the old mixed class `["'][^"']*["']` mis-closed on the embedded single quote (the same trap the java-sql rule below
// already documents). A SQL string that quotes a value is exactly the shape that gets concatenated.
const SQL_LIT = `(?:"[^"]*(?:${SQL_KW})[^"]*"|'[^']*(?:${SQL_KW})[^']*')`;

const DIRECT_PATTERNS = [
  // per-quote (a SQL f-string routinely embeds the other quote : f"… name = '{x}'") — same trap as SQL_LIT above.
  ["fstring-sql", new RegExp(`\\b(?:${SINK})\\s*\\(\\s*(?:f"[^"]*\\{[^}]*(?:${REQ})|f'[^']*\\{[^}]*(?:${REQ}))`)],
  ["interp-sql", new RegExp(`\\b(?:${SINK}|where|find_by_sql)\\s*\\(\\s*(?:["'][^"']*#\\{[^}]*(?:${REQ})|\`[^\`]*\\$\\{[^}]*(?:${REQ}))`)],
  ["concat-sql", new RegExp(`\\b(?:${SINK})\\s*\\(\\s*[^;]*${SQL_LIT}\\s*(?:\\+|\\.|%)\\s*[^;]*(?:${REQ})`)],
  ["php-inline-sql", new RegExp(`\\b(?:mysqli_query|mysql_query|pg_query|pg_exec|->\\s*query|->\\s*exec(?:ute)?)\\s*\\([^;]*["'][^"']*\\$_(?:GET|POST|REQUEST|COOKIE)`)],
  // Java (JDBC Statement + JPA/Hibernate) — a SQL/JPQL string concatenated with an HttpServletRequest accessor at a
  // query sink. The base concat-sql above covers Python/Node/PHP/Ruby sources only; Java's request.getParameter /
  // getHeader and the createQuery/createNativeQuery (JPA/Hibernate) + executeQuery/executeUpdate (JDBC) sinks are
  // Java-specific and were missed. 0-FP: a SQL/JPQL string literal + `+` concat + a CONCRETE request accessor on the
  // sink statement — a bound setParameter/`?` placeholder keeps the request value off the concatenation, so never fires.
  // Java strings are double-quoted and SQL routinely embeds single quotes ("… name = '"), so match a double-quoted
  // literal only (`"[^"]*"`) — a mixed ["'] class would mis-close on the embedded single quote.
  ["java-sql", new RegExp(`\\b(?:createQuery|createNativeQuery|createSQLQuery|executeQuery|executeUpdate|executeLargeUpdate|prepareStatement)\\s*\\(\\s*[^;]*"[^"]*(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM|ORDER\\s+BY|UNION)[^"]*"\\s*\\+\\s*[^;]*\\b(?:request|req|httpRequest)\\s*\\.\\s*get(?:Parameter|ParameterValues|Header|QueryString|PathInfo)\\b`)],
];

import { runTaintPass, mentions } from "./taint-core.mjs";
import { findSinkWrappers, interprocHit } from "./taint-interproc.mjs";

const isComment = (l) => /^\s*(\/\/|\*|#|--|;|<!--)/.test(l);

// ── Taint-pass vocabulary (fed to the shared runTaintPass engine) ────────────────────────────────────────────────
const REQ_RE = new RegExp(REQ);
// A string literal that contains a SQL keyword — evidence the RHS is building a query, not an arbitrary string.
const SQL_STRING = /["'`][^"'`]*\b(?:SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM|DELETE|WHERE|FROM|VALUES|ORDER\s+BY|GROUP\s+BY|UNION|DROP\s+TABLE|--)\b/i;
// An escaping / parameterizing call — assume it makes the value safe → clear taint (don't cry wolf).
const SQL_SANITIZE = /\b(?:parameteriz\w*|escape\w*|quote\w*|sanitiz\w*|bind_?param\w*|prepared?|mogrify|sql\.Identifier|quote_ident|placeholder)\b/i;
const esc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const sink = (v) => new RegExp(`\\b(?:${SINK})\\s*\\(\\s*${esc(v)}\\s*[),]`);
// A sink CALL on the line (any argument shape) — used with `interpolated` below for the one-step user-var build.
const SINK_CALL = new RegExp(`\\b(?:${SINK})\\s*\\(`);
// Is the (user-tainted) var `v` built INTO a string literal on this line — f"…{v}", `…${v}`, "…#{v}", "…" + v,
// "…" % v, "…".format(v), v + "…" ? The DISCRIMINATOR vs a bound parameter (`"… %s", (v,)` / `"… $1", [v]`) : a bound
// value sits after a `,`, never glued to the literal by an operator or inside a placeholder. Release audit B-P1-6 :
// `name = request.args.get(..)` then `cur.execute(f"… '{name}'")` — the value was "user"-tainted but the sink check
// only fired on "sql"-tainted vars, so the one-step build at the sink itself was invisible.
const interpolated = (v, l) => {
  const V = esc(v);
  return new RegExp(`f"[^"]*\\{[^}]*\\b${V}\\b[^}]*\\}|f'[^']*\\{[^}]*\\b${V}\\b[^}]*\\}`).test(l)   // per-quote, see SQL_LIT
    || new RegExp(`\`[^\`]*\\$\\{[^}]*\\b${V}\\b[^}]*\\}`).test(l)
    || new RegExp(`"[^"]*#\\{[^}]*\\b${V}\\b|'[^']*#\\{[^}]*\\b${V}\\b`).test(l)
    || new RegExp(`["'\`]\\s*(?:\\+|%|\\.format\\s*\\()\\s*\\(?\\s*\\b${V}\\b`).test(l)
    || new RegExp(`\\b${V}\\b\\s*\\+\\s*["'\`]`).test(l);
};
// A cheap file-level gate: no execute-family token ⇒ no possible SQL sink ⇒ skip the inter-procedural pass.
const HAS_SINK = new RegExp(`\\b(?:${SINK})\\b`);
const sqliSinkTest = (l, v) => sink(v).test(l);
/** The SQLi wrapper config — shared by the walker's cross-file registry build and the calibration harness. */
export const sqliWrapperCfg = { sinkTest: sqliSinkTest, sanitizer: SQL_SANITIZE, sourceTest: REQ_RE, hasSink: HAS_SINK };

/**
 * SQL-taint pass — intra-function (the two-step build→execute) + inter-procedural (a user-built query into a local
 * execute-wrapper) + cross-file (an execute-wrapper imported from another module). Tags: "user" / "sql".
 */
function taintPass(lines, text, importedWrappers) {
  // A local function whose param reaches an execute sink is a query-runner wrapper (seed the param as a query string).
  const wrappers = HAS_SINK.test(text)
    ? findSinkWrappers(lines, { sinkTest: sqliSinkTest, sanitizer: SQL_SANITIZE, sourceTest: REQ_RE })
    : new Map();
  const imported = importedWrappers instanceof Map ? importedWrappers : new Map();
  const dangerous = (taint) => (a) => (SQL_STRING.test(a) && REQ_RE.test(a)) || [...taint].some(([v, t]) => t === "sql" && mentions(v, a));
  return runTaintPass(lines, {
    sanitizer: SQL_SANITIZE,
    checkSinks(l, taint, emit) {
      for (const [v, tag] of taint) if (tag === "sql" && sink(v).test(l)) { emit("taint-sql"); return; }
      // One-step build AT the sink : a raw user value interpolated into a SQL literal inside the execute call
      // (f-string / template / concat / % / .format). A bound parameter after a `,` does not match `interpolated`.
      if (SINK_CALL.test(l) && SQL_STRING.test(l)) {
        for (const [v, tag] of taint) if (tag === "user" && interpolated(v, l)) { emit("taint-sql"); return; }
      }
      // Inter-procedural: a user-built query string (inline) OR a sql-tainted var at a flowing arg of a LOCAL query-runner.
      if (wrappers.size && interprocHit(l, wrappers, dangerous(taint))) { emit("taint-interproc"); return; }
      // Cross-file: same, into a query-runner IMPORTED from another module.
      if (imported.size && interprocHit(l, imported, dangerous(taint))) { emit("taint-xfile"); return; }
    },
    updateTaint(l, taint, sa) {
      if (!sa) return;
      const { name, rhs } = sa;
      const hasReq = REQ_RE.test(rhs);
      const hasUserVar = [...taint].some(([v, t]) => t === "user" && mentions(v, rhs));
      const hasSqlVar = [...taint].some(([v, t]) => t === "sql" && mentions(v, rhs));
      const buildsSql = SQL_STRING.test(rhs);
      if ((hasReq || hasUserVar) && buildsSql) taint.set(name, "sql");   // query string built with user data
      else if (hasSqlVar) taint.set(name, "sql");                        // propagate: q2 = q + " ORDER BY …"
      else if (hasReq || hasUserVar) taint.set(name, "user");            // raw user value, not SQL yet
      else taint.delete(name);                                           // reassigned to something clean
    },
  });
}

/** Scan one file → [{line, kind}]. Direct + taint + inter-proc; `importedWrappers` enables the cross-file layer. */
export function extractSqli(text, importedWrappers) {
  const out = [];
  const lines = String(text).split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const l = lines[i];
    if (l.length > 4000) continue;   // minified blob — noise
    if (isComment(l)) continue;      // a sink named in a comment is documentation, not live code
    for (const [kind, re] of DIRECT_PATTERNS) {
      if (re.test(l)) out.push({ line: i + 1, kind });
    }
  }
  for (const h of taintPass(lines, text, importedWrappers)) out.push(h);
  return out;
}

/** The SQL-injection fingerprint for one file — locations + kinds, no source. `importedWrappers` enables cross-file. */
export function extractSqliFingerprint(text, file, importedWrappers) {
  return { file, hits: extractSqli(text, importedWrappers) };
}
