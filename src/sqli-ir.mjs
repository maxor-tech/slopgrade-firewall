// SQL injection on the syntax tree (expert panel P0-3, first consumer of ts-ir.mjs). Same vocabulary as the line
// extractor (sqli-extract.mjs : request sources, framework sources, sink names, sanitizer names) so a benchmark
// isolates what the TREE adds :
//   • expressions, not lines — a call broken over 6 lines, a query built in a nested call, several statements on a line ;
//   • the FIRST argument of a sink only — `cur.execute("… %s", (name,))` binds `name` as a parameter : safe ;
//   • assignment / destructuring / augmented assignment def-use, per function, in source order ; a nested function
//     (a callback) starts from its parent's taint at the point it is defined ;
//   • a sanitizer or numeric cast cleans only what it returns (effect-based, as taint-core.sanitizerEffect).
// Tags : "user" (a request value) · "sql" (a SQL string built with a request value). A sink whose first argument is
// "sql", or builds SQL text with a "user" value in the same expression, is a hit. Python, JavaScript, TypeScript, TSX.
import { parseFile } from "./ts-ir.mjs";
import { REQ, SINK, SQL_SANITIZE } from "./sqli-extract.mjs";
import { FRAMEWORK_SOURCE, paramSources } from "./sources.mjs";

const SOURCE_RE = new RegExp(`${REQ}|${FRAMEWORK_SOURCE}`);
const SINKS = new Set(SINK.split("|"));
const SQL_TEXT = /\b(?:SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM|DELETE|WHERE|FROM|VALUES|ORDER\s+BY|GROUP\s+BY|UNION|DROP\s+TABLE)\b/i;
const CAST = /^(?:int|float|bool|Number|parseInt|parseFloat|Boolean|BigInt|uuid\.UUID|UUID)$/;
const FN = new Set(["function_definition", "function_declaration", "function_expression", "function", "arrow_function", "method_definition", "generator_function_declaration", "generator_function", "lambda"]);
const STRINGS = new Set(["string", "template_string", "concatenated_string"]);

/** The called name : `cur.execute` → "execute", `db.query` → "query", `run` → "run". */
function calleeName(call) {
  const f = call.childForFieldName("function");
  if (!f) return "";
  if (f.type === "identifier") return f.text;
  const prop = f.childForFieldName("attribute") ?? f.childForFieldName("property");
  return prop ? prop.text : f.text.split(/[.\s]/).pop();
}
const firstArg = (call) => {
  const args = call.childForFieldName("arguments");
  const a = args ? (args.namedChildren.find((c) => c.type !== "comment" && c.type !== "keyword_argument") ?? null) : null;
  // `client.query({ query: "… {teamId: UUID}", query_params: { teamId: req.… } })` : only the SQL text property is the
  // statement ; the others are bound values (2026-11-01 real-code sweep, firecrawl / ClickHouse).
  if (a?.type === "object") {
    const sql = a.namedChildren.find((p) => p.type === "pair" && /^["'`]?(?:query|sql|text|statement)["'`]?$/.test(p.childForFieldName("key")?.text ?? ""));
    return sql ? sql.childForFieldName("value") : null;
  }
  return a;
};

/** Taint of an expression → { user, sql, lit } (lit = it contains SQL text). */
// Depth cap for both recursive walks : a generated / minified file nests thousands deep (a 4,000-term string
// concatenation overflowed the stack on the 2026-11-01 real-code sweep). Past the cap the subtree is not read.
const MAX_DEPTH = 300;
let depth = 0;
function evalT(n, taint) {
  if (depth > MAX_DEPTH) return { user: false, sql: false, lit: false };
  depth++;
  try { return evalTInner(n, taint); } finally { depth--; }
}
function evalTInner(n, taint) {
  const z = { user: false, sql: false, lit: false };
  if (!n || FN.has(n.type)) return z;          // a callback passed as an argument is code, not a value (tldraw `execute(async (tx) => …)`)
  const or = (a, b) => ({ user: a.user || b.user, sql: a.sql || b.sql, lit: a.lit || b.lit });
  switch (n.type) {
    case "identifier": case "shorthand_property_identifier": {
      const t = taint.get(n.text);
      return { user: t === "user", sql: t === "sql", lit: false };
    }
    case "call": case "call_expression": {
      const name = calleeName(n);
      if (SQL_SANITIZE.test(name) || CAST.test(name)) return z;          // the returned value is clean
      let r = z;
      const f = n.childForFieldName("function");
      if (f && f.type !== "identifier") r = or(r, evalT(f.childForFieldName("object") ?? f, taint));
      const args = n.childForFieldName("arguments");
      if (args?.type === "generator_expression") r = or(r, evalT(args, taint));   // `join('?' for _ in xs)` : the generator IS the argument
      else for (const a of args?.namedChildren ?? []) r = or(r, evalT(a.type === "keyword_argument" ? a.childForFieldName("value") : a, taint));
      if (SOURCE_RE.test(n.text)) r.user = true;
      return r;
    }
    // A placeholder list is built from constant text only, whatever it iterates over : `'?' for _ in names`,
    // `['%s' for x in ids]`, `['?'] * len(ids)` (AI-Trader routes_signals.py, 2026-11-01 live /try run) — the values
    // themselves are bound in the next argument.
    case "generator_expression": case "list_comprehension": case "set_comprehension": {
      // the loop variable carries its iterable's taint (`f"'{n}'" for n in names` is user text ; `'?' for _ in names` is not)
      const local = new Map(taint);
      for (const c of n.namedChildren) if (c.type === "for_in_clause") {
        const t = tagOf(evalT(c.childForFieldName("right"), taint));
        for (const v of targets(c.childForFieldName("left"))) { if (t) local.set(v, t); else local.delete(v); }
      }
      return evalT(n.childForFieldName("body") ?? n.namedChildren[0], local);
    }
    case "binary_operator": case "binary_expression":
      if ((n.childForFieldName("operator")?.text ?? n.children[1]?.text) === "*") {
        const sides = [n.childForFieldName("left"), n.childForFieldName("right")];
        const lit = sides.find((s) => s && /^(?:list|array|string|tuple)$/.test(s.type) && !SOURCE_RE.test(s.text) && s.namedChildren.every((c) => /^(?:string|string_fragment|string_content|string_start|string_end)$/.test(c.type)));
        if (lit) return evalT(lit, taint);
      }
      return evalChildren(n, taint);
    case "attribute": case "member_expression": case "subscript": case "subscript_expression":
      if (SOURCE_RE.test(n.text)) return { ...z, user: true };
      return evalT(n.childForFieldName("object") ?? n.childForFieldName("value") ?? n.namedChildren[0], taint);
    default:
      return evalChildren(n, taint);
  }
}
/** A node's own text facts (SQL text, a request source) united with its children's taint. */
function evalChildren(n, taint) {
  let r = { user: false, sql: false, lit: STRINGS.has(n.type) || n.type === "string_fragment" || n.type === "string_content" ? SQL_TEXT.test(n.text) : false };
  if (SOURCE_RE.test(n.text) && !STRINGS.has(n.type)) r.user = true;
  for (const c of n.namedChildren) if (!FN.has(c.type)) { const x = evalT(c, taint); r = { user: r.user || x.user, sql: r.sql || x.sql, lit: r.lit || x.lit }; }
  return r;
}
const tagOf = (r) => (r.sql || (r.user && r.lit) ? "sql" : r.user ? "user" : null);

/** Identifiers bound by an assignment target (a name, a tuple / list / object / array pattern). */
function targets(n, out = []) {
  if (!n) return out;
  if (n.type === "identifier" || n.type === "shorthand_property_identifier_pattern") out.push(n.text);
  else if (/pattern|pattern_list|tuple|list|expression_list/.test(n.type)) for (const c of n.namedChildren) {
    if (c.type === "pair_pattern") targets(c.childForFieldName("value"), out);
    else targets(c, out);
  }
  return out;
}
// `q, p = ("SELECT … ?", (author,)) if author else ("SELECT …", ())` : a tuple target over a tuple value (or a
// conditional between tuples) binds element by element — the bound `p` does not taint the query `q` (GenericAgent).
const TUPLE = /^(?:tuple|expression_list|pattern_list|tuple_pattern|array|array_pattern|list|list_pattern)$/;
function parts(rhs, n) {
  if (!rhs) return null;
  if (rhs.type === "parenthesized_expression") return parts(rhs.namedChildren[0], n);
  if (TUPLE.test(rhs.type) && rhs.namedChildren.length === n) return rhs.namedChildren.map((c) => [c]);
  if (rhs.type === "conditional_expression" || rhs.type === "ternary_expression") {
    const branches = rhs.type === "conditional_expression" ? [rhs.namedChildren[0], rhs.namedChildren[2]]
      : [rhs.childForFieldName("consequence"), rhs.childForFieldName("alternative")];
    const ps = branches.map((b) => parts(b, n));
    if (ps.every(Boolean)) return ps[0].map((p, k) => [...p, ...ps[1][k]]);
  }
  return null;
}
function assign(lhs, rhs, taint, aug = false) {
  const lhsItems = lhs && TUPLE.test(lhs.type) ? lhs.namedChildren : null;
  const split = lhsItems && parts(rhs, lhsItems.length);
  if (split && !aug) {
    const tags = split.map((nodes) => tagOf(nodes.reduce((a, x) => { const r = evalT(x, taint); return { user: a.user || r.user, sql: a.sql || r.sql, lit: a.lit || r.lit }; }, { user: false, sql: false, lit: false })));
    lhsItems.forEach((item, k) => { for (const v of targets(item)) { if (tags[k]) taint.set(v, tags[k]); else taint.delete(v); } });
    return;
  }
  const t = tagOf(evalT(rhs, taint));
  for (const v of targets(lhs)) {
    const prev = aug ? taint.get(v) : null;
    const next = t === "sql" || prev === "sql" ? "sql" : t === "user" || prev === "user" ? "user" : null;
    if (next) taint.set(v, next); else taint.delete(v);
  }
}

/** Walk one scope in source order ; nested functions recurse with a copy of the taint at their definition. */
function walk(n, taint, lines, hits) {
  if (depth > MAX_DEPTH) return;
  depth++;
  try { walkInner(n, taint, lines, hits); } finally { depth--; }
}
function walkInner(n, taint, lines, hits) {
  if (FN.has(n.type)) { scope(n, new Map(taint), lines, hits); return; }
  switch (n.type) {
    case "assignment": assign(n.childForFieldName("left"), n.childForFieldName("right"), taint); break;
    case "augmented_assignment": case "augmented_assignment_expression": assign(n.childForFieldName("left"), n.childForFieldName("right"), taint, true); break;
    case "assignment_expression": assign(n.childForFieldName("left"), n.childForFieldName("right"), taint); break;
    case "variable_declarator": assign(n.childForFieldName("name"), n.childForFieldName("value"), taint); break;
    case "if_statement": {
      // A guard : the condition compares / tests membership of / validates a value, and the branch rejects (raise,
      // throw, return) → past the `if`, that value is checked (`if table not in info: raise …` — DB-GPT). Same rule
      // as taint-core.sanitizerEffect's guard.
      const cond = n.childForFieldName("condition"), body = n.childForFieldName("consequence");
      const first = body?.type === "block" || body?.type === "statement_block" ? body.namedChildren[0] : body;
      if (cond && first && /^(?:raise_statement|return_statement|throw_statement)$/.test(first.type) && /\bnot\s+in\b|\bin\b|[!=]==?|\b(?:includes|has|match|test|isValid\w*|validate\w*|is_valid\w*)\b/.test(cond.text)) {
        for (const c of n.namedChildren) if (c !== cond) walk(c, taint, lines, hits);
        for (const v of [...taint.keys()]) if (new RegExp(`(?<![\\w$.])${v.replace(/[$]/g, "\\$")}(?![\\w$])`).test(cond.text)) taint.delete(v);
        return;
      }
      break;
    }
    case "call": case "call_expression": {
      if (SINKS.has(calleeName(n))) {
        const r = evalT(firstArg(n), taint);
        if (r.sql || (r.user && r.lit)) hits.set(n.startPosition.row + 1, "ir-sql");
      }
      break;
    }
  }
  for (const c of n.namedChildren) walk(c, taint, lines, hits);
}
function scope(fn, taint, lines, hits) {
  // the handler's request parameters (paramSources reads decorators + signature) : the whole decorator block above
  // the def, not a fixed 3 lines (`@router.get(\n "/…/{table}/rows",\n dependencies=[…],\n)` spans 4 — DB-GPT)
  const row = fn.startPosition.row;
  let top = row;
  while (top > 0 && row - top < 12 && /^\s*(?:@|[)\]"',]|\w+\s*=|\S.*[,(]\s*$)/.test(lines[top - 1] ?? "")) top--;
  for (let i = top; i <= row; i++) for (const v of paramSources(lines, i)) taint.set(v, "user");
  const body = fn.childForFieldName("body");
  if (body) walk(body, taint, lines, hits);
}

/** Scan one file → [{line, kind:"ir-sql"}], or null when the file has no loaded grammar (caller keeps the line reader). */
export function extractSqliIr(text, file) {
  const p = parseFile(text, file);
  if (!p) return null;
  const lines = String(text).split(/\r?\n/);
  const hits = new Map();
  depth = 0;
  try { walk(p.tree.rootNode, new Map(), lines, hits); }
  catch { return null; }                       // never throw from an extractor : the caller keeps the line reader
  finally { p.tree.delete?.(); }
  return [...hits].map(([line, kind]) => ({ line, kind })).sort((a, b) => a.line - b.line);
}
