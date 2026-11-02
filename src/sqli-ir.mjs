// SQL keeps its existing vocabulary and bound-argument rules; shared dataflow adds joins and local summaries.
import { runTaintIr } from "./taint-ir.mjs";
import { REQ, SINK, SQL_SANITIZE } from "./sqli-extract.mjs";
import { FRAMEWORK_SOURCE } from "./sources.mjs";

// The Rails `params[…]` / `params.require` source is Ruby ; the tree reads Python / JS / TS / PHP / Go, where
// `params[…]` is an ordinary dict / array (DocsGPT `inspect.signature(…).parameters["table_name"]` — 5,300-repo sweep).
const RAILS_PARAMS = REQ.indexOf("|(?<![\\w.$])params");
if (RAILS_PARAMS < 0) throw new Error("sqli-ir : the Rails params source moved in sqli-extract REQ");
const SOURCE_RE = new RegExp(`${REQ.slice(0, RAILS_PARAMS)}|${FRAMEWORK_SOURCE}`);
const SINKS = new Set(SINK.split("|"));
const SQL_TEXT = /\b(?:SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM|DELETE|WHERE|FROM|VALUES|ORDER\s+BY|GROUP\s+BY|UNION|DROP\s+TABLE)\b/i;
const CAST = /^(?:int|float|bool|Number|parseInt|parseFloat|Boolean|BigInt|uuid\.UUID|UUID)$/;
const STRINGS = new Set(["string", "template_string", "concatenated_string", "string_fragment", "string_content"]);
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

const SPEC = {
  sourceRe: SOURCE_RE,
  isClean: (name) => SQL_SANITIZE.test(name) || CAST.test(name),
  sinkArg(call) {
    const f = call.childForFieldName("function");
    const name = f?.childForFieldName("attribute") ?? f?.childForFieldName("property") ?? f;
    // `fileRegex.exec(text)` / `/x/.exec(s)` is a regular-expression match, not a SQL call (5,300-repo sweep
    // 2026-11-01 : 5 false hits in one LLM-output parser once the loop join carried the model's text into the loop).
    const recv = f?.childForFieldName("object");
    if (recv && /^(?:exec|test|match)$/.test(name?.text ?? "")
      && (recv.type === "regex" || /(?:regexp?|pattern)$/i.test(recv.text) || /(?:^(?:re|rx)|[a-z0-9_](?:Re|Rx|_re|_rx))$/.test(recv.text))) return null;
    return SINKS.has(name?.text) ? firstArg(call) : null;
  },
  hitKind: (r) => r.sql || (r.user && r.lit) ? "ir-sql" : null,
  langs: ["python", "javascript", "typescript", "tsx"],   // the injection specs' vocabulary ; php / go keep the line reader
  textGate: new RegExp(`\\b(?:${SINK})\\b`),   // the sink names sinkArg accepts
  interprocKind: "ir-sql-interproc",
  textFact: (n) => STRINGS.has(n.type) && SQL_TEXT.test(n.text),
};

/** Scan one file, or null when the caller must retain its line reader. */
export function extractSqliIr(text, file) { return runTaintIr(text, file, SPEC); }
