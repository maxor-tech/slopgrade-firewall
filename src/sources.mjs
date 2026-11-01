// Untrusted-input model shared by the taint consumers (expert panel 2026-10-31, P1-5). The consumers used to know only
// the web-request objects (`req.query`, `request.args`, `$_GET`, `params[…]`) ; framework-typed inputs, LLM output and
// MCP tool arguments were invisible (panel probes : Spring `@RequestParam`, FastAPI params, `nextUrl.searchParams`,
// Laravel `$request->input`, an MCP handler's `{ command }`, `completion.choices[0].message.content`). Two parts :
//   · FRAMEWORK_SOURCE — an inline accessor that returns request or model data, matched like the request objects ;
//   · paramSources(lines, i) — the parameters of the handler DECLARED at line i that a framework fills from the request
//     (or an MCP client), seeded as tainted when the function body starts.
// Library functions and plain parameters stay clean : a parameter is a source only when a route / tool marker says so.

export const FRAMEWORK_SOURCE = [
  // Next.js / Web Request : URL params and parsed bodies
  "\\b(?:nextUrl\\s*\\.\\s*)?searchParams\\s*\\.\\s*(?:get|getAll)\\s*\\(",
  "\\bawait\\s+(?:req|request)\\s*\\.\\s*(?:json|formData|text)\\s*\\(\\s*\\)",
  // Express extras
  "\\breq\\s*\\.\\s*(?:headers|cookies|files|file)\\b",
  // Laravel / Symfony
  "\\$request\\s*->\\s*(?:input|query|get|post|all|only|route|cookie|header|json)\\s*\\(",
  "\\bRequest\\s*::\\s*(?:input|query|get|all)\\s*\\(",
  // (Go handlers are read by the go* extractors, which keep their own source lists — no Go accessor belongs here.)
  // LLM output : OpenAI-style and Anthropic-style completions
  "\\.\\s*choices\\s*\\[\\s*\\d+\\s*\\]\\s*\\.\\s*(?:message\\s*\\.\\s*content|text)\\b",
  "\\.\\s*content\\s*\\[\\s*\\d+\\s*\\]\\s*\\.\\s*text\\b",
  "\\.\\s*output_text\\b",
].join("|");
export const FRAMEWORK_SOURCE_RE = new RegExp(FRAMEWORK_SOURCE);

// Java / Kotlin (Spring) : an annotated handler parameter.
const SPRING_PARAM = /@(?:RequestParam|PathVariable|RequestBody|RequestHeader|CookieValue|ModelAttribute|RequestPart)\b(?:\s*\([^)]*\))?\s+(?:final\s+)?[\w.<>\[\], ?]+?\s+(\w+)\s*(?=[,)])/g;
// .NET : a binding-source attribute on an action parameter.
const DOTNET_PARAM = /\[\s*From(?:Query|Route|Body|Form|Header)\b(?:\s*\([^)]*\))?\s*\]\s*[\w.<>\[\]?]+\s+(\w+)/g;
// Python : a route or MCP-tool decorator on the lines above a `def`.
const PY_ROUTE_DECORATOR = /^\s*@[\w.]*\b(?:route|get|post|put|patch|delete|api_route|websocket|tool)\s*\(/;
const PY_DEF = /^\s*(?:async\s+)?def\s+\w+\s*\(([^)]*)\)/;
const PY_NOT_INPUT = /^(?:self|cls|request|req|db|session|background_tasks|current_user|user|ctx|context|response)$/;
// JS / TS : an MCP tool handler `server.tool("name", schema, async ({ a, b }) =>` (also registerTool).
const MCP_JS_HANDLER = /\.\s*(?:tool|registerTool)\s*\(\s*["'`][^"'`]+["'`][\s\S]*?\(\s*\{([^}]*)\}\s*(?::\s*[^)]*)?\)\s*=>/;

/** The names a framework fills from untrusted input, for the handler declared at line i (empty when none). */
export function paramSources(lines, i) {
  const l = String(lines[i] ?? "");
  const out = [];
  for (const m of l.matchAll(SPRING_PARAM)) out.push(m[1]);
  for (const m of l.matchAll(DOTNET_PARAM)) out.push(m[1]);
  const mcp = MCP_JS_HANDLER.exec(l);
  if (mcp) for (const raw of mcp[1].split(",")) { const n = raw.trim().split(/[:=]/)[0].trim(); if (/^[A-Za-z_$][\w$]*$/.test(n)) out.push(n); }
  const def = PY_DEF.exec(l);
  if (def) {
    let decorated = false;
    // Walk up over the decorators, including the continuation lines of one split over several lines
    // (`@router.get(\n    "/x/{table}",\n    dependencies=[…],\n)` — DB-GPT, 2026-11-01 real-code sweep).
    for (let j = i - 1; j >= 0 && j >= i - 10; j--) {
      const p = String(lines[j]);
      if (!p.trim()) continue;
      if (/^\s*@/.test(p)) { if (PY_ROUTE_DECORATOR.test(p)) { decorated = true; break; } continue; }
      if (/^\s*(?:\)|\]|["'].*[,)]?\s*$|\w+\s*=.*,?\s*$)/.test(p)) continue;   // inside a decorator's arguments
      break;
    }
    if (decorated) {
      for (const raw of def[1].split(",")) {
        if (/Depends\s*\(|Security\s*\(/.test(raw)) continue;
        const n = raw.trim().replace(/^\*+/, "").split(/[:=]/)[0].trim();
        if (/^[A-Za-z_]\w*$/.test(n) && !PY_NOT_INPUT.test(n)) out.push(n);
      }
    }
  }
  return out;
}

// ── Opt-in sources (expert panel P1-5 ; Jeff 2026-11-01 : opt-in per repo) ─────────────────────────────────────
// CLI arguments and queue-message payloads are untrusted only for a repo that says so (the Action input
// `untrusted-inputs: "cli,queue"`) : a CLI tool runs with its own user's privileges, so treating argv as hostile in every
// repo would block intended behaviour. Off by default ; the shared taint engine (taint-core.mjs) reads optInSource().
const OPT_IN_PATTERNS = {
  // Python sys.argv / argparse namespace, Node process.argv, Go os.Args / flag.Arg(s), Ruby ARGV, Java/C# main args[i]
  // (`args = parser.parse_args()` : the whole argparse namespace — persona walk 2026-11-01)
  cli: /\bsys\s*\.\s*argv\b|\bparse_args\s*\(|\bprocess\s*\.\s*argv\b|\bos\s*\.\s*Args\b|\bflag\s*\.\s*Args?\s*\(|\bARGV\b|\bargs\s*\[\s*\d+\s*\]/,
  // a consumed message : SQS / SNS / Lambda event records, Kafka / RabbitMQ / NATS / Pub-Sub payloads — attribute
  // (`message.value`) or subscript (`record["body"]`, the Python SQS form — persona walk 2026-11-01)
  queue: /\b(?:message|msg|rec|record|event|evt|delivery|payload)\s*(?:\.\s*(?:body|value|data|payload|Body|Value|Data)\b|\[\s*["'](?:body|Body|value|data|payload|Message)["']\s*\])|\bRecords\s*\[[^\]]*\]\s*\.\s*(?:body|Sns|kinesis)\b|\.\s*(?:receive_message|consume|poll)\s*\(/,
};
let optIn = [];
/** The tokens of an opt-in spec : comma and / or space separated, lower-cased. */
export const optInTokens = (spec) => String(spec ?? "").split(/[\s,;]+/).map((s) => s.trim().toLowerCase()).filter(Boolean);
/** Turn the opt-in sources on for this run : `cli` / `queue`, comma or space separated (unknown tokens are ignored —
 *  the caller names them, see optInTokens). */
export function setOptInSources(spec) {
  optIn = [...new Set(optInTokens(spec).filter((k) => Object.prototype.hasOwnProperty.call(OPT_IN_PATTERNS, k)))];
  return [...optIn];
}
/** True when an expression reads an opted-in source (always false when nothing is opted in). */
export function optInSource(expr) {
  if (!optIn.length) return false;
  const s = String(expr ?? "");
  return optIn.some((k) => OPT_IN_PATTERNS[k].test(s));
}
