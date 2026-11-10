// Surface delta (0.17.0) — does this PR ADD a network entry point (route, handler, socket event, server, MCP tool)?
// Deterministic, $0, no egress. Ported 1:1 from the slopGrade research detector (novelty n2_surface_delta.py, PREREG-N2):
// the same regex list over the ADDED lines, outside tests / examples / docs.
//
// Why it matters (measured, REPORT.md §2.1-2.5): in AI-written commits, 36 of 90 real flaws are a missing access check
// and 15 a missing size / rate bound — absent controls on new surface. On 140 fresh labeled commits that add an entry
// point, 19 held a real flaw (13.6 %), against 0.92 % of commits that add none: about 15x. The focused AI pass
// (ai-review.mjs AI_FOCUS_SYSTEM) runs only where this returns surface: true.

const ROUTE = [
  /\b(?:app|router|api|server|fastify|hono|route|routes|\w+Router|\w+App)\.(?:get|post|put|patch|delete|all|options|ws|websocket)\(\s*[`'"/]/,
  /export\s+(?:async\s+)?function\s+(?:GET|POST|PUT|PATCH|DELETE)\b/,
  /export\s+const\s+(?:GET|POST|PUT|PATCH|DELETE)\s*=/,
  /\b(?:socket|io|ws|wss|client|conn|connection)\.on\(\s*[`'"]/,
  /\b(?:public|protected)Procedure\b|\.(?:query|mutation)\(\s*(?:async)?\s*\(/,
  /@(?:app|router|bp|api|blueprint|\w+_bp|\w+_router|mcp|server)\.(?:get|post|put|patch|delete|route|websocket|tool|resource)\(/,
  /@api_view\(|@action\(|\b(?:path|re_path|url)\(\s*r?[`'"]/,
  /\.(?:GET|POST|PUT|PATCH|DELETE|Handle|HandleFunc|Methods)\(\s*"/,
  /@(?:Get|Post|Put|Delete|Patch|Request|Message)Mapping\b|@Path\(|@(?:GET|POST|PUT|DELETE)\b/,
  /\[Http(?:Get|Post|Put|Delete|Patch)|\.Map(?:Get|Post|Put|Delete|Patch|Hub)\(/,
  /^\s*(?:get|post|put|patch|delete|resources?|match)\s+[:'"]/,
  /Route::(?:get|post|put|patch|delete|any|match|resource|apiResource)\(/,
  /\.route\(\s*"|#\[(?:get|post|put|delete|patch)\(/,
  /addEventListener\(\s*['"](?:fetch|message)['"]|onmessage\s*=|\bserver\.tool\(|registerTool\(/,
  /createServer\(|\.listen\(|serve\(\s*\{|Deno\.serve|Bun\.serve|http\.ListenAndServe/,
];
const NEWFILE_ROUTE = /(?:^|\/)(?:app|pages)\/api\/|\/route\.(?:ts|js)$|(?:^|\/)routes?\/|(?:^|\/)(?:controllers?|handlers?|endpoints?|views)\//i;
const TESTPATH = /(?:^|\/)(?:tests?|__tests__|spec|e2e|fixtures?|mocks?|examples?|docs?)\/|\.(?:test|spec)\.|_test\.|\.md$|\.json$|\.ya?ml$|\.lock$/i;

/**
 * hunks ([{ path, text }], text = the hunk's ' ' / '+' / '-' lines) -> { surface, routeLines, newRoutedFiles }.
 * routeLines = added route lines not also removed in the same file (a move is not new surface).
 * newRoutedFiles = files under a routed directory with 5+ added lines and none removed (a new handler file).
 */
export function surfaceDelta(hunks) {
  const added = new Map(), removed = new Map();
  for (const hk of Array.isArray(hunks) ? hunks : []) {
    const path = String(hk?.path ?? "");
    if (!path || TESTPATH.test(path)) continue;
    for (const l of String(hk?.text ?? "").split("\n")) {
      if (l[0] === "+" && !l.startsWith("+++")) { if (!added.has(path)) added.set(path, []); added.get(path).push(l.slice(1)); }
      else if (l[0] === "-" && !l.startsWith("---")) { if (!removed.has(path)) removed.set(path, []); removed.get(path).push(l.slice(1)); }
    }
  }
  let routeLines = 0, newRoutedFiles = 0;
  for (const [path, lines] of added) {
    const rem = (removed.get(path) ?? []).join("\n");
    for (const l of lines) if (ROUTE.some((r) => r.test(l)) && !rem.includes(l.trim())) routeLines++;
    if (!removed.has(path) && NEWFILE_ROUTE.test(path) && lines.length >= 5) newRoutedFiles++;
  }
  return { surface: routeLines > 0 || newRoutedFiles > 0, routeLines, newRoutedFiles };
}
