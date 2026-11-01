// The untrusted-input model (sources.mjs, expert panel P1-5). Each probe was a miss on main : a framework fills the
// value from the request (Spring, .NET, FastAPI, Flask, Next.js, Laravel), an MCP client chooses it, or a model
// produced it. Controls : an undecorated function's parameters, an unrelated decorator and a FastAPI dependency stay clean.
import { test } from "node:test";
import assert from "node:assert/strict";
import { paramSources } from "../sources.mjs";
import { extractCmdi } from "../cmdi-extract.mjs";
import { extractSqli } from "../sqli-extract.mjs";
import { extractSsrf } from "../ssrf-extract.mjs";
import { extractXss } from "../xss-extract.mjs";
import { extractPathTraversal } from "../pathtraversal-extract.mjs";

const n = (fn, src, file) => fn(src, new Map(), file).length;

test("paramSources names the framework-filled parameters only", () => {
  assert.deepEqual(paramSources(['public List<User> find(@RequestParam String name, @PathVariable("id") Long id, Model model) {'], 0), ["name", "id"]);
  assert.deepEqual(paramSources(["public IActionResult Get([FromQuery] string q, [FromRoute] int id, ILogger log)"], 0), ["q", "id"]);
  assert.deepEqual(paramSources(['@app.get("/items")', "async def read(q: str, db: Session = Depends(get_db)):"], 1), ["q"]);
  assert.deepEqual(paramSources(['@bp.route("/f/<name>")', "def f(name):"], 1), ["name"]);
  assert.deepEqual(paramSources(['server.tool("run", { command: z.string() }, async ({ command, cwd }) => {'], 0), ["command", "cwd"]);
  assert.deepEqual(paramSources(["@mcp.tool()", "def run(command: str, ctx: Context):"], 1), ["command"]);
  assert.deepEqual(paramSources(["def helper(name, path):"], 0), [], "an undecorated function's parameters are not sources");
  assert.deepEqual(paramSources(["@functools.lru_cache()", "def helper(name):"], 1), [], "an unrelated decorator is not a route");
});

test("framework-filled values now reach the sinks", () => {
  assert.equal(n(extractSqli, 'public List<User> find(@RequestParam String name) {\n  return jdbc.queryForList("SELECT * FROM u WHERE n=\'" + name + "\'");\n}', "U.java"), 1, "Spring @RequestParam → SQL");
  assert.equal(n(extractSqli, '@app.get("/items")\nasync def read(q: str):\n    cursor.execute("SELECT * FROM t WHERE n = \'" + q + "\'")', "api.py"), 1, "FastAPI param → SQL");
  assert.equal(n(extractCmdi, 'export async function GET(req) {\n  const host = req.nextUrl.searchParams.get("h");\n  execSync("ping " + host);\n}', "route.ts"), 1, "Next.js searchParams → command");
  assert.equal(n(extractSsrf, '@app.route("/proxy/<path:target>")\ndef proxy(target):\n    return requests.get(target).text', "app.py"), 1, "Flask route param → SSRF");
  assert.equal(n(extractXss, 'app.get("/x", (req, res) => {\n  const h = req.cookies.theme;\n  el.innerHTML = h;\n});', "x.js"), 1, "req.cookies → HTML");
  assert.equal(n(extractPathTraversal, 'public function show(Request $request) {\n  $f = $request->input("file");\n  readfile($f);\n}', "C.php"), 1, "Laravel $request->input → read path");
});

test("MCP tool arguments and LLM output are untrusted", () => {
  assert.equal(n(extractCmdi, 'server.tool("run", { command: z.string() }, async ({ command }) => {\n  return execSync(command).toString();\n});', "server.ts"), 1, "MCP tool argument → command");
  assert.equal(n(extractCmdi, "const out = completion.choices[0].message.content;\nexecSync(out);", "agent.js"), 1, "LLM output → command");
});

test("CONTROL : a plain library function's parameter stays clean", () => {
  assert.equal(n(extractCmdi, "function build(cmd) {\n  return execSync(cmd);\n}", "lib.js"), 0);
  assert.equal(n(extractSqli, "def find(name):\n    cursor.execute('SELECT * FROM t WHERE n = ' + name)", "lib.py"), 0);
});
