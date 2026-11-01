// Logical statements (expert panel P0-3, first layer) : a call broken across lines is read whole on its first line
// (line numbers kept), a block opener is never joined, and several `;` statements on one line are read in order.
import { test } from "node:test";
import assert from "node:assert/strict";
import { logicalLines } from "../lang-scope.mjs";
import { statementsOf } from "../taint-core.mjs";
import { extractDeser } from "../deser-extract.mjs";
import { extractCmdi } from "../cmdi-extract.mjs";
import { extractSsrf } from "../ssrf-extract.mjs";

test("a call broken across lines is joined on its first line ; the line count stays", () => {
  assert.deepEqual(logicalLines(["data = yaml.load(raw,", "    Loader=yaml.SafeLoader)", "x = 1"]), ["data = yaml.load(raw, Loader=yaml.SafeLoader)", "", "x = 1"]);
  assert.deepEqual(logicalLines(["q = db.table('t')", "  .where(id)"]), ["q = db.table('t') .where(id)", ""]);
  assert.deepEqual(logicalLines(["subprocess.run(cmd,  # run it", "    shell=True)"]), ["subprocess.run(cmd, shell=True)  # run it", ""]);
});

test("a block opener is not joined, and a joined statement stops at JOIN_MAX lines", () => {
  assert.deepEqual(logicalLines(["app.get('/x', (req, res) => {", "  const h = req.query.h;", "});"]), ["app.get('/x', (req, res) => {", "  const h = req.query.h;", "});"]);
  const runaway = ["f("].concat(Array.from({ length: 30 }, () => "  a,"));
  assert.equal(logicalLines(runaway).filter((l) => l === "").length, 12);
});

test("statementsOf splits top-level `;` and block openers, never a string, a for header or an object literal", () => {
  assert.deepEqual(statementsOf("function h(req){ const u = req.query.b; fetch(u) }"), ["function h(req){", " const u = req.query.b", " fetch(u) }"]);
  assert.deepEqual(statementsOf("const opts = { url: req.query.u }; axios(opts)"), ["const opts = { url: req.query.u }", " axios(opts)"]);
  assert.deepEqual(statementsOf("for (let i = 0; i < n; i++) x(i)"), ["for (let i = 0; i < n; i++) x(i)"]);
  assert.deepEqual(statementsOf('s = "a;b"; t = 1'), ['s = "a;b"', " t = 1"]);
});

test("the extractors read the joined statement : a split safe loader stays safe, a split shell flag and one-line flows fire", () => {
  assert.equal(extractDeser("data = yaml.load(raw,\n    Loader=yaml.SafeLoader)", "a.py").length, 0);
  assert.equal(extractCmdi("def h():\n  cmd = request.args['c']\n  subprocess.run(cmd,\n      shell=True)", new Map(), "a.py").length, 1);
  assert.equal(extractSsrf("function h(req){ const u = req.query.base; const full = u + '/x'; fetch(full) }", new Map()).length, 1);
});
