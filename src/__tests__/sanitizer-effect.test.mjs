// A sanitizer acts by its EFFECT, not by being named on a line (expert panel 2026-10-31, P0-4). Probes from the panel :
// an ignored `escape(id);`, `s = escapeHtml(h)` (which used to clean `h` itself), `el.textContent = h`, and a bare
// `if (u) {` all made a request value look safe. Controls : a real reassignment, a rejecting validation guard and a
// validator statement still clear.
import { test } from "node:test";
import assert from "node:assert/strict";
import { extractXss } from "../xss-extract.mjs";
import { extractSqli } from "../sqli-extract.mjs";
import { extractSsrf } from "../ssrf-extract.mjs";
import { extractPathTraversal } from "../pathtraversal-extract.mjs";

const n = (hits) => hits.length;
const xss = (body) => n(extractXss(`app.get('/x', (req, res) => {\n  const h = req.query.h;\n${body}\n});`, new Map(), "x.js"));
const sql = (body) => n(extractSqli(`def h():\n  id = request.args['id']\n${body}`, new Map(), "app.py"));
const ssrf = (body) => n(extractSsrf(`def h():\n  url = request.args['u']\n${body}`, new Map(), "app.py"));

test("a pure transform cleans only the value it returns", () => {
  assert.equal(xss("  const s = escapeHtml(h);\n  el.innerHTML = h;"), 1, "h itself stays tainted after s = escapeHtml(h)");
  assert.equal(xss("  const s = escapeHtml(h);\n  el.innerHTML = s;"), 0, "the escaped copy is clean");
  assert.equal(xss("  el.textContent = h;\n  el.innerHTML = h;"), 1, "a safe sink does not clean the value");
  assert.equal(sql("  escape(id)\n  cursor.execute('SELECT * FROM t WHERE id=' + id)"), 1, "an ignored escape() result does nothing");
  assert.equal(sql("  q = 'SELECT * FROM t WHERE a=' + escape(id) + ' AND b=' + request.args['b']\n  cursor.execute(q)"), 1, "a raw part keeps the query tainted");
});

test("a guard validates only when it checks the value and rejects", () => {
  assert.equal(ssrf("  if url:\n    pass\n  requests.get(url)"), 1, "a truthiness test is not validation");
  assert.equal(ssrf("  if not url: return\n  requests.get(url)"), 1, "a null check is not validation");
});

test("CONTROL : a reassignment, a rejecting guard or a validator statement still clear", () => {
  assert.equal(ssrf("  if not is_allowed(url): abort(403)\n  requests.get(url)"), 0);
  assert.equal(ssrf("  url = validate_host(url)\n  requests.get(url)"), 0);
  assert.equal(ssrf("  if urlparse(url).hostname not in ALLOWED_HOSTS:\n    abort(400)\n  requests.get(url)"), 0);
  assert.equal(sql("  id = escape(id)\n  cursor.execute('SELECT * FROM t WHERE id=' + id)"), 0);
  assert.equal(xss("  el.innerHTML = DOMPurify.sanitize(h);"), 0);
});

// Evidence harvest v7 (2026-11-02, blind labels) : Jinja `Markup(...).striptags()` returns plain text with every tag
// removed — not an HTML sink value. Mirrors the server round 5 (maxor-tech/slopgrade#1595).
test("striptags : Markup(request...).striptags() is plain text ; Markup(request...) alone still fires", () => {
  const py = (line) => extractXss(`@app.route("/n")\ndef n():\n    name = ${line}\n    return "<p>" + name + "</p>"\n`, new Map(), "app.py").map((h) => h.line);
  assert.deepEqual(py('Markup(request.args["n"]).striptags()'), []);
  assert.deepEqual(py('Markup(request.args["n"])'), [3]);
});

// Value-flow exemptions (2026-11-02, mirror of maxor-tech/slopgrade#1599) : a constant ternary, a constant table entry,
// a non-HTML response, an inline character strip. Each has a CONTROL that still fires.
test("value flow : constant ternary, constant table, non-HTML response, inline strip are not HTML sinks", () => {
  const L = (c, f) => extractXss(c, new Map(), f).map((h) => h.line);
  assert.deepEqual(L(`<input <?php echo $_COOKIE ["split"] ? ' checked' : ''; ?> />\n`, "boxes.php"), []);
  assert.deepEqual(L(`<p><?php echo $_COOKIE["split"]; ?></p>\n`, "boxes.php"), [1]);
  assert.deepEqual(L("function b(el) {\n  const v = location.hash.slice(1);\n  el.innerHTML = ICONS[v];\n}\n", "c.js"), []);
  assert.deepEqual(L("function b(el) {\n  const v = location.hash.slice(1);\n  el.innerHTML = v;\n}\n", "c.js"), [3]);
  assert.deepEqual(L("app.get('/pl', (req, res) => {\n  res.setHeader('Content-Disposition', 'attachment; filename=a.xspf');\n  res.send('<track>' + req.query.name);\n});\n", "p.js"), []);
  assert.deepEqual(L("app.get('/p', (req, res) => {\n  res.send('<h1>' + req.query.name);\n});\n", "p.js"), [2]);
  const strip = (s) => "function px(div, Xt_i) {\n  var Xt_r = document.referrer;\n  div.innerHTML = Xt_i + '&ref=' + Xt_r" + s + " + '\" title=\"x\">';\n}\n";
  assert.deepEqual(L(strip(".replace(/[<>\"]/g, '')"), "s.js"), []);
  assert.deepEqual(L(strip(""), "s.js"), [3]);
});

// Path-traversal sanitizer summaries (2026-11-02, mirror of maxor-tech/slopgrade#1604) : a same-file helper whose BODY
// contains the path cleans its result ; a helper that only joins keeps the taint.
test("path : a containing helper cleans its result ; a plain joiner keeps the taint", () => {
  const L = (c, f) => extractPathTraversal(c, new Map(), f).map((h) => h.line);
  const safe = ["function getFilename(name) {", "  if (name.includes('..')) throw new Error('bad');", "  return path.join(DIR, name);", "}",
    "app.get('/s', (req, res) => {", "  const filename = getFilename(req.query.name);", "  fs.unlink(path.join(DIR, filename), () => res.end());", "});", ""].join("\n");
  assert.deepEqual(L(safe, "service.js"), []);
  assert.deepEqual(L(safe.replace("  if (name.includes('..')) throw new Error('bad');\n", ""), "service.js"), [6]);
});
