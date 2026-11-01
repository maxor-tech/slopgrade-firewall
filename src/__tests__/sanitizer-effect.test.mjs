// A sanitizer acts by its EFFECT, not by being named on a line (expert panel 2026-10-31, P0-4). Probes from the panel :
// an ignored `escape(id);`, `s = escapeHtml(h)` (which used to clean `h` itself), `el.textContent = h`, and a bare
// `if (u) {` all made a request value look safe. Controls : a real reassignment, a rejecting validation guard and a
// validator statement still clear.
import { test } from "node:test";
import assert from "node:assert/strict";
import { extractXss } from "../xss-extract.mjs";
import { extractSqli } from "../sqli-extract.mjs";
import { extractSsrf } from "../ssrf-extract.mjs";

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
