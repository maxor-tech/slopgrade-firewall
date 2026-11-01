// SSRF taint follows a NEW variable when the tainted value controls the host (expert panel P0-3 : recall-benchmark
// pinned `full = u + '/x'` as invisible). A value appended after a fixed host only picks a path and stays clean.
import { test } from "node:test";
import assert from "node:assert/strict";
import { extractSsrf } from "../ssrf-extract.mjs";

const n = (src) => extractSsrf(src, new Map()).length;

test("a tainted base URL carried into a new variable reaches the sink", () => {
  assert.equal(n("function h(req){\n  const u = req.query.base;\n  const full = u + '/x';\n  fetch(full);\n}"), 1);
  assert.equal(n("function h(req){\n  const host = req.query.h;\n  const url = `https://${host}/api`;\n  fetch(url);\n}"), 1);
  assert.equal(n("def h():\n  host = request.args['h']\n  url = 'https://' + host + '/api'\n  requests.get(url)"), 1);
  assert.equal(n("def h():\n  base = request.args['b']\n  url = f\"{base}/v1/items\"\n  requests.get(url)"), 1);
  assert.equal(n("def h():\n  base = request.args['b']\n  first = base + '/x'\n  second = first + '?q=1'\n  requests.get(second)"), 1);
});

test("CONTROL : a user value after a fixed host is a path, not SSRF", () => {
  assert.equal(n("function h(req){\n  const id = req.query.id;\n  const url = 'https://api.example.com/users/' + id;\n  fetch(url);\n}"), 0);
  assert.equal(n("function h(req){\n  const id = req.query.id;\n  const url = `${API_BASE}/users/${id}`;\n  fetch(url);\n}"), 0);
  assert.equal(n("def h():\n  q = request.args['q']\n  url = BASE + '/search?q=' + q\n  requests.get(url)"), 0);
});
