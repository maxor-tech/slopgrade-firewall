// A trailing comment never decides a sink or a sanitizer (expert-panel red team 2026-10-31) : `// sanitize` and
// `// validate` on a code line used to clear the taint of a request value, so the finding vanished. A real sanitizer call
// still clears it, and a `#` inside code (a JS private field, a Ruby interpolation) is not a comment.
import { test } from "node:test";
import assert from "node:assert/strict";
import { codeOnly } from "../taint-core.mjs";
import { extractCmdi } from "../cmdi-extract.mjs";
import { extractXss } from "../xss-extract.mjs";

const kinds = (hits) => hits.map((h) => h.kind);
const CMD = "const cp = require('child_process');\napp.get('/r', (req, res) => {\n  const c = req.query.cmd;\n  cp.exec(c);\n});";
const XSS = "app.get('/x', (req, res) => {\n  const h = req.query.h;\n  el.innerHTML = h;\n});";

test("codeOnly cuts comments and keeps quoted text and code #", () => {
  assert.equal(codeOnly("el.innerHTML = h; // sanitize"), "el.innerHTML = h; ");
  assert.equal(codeOnly("x = 1  # validate it"), "x = 1  ");
  assert.equal(codeOnly("a = b /* escape */ + c"), "a = b   + c");
  assert.equal(codeOnly('u = "http://x/y" // c'), 'u = "http://x/y" ');
  assert.equal(codeOnly("this.#x = 1"), "this.#x = 1");
  assert.equal(codeOnly('s = "#{name}"'), 's = "#{name}"');
  assert.equal(codeOnly(String.raw`s = 'it\'s // not' + t`), String.raw`s = 'it\'s // not' + t`);
});

test("a sanitizer word in a comment no longer clears the taint", () => {
  assert.deepEqual(kinds(extractCmdi(CMD.replace("  cp.exec(c);", "  console.log(c); // validate\n  cp.exec(c);"), new Map(), "r.js")), ["taint-cmd"]);
  assert.deepEqual(kinds(extractXss(XSS.replace("el.innerHTML = h;", "el.innerHTML = h; // sanitize"), new Map(), "x.js")), ["taint-xss"]);
});

test("CONTROL : a real sanitizer call still clears the taint", () => {
  assert.deepEqual(kinds(extractXss(XSS.replace("el.innerHTML = h;", "el.innerHTML = DOMPurify.sanitize(h);"), new Map(), "x.js")), []);
  assert.deepEqual(kinds(extractCmdi(CMD.replace("  cp.exec(c);", "  const s = shellEscape(c);\n  c = s;\n  cp.exec(c);"), new Map(), "r.js")), []);
});
