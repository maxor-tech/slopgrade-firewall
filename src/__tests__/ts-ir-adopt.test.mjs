// The pro bundle is its own module on the runner : it has no tree-sitter runtime of its own, so the client lends its
// parser. A second instance of ts-ir stands in for the bundle's copy, because a module has one state per URL.
import { test } from "node:test";
import assert from "node:assert/strict";

const fresh = (tag) => import(`../ts-ir.mjs?instance=${tag}`);

test("an instance with no runtime reads nothing, then reads through the instance that lent it one", () => {
  return fresh("a").then((bundle) => {
    assert.equal(bundle.irReady("a.js"), false);
    assert.equal(bundle.parseFile("x", "a.js"), null);
    const lent = { irReady: (f) => f.endsWith(".js"), parseFile: (text, file) => ({ tree: text, lang: file }) };
    bundle.adoptIr(lent);
    assert.equal(bundle.irReady("a.js"), true);
    assert.equal(bundle.irReady("a.py"), false);
    assert.deepEqual(bundle.parseFile("x", "a.js"), { tree: "x", lang: "a.js" });
  });
});

test("a malformed lender is refused : the instance stays on its own, empty runtime", () => {
  return fresh("b").then((bundle) => {
    for (const bad of [null, undefined, {}, { parseFile: () => null }, { irReady: "x", parseFile: () => null }]) {
      bundle.adoptIr(bad);
      assert.equal(bundle.irReady("a.js"), false);
      assert.equal(bundle.parseFile("x", "a.js"), null);
    }
  });
});
