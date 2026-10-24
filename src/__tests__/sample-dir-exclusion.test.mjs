// P4 (benchmark 2026-10-24): sample / tutorial / lab directories beyond examples/ are excluded from the walk and ranked
// as dev-only for Deep Scan. Product directories with a similar spelling are not.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { walk, SAMPLE_DIR_SRC } from "../extract.mjs";
import { DEV_PATH } from "../deep-scan.mjs";

const SKIPPED = [
  "spring-cloud-alibaba-examples/a/App.java", "aws-doc-sdk-examples/x.py", "acme-samples/x.js", "shop-demo/x.js",
  "docs-demos/x.js", "example-app/x.js", "examples-basic/x.js", "tutorial/x.js", "tutorials/x.js", "courses/x.js",
  "labs/x.js", "workshop/x.js", "workshops/x.js", "deep/nested/my_samples/x.js", "Foo-Examples/x.js",
];
const KEPT = [
  "exampleservice/x.js", "sampler/x.js", "demographics/x.js", "labstore/x.js", "samplesheet/x.js", "lab/x.js",
  "src/main/x.js", "demo/../x.js".replace("demo/../", ""), "tutorialize/x.js", "coursework/x.js", "workshopper/x.js",
  "my-exampleservice/x.js", "sample/../keep.js".replace("sample/../", ""),
];

function tree(files) {
  const root = mkdtempSync(join(tmpdir(), "sg-sample-"));
  for (const f of files) {
    const p = join(root, f);
    mkdirSync(join(p, ".."), { recursive: true });
    writeFileSync(p, "x\n");
  }
  return root;
}
const rel = (root, list) => list.map((p) => p.slice(root.length + 1)).sort();

test("walk skips sample / tutorial / lab directories", () => {
  const root = tree([...SKIPPED, "keep/ok.js"]);
  try { assert.deepEqual(rel(root, walk(root, /\.(js|java|py)$/)), ["keep/ok.js"]); } finally { rmSync(root, { recursive: true, force: true }); }
});

test("walk keeps product directories with a similar spelling", () => {
  const root = tree(KEPT);
  try { assert.deepEqual(rel(root, walk(root, /\.js$/)), [...KEPT].sort()); } finally { rmSync(root, { recursive: true, force: true }); }
});

test("a repo ROOT named like a sample dir is still scanned (match is root-relative)", () => {
  const base = mkdtempSync(join(tmpdir(), "sg-base-"));
  const root = join(base, "acme-demo");
  mkdirSync(join(root, "src"), { recursive: true });
  writeFileSync(join(root, "src", "app.js"), "x\n");
  try { assert.deepEqual(rel(root, walk(root, /\.js$/)), ["src/app.js"]); } finally { rmSync(base, { recursive: true, force: true }); }
});

test("a custom exclusion regex is untouched by the sample-dir widening", () => {
  const root = tree(["tutorials/x.js", "keep/y.js"]);
  try { assert.deepEqual(rel(root, walk(root, /\.js$/, /nomatch/)), ["keep/y.js", "tutorials/x.js"]); } finally { rmSync(root, { recursive: true, force: true }); }
});

test("DEV_PATH ranks the same sample segments as dev-only and leaves product dirs alone", () => {
  for (const p of SKIPPED) assert.ok(DEV_PATH.test(p), p);
  for (const p of ["src/main/x.js", "exampleservice/x.js", "sampler/x.js", "demographics/x.js", "labstore/x.js", "coursework/x.js", "tutorialize/x.js"]) {
    assert.ok(!DEV_PATH.test(p), p);
  }
});

test("SAMPLE_DIR_SRC is a whole-segment pattern", () => {
  const re = new RegExp("^" + SAMPLE_DIR_SRC + "$", "i");
  for (const s of ["x-examples", "x_samples", "app-demo", "example-app", "tutorials", "labs", "courses", "workshop"]) assert.ok(re.test(s), s);
  for (const s of ["exampleservice", "sampler", "demographics", "labstore", "lab", "src"]) assert.ok(!re.test(s), s);
});
