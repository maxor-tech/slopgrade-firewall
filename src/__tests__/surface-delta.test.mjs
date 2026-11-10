// Surface delta (0.17.0) — does a PR ADD a network entry point? Ported 1:1 from the research detector
// (novelty n2_surface_delta.py). Measured on fresh AI-written commits: 13.6 % of commits that add an entry point hold a
// real flaw, against 0.92 % of the others (about 15x, REPORT.md §2.5).
import { test } from "node:test";
import assert from "node:assert/strict";
import { surfaceDelta } from "../surface-delta.mjs";

const h = (path, lines, newStart = 1) => ({ path, newStart, text: lines.join("\n") });

test("surfaceDelta: added route lines across stacks are entry points", () => {
  const cases = [
    ["server/app.js", "+app.post('/api/upload', handler)"],
    ["app/api/users/route.ts", "+export async function POST(req) {"],
    ["src/app/api/x/route.ts", "+export const GET = async () => {"],
    ["server/ws.js", "+io.on('connection', (s) => {"],
    ["api/views.py", "+@app.route('/admin/export')"],
    ["api/urls.py", "+    path('reports/<id>/', views.report),"],
    ["cmd/main.go", "+\tr.HandleFunc(\"/v1/files\", h)"],
    ["src/Controller.java", "+    @PostMapping(\"/orders\")"],
    ["Api/Program.cs", "+app.MapGet(\"/items/{id}\", Get);"],
    ["config/routes.rb", "+  post 'webhooks/stripe'"],
    ["routes/web.php", "+Route::post('/pay', [Pay::class, 'store']);"],
    ["src/mcp.ts", "+server.tool('read_file', schema, fn)"],
    ["src/index.ts", "+Bun.serve({ fetch })"],
  ];
  for (const [path, line] of cases) {
    const r = surfaceDelta([h(path, [" ctx", line])]);
    assert.equal(r.surface, true, `${path}: ${line}`);
    assert.equal(r.routeLines, 1, path);
  }
});

test("surfaceDelta: a new routed file with 5+ added lines counts even without a route line", () => {
  const body = ["+import x from 'y'", "+const a = 1", "+const b = 2", "+function f() {}", "+export default f"];
  const r = surfaceDelta([h("pages/api/report.js", body)]);
  assert.deepEqual(r, { surface: true, routeLines: 0, newRoutedFiles: 1 });
  // control: 4 lines is below the cut ; a file that also removes lines is an edit, not a new file
  assert.equal(surfaceDelta([h("pages/api/report.js", body.slice(0, 4))]).surface, false);
  assert.equal(surfaceDelta([h("pages/api/report.js", [...body, "-old line"])]).surface, false);
});

test("surfaceDelta: controls — moved, removed, test and docs route lines are not new surface", () => {
  // the same route line removed and re-added (a move or reformat) is not new
  assert.equal(surfaceDelta([h("server/app.js", ["-app.post('/api/upload', handler)", "+app.post('/api/upload', handler)"])]).surface, false);
  // a removed route only
  assert.equal(surfaceDelta([h("server/app.js", ["-app.post('/api/upload', handler)"])]).surface, false);
  // context line only
  assert.equal(surfaceDelta([h("server/app.js", [" app.post('/api/upload', handler)", "+const x = 1"])]).surface, false);
  // test, example and docs paths are excluded
  for (const p of ["tests/app.test.js", "src/__tests__/a.js", "examples/server.js", "docs/api.js", "e2e/s.js", "src/a.spec.ts"]) {
    assert.equal(surfaceDelta([h(p, ["+app.post('/api/upload', handler)"])]).surface, false, p);
  }
  // an ordinary change
  assert.equal(surfaceDelta([h("src/util.js", ["+export const sum = (a, b) => a + b"])]).surface, false);
  assert.deepEqual(surfaceDelta([]), { surface: false, routeLines: 0, newRoutedFiles: 0 });
  assert.deepEqual(surfaceDelta(null), { surface: false, routeLines: 0, newRoutedFiles: 0 });
});

test("surfaceDelta: lines are matched per file, so a route removed in one file and added in another is new", () => {
  const r = surfaceDelta([h("old/app.js", ["-app.get('/a', f)"]), h("new/app.js", ["+app.get('/a', f)"])]);
  assert.equal(r.routeLines, 1);
});
