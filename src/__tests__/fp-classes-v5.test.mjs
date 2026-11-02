// Precision round 4 (independent sets v4 + v5, 2026-11-02) in the client's path-traversal extractor : a record loaded
// through a lookup is not a user-chosen path ; a path BUILT from the user value, a field read on it, a same-file or
// path-named helper all keep firing. Mirror of maxor-tech/slopgrade fp-classes-v5.
import { test } from "node:test";
import assert from "node:assert/strict";
import { extractPathTraversal } from "../pathtraversal-extract.mjs";

const pt = (code, file = "routes.js") => extractPathTraversal(code, new Map(), file).map((h) => h.line);

test("a looked-up record is not a user path ; built paths, field reads and path helpers still fire", () => {
  assert.deepEqual(pt("app.get('/s/:id', async (req, res) => {\n  const id = req.params.id;\n  const p = (await db.findById(id)).path;\n  fs.createReadStream(p).pipe(res);\n});\n"), []);
  assert.ok(pt("app.get('/f', (req, res) => {\n  const p = path.resolve(ROOT, req.query.f);\n  fs.createReadStream(p).pipe(res);\n});\n").length > 0);
  assert.ok(pt('@router.post("/t")\nasync def t(request: Request):\n    req_data = await request.json()\n    data_path = req_data.get("data_path", "")\n    with open(data_path) as f:\n        return f.read()\n', "app.py").length > 0);
  assert.ok(pt('@router.post("/w/{gid}/{wid}")\ndef upd(gid, wid):\n    file_path = registry.get_workflow_path(gid, wid)\n    os.remove(file_path)\n', "app.py").length > 0);
});
