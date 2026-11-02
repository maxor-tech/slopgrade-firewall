// Precision round 3 (independent set v4, 2026-11-01) in the client's path-traversal extractor : the path an upload
// middleware stored the file at is server-chosen ; client-chosen values still fire. Mirror of maxor-tech/slopgrade fp-classes-v4.
import { test } from "node:test";
import assert from "node:assert/strict";
import { extractPathTraversal } from "../pathtraversal-extract.mjs";

const pt = (code) => extractPathTraversal(code, new Map(), "api/routes/avatar.js").map((h) => h.line);

test("a stored upload path is not traversal ; originalname and query values still are", () => {
  assert.deepEqual(pt("router.post('/', async (req, res) => {\n  const input = await fs.readFile(req.file.path);\n});\n"), []);
  assert.deepEqual(pt("router.post('/', async (req, res) => {\n  const buffer = await fs.readFile(req.files[0].path);\n});\n"), []);
  assert.ok(pt("router.post('/', async (req, res) => {\n  const n = req.file.originalname;\n  fs.createReadStream('/uploads/' + n).pipe(res);\n});\n").length > 0);
  assert.ok(pt("app.get('/f', (req, res) => {\n  const p = req.query.path;\n  fs.createReadStream(p).pipe(res);\n});\n").length > 0);
});
