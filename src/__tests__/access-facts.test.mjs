// Access facts of a by-id query (expert panel P0-2, BOLA) : the fingerprint says whether the id comes from the request
// and whether an ownership / authorization check sits nearby — two booleans that cross the egress boundary, never source.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildFingerprint } from "../fingerprint.mjs";
import { sanitizeFingerprint } from "../client-lib.mjs";

function facts(code, name = "route.ts") {
  const dir = mkdtempSync(join(tmpdir(), "sg-af-"));
  try {
    const f = join(dir, name);
    writeFileSync(f, code, "utf8");
    const q = sanitizeFingerprint(buildFingerprint([f], dir)).queries.find((x) => x.kind === "prisma");
    return q && { idFromRequest: q.idFromRequest, ownerCheckNear: q.ownerCheckNear };
  } finally { rmSync(dir, { recursive: true, force: true }); }
}

test("a request id read with no ownership check is flagged as such", () => {
  assert.deepEqual(facts("export async function GET(req, { params }) {\n  const invoice = await prisma.invoice.findUnique({ where: { id: params.id } });\n  return Response.json(invoice);\n}"), { idFromRequest: true, ownerCheckNear: false });
  assert.deepEqual(facts("app.get('/i/:id', async (req, res) => {\n  const { id } = req.params;\n  const inv = await prisma.invoice.findUnique({ where: { id } });\n  res.json(inv);\n});"), { idFromRequest: true, ownerCheckNear: false });
});

test("an ownership comparison or an authorization call nearby is seen", () => {
  assert.deepEqual(facts("app.get('/i/:id', async (req, res) => {\n  const inv = await prisma.invoice.findUnique({ where: { id: req.params.id } });\n  if (inv.orgId !== req.user.orgId) return res.status(404).end();\n  res.json(inv);\n});"), { idFromRequest: true, ownerCheckNear: true });
  assert.deepEqual(facts("app.get('/i/:id', async (req, res) => {\n  await authorize(req.user, 'invoice:read');\n  const inv = await prisma.invoice.findUnique({ where: { id: req.params.id } });\n  res.json(inv);\n});"), { idFromRequest: true, ownerCheckNear: true });
});

test("an id that does not come from the request is not request-supplied", () => {
  assert.deepEqual(facts("async function load(invoiceId) {\n  return prisma.invoice.findUnique({ where: { id: invoiceId } });\n}", "lib.ts"), { idFromRequest: false, ownerCheckNear: false });
});
