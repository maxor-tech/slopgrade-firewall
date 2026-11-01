// Prisma `where: { id }` shorthand (BOLA benchmark 2026-11-01) : the by-id constraint is read from the ES shorthand
// too. Before, `update({ where: { id }, data })` had no id constraint → the server read it as an unscoped update →
// a false hard leak that blocked the build.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildFingerprint } from "../fingerprint.mjs";

function prismaQuery(code) {
  const ws = mkdtempSync(join(tmpdir(), "sg-prisma-")).replace(/\\/g, "/");
  try {
    mkdirSync(`${ws}/src`, { recursive: true });
    writeFileSync(`${ws}/src/route.ts`, code);
    return buildFingerprint([`${ws}/src/route.ts`], ws).queries.find((q) => q.kind === "prisma");
  } finally { rmSync(ws, { recursive: true, force: true }); }
}

test("the shorthand `where: { id }` is an id constraint", () => {
  assert.equal(prismaQuery(`const { id, name } = req.body;\nawait prisma.project.update({ where: { id }, data: { name } });`).hasIdConstraint, true);
  assert.equal(prismaQuery(`await prisma.project.delete({ where: { orgId, id } });`).hasIdConstraint, true);
  assert.equal(prismaQuery(`await prisma.session.findUnique({ where: { token } });`).hasIdConstraint, true);
});

test("CONTROL : no id in the where — or an id only in `data` — is not an id constraint", () => {
  assert.equal(prismaQuery(`await prisma.project.updateMany({ where: { archived }, data: { name } });`).hasIdConstraint, false);
  assert.equal(prismaQuery(`await prisma.project.updateMany({ where: { valid }, data: { id } });`).hasIdConstraint, false);
  assert.equal(prismaQuery(`await prisma.project.findMany({ where: { userId } });`).hasIdConstraint, false);
});
