// P9 client half: rls.loc = { table: { file, line } } — the definition site of each table lacking RLS + policy, so the
// server can put file/line on rls-off / rls-no-policy leaks and the client can scope them to the PR that touches the file.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildFingerprint } from "../fingerprint.mjs";
import { sanitizeFingerprint, parseLeak } from "../client-lib.mjs";

const BS = String.fromCharCode(92);

function repo(files) {
  const root = mkdtempSync(join(tmpdir(), "sg-loc-"));
  const paths = [];
  for (const [rel, body] of Object.entries(files)) {
    const p = join(root, rel);
    mkdirSync(join(p, ".."), { recursive: true });
    writeFileSync(p, body);
    paths.push(p);
  }
  return { root, paths };
}

test("CREATE TABLE and Prisma model definition sites are emitted for tables without RLS + policy", () => {
  const { root, paths } = repo({
    "db/migrations/001.sql": "-- header\n\ncreate table public.orders (id uuid primary key, org_id uuid);\ncreate table public.invoices (id uuid primary key, org_id uuid);\nalter table public.invoices enable row level security;\ncreate policy p on public.invoices for all using (true);\n",
    "prisma/schema.prisma": "generator client {\n  provider = \"prisma-client-js\"\n}\n\nmodel Account {\n  id    String @id\n  orgId String\n}\n",
  });
  try {
    const fp = buildFingerprint(paths, root);
    assert.deepEqual(fp.rls.loc.orders, { file: "db/migrations/001.sql", line: 3 });
    assert.equal(fp.rls.loc.invoices, undefined, "a table with RLS + policy is not a leak candidate");
    assert.deepEqual(fp.rls.loc.account, { file: "prisma/schema.prisma", line: 5 });
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("emission is capped at 200 entries", () => {
  const sql = Array.from({ length: 260 }, (_, i) => `create table public.t${i} (id uuid, org_id uuid);`).join("\n");
  const { root, paths } = repo({ "m.sql": sql });
  try { assert.equal(Object.keys(buildFingerprint(paths, root).rls.loc).length, 200); } finally { rmSync(root, { recursive: true, force: true }); }
});

test("sanitizeFingerprint carries valid loc entries to the wire", () => {
  const fp = { signals: {}, tableCols: {}, rls: { on: [], policy: [], loc: { orders: { file: "db/001.sql", line: 3 } } }, queries: [] };
  assert.deepEqual(sanitizeFingerprint(fp).rls.loc, { orders: { file: "db/001.sql", line: 3 } });
});

test("sanitizeFingerprint drops hostile loc entries", () => {
  const long = "a".repeat(301);
  const loc = {
    ok: { file: "a/b.sql", line: 7 },
    abs: { file: "/etc/passwd", line: 1 },
    back: { file: BS + BS + "server" + BS + "share" + BS + "x.sql", line: 1 },
    drive: { file: "C:/x.sql", line: 1 },
    dotdot: { file: "a/../../x.sql", line: 1 },
    dotdotWin: { file: "a" + BS + ".." + BS + "x.sql", line: 1 },
    ctrl: { file: "a" + String.fromCharCode(0) + "b.sql", line: 1 },
    longFile: { file: long, line: 1 },
    zero: { file: "a.sql", line: 0 },
    neg: { file: "a.sql", line: -4 },
    frac: { file: "a.sql", line: 1.5 },
    str: { file: "a.sql", line: "9" },
    nofile: { line: 2 },
    notObj: "a.sql",
    [long]: { file: "a.sql", line: 1 },
  };
  assert.deepEqual(sanitizeFingerprint({ rls: { loc } }).rls.loc, { ok: { file: "a/b.sql", line: 7 } });
  assert.deepEqual(sanitizeFingerprint({ rls: { loc: [1, 2] } }).rls.loc, {});
  assert.deepEqual(sanitizeFingerprint({ rls: { loc: "x" } }).rls.loc, {});
  assert.deepEqual(sanitizeFingerprint({ rls: {} }).rls.loc, {});
  const proto = JSON.parse('{"__proto__": {"file": "a.sql", "line": 1}}');
  assert.deepEqual(Object.keys(sanitizeFingerprint({ rls: { loc: proto } }).rls.loc), []);
});

test("sanitizeFingerprint caps loc at 200 entries", () => {
  const loc = Object.fromEntries(Array.from({ length: 250 }, (_, i) => [`t${i}`, { file: "a.sql", line: i + 1 }]));
  assert.equal(Object.keys(sanitizeFingerprint({ rls: { loc } }).rls.loc).length, 200);
});

test("a located rls-off leak from the server parses to its file and line", () => {
  assert.deepEqual(parseLeak({ kind: "rls-off", table: "orders", file: "db/migrations/001.sql", line: 3 }),
    { file: "db/migrations/001.sql", line: 3, message: "rls-off orders" });
  assert.equal(parseLeak({ kind: "rls-off", table: "orders" }).file, null);
});
