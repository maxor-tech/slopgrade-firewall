// Dogfood gaps (slopGrade on its own repo, run 36265738717): (1) the egress boundary dropped rls.granted / rls.revoked,
// (2) the client never extracted them, (3) the server's leak OBJECTS {kind, table, file, line} printed "[object Object]"
// and — worse — parseLeak could never locate them, so located leaks vanished from annotations / SARIF / PR review.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildFingerprint } from "../fingerprint.mjs";
import { sanitizeFingerprint, parseLeak, leakText, buildSarif } from "../client-lib.mjs";

const SQL = `
create table public.email_change_requests (id uuid primary key, user_id uuid, token text);
alter table public.email_change_requests enable row level security;
revoke all on table public.email_change_requests from anon, authenticated;
create table public.orders (id uuid primary key, org_id uuid);
alter table public.orders enable row level security;
grant select, insert on public.orders to authenticated;
grant usage on schema public to anon;
revoke execute on function public.do_thing() from public;
grant select on public.audit_log to service_role;
`;

test("buildFingerprint extracts client-role GRANT / REVOKE facts (tables only, client roles only)", () => {
  const dir = mkdtempSync(join(tmpdir(), "sg-fp-"));
  try {
    const f = join(dir, "0001_init.sql");
    writeFileSync(f, SQL, "utf8");
    const fp = buildFingerprint([f], dir);
    assert.deepEqual(fp.rls.revoked, ["email_change_requests"]);
    assert.deepEqual(fp.rls.granted, ["orders"], "schema/function objects and a non-client role (service_role) are ignored");
    assert.deepEqual(fp.rls.on.sort(), ["email_change_requests", "orders"]);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("sanitizeFingerprint now carries granted / revoked across the egress boundary, coerced like on / policy", () => {
  const out = sanitizeFingerprint({
    signals: {}, tableCols: {}, queries: [],
    rls: { on: ["orders"], policy: [], granted: ["orders", { evil: 1 }], revoked: ["email_change_requests"], extra: ["x"] },
  });
  assert.deepEqual(out.rls.granted[0], "orders");
  assert.equal(typeof out.rls.granted[1], "string", "a non-string entry is coerced, never passed through as an object");
  assert.deepEqual(out.rls.revoked, ["email_change_requests"]);
  assert.equal(out.rls.extra, undefined, "whitelist: unknown rls keys still never leave");
  assert.deepEqual(sanitizeFingerprint({ rls: { on: [] } }).rls.granted, [], "absent → empty, not undefined");
});

test("parseLeak locates the server's leak OBJECTS (the old path lost every located leak)", () => {
  assert.deepEqual(parseLeak({ kind: "list-bulk-unscoped", file: "app/api/x/route.ts", line: 42, table: "orders" }),
    { file: "app/api/x/route.ts", line: 42, message: "list-bulk-unscoped orders" });
  assert.deepEqual(parseLeak({ kind: "rls-no-policy", table: "email_change_requests" }),
    { file: null, line: 0, message: "rls-no-policy email_change_requests" }, "a table-level leak has no source location");
  assert.deepEqual(parseLeak({ kind: "unscoped", file: "a.py", table: "t", method: "findMany" }),
    { file: "a.py", line: 1, message: "unscoped t findMany" }, "missing line → 1, never 0 (SARIF needs ≥ 1)");
  assert.deepEqual(parseLeak("lib/db.ts:7  [orders]  unscoped"), { file: "lib/db.ts", line: 7, message: "[orders]  unscoped" }, "legacy string form unchanged");
});

test("leakText never prints [object Object]", () => {
  assert.equal(leakText({ kind: "rls-no-policy", table: "email_change_requests" }), "rls-no-policy email_change_requests");
  assert.equal(leakText({ kind: "search-path-public", file: "db.py", line: 3, table: "users" }), "db.py:3 search-path-public users");
  assert.equal(leakText("lib/db.ts:7  unscoped"), "lib/db.ts:7  unscoped");
  assert.doesNotMatch(leakText({}), /object Object/);
});

test("buildSarif turns located leak objects into results (they used to be dropped)", () => {
  const sarif = buildSarif([{ kind: "list-bulk-unscoped", file: "app/x.ts", line: 9, table: "orders" }, { kind: "rls-off", table: "t" }]);
  const results = sarif.runs[0].results.filter((r) => r.ruleId === "cross-tenant-isolation-leak");
  assert.equal(results.length, 1, "the located one becomes a result; the table-level one has no path and is skipped");
  assert.equal(results[0].locations[0].physicalLocation.artifactLocation.uri, "app/x.ts");
  assert.equal(results[0].locations[0].physicalLocation.region.startLine, 9);
});
