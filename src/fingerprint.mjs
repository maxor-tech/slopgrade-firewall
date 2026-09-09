// THE CLIENT HALF of the boundary. `buildFingerprint` = the LOCAL extractor (runs in the client / the npx Action):
// it produces a serializable STRUCTURAL fingerprint — tables, columns, RLS facts, and per-query {table, verb,
// where id-columns, search_path state} — WITHOUT ever emitting file contents. It imports ONLY `extract.mjs`
// (parsing). It carries NO classification rule: the classification heuristics are hosted server-side and are
// intentionally not shipped in this repository, which is exactly what makes this client fully auditable.
import { readFileSync, statSync } from "node:fs";
import {
  extractCallStrings, extractCreateTables, extractPrismaModels, extractPrismaQueries,
  classifyDml, normKey, lineOf, ADMIN_CTX, supabaseChains,
} from "./extract.mjs";

// Capture *_id AND ownership columns (owner / owned_by). Sans ça, une query scopée par `owner` — ex. un store
// SQLite local dont la PK est (owner, …) — a des whereIdCols VIDES → le brain la lit « LIST/BULK sans AUCUN scope »
// = faux hard-leak (mesuré 2026-09-07 : odysseus, un client email mono-user, faux-bloqué). `owner` n'est PAS une clé
// TENANT (CANDIDATE_KEY ne le matche pas) → la query tombe en by-id CONDITIONNEL (non bloquant), pas « scoped » ni
// « hard ». Volontairement PAS de `*_key` générique : `api_key`/`cache_key` masqueraient un vrai leak (recall).
//
// SCOPE_FRAG — a WHERE that INTERPOLATES a runtime-composed SQL fragment: `f"… AND {owner_clause}"`, `%(tenant_filter)s`.
// The query IS scoped but static extraction can't see through the variable → empty whereIdCols → false hard-leak
// (measured odysseus routes/email_routes.py:2739). Recognized by NAME: an interpolation prefix `{`/`%` FOLLOWED by an
// identifier <ownership/tenant-stem>…<clause|filter|where|scope|cond|predicate>. The mandatory prefix excludes a real
// literal column (`WHERE user_scope = 1` has no `{`), the suffix excludes a display interpolation (`{user_name}`).
// RECALL-SAFE: it only yields a by-id marker (never a CANDIDATE_KEY) → can move hard→by-id (conditional, non-blocking)
// but NEVER "tenant-scoped", so no genuine unscoped bulk read is masked. Sync with lib/tenant-isolation/fingerprint.mjs.
const SCOPE_FRAG = /[{%][({]?\s*((?:owner|owned_by|tenant|org|account|user|workspace|customer|team)_?[a-z_]*(?:clause|filter|where|scope|cond|predicate))/gi;
const idColsOf = (text) => [...new Set(
  (text.match(/\b([a-z_]*_?id|owner|owned_by)\b/gi) ?? [])
    .concat([...text.matchAll(SCOPE_FRAG)].map((m) => m[1]))
    .map(normKey),
)];
const short = (f) => f.split(/[\\/]/).slice(-2).join("/");
// Path RELATIVE to the repo root (posix slashes) — needed for the verdict to map onto the PR diff (SARIF / inline
// annotations). Falls back to the 2-segment short form when no root is known (e.g. a local dry run outside CI).
const relOf = (f, root) => {
  if (!root) return short(f);
  const nf = f.replace(/\\/g, "/"), nr = root.replace(/\\/g, "/").replace(/\/+$/, "");
  return nf.startsWith(nr + "/") ? nf.slice(nr.length + 1) : short(f);
};
const MAX_FILE_BYTES = 4 * 1024 * 1024; // skip files over 4MB — a multi-GB generated file would OOM the read

// ── LOCAL — produces the fingerprint (no source leaves) ──────────────────────
// `root` (the repo root) makes query `file` paths repo-relative; omit it for a 2-segment short form.
export function buildFingerprint(files, root = "") {
  const signals = { schemaPath: 0, rlsPolicy: 0, rlsSupabase: 0 };
  const tableCols = {};                       // table → [columns] (arrays, serializable)
  const rlsOn = new Set(), policy = new Set();
  const queries = [];
  for (const f of files) {
    try { if (statSync(f).size > MAX_FILE_BYTES) continue; } catch { continue; }
    let t; try { t = readFileSync(f, "utf8"); } catch { continue; }
    signals.schemaPath += (t.match(/SET\s+search_path|set_tenant_schema|search_path\s*(TO|=)/gi) ?? []).length;
    signals.rlsPolicy += (t.match(/ENABLE\s+ROW\s+LEVEL\s+SECURITY|CREATE\s+POLICY/gi) ?? []).length;
    // `\.rls\b` targeted a real Supabase client `.rls(...)` call — but also matched a DOTTED CONFIG KEY
    // `"proxy.rls.maxPoliciesPerCollection"` (milvus, a C++/Go vector DB with its own "rls" config namespace)
    // → 11 false signals → milvus false-classified "Postgres multi-tenant RLS" → 13 false hard-leaks. Require a
    // real method call `.rls(` (followed by a paren), never a dotted path segment `.rls.` / `.rls_x`.
    signals.rlsSupabase += (t.match(/auth\.uid\(\)|internal_org_id|\.rls\s*\(/gi) ?? []).length;
    const execStrings = extractCallStrings(t, "execute");
    const sqlBlob = t + "\n" + execStrings.map((c) => c.text).join("\n;\n");
    // A raw `CREATE TABLE` DDL literal INSIDE a UI component (.tsx/.jsx/.vue/.svelte) is a DOC sample (a marketing /
    // RLS-guide page — e.g. supabase apps/www/.../RLSSection.tsx shows `create table members (…)`), never a runtime
    // schema: real schemas live in .sql/.prisma/migrations. So we do NOT derive tableCols from it (else `members`
    // becomes a false tenant table → false hard-leak). A .tsx's real queries (.from()/prisma) are still extracted
    // below. RECALL-SAFE: no real multi-tenant schema is ever defined via CREATE TABLE in a .tsx.
    const uiDocFile = /\.(tsx|jsx|vue|svelte)$/i.test(f);
    const created = uiDocFile ? [] : extractCreateTables(sqlBlob);
    for (const { table, cols } of created.concat(/\.prisma$/.test(f) || /\bmodel\s+\w+\s*\{/.test(t) ? extractPrismaModels(t) : [])) tableCols[table] = [...cols];
    for (const m of sqlBlob.matchAll(/ALTER\s+TABLE\s+(?:ONLY\s+)?["'`]?(?:public\.)?([a-z_][a-z0-9_]*)["'`]?\s+ENABLE\s+ROW\s+LEVEL\s+SECURITY/gi)) rlsOn.add(m[1].toLowerCase());
    for (const m of sqlBlob.matchAll(/CREATE\s+POLICY\s+[^;]*?\bON\s+["'`]?(?:public\.)?([a-z_][a-z0-9_]*)/gi)) policy.add(m[1].toLowerCase());

    const isAdmin = ADMIN_CTX.test(f);
    // (a) SQL execute() — linear scan for the search_path state (schema-per-tenant) + the where id-columns.
    const lines = t.split("\n"); let sp = "unknown";
    for (let i = 0; i < lines.length; i++) {
      const l = lines[i];
      if (/^\s*(async\s+)?def\s/.test(l)) sp = "unknown";
      const setSp = l.match(/search_path\s*(?:TO|=)\s*["'%(]?\s*([a-z_%{][a-z0-9_%{}().]*)/i);
      if (setSp) sp = /^public\b/i.test(setSp[1]) ? "public" : "tenant";
      if (!/execute\s*\(/i.test(l)) continue;
      const sub = extractCallStrings(lines.slice(i, i + 30).join("\n"), "execute")[0];
      if (!sub) continue;
      const d = classifyDml(sub.text); if (!d || !d.table) continue;
      queries.push({ kind: "sql", table: d.table, verb: d.verb, whereIdCols: idColsOf(sub.text), spState: sp, isAdmin, file: relOf(f, root), line: i + 1 });
    }
    // (b) Supabase chains (`.from("x")…`) — row-column/RLS, no search_path state.
    for (const { text, index } of supabaseChains(t)) {
      const d = classifyDml(text); if (!d || !d.table) continue;
      queries.push({ kind: "sql", table: d.table, verb: d.verb, whereIdCols: idColsOf(text), spState: "unknown", isAdmin, file: relOf(f, root), line: lineOf(t, index) });
    }
    // (c) Prisma queries (the dominant ORM case).
    for (const { model, method, body, index } of extractPrismaQueries(t)) {
      queries.push({ kind: "prisma", table: model, method, whereIdCols: idColsOf(body), hasIdConstraint: /\bid\b\s*:|\buid\b\s*:|\bslug\b\s*:|\btoken\b\s*:/i.test(body), isBulk: /findMany|updateMany|deleteMany/i.test(method), isAdmin, file: relOf(f, root), line: lineOf(t, index) });
    }
  }
  return { signals, tableCols, rls: { on: [...rlsOn], policy: [...policy] }, queries };
}
