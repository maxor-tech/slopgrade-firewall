// Shared extraction — deterministic, $0. Reads COMPLETE (multi-line) SQL string literals and CREATE TABLE blocks.
import { readdirSync, lstatSync } from "node:fs";

// Excludes non-source dirs AND test/spec/fixture files. A `WHERE` in a test or fixture is never a production
// cross-tenant read — scanning it produces false-positive "leaks" that would wrongly block a build in gate mode.
// Test-file exclusion is standard for every security/lint scanner; it is a commodity path check, not a rule.
// `examples?/samples?/demo/sandbox/playground/cookbook` are excluded for the SAME reason as tests — sample/demo apps
// bundled in a repo (common in platform monorepos: bundled example / edge-function / realtime apps) are not the
// product's production tenant surface; their migrations/queries are illustrative, never a customer's build.
const DEFAULT_EXCL = /(node_modules|\/dist\/|\/build\/|\.min\.|\.venv|__pycache__|\/\.git\/|\.next|\.(test|spec|stories)\.[a-z]+$|_(test|spec)\.[a-z]+$|[._-](examples?|samples?)\.[a-z]+$|(^|\/)(tests?|specs?|__tests__|__mocks__|e2e|fixtures?|mocks?|testdata|examples?|samples?|demos?|sandbox|playground|cookbook)\/|(^|\/)test_[^/]*\.py$|(^|\/)conftest\.py$)/i;

const MAX_DEPTH = 40;      // bound recursion (defense against pathological trees)
const MAX_FILES = 200_000; // bound total collected files (DoS ceiling)

// Collects candidate files. Uses lstatSync and SKIPS symlinks: a symlink cycle (self -> .) would otherwise recurse
// unbounded (RangeError) and a symlink out of the tree (link -> /) would fingerprint paths from outside the repo.
// Depth- and count-capped. `depth` is internal.
export function walk(dir, exts, excl = DEFAULT_EXCL, out = [], depth = 0) {
  if (depth > MAX_DEPTH || out.length >= MAX_FILES) return out;
  let entries;
  try { entries = readdirSync(dir); } catch { return out; }
  for (const e of entries) {
    if (out.length >= MAX_FILES) break;
    const p = `${dir}/${e}`;
    if (excl.test(p)) continue;
    let s; try { s = lstatSync(p); } catch { continue; }
    if (s.isSymbolicLink()) continue;              // never follow symlinks (cycle + out-of-tree guard)
    if (s.isDirectory()) walk(p, exts, excl, out, depth + 1);
    else if (s.isFile() && exts.test(p)) out.push(p);
  }
  return out;
}

export const lineOf = (src, idx) => src.slice(0, idx).split("\n").length;

// Extracts the COMPLETE string literal passed to `<callName>(` — handles '''…''', """…""", '…', "…", and f/r/b/u
// prefixes. Returns [{ text, index }] where index = the call position. This is the fix for the "the window truncates
// the WHERE" false positive.
//
// IMPLICIT (Python/C) CONCATENATION: `execute(f"SELECT … " f"WHERE owner=? …")` — Python glues ADJACENT string
// literals. Reading only the first fragment truncated the WHERE → empty whereIdCols → a false hard-leak.
// We now read ALL adjacent literals (separated only by whitespace, `\`
// line-continuations, and `#`/`//` comments) and concatenate them. RECALL-SAFE: it only ever REVEALS MORE of the
// true query — a `,`/`)`/`+`/identifier between two literals ends the concat (2nd argument, not more of the SQL).
export function extractCallStrings(src, callName) {
  const out = [];
  const re = new RegExp(callName + "\\s*\\(", "gi");
  let m;
  while ((m = re.exec(src))) {
    let i = m.index + m[0].length;
    while (i < src.length && /[\sfrbuFRBU]/.test(src[i]) && src[i] !== '"' && src[i] !== "'") i++;
    if (src[i] !== '"' && src[i] !== "'") continue;
    let text = "", pos = i, first = true;
    while (pos < src.length) {
      let p = pos;
      if (!first) {
        // Between two literals only whitespace, `\` continuation, and `#` / `//` comments are tolerated.
        while (p < src.length) {
          if (/\s/.test(src[p]) || src[p] === "\\") { p++; continue; }
          if (src[p] === "#") { while (p < src.length && src[p] !== "\n") p++; continue; }
          if (src[p] === "/" && src[p + 1] === "/") { while (p < src.length && src[p] !== "\n") p++; continue; }
          break;
        }
        let q2 = p;
        while (q2 < src.length && /[frbuFRBU]/.test(src[q2])) q2++;   // skip an f/r/b/u prefix glued to the quote
        if (src[q2] !== '"' && src[q2] !== "'") break;                // not another literal → concat ends
        p = q2;
      }
      const q = src[p];
      const triple = src.substr(p, 3) === q + q + q;
      const open = triple ? q + q + q : q;
      let j = p + open.length;
      while (j < src.length) {
        if (src.substr(j, open.length) === open && (triple || src[j - 1] !== "\\")) break;
        text += src[j]; j++;
      }
      pos = j + open.length;   // past the closing quote
      first = false;
    }
    out.push({ text, index: m.index });
  }
  return out;
}

// Parses CREATE TABLE (paren-balanced) → [{ table, cols:Set }]. Works on raw SQL OR SQL embedded in strings.
export function extractCreateTables(src) {
  const out = [];
  const re = /CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?["'`]?([a-z_][a-z0-9_.]*)["'`]?\s*\(/gi;
  let m;
  while ((m = re.exec(src))) {
    const table = m[1].split(".").pop();
    let depth = 1, k = m.index + m[0].length, body = "";
    while (k < src.length && depth > 0) {
      if (src[k] === "(") depth++;
      else if (src[k] === ")") depth--;
      if (depth > 0) body += src[k];
      k++;
    }
    const cols = new Set(
      (body.match(/(?:^|,)\s*["'`]?([a-z_][a-z0-9_]*)["'`]?\s+[a-z]/gim) ?? [])
        .map((c) => c.replace(/^[,\s]*/, "").replace(/["'`]/g, "").split(/\s+/)[0].toLowerCase())
        .filter((c) => !/^(primary|foreign|unique|constraint|check|key|index)$/i.test(c)),
    );
    out.push({ table, cols });
  }
  return out;
}

// Prisma ORM adapter: `model User { organizationId String }` → { table, cols }. The dominant real-world case
// for many Node/TS stacks — the schema is NOT CREATE TABLE. camelCase fields are kept as-is.
export function extractPrismaModels(src) {
  const out = [];
  const re = /(?:^|\n)\s*model\s+(\w+)\s*\{/g;
  let m;
  while ((m = re.exec(src))) {
    let depth = 1, k = re.lastIndex, body = "";
    while (k < src.length && depth > 0) { if (src[k] === "{") depth++; else if (src[k] === "}") depth--; if (depth > 0) body += src[k]; k++; }
    const cols = new Set(
      (body.match(/^\s*(\w+)\s+\w/gm) ?? [])
        .map((l) => l.trim().split(/\s+/)[0].toLowerCase())
        .filter((c) => !/^(@@|\/\/)/.test(c)),
    );
    out.push({ table: m[1].toLowerCase(), cols });
  }
  return out;
}

// Prisma QUERY extractor: `prisma.booking.findMany({ where: { userId } })`. Returns the model + the complete
// argument body (paren-balanced). Covers the dominant Prisma/TS stack.
export function extractPrismaQueries(src) {
  const out = [];
  const re = /\b(?:prisma|db|tx|prismaClient)\b(?:\.[a-z]\w*)*\s*\.\s*([a-z]\w*)\s*\.\s*(findMany|findFirst|findUnique|findUniqueOrThrow|findFirstOrThrow|update|updateMany|delete|deleteMany|upsert|count|aggregate|groupBy)\s*\(/gi;
  let m;
  while ((m = re.exec(src))) {
    const model = m[1].toLowerCase(), method = m[2];
    let depth = 1, k = re.lastIndex, body = "";
    while (k < src.length && depth > 0) { const ch = src[k]; if (ch === "(") depth++; else if (ch === ")") depth--; if (depth > 0) body += ch; k++; }
    out.push({ model, method, body, index: m.index });
  }
  return out;
}

// Normalizes a key/column for cross-convention comparison: user_id == userId == userid.
export const normKey = (s) => s.replace(/_/g, "").toLowerCase();

// ADMIN/system context (by path) — an unscoped query is expected here (service-role, migration, backfill, ETL
// export/import, management commands, background jobs), so it is excluded from leaks. Commodity: this is a context
// heuristic on the file PATH, not a secret classification rule.
// `[\/_]cli\/`: a CLI package is named `cli/` OR `<app>_cli/` — operator code (hand-run commands),
// same as /commands/ /console/ /management/ already exempted; an unscoped access there is expected, not a tenant
// leak. Completes the existing CLI exemption which missed the `_cli/` naming variant.
export const ADMIN_CTX = /service.?role|admin_only|is_superadmin|migrat|seed|backfill|repair|auto_migrate|startup|export|import_|_import|dumpdata|loaddata|\baudit|\/management\/|\/commands?\/|\/tasks?\/|\/jobs?\/|\/workers?\/|\/console\/|\/rake\/|[\/_]cli\//i;

// Supabase `.from("x")…` chains normalized into pseudo-SQL so they can flow through classifyDml. Commodity (extraction).
export function supabaseChains(src) {
  const out = []; const re = /\.from\(\s*["'`]([a-z_][a-z0-9_]*)["'`]\s*\)/gi; let m;
  while ((m = re.exec(src))) {
    const chain = src.slice(m.index, m.index + 400).split(/;|\n\n/)[0];
    out.push({ text: `SELECT * FROM ${m[1]} ${chain}`, index: m.index });
  }
  return out;
}

// The SQL verb + target table of a DML statement.
export function classifyDml(sql) {
  const verb = (sql.match(/^\s*(SELECT|UPDATE|DELETE|INSERT)\b/i) ?? [])[1];
  if (!verb) return null;
  const tbl = (sql.match(/\bFROM\s+["'`]?([a-z_][a-z0-9_.]*)/i)
    || sql.match(/\bUPDATE\s+["'`]?([a-z_][a-z0-9_.]*)/i)
    || sql.match(/DELETE\s+FROM\s+["'`]?([a-z_][a-z0-9_.]*)/i)
    || sql.match(/INSERT\s+INTO\s+["'`]?([a-z_][a-z0-9_.]*)/i)
    || [])[1];
  return { verb: verb.toUpperCase(), table: tbl ? tbl.split(".").pop().toLowerCase() : null };
}
