// The SQL-injection fingerprint the SERVER's own scans use (the /try trial — lib/try/repo-scan.ts). Server-only : the
// client keeps the line reader until its own release wires the tree (Jeff 2026-11-01 : server first, then the client).
// For a Python / JavaScript / TypeScript file whose grammar is loaded, the syntax tree replaces the line reader's
// intra-function taint and direct patterns ; the line reader's inter-procedural and cross-file hits are kept (the tree
// is intra-function). Measured on 5,300 real repos (468,379 files, 2026-11-01) : 56 shared hits kept, 6 product-code
// line-only false flags removed (a bound parameter tuple, SQLAlchemy builders, an allowlisted table), 0 tree-only hits
// in product code. Any other file, a grammar not loaded, or a tree that returns null → the line reader, unchanged.
import { extractSqliFingerprint } from "./sqli-extract.mjs";
import { irReady } from "./ts-ir.mjs";
import { extractSqliIr } from "./sqli-ir.mjs";

const LINE_ONLY_KINDS = new Set(["taint-interproc", "taint-xfile"]);

/** Same shape as extractSqliFingerprint : { file, hits: [{line, kind}] } — tree hits carry the "taint-sql" kind. */
export function extractSqliFingerprintBest(text, file, importedWrappers) {
  const line = extractSqliFingerprint(text, file, importedWrappers);
  if (!irReady(file)) return line;
  const tree = extractSqliIr(text, file);
  if (tree === null) return line;
  return { file, hits: [...tree.map((h) => ({ line: h.line, kind: "taint-sql" })), ...line.hits.filter((h) => LINE_ONLY_KINDS.has(h.kind))] };
}
