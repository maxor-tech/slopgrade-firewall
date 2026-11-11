// Go reachability, import level (0.19.0): does the repository's OWN Go code import a package an advisory names?
// OSV Go records list the affected import paths (affected[].ecosystem_specific.imports[].path). A version whose affected
// package your code imports gets the label « imported by your code » and is always annotated, after the KEV ones.
//
// Measured (slopGrade release run, PREREG / READ-DEPS-6): of 231 pull requests that added a Go module version with a
// published advisory, the repository's own code imported an affected package in 32 (13.9 %). A transitive call through
// another module is NOT seen, so the label only raises a warning — it never hides one. Deterministic, no network.

// own code = .go files outside vendor/ and testdata/, not _test.go
export const isOwnGoFile = (p) => /\.go$/.test(p) && !/_test\.go$/.test(p) && !/(^|\/)(vendor|testdata)\//.test(p);
export const GO_SCAN_MAX_FILES = 8000;
export const GO_SCAN_MAX_BYTES = 64 * 1024 * 1024;

const BLOCK = /^import\s*\(([\s\S]*?)\)/gm;
const ONE = /^import\s+(?:[A-Za-z_][A-Za-z0-9_]*\s+|\.\s+|_\s+)?"([^"]+)"/gm;
const SPEC = /^\s*(?:[A-Za-z_][A-Za-z0-9_]*\s+|\.\s+|_\s+)?"([^"]+)"/gm;

/** One Go source text -> the import paths it declares (block and single forms; comments inside a block are skipped). */
export function goImports(src) {
  const text = String(src ?? "");
  const out = new Set();
  for (const m of text.matchAll(BLOCK)) for (const s of m[1].replace(/\/\/[^\n]*/g, "").matchAll(SPEC)) out.add(s[1]);
  for (const m of text.matchAll(ONE)) out.add(m[1]);
  return out;
}

/**
 * The affected import paths of each Go advisory record, for one module: OSV record body -> [path]. Records without
 * import data give [] (the label is then never set: it is only a raise, never a hide).
 */
export function affectedGoPaths(record, module) {
  const out = [];
  for (const a of Array.isArray(record?.affected) ? record.affected : []) {
    if (a?.package?.ecosystem !== "Go" || a.package.name !== module) continue;
    for (const imp of a.ecosystem_specific?.imports || []) if (typeof imp?.path === "string") out.push(imp.path);
  }
  return out;
}

/**
 * Mark the Go vulnerable versions whose affected packages the repository imports: `imported: [paths]`. `wanted` comes
 * from addKev (`v.goPaths`). `listFiles()` returns tracked paths, `read(p)` a file's text; both may throw. Never throws;
 * stops at GO_SCAN_MAX_FILES files or GO_SCAN_MAX_BYTES bytes (then says so in `scanNote`).
 */
export function markGoImported(r, listFiles, read) {
  if (!r || r.error || !r.vulnerable?.some((v) => v.goPaths?.length)) return r;
  const wanted = new Set(r.vulnerable.flatMap((v) => v.goPaths || []));
  const found = new Set();
  let files = [], bytes = 0, scanned = 0, note;
  try { files = listFiles().filter(isOwnGoFile); } catch { return { ...r, scanNote: "Go import check skipped (file list unavailable)" }; }
  for (const p of files) {
    if (scanned >= GO_SCAN_MAX_FILES || bytes >= GO_SCAN_MAX_BYTES) { note = `Go import check stopped after ${scanned} of ${files.length} files`; break; }
    let src;
    try { src = read(p); } catch { continue; }
    scanned++; bytes += src.length;
    for (const path of goImports(src)) if (wanted.has(path)) found.add(path);
    if (found.size === wanted.size) break;
  }
  const vulnerable = r.vulnerable.map((v) => {
    const hit = (v.goPaths || []).filter((p) => found.has(p));
    return hit.length ? { ...v, imported: [...new Set(hit)] } : v;
  });
  vulnerable.sort((a, b) => (b.kev ? 2 : b.imported ? 1 : 0) - (a.kev ? 2 : a.imported ? 1 : 0));
  return { ...r, vulnerable, ...(note ? { scanNote: note } : {}) };
}
