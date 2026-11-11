// Go reachability, import level (0.19.0): does the repository's OWN Go code import a package an advisory names?
// OSV Go records list the affected import paths (affected[].ecosystem_specific.imports[].path). A version whose affected
// package your code imports gets the label « imported by your code » and is always annotated, after the KEV ones.
//
// Measured (slopGrade release run, PREREG / READ-DEPS-6): of 231 pull requests that added a Go module version with a
// published advisory, the repository's own code imported an affected package in 32 (13.9 %). A transitive call through
// another module is NOT seen, so the label only raises a warning — it never hides one. Deterministic, no network.
//
// Call level, by name (0.19.0): OSV also lists the affected functions (« Func », « Type.Method »). When a file that
// imports the package writes « name.Func » or « name.Type », the version is labeled « affected symbol referenced by
// your code »; for a method only the type name is matched, and the message says so. This is a name match, not a call
// graph: a method reached through an interface or another module is not seen.
// Measured on the same 231 pull requests: PREREG / READ-DEPS-7 in the novelty ledger.

// own code = .go files outside vendor/ and testdata/, not _test.go
export const isOwnGoFile = (p) => /\.go$/.test(p) && !/_test\.go$/.test(p) && !/(^|\/)(vendor|testdata)\//.test(p);
export const GO_SCAN_MAX_FILES = 8000;
export const GO_SCAN_MAX_BYTES = 64 * 1024 * 1024;

const BLOCK = /^import\s*\(([\s\S]*?)\)/gm;
const ONE = /^import\s+([A-Za-z_][A-Za-z0-9_]*\s+|\.\s+|_\s+)?"([^"]+)"/gm;
const SPEC = /^\s*([A-Za-z_][A-Za-z0-9_]*\s+|\.\s+|_\s+)?"([^"]+)"/gm;

/** One Go source text -> [[alias | null, path]] for each import it declares (block and single forms; comments inside a block skipped). */
export function goImportSpecs(src) {
  const text = String(src ?? "");
  const out = [];
  for (const m of text.matchAll(BLOCK)) for (const s of m[1].replace(/\/\/[^\n]*/g, "").matchAll(SPEC)) out.push([s[1]?.trim() || null, s[2]]);
  for (const m of text.matchAll(ONE)) out.push([m[1]?.trim() || null, m[2]]);
  return out;
}

/** One Go source text -> the set of import paths it declares. */
export const goImports = (src) => new Set(goImportSpecs(src).map(([, p]) => p));

/**
 * The name Go code uses for an import without an alias: the last path element, without a /vN major-version element,
 * a gopkg.in « .vN » suffix, a « go- » prefix or a « -go » / « .go » suffix (the usual Go naming conventions; the real
 * name is declared in the package, which is not read).
 */
export function goDefaultName(path) {
  const parts = String(path).split("/");
  let last = parts[parts.length - 1];
  if (/^v\d+$/.test(last) && parts.length > 1) last = parts[parts.length - 2];
  return last.replace(/\.v\d+$/, "").replace(/^go-/, "").replace(/[-.]go$/, "").replace(/[^A-Za-z0-9_]/g, "_");
}

/**
 * The affected imports of a Go advisory record, for one module: OSV record body -> [{path, symbols}]. `symbols` is the
 * list OSV gives (« Func » or « Type.Method »), [] when the whole package is affected. No import data gives [] (the
 * label is then never set: it is only a raise, never a hide).
 */
export function affectedGoImports(record, module) {
  const out = [];
  for (const a of Array.isArray(record?.affected) ? record.affected : []) {
    if (a?.package?.ecosystem !== "Go" || a.package.name !== module) continue;
    for (const imp of a.ecosystem_specific?.imports || []) {
      if (typeof imp?.path !== "string") continue;
      out.push({ path: imp.path, symbols: (Array.isArray(imp.symbols) ? imp.symbols : []).filter((s) => typeof s === "string" && /^[A-Za-z_][\w.]*$/.test(s)) });
    }
  }
  return out;
}

/** The affected import paths only (see affectedGoImports). */
export const affectedGoPaths = (record, module) => affectedGoImports(record, module).map((i) => i.path);

/**
 * Mark the Go vulnerable versions whose affected packages the repository imports: `imported: [paths]`, and, when a file
 * that imports one names an affected symbol, `named: ["http2.Server.ServeConn"]`. Both come from addKev (`v.goPaths`,
 * `v.goSymbols`). Sort: KEV, then named, then imported. `listFiles()` returns tracked paths, `read(p)` a file's text; both may throw. Never throws;
 * stops at GO_SCAN_MAX_FILES files or GO_SCAN_MAX_BYTES bytes (then says so in `scanNote`).
 */
export function markGoImported(r, listFiles, read) {
  if (!r || r.error || !r.vulnerable?.some((v) => v.goPaths?.length)) return r;
  const wanted = new Set(r.vulnerable.flatMap((v) => v.goPaths || []));
  const wantedSyms = new Map();   // path -> Set(symbol), from every version's advisories
  for (const v of r.vulnerable) for (const [p, syms] of Object.entries(v.goSymbols || {})) for (const s of syms) {
    if (!wantedSyms.has(p)) wantedSyms.set(p, new Set());
    wantedSyms.get(p).add(s);
  }
  const nSyms = [...wantedSyms.values()].reduce((n, s) => n + s.size, 0);
  const found = new Set(), named = new Set();   // named: « path symbol »
  let files = [], bytes = 0, scanned = 0, note;
  try { files = listFiles().filter(isOwnGoFile); } catch { return { ...r, scanNote: "Go import check skipped (file list unavailable)" }; }
  for (const p of files) {
    if (scanned >= GO_SCAN_MAX_FILES || bytes >= GO_SCAN_MAX_BYTES) { note = `Go import check stopped after ${scanned} of ${files.length} files`; break; }
    let src;
    try { src = read(p); } catch { continue; }
    scanned++; bytes += src.length;
    for (const [alias, path] of goImportSpecs(src)) {
      if (!wanted.has(path)) continue;
      found.add(path);
      // call level, by name: « name.Func » or « name.Type » (for « Type.Method ») in this file. A dot or blank import
      // gives no qualified name, so it stays at import level.
      const name = alias ?? goDefaultName(path);
      if (name === "." || name === "_") continue;
      for (const s of wantedSyms.get(path) || []) {
        if (named.has(`${path} ${s}`)) continue;
        if (new RegExp(`\\b${name}\\.${s.split(".")[0]}\\b`).test(src)) named.add(`${path} ${s}`);
      }
    }
    if (found.size === wanted.size && named.size === nSyms) break;
  }
  const vulnerable = r.vulnerable.map((v) => {
    const hit = (v.goPaths || []).filter((p) => found.has(p));
    if (!hit.length) return v;
    // what was matched, said as such: « http2.Parse », or « http2.Server (affected: Server.ServeConn) » for a method
    const shown = (p, s) => (s.includes(".") ? `${goDefaultName(p)}.${s.split(".")[0]} (affected: ${s})` : `${goDefaultName(p)}.${s}`);
    const syms = Object.entries(v.goSymbols || {}).flatMap(([p, ss]) => ss.filter((s) => named.has(`${p} ${s}`)).map((s) => shown(p, s)));
    return { ...v, imported: [...new Set(hit)], ...(syms.length ? { named: [...new Set(syms)] } : {}) };
  });
  const rank = (v) => (v.kev ? 3 : v.named ? 2 : v.imported ? 1 : 0);
  vulnerable.sort((a, b) => rank(b) - rank(a));
  return { ...r, vulnerable, ...(note ? { scanNote: note } : {}) };
}
