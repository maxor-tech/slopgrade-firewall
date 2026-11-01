// Syntax-tree layer (expert panel P0-3 : the dataflow core). tree-sitter grammars compiled to WebAssembly
// (@vscode/tree-sitter-wasm : the runtime + the grammars VS Code ships, MIT, no native build). One async init loads
// the runtime ; each grammar loads on first use and is cached. After that, parsing is synchronous, so an extractor can
// stay a plain `(text, file) → hits` function : `await initIr()` once, then `parseFile(text, file)`.
// A file whose language has no grammar here, or a parse that fails, returns null : the caller keeps its line reader.
import { createRequire } from "node:module";
import { readFileSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";

const GRAMMAR = { python: "python", javascript: "javascript", typescript: "typescript", tsx: "tsx" };
/** The grammar for a file path, or null. */
export function langOf(file) {
  const f = String(file ?? "").toLowerCase();
  if (/\.py$/.test(f)) return "python";
  if (/\.(?:js|mjs|cjs|jsx)$/.test(f)) return "javascript";
  if (/\.tsx$/.test(f)) return "tsx";
  if (/\.(?:ts|mts|cts)$/.test(f)) return "typescript";
  return null;
}

let rt = null;                     // { Parser, Language, dir }
const langs = new Map();           // grammar → Language
const parsers = new Map();         // grammar → Parser

// The package's wasm/ folder. In a bundled server (Next / Turbopack on Vercel) `require.resolve` can return a module id
// instead of a path, while the traced files sit under <cwd>/node_modules : try each candidate, keep the one that holds
// the runtime (2026-11-01 : /try on production read SQL by lines although the trace shipped the wasm).
function packageWasmDir(require) {
  const candidates = [];
  try { const p = require.resolve("@vscode/tree-sitter-wasm/package.json"); if (typeof p === "string") candidates.push(join(dirname(p), "wasm")); }
  catch { /* @swallow: an unresolvable package leaves the cwd candidate below */ }
  candidates.push(join(process.cwd(), "node_modules", "@vscode", "tree-sitter-wasm", "wasm"));
  const found = candidates.find((d) => existsSync(join(d, "tree-sitter.wasm")));
  if (!found) throw new Error(`tree-sitter runtime not found (tried ${candidates.join(", ")})`);
  return found;
}

/**
 * Load the runtime and the given grammars (default : all). Idempotent.
 * `runtime` = { Parser, Language, dir } supplied by the caller — the OSS client passes its VENDORED copy (no npm
 * install in a customer's runner) ; omitted, the server resolves the @vscode/tree-sitter-wasm package.
 */
export async function initIr(grammars = Object.keys(GRAMMAR), runtime = null) {
  if (!rt) {
    let { Parser, Language, dir } = runtime ?? {};
    if (!Parser) {
      const require = createRequire(import.meta.url);
      dir = packageWasmDir(require);
      // the package main IS wasm/tree-sitter.js ; a static specifier (a computed require path fails the Next/Turbopack build)
      ({ Parser, Language } = require("@vscode/tree-sitter-wasm"));
    }
    await Parser.init({ locateFile: () => join(dir, "tree-sitter.wasm") });
    rt = { Parser, Language, dir };
  }
  for (const g of grammars) {
    if (langs.has(g)) continue;
    const lang = await rt.Language.load(readFileSync(join(rt.dir, `tree-sitter-${GRAMMAR[g]}.wasm`)));
    langs.set(g, lang);
    const p = new rt.Parser(); p.setLanguage(lang); parsers.set(g, p);
  }
}

/** True once initIr() has loaded the grammar for this file. */
export const irReady = (file) => parsers.has(langOf(file) ?? "");

/** Parse one file → { tree, lang } or null (no grammar loaded, or a parse error at the root). */
export function parseFile(text, file) {
  const lang = langOf(file);
  const p = lang && parsers.get(lang);
  if (!p) return null;
  try {
    const tree = p.parse(String(text ?? ""));
    return tree ? { tree, lang } : null;
  } catch { return null; }
}
