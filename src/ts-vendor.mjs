// The client's tree-sitter runtime : the VENDORED copy in vendor/tree-sitter/ (see its NOTICE.md — copied unchanged
// from @vscode/tree-sitter-wasm, hashes listed), so the Action installs nothing in a customer's runner. Passed to
// initIr() (src/ts-ir.mjs). Any load failure returns null : the SQL pass then keeps the line reader.
import { createRequire } from "node:module";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const DIR = join(dirname(fileURLToPath(import.meta.url)), "..", "vendor", "tree-sitter");

/** { Parser, Language, dir } from the vendored runtime, or null when the folder is absent. */
export function vendoredRuntime() {
  if (!existsSync(join(DIR, "tree-sitter.js"))) return null;
  try {
    const { Parser, Language } = createRequire(import.meta.url)(join(DIR, "tree-sitter.js"));
    return Parser && Language ? { Parser, Language, dir: DIR } : null;
  } catch { return null; }
}
