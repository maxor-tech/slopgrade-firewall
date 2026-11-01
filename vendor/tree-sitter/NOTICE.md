# Vendored tree-sitter runtime and grammars

Copied unchanged from the npm package `@vscode/tree-sitter-wasm@0.3.1` (Microsoft, MIT — `LICENSE` in this folder),
so the GitHub Action installs nothing in your runner. Used by `src/ts-ir.mjs` to read Python / JavaScript / TypeScript as
syntax trees (SQL injection pass, `src/sqli-ir.mjs`). No network access, no native code.

Upstream licences : tree-sitter (runtime, MIT, Max Brunsfeld), tree-sitter-python, tree-sitter-javascript and
tree-sitter-typescript (MIT, the tree-sitter project).

| File | SHA-256 |
|---|---|
| `tree-sitter.js` | `874f4a37c4beddef04d8eb9a8dbd28a65b63111f2d2123a38fd3f5333ee046dd` |
| `tree-sitter.wasm` | `3a31af706ffdf4a7116b064cdd4988df6791823298615009fc5b6bccbd42909b` |
| `tree-sitter-python.wasm` | `16108b50df4ee9a30168794252ab55e7c93bfc5765d7fa0aa3e335752c515f47` |
| `tree-sitter-javascript.wasm` | `5fb488d0cabb4775a594bab85682de5ad6ce83c0d6ac997a9f82dd084d571240` |
| `tree-sitter-typescript.wasm` | `778025db5a8be0e70f8ccc3671e486dfeddd048c25d9e8a70c26de2e1bf6f97d` |
| `tree-sitter-tsx.wasm` | `79e5da75ea62855a0cd67177685f0164eac87d5f630b3cbe1e0a099751ad30f8` |
