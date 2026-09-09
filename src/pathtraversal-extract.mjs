// Path Traversal / Local File Inclusion (CWE-22 · CWE-98) — LANGUAGE-AGNOSTIC client fingerprint. Mirror of
// cmdi-extract: emit {file, line, kind} — NEVER the source line. A request-derived value used DIRECTLY as the path
// of a file-open / file-read / include sink lets an attacker read `../../../etc/passwd` or app secrets (and, for a
// PHP include/require, run code — LFI→RCE). We scope TIGHT: the untrusted value must be the DIRECT argument of the
// sink — so `open(safe_join(base, request.args['f']))` (sanitized: safe_join is the arg) does NOT fire; only
// `open(request.args['f'])` does. Precision over recall = ~0 FP; broad path taint would need dataflow.

import { runTaintPass, mentions } from "./taint-core.mjs";
import { findSinkWrappers, interprocHit } from "./taint-interproc.mjs";

const REQ = "request|req\\b|\\$_(?:GET|POST|REQUEST|COOKIE)";
// STRICT source-access form (a request SUB-FIELD, never the bare word) — safe to match nested in a sink's args
// without flagging a string literal that merely contains "request".
const SRC = "request\\s*\\.\\s*(?:args|form|values|GET|POST|json|data)|req(?:uest)?\\s*\\.\\s*(?:query|body|params)|\\$_(?:GET|POST|REQUEST|COOKIE)";
const PATTERNS = [
  // Python — open()/send_file() with a request value as the path. send_from_directory (the SAFE Flask helper) is NOT
  // matched. `os.path.join(..., request…)` is excluded: join is the sanitization boundary, not the sink.
  ["py-open", new RegExp(`\\b(?:open|send_file)\\s*\\(\\s*(?:${REQ})`)],
  // Python — a user SUB-FIELD nested anywhere in a file sink's args: open(os.path.join(base, request.args[…])),
  // io.open, os.remove/unlink/rename, and pathlib Path(request…). The strict SRC form keeps a string literal clean.
  ["py-file-nested", new RegExp(`\\b(?:open|io\\.open|send_file|os\\.(?:remove|unlink|rename))\\s*\\([^)]*(?:${SRC})`)],
  ["py-pathlib", new RegExp(`\\bPath\\s*\\([^)]*(?:${SRC})`)],
  // Node — fs read/open/stream or res.sendFile with a request value as the path.
  ["node-fs", /\bfs\s*\.\s*(?:readFile|readFileSync|createReadStream|open|openSync|readdir|readdirSync)\s*\(\s*(?:req|request)\b|\.\s*sendFile\s*\(\s*(?:req|request)\b/],
  // PHP — include/require (LFI→RCE) or a file-read function on a superglobal.
  ["php-include", /\b(?:include|include_once|require|require_once|fopen|readfile|file_get_contents|highlight_file|show_source)\s*\(\s*[^;]*\$_(?:GET|POST|REQUEST|COOKIE)/],
  // Java — new File / Files.read / FileInputStream built from a request parameter.
  ["java-file", /new\s+File\s*\([^;]*request\.getParameter|Files\s*\.\s*(?:readAllBytes|newInputStream|readAllLines|lines)\s*\([^;]*\brequest\b|new\s+FileInputStream\s*\([^;]*\brequest\b/],
  // Ruby — File.read/open/new or send_file on params.
  ["ruby-file", /\bFile\s*\.\s*(?:read|open|new|readlines)\s*\(\s*params\b|\bsend_file\s*\(\s*params\b/],
];

const isComment = (l) => /^\s*(\/\/|\*|#|--|;|<!--)/.test(l);

// ── Taint-pass vocabulary (Python + Node ; fed to the shared runTaintPass engine) ───────────────────────────────
// Source = a request-derived value on the RHS (property access only; bare `params` excluded per the direct pack).
const SOURCE = /\brequest\s*\.\s*(?:args|form|values|GET|POST|json|data)\b|\breq(?:uest)?\s*\.\s*(?:query|body|params)\b/;
// A path-sanitizing marker OR a conditional guard on the value — assume the path is made safe → clear taint.
// basename/secure_filename strip the directory; realpath/resolve/abspath+check + safe_join canonicalize; a
// .replace/.strip/.sub is treated as manual `..`-stripping (precision-first — recall cost accepted).
const PATH_SANITIZE = /\b(?:basename|secure_filename|realpath|resolve|canonical\w*|safe_join|abspath|allowlist|whitelist|sanitiz\w*|valid\w*|escape\w*)\b|\.(?:replace|strip|lstrip|sub)\b|^\s*(?:if|elif|else\s+if|while|assert|unless)\b/i;
const esc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
// A file sink containing the tainted var: Python open/send_file/io.open/os.remove|unlink|rename ; Node fs.* / sendFile.
const sink = (v) => {
  const V = esc(v);
  return new RegExp(
    `\\b(?:open|send_file)\\s*\\([^)]*\\b${V}\\b` +
    `|\\bio\\.open\\s*\\([^)]*\\b${V}\\b` +
    `|\\bos\\.(?:remove|unlink|rename)\\s*\\([^)]*\\b${V}\\b` +
    `|\\bfs\\s*\\.\\s*(?:readFile|readFileSync|createReadStream|open|openSync|writeFile|writeFileSync|unlink|createWriteStream|readdir|readdirSync)\\s*\\([^)]*\\b${V}\\b` +
    `|\\.\\s*sendFile\\s*\\([^)]*\\b${V}\\b`
  );
};

// A cheap file-level gate: no file-sink token ⇒ skip the inter-procedural pass.
const HAS_SINK = /\b(?:open|send_file|sendFile)\s*\(|\bfs\s*\.\s*(?:readFile|readFileSync|createReadStream|open|openSync|writeFile|writeFileSync|unlink|createWriteStream|readdir|readdirSync)|\bos\.(?:remove|unlink|rename)/;
// For pass 1, a wrapper param reaches the sink only if the same line is NOT itself sanitized (mirrors checkSinks).
const ptSinkTest = (l, v) => !PATH_SANITIZE.test(l) && sink(v).test(l);
/** The path-traversal wrapper config — shared by the walker's cross-file registry build. */
export const pathTraversalWrapperCfg = { sinkTest: ptSinkTest, sanitizer: PATH_SANITIZE, sourceTest: SOURCE, hasSink: HAS_SINK };

/** Path-traversal taint pass — intra-function + inter-procedural + cross-file (a file-sink wrapper imported from another module). */
function taintPass(lines, text, importedWrappers) {
  const wrappers = HAS_SINK.test(text)
    ? findSinkWrappers(lines, { sinkTest: ptSinkTest, sanitizer: PATH_SANITIZE, sourceTest: SOURCE })
    : new Map();
  const imported = importedWrappers instanceof Map ? importedWrappers : new Map();
  const dangerous = (taint) => (a) => SOURCE.test(a) || [...taint.keys()].some((v) => mentions(v, a));
  return runTaintPass(lines, {
    sanitizer: PATH_SANITIZE,
    checkSinks(l, taint, emit) {
      if (PATH_SANITIZE.test(l)) return;   // an inline basename/secure_filename/… on the sink line → treat as safe
      for (const v of taint.keys()) if (sink(v).test(l)) { emit("taint-path"); return; }
      // Inter-procedural: an inline user source OR a tainted var at a flowing arg of a LOCAL file-sink wrapper.
      if (wrappers.size && interprocHit(l, wrappers, dangerous(taint))) { emit("taint-interproc"); return; }
      // Cross-file: same, into a file-sink wrapper IMPORTED from another module. (Note: a wrapper whose body sanitizes
      // is excluded at registry time via ptSinkTest, so an imported basename-ing helper is never a wrapper.)
      if (imported.size && interprocHit(l, imported, dangerous(taint))) { emit("taint-xfile"); return; }
    },
    updateTaint(l, taint, sa) {
      if (!sa) return;
      const { name, rhs } = sa;
      const hasSource = SOURCE.test(rhs);
      const hasTaintVar = [...taint.keys()].some((v) => v !== name && mentions(v, rhs));
      if (hasSource || hasTaintVar) taint.set(name, "t");
      else taint.delete(name);
    },
  });
}

/** Scan one file → [{line, kind}]. Direct regex + path-traversal taint. Source line NEVER leaves this function. */
export function extractPathTraversal(text, importedWrappers) {
  const out = [];
  const lines = String(text).split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const l = lines[i];
    if (l.length > 4000) continue;   // minified blob — noise
    if (isComment(l)) continue;      // a sink named in a comment is documentation, not live code
    for (const [kind, re] of PATTERNS) {
      // The NESTED patterns (source anywhere in the args) must respect an inline sanitizer on the same line:
      // open(secure_filename(request.args['f'])) is SAFE. The tight py-open (source directly after open() cannot
      // match a wrapped source, so it stays ungated.
      if ((kind === "py-file-nested" || kind === "py-pathlib") && PATH_SANITIZE.test(l)) continue;
      if (re.test(l)) out.push({ line: i + 1, kind });
    }
  }
  for (const h of taintPass(lines, text, importedWrappers)) out.push(h);
  return out;
}

/** The path-traversal fingerprint for one file — locations + kinds, no source. */
export function extractPathTraversalFingerprint(text, file, importedWrappers) {
  return { file, hits: extractPathTraversal(text, importedWrappers) };
}
