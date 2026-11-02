// Path Traversal / Local File Inclusion (CWE-22 · CWE-98) — LANGUAGE-AGNOSTIC client fingerprint. Mirror of
// cmdi-extract: emit {file, line, kind} — NEVER the source line. A request-derived value used DIRECTLY as the path
// of a file-open / file-read / include sink lets an attacker read `../../../etc/passwd` or app secrets (and, for a
// PHP include/require, run code — LFI→RCE). We scope TIGHT: the untrusted value must be the DIRECT argument of the
// sink — so `open(safe_join(base, request.args['f']))` (sanitized: safe_join is the arg) does NOT fire; only
// `open(request.args['f'])` does. Precision over recall = ~0 FP; broad path taint would need dataflow.

import { isDecompiledSource, isPackedSource, kindAppliesToFile, logicalLines } from "./lang-scope.mjs";
import { runTaintPass, mentions } from "./taint-core.mjs";
import { FRAMEWORK_SOURCE, paramSources } from "./sources.mjs";
import { findSinkWrappers, interprocHit } from "./taint-interproc.mjs";

// STRICT source-access form (a request SUB-FIELD, never the bare word) — safe to match nested in a sink's args
// without flagging a string literal that merely contains "request".
const SRC = "request\\s*\\.\\s*(?:args|form|values|GET|POST|json|data)|req(?:uest)?\\s*\\.\\s*(?:query|body|params)|\\$_(?:GET|POST|REQUEST|COOKIE)";
const PATTERNS = [
  // Python — open()/send_file() with a request value as the path. send_from_directory (the SAFE Flask helper) is NOT
  // matched. `os.path.join(..., request…)` is excluded: join is the sanitization boundary, not the sink.
  // A BARE call only (real-code corpus FP: `opener.open(req)` urllib, `Image.open(requests.get(url).raw)`, a TS/Go/Rust
  // method `open(request: T)`) — and the request value must be ACCESSED (`request.args…`, `req.query…`, `request[…]`):
  // a bare `request` / `req` argument is a request OBJECT, never a path, and `requests` is the HTTP library.
  ["py-open", new RegExp(`(?<![\\w.])(?:open|send_file)\\s*\\(\\s*(?:(?:request|req)\\s*[.[]|\\$_(?:GET|POST|REQUEST|COOKIE))`)],
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
// fopen / readfile / file_get_contents on a literal http(s):// URL FETCH a page (the superglobal is a query value), they
// do not open a local path (hcaptcha siteverify — benchmark re-checked 2026-10-31). include/require with a URL stay
// flagged : that is remote file inclusion.
const PHP_URL_FETCH = /\b(?:fopen|readfile|file_get_contents)\s*\(\s*['"]https?:\/\//i;

// ── Taint-pass vocabulary (Python + Node ; fed to the shared runTaintPass engine) ───────────────────────────────
// Source = a request-derived value on the RHS (property access only; bare `params` excluded per the direct pack).
const SOURCE = new RegExp(`\\brequest\\s*\\.\\s*(?:args|form|values|GET|POST|json|data)\\b|\\breq(?:uest)?\\s*\\.\\s*(?:query|body|params)\\b|${FRAMEWORK_SOURCE}`);   // + framework / LLM sources (sources.mjs)
// A path-sanitizing marker OR a conditional guard on the value — assume the path is made safe → clear taint.
// basename/secure_filename strip the directory; realpath/resolve/abspath+check + safe_join canonicalize; a
// .replace/.strip/.sub is treated as manual `..`-stripping (precision-first — recall cost accepted).
const PATH_SANITIZE = /\b(?:basename|secure_filename|realpath|resolve|canonical\w*|safe_join|abspath|allowlist|whitelist|sanitiz\w*|valid\w*|escape\w*)\b|\.(?:replace|strip|lstrip|sub)\b|^\s*(?:if|elif|else\s+if|while|assert|unless)\b/i;
const HASHED = /\.hexdigest\s*\(|\.digest\s*\(\s*['"]hex['"]|\buuid\d?\s*\(|\buuid\.uuid\d\s*\(/;
const esc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
// A file sink containing the tainted var: Python open/send_file/io.open/os.remove|unlink|rename ; Node fs.* / sendFile.
// A call whose FIRST argument is a plain quoted path reads / writes a CONSTANT file : the tainted value in a later
// argument is content, not a path (`fs.writeFile('views/qr/code.txt', QRcode, cb)` — benchmark re-checked 2026-10-31).
// A template literal can interpolate, so only '…' / "…" count as constant.
const CONST_FIRST = `(?!\\s*['"][^'"\\n]*['"]\\s*[,)])`;
// `Image.open(BytesIO(data))` / `pdfplumber.open(io.BytesIO(contents))` / `Image.open(upload.file)` decode an IN-MEMORY
// stream of uploaded bytes : the bytes are never read as a filesystem path (independent set v1, 2026-11-01 : 3 blocking
// FPs — LaTeX-OCR, HealthRecordAgent). A path argument to the same `.open` still fires.
const STREAM_FIRST = `(?!\\s*(?:io\\s*\\.\\s*)?(?:BytesIO|StringIO)\\s*\\(|\\s*\\w+\\s*\\.\\s*(?:file|stream|raw)\\s*\\))`;
const sink = (v) => {
  const V = esc(v);
  return new RegExp(
    `\\b(?:open|send_file)\\s*\\(${CONST_FIRST}${STREAM_FIRST}[^)]*\\b${V}\\b` +
    `|\\bio\\.open\\s*\\(${CONST_FIRST}[^)]*\\b${V}\\b` +
    `|\\bos\\.(?:remove|unlink|rename)\\s*\\(${CONST_FIRST}[^)]*\\b${V}\\b` +
    `|\\bfs\\s*\\.\\s*(?:readFile|readFileSync|createReadStream|open|openSync|writeFile|writeFileSync|unlink|createWriteStream|readdir|readdirSync)\\s*\\(${CONST_FIRST}[^)]*\\b${V}\\b` +
    `|\\.\\s*sendFile\\s*\\(${CONST_FIRST}[^)]*\\b${V}\\b` +
    // PHP and Java file APIs (expert panel P1-5 : a Laravel `$request->input` or a Spring `@RequestParam` value had no
    // taint sink to reach). A PHP variable starts with `$`, so its boundaries are `$`-aware, not `\b`.
    `|\\b(?:readfile|file_get_contents|fopen|file_put_contents|unlink|include|include_once|require|require_once|highlight_file|show_source)\\s*\\(${CONST_FIRST}[^)]*(?<![\\w$])${V}(?![\\w$])` +
    `|\\bnew\\s+File(?:InputStream|OutputStream|Reader|Writer)?\\s*\\(${CONST_FIRST}[^)]*\\b${V}\\b` +
    `|\\b(?:Paths\\s*\\.\\s*get|Path\\s*\\.\\s*of)\\s*\\(${CONST_FIRST}[^)]*\\b${V}\\b`
  );
};

// A cheap file-level gate: no file-sink token ⇒ skip the inter-procedural pass.
const HAS_SINK = /\b(?:open|send_file|sendFile|readfile|file_get_contents|fopen|file_put_contents|include|require)\s*\(|\bnew\s+File\w*\s*\(|\b(?:Paths\s*\.\s*get|Path\s*\.\s*of)\s*\(|\bfs\s*\.\s*(?:readFile|readFileSync|createReadStream|open|openSync|writeFile|writeFileSync|unlink|createWriteStream|readdir|readdirSync)|\bos\.(?:remove|unlink|rename)/;
// For pass 1, a wrapper param reaches the sink only if the same line is NOT itself sanitized (mirrors checkSinks).
const ptSinkTest = (l, v) => !PATH_SANITIZE.test(l) && sink(v).test(l);
/** The path-traversal wrapper config — shared by the walker's cross-file registry build and the calibration harness. */
export const pathTraversalWrapperCfg = { sinkTest: ptSinkTest, sanitizer: PATH_SANITIZE, sourceTest: SOURCE, hasSink: HAS_SINK };

/** Path-traversal taint pass — intra-function + inter-procedural + cross-file (a file-sink wrapper imported from another module). */
function taintPass(lines, text, importedWrappers) {
  const wrappers = HAS_SINK.test(text)
    ? findSinkWrappers(lines, { sinkTest: ptSinkTest, sanitizer: PATH_SANITIZE, sourceTest: SOURCE })
    : new Map();
  const imported = importedWrappers instanceof Map ? importedWrappers : new Map();
  const dangerous = (taint) => (a) => SOURCE.test(a) || [...taint.keys()].some((v) => mentions(v, a));
  return runTaintPass(lines, {
    paramSources, paramTag: "t",
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
      // A hash / uuid of the user value is a fixed-alphabet hex token, never traversable (real-code corpus FP:
      // `name = hashlib.sha256(await request.body()).hexdigest()` → a cache path `f'{name}.json'`).
      if ((hasSource || hasTaintVar) && !HASHED.test(rhs)) taint.set(name, "t");
      else taint.delete(name);
    },
  });
}

// The path an upload middleware STORED the file at (multer `req.file.path`, `req.files[0].path`, `.destination`) is
// chosen by the server, not the client — reading it back is not traversal (independent set v4, 2026-11-01 : 2 blocking
// FP rows, LibreChat avatar + assistants uploads). `req.file.originalname` stays a source. Path traversal only : the
// shared FRAMEWORK_SOURCE keeps `req.file` for the packs where the client-chosen fields matter.
const HEISEN_STORED_UPLOAD = /\breq\s*\.\s*files?\b(?:\s*\[[^\]]*\]|\s*\.\s*[A-Za-z_$][\w$]*)?(?:\s*\[[^\]]*\])?\s*\.\s*(?:path|destination)\b/g;

/** Scan one file → [{line, kind}]. Direct regex + path-traversal taint. Source line NEVER leaves this function. */
export function extractPathTraversal(text, importedWrappers, file) {
  const out = [];
  if (isPackedSource(text) || isDecompiledSource(text, file)) return out;   // a vendored / packed build, or decompiler output (lang-scope.mjs)
  const lines = logicalLines(String(text).split(/\r?\n/)).map((l) => l.replace(HEISEN_STORED_UPLOAD, "heisenStoredUpload"));   // statements read whole ; stored upload paths neutral
  for (let i = 0; i < lines.length; i++) {
    const l = lines[i];
    if (l.length > 4000) continue;   // minified blob — noise
    if (isComment(l)) continue;      // a sink named in a comment is documentation, not live code
    for (const [kind, re] of PATTERNS) {
      if (!kindAppliesToFile(kind, file)) continue;   // a language rule fires only on its own files (lang-scope.mjs)
      if (kind === "php-include" && PHP_URL_FETCH.test(l)) continue;   // an HTTP fetch, not a local path
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
  return { file, hits: extractPathTraversal(text, importedWrappers, file) };
}
