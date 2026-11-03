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

// The RHS is ONE call (optionally awaited, optionally followed by member / index access) whose callee does not build a
// path or a string : `await getItem(id)`, `db.get(Model, pk).file_path`, `pool.lookup(model_id)["path"]`.
const PATH_BUILDER = /(?:^|\.)(?:join|resolve|normalize|normpath|abspath|realpath|relpath|expanduser|Path|PurePath|PosixPath|str|String|format|concat|replace|strip|lstrip|rstrip|lower|upper|trim|slice|substring|decodeURIComponent|unquote|url2pathname|fspath|toString)$/;
const MEMBER_TAIL = /^\s*(?:(?:\?\.|\.)\s*[A-Za-z_$][\w$]*|\[[^\]]*\]|\s)*;?\s*$/;
// A helper DEFINED IN THIS FILE usually builds the path itself (`_get_file_path(file_id)` base64-decodes and joins,
// `get_workflow_path(id)`, `_get_data_template_path(name)`) : the taint stays (blind labels of the 82 hits the rule
// first removed : the 9 true ones all called a same-file helper ; the false ones called records / lookups defined elsewhere).
const definedHere = (name, text) => new RegExp(`(?:\\bdef\\s+|\\bfunction\\s*\\*?\\s*|\\b(?:const|let|var)\\s+)${name.replace(/[$]/g, "\\$")}\\b|^\\s*(?:async\\s+)?${name.replace(/[$]/g, "\\$")}\\s*\\([^)]*\\)\\s*\\{`, "m").test(text);
function heisenLoadedThroughCall(rhs, text = "", taintedNames = []) {
  // `(await db.findById(id)).path` : a parenthesized loaded call, then member access only
  if (/^\s*\(/.test(rhs)) {
    let depth = 0, k = rhs.indexOf("(");
    for (; k < rhs.length; k++) { if (rhs[k] === "(") depth++; else if (rhs[k] === ")" && --depth === 0) break; }
    return k < rhs.length && MEMBER_TAIL.test(rhs.slice(k + 1)) && heisenLoadedThroughCall(rhs.slice(rhs.indexOf("(") + 1, k), text, taintedNames);
  }
  const m =/^\s*(?:await\s+)?([A-Za-z_$][\w$.]*)\s*\(/.exec(rhs);
  if (!m || PATH_BUILDER.test(m[1])) return false;
  // a bare / self. / this. / cls. call to a function defined in this file : it may build the path → keep the taint
  const local = /^(?:(?:self|this|cls)\.)?([A-Za-z_$][\w$]*)$/.exec(m[1]);
  if (local && definedHere(local[1], text)) return false;
  // a helper whose NAME says it returns a path (`_get_data_template_path(name)`, `registry.get_workflow_path(id)`) builds it
  if (/(?:path|file|dir|folder|location)\w*$/i.test(m[1].split(".").pop())) return false;
  // a method ON the user value reads a field of it (`req_data.get("data_path")`, `body.pop("f")`) : not a lookup
  const recv = m[1].includes(".") ? m[1].slice(0, m[1].lastIndexOf(".")) : "";
  if (recv && taintedNames.some((v) => recv === v || recv.startsWith(v + ".") || recv.startsWith(v + "["))) return false;
  // the whole RHS is that call (+ member / index access) — no `+` / template / f-string building around it
  let depth = 0, k = rhs.indexOf("(", m.index);
  for (; k < rhs.length; k++) { if (rhs[k] === "(") depth++; else if (rhs[k] === ")" && --depth === 0) break; }
  return MEMBER_TAIL.test(rhs.slice(k + 1));
}

// ── Sanitizer summaries (P1, docs/FIREWALL-DATAFLOW-PATH-SSRF-PLAN.md) ─────────────────────────────────────────────
// A same-file helper keeps the taint (definedHere above) because helpers usually BUILD the path. A helper whose BODY
// sanitizes or contains the path is the opposite : its result is safe. Body = a sanitizer call (PATH_SANITIZE) or a
// containment guard — `startswith` / `startsWith` / `commonpath` / `is_relative_to` / `relative_to` / a `..` test.
const HEISEN_CONTAINMENT = /\.\s*(?:startswith|startsWith)\s*\(|\bcommonpath\s*\(|\.\s*(?:is_relative_to|relative_to)\s*\(|['"]\.\.['"]\s*(?:in|===?|!==?)|(?:includes|indexOf|contains)\s*\(\s*['"]\.\.['"]/;
/** The body of the function `name` defined in this file (Python indent block / JS braces), or null. */
function heisenFunctionBody(name, text) {
  const n = name.replace(/[$]/g, "\\$");
  const lines = String(text).split(/\r?\n/);
  const py = new RegExp(`^(\\s*)(?:async\\s+)?def\\s+${n}\\s*\\(`);
  const js = new RegExp(`(?:\\bfunction\\s*\\*?\\s*${n}\\s*\\(|\\b(?:const|let|var)\\s+${n}\\s*=\\s*(?:async\\s*)?(?:function\\b|\\([^)]*\\)\\s*=>|[A-Za-z_$][\\w$]*\\s*=>)|^\\s*(?:(?:public|private|protected|static|async)\\s+)*${n}\\s*\\([^)]*\\)\\s*\\{)`);
  for (let i = 0; i < lines.length; i++) {
    const p = py.exec(lines[i]);
    if (p) {
      const indent = p[1].length, body = [];
      for (let j = i + 1; j < lines.length && j < i + 200; j++) {
        if (lines[j].trim() && lines[j].match(/^(\s*)/)[1].length <= indent) break;
        body.push(lines[j]);
      }
      return body.join("\n");
    }
    if (js.test(lines[i])) {
      let depth = 0, started = false; const body = [];
      for (let j = i; j < lines.length && j < i + 200; j++) {
        body.push(lines[j]);
        for (const ch of lines[j]) { if (ch === "{") { depth++; started = true; } else if (ch === "}") depth--; }
        if (started && depth <= 0) break;
        if (!started && j > i && /=>\s*[^{\s]/.test(lines[i])) break;   // expression-bodied arrow : one line
      }
      return body.join("\n");
    }
  }
  return null;
}
/** The RHS is one call to a same-file helper whose body sanitizes / contains the path. */
function heisenLocalSanitizer(rhs, text) {
  const m = /^\s*(?:await\s+)?(?:(?:self|this|cls)\.)?([A-Za-z_$][\w$]*)\s*\(/.exec(rhs);
  if (!m || !definedHere(m[1], text)) return false;
  const body = heisenFunctionBody(m[1], text);
  return body !== null && (PATH_SANITIZE.test(body) || HEISEN_CONTAINMENT.test(body));
}

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
      // A value LOADED through a call with the user value as an argument (`item = await getItem(id)`,
      // `pool.get(model_id).path`) is a record, not a user-chosen path ; only a call that BUILDS a path or string from it
      // carries the taint (independent sets v4 + v5, 2026-11-02 : frigate, chatchat, omlx x2, stf ; the main false class of
      // the 5,300-repo tree sweep too). An inline request source on the RHS still taints.
      if (!hasSource && hasTaintVar && heisenLoadedThroughCall(rhs, text, [...taint.keys()])) { taint.delete(name); return; }
      // a same-file helper whose body sanitizes / contains the path returns a safe value (sanitizer summary, P1)
      if ((hasSource || hasTaintVar) && heisenLocalSanitizer(rhs, text)) { taint.delete(name); return; }
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
