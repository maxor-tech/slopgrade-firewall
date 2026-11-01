// XSS / HTML injection (CWE-79) — LANGUAGE-AGNOSTIC client fingerprint. Emit {file, line, kind} — NEVER the source
// line. Unescaped user input reaching an HTML sink runs attacker JS in the victim's session (cookie/session theft,
// account takeover). XSS is the FP-trickiest class — innerHTML / dangerouslySetInnerHTML are usually constant or
// sanitized — so both layers scope TIGHT and any sanitizing call on the value keeps it clean.
//
// TWO detection layers, both client-side; only the {line, kind} egresses:
//   1. DIRECT (line-regex) — the source is INLINE at the sink: a PHP superglobal echoed raw, Rails raw(params),
//      mark_safe(request), dangerouslySetInnerHTML __html:req, or a DOM sink fed straight from location/document.URL.
//   2. TAINT (dataflow)    — intra-function: `const h = req.query.msg` … `el.innerHTML = h`, or `h = location.hash`
//      … `node.insertAdjacentHTML('beforeend', h)`. A var derived from an untrusted source reaching an HTML sink
//      (innerHTML/outerHTML/document.write/insertAdjacentHTML/dangerouslySetInnerHTML) fires — UNLESS a sanitizer
//      (DOMPurify/escape/encodeURI/textContent) appears on the value first.
//   3. REFLECTED (server)   — an HTTP response body built as HTML with a request value concatenated straight in
//      (res.send('<h1>' + req.query.name) / res.send(`<h1>${req.query.name}`) / echo "<div>".$_GET). Scoped TIGHT to
//      hold ~0 FP: the arg must carry an HTML-markup literal AND the source must be DIRECTLY adjacent to a `+`/`${`
//      (Node) or `.` (PHP) — so a sanitized `res.send('<h1>' + escapeHtml(req.query.x))` never fires (the source is
//      behind a call paren, not an operator).

const PATTERNS = [
  // PHP reflected — echo/print a superglobal directly (echo htmlspecialchars($_GET) does NOT match: the superglobal
  // is not the first token after echo).
  ["php-echo", /\b(?:echo|print)\s+\$_(?:GET|POST|REQUEST|COOKIE)\b/],
  // Rails — raw()/html_safe on params (bypasses ERB autoescaping).
  ["rails-raw", /\braw\s*\(\s*params\b|params\s*\[[^\]]*\]\s*\.\s*html_safe\b/],
  // Django/Flask — mark_safe()/Markup() on a request value (bypasses template autoescaping).
  ["py-marksafe", /\b(?:mark_safe|Markup)\s*\(\s*request\b/],
  // React — dangerouslySetInnerHTML __html taken straight from a request value.
  ["react-dsih", /dangerouslySetInnerHTML\s*=\s*\{\{\s*__html\s*:\s*(?:req|request)\b/],
  // DOM-based — innerHTML/outerHTML/document.write fed directly from a URL-controlled source.
  ["dom-sink", /\.(?:innerHTML|outerHTML)\s*=\s*(?:window\s*\.\s*)?(?:location|document\s*\.\s*(?:URL|referrer|location))\b|document\s*\.\s*write\s*\(\s*(?:window\s*\.\s*)?(?:location|document\s*\.\s*(?:URL|referrer))\b/],
  // Reflected — an HTTP response body built as HTML with a request value concatenated directly in. The first arg must
  // carry an HTML-markup literal (`'<h1>'`/`` `<h1> ``) AND the request source must be immediately after a `+`/`${`
  // (Node) or a `.` (PHP) — an escaping call (source behind a `(`) never matches, so it stays ~0 FP.
  ["reflected-html", new RegExp(
    `\\b(?:res|response|reply|ctx)\\s*\\.\\s*(?:send|write|end)\\s*\\(\\s*(?=[^,)]*["'\`]\\s*<\\s*[A-Za-z!\\/])[^,)]*(?:\\+\\s*|\\$\\{\\s*)(?:${"req(?:uest)?\\s*\\.\\s*(?:query|body|params)|request\\s*\\.\\s*(?:args|json|form|values)"})\\b` +
    `|\\b(?:echo|print)\\b(?=[^;]*["']\\s*<\\s*[A-Za-z!\\/])[^;]*\\.\\s*\\$_(?:GET|POST|REQUEST|COOKIE)\\b`)],
];

import { isDecompiledSource, isPackedSource, kindAppliesToFile, logicalLines } from "./lang-scope.mjs";
import { runTaintPass, mentions } from "./taint-core.mjs";
import { FRAMEWORK_SOURCE, paramSources } from "./sources.mjs";
import { findSinkWrappers, interprocHit } from "./taint-interproc.mjs";

// A superglobal that is only COMPARED in a ternary whose two outputs are literals echoes one of two constants
// (`echo $_GET["t"] == "d" ? "folder" : "file";` — benchmark 2026-10-24 re-checked 2026-10-31 : 4 wrong blocks).
const PHP_ECHO_CONST_TERNARY = /\b(?:echo|print)\s+\$_(?:GET|POST|REQUEST|COOKIE)\s*\[[^\]]*\]\s*(?:[=!]==?|[<>]=?)\s*(?:"[^"\n]*"|'[^'\n]*'|-?\d+)\s*\?\s*(?:"[^"\n]*"|'[^'\n]*'|-?\d+)\s*:\s*(?:"[^"\n]*"|'[^'\n]*'|-?\d+)\s*;/;
const isComment = (l) => /^\s*(\/\/|\*|#|--|;|<!--)/.test(l);

// ── Taint-pass vocabulary (fed to the shared runTaintPass engine) ────────────────────────────────────────────────
// An untrusted source: a request bag (node/py) OR a DOM-controlled value (location parts, document.URL/referrer,
// window.name). location.pathname is excluded (server-fixed); only attacker-influenced parts are sources.
const SRC = "req(?:uest)?\\s*\\.\\s*(?:query|body|params)|request\\s*\\.\\s*(?:args|json|form|values)|location\\s*\\.\\s*(?:hash|search|href)|document\\s*\\.\\s*(?:URL|referrer)|window\\s*\\.\\s*name";
const SRC_RE = new RegExp(`${SRC}|${FRAMEWORK_SOURCE}`);   // + framework / LLM sources (sources.mjs)
const esc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
// An HTML sink fed the given var: innerHTML/outerHTML assignment, document.write, insertAdjacentHTML, dsih __html.
const sink = (v) => new RegExp(
  `\\.\\s*(?:innerHTML|outerHTML)\\s*=\\s*[^;]*\\b${esc(v)}\\b` +
  `|document\\s*\\.\\s*write(?:ln)?\\s*\\([^)]*\\b${esc(v)}\\b` +
  `|\\.\\s*insertAdjacentHTML\\s*\\([^)]*,\\s*[^)]*\\b${esc(v)}\\b` +
  `|dangerouslySetInnerHTML\\s*=\\s*\\{\\{\\s*__html\\s*:\\s*[^}]*\\b${esc(v)}\\b` +
  // reflected: the tainted var concatenated (directly after `+`/`${`) into an HTML response body.
  `|\\b(?:res|response|reply|ctx)\\s*\\.\\s*(?:send|write|end)\\s*\\(\\s*(?=[^,)]*["'\`]\\s*<\\s*[A-Za-z!\\/])[^,)]*(?:\\+\\s*|\\$\\{\\s*)${esc(v)}\\b`);
// A cheap file-level gate: no HTML-sink token ⇒ skip the inter-procedural pass.
const HAS_SINK = /innerHTML|outerHTML|document\s*\.\s*write|insertAdjacentHTML|dangerouslySetInnerHTML|\b(?:res|response|reply|ctx)\s*\.\s*(?:send|write|end)\s*\(/;
// Any escaping / sanitizing / text-only assignment makes the value safe → clear taint (don't cry wolf). Guarded at the
// sink too (the sink check runs before the per-line sanitizer sweep, so an inline `innerHTML = DOMPurify.sanitize(h)`
// must not fire).
const XSS_SANITIZE = /\b(?:DOMPurify|sanitize\w*|escapeHtml|escapeHTML|escape\w*|encodeURI\w*|textContent|innerText|createTextNode)\b/;
const xssSinkTest = (l, v) => sink(v).test(l);
/** The XSS wrapper config — shared by the walker's cross-file registry build. */
export const xssWrapperCfg = { sinkTest: xssSinkTest, sanitizer: XSS_SANITIZE, sourceTest: SRC_RE, hasSink: HAS_SINK };

/**
 * XSS-taint pass — intra-function (an untrusted value → an HTML sink) + inter-procedural (into a local html-setter) +
 * cross-file (an html-setter imported from another module). Tag: "user".
 */
function taintPass(lines, text, importedWrappers) {
  const wrappers = HAS_SINK.test(text)
    ? findSinkWrappers(lines, { sinkTest: xssSinkTest, sanitizer: XSS_SANITIZE, sourceTest: SRC_RE })
    : new Map();
  const imported = importedWrappers instanceof Map ? importedWrappers : new Map();
  const dangerous = (taint) => (a) => SRC_RE.test(a) || [...taint].some(([v, t]) => t === "user" && mentions(v, a));
  return runTaintPass(lines, {
    paramSources, paramTag: "user",
    sanitizer: XSS_SANITIZE,
    checkSinks(l, taint, emit) {
      if (XSS_SANITIZE.test(l)) return;   // an escaping call on this very line defuses the value — never fire
      for (const [v, tag] of taint) if (tag === "user" && sink(v).test(l)) { emit("taint-xss"); return; }
      if (wrappers.size && interprocHit(l, wrappers, dangerous(taint))) { emit("taint-interproc"); return; }
      if (imported.size && interprocHit(l, imported, dangerous(taint))) { emit("taint-xfile"); return; }
    },
    updateTaint(l, taint, sa) {
      if (!sa) return;
      const { name, rhs } = sa;
      const hasSrc = SRC_RE.test(rhs);
      const hasUserVar = [...taint].some(([v, t]) => t === "user" && mentions(v, rhs));
      if (hasSrc || hasUserVar) taint.set(name, "user");   // untrusted value or a value built from one (concat)
      else taint.delete(name);                             // reassigned to something clean
    },
  });
}

/** Scan one file → [{line, kind}]. Direct + taint + inter-proc; `importedWrappers` enables the cross-file layer. */
export function extractXss(text, importedWrappers, file) {
  const out = [];
  if (isPackedSource(text) || isDecompiledSource(text, file)) return out;   // a vendored / packed build, or decompiler output (lang-scope.mjs)
  const lines = logicalLines(String(text).split(/\r?\n/));   // statements broken across lines read whole (lang-scope.mjs)
  for (let i = 0; i < lines.length; i++) {
    const l = lines[i];
    if (l.length > 4000) continue;   // minified blob — noise
    if (isComment(l)) continue;      // a sink named in a comment is documentation, not live code
    for (const [kind, re] of PATTERNS) {
      if (!kindAppliesToFile(kind, file)) continue;   // a language rule fires only on its own files (lang-scope.mjs)
      if (kind === "php-echo" && PHP_ECHO_CONST_TERNARY.test(l)) continue;   // compared, not echoed
      if (re.test(l)) out.push({ line: i + 1, kind });
    }
  }
  for (const h of taintPass(lines, text, importedWrappers)) out.push(h);
  return out;
}

/** The XSS fingerprint for one file — locations + kinds, no source. `importedWrappers` enables cross-file. */
export function extractXssFingerprint(text, file, importedWrappers) {
  return { file, hits: extractXss(text, importedWrappers, file) };
}
