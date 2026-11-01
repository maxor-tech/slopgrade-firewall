// Shared intra-function taint engine (CWE-918 SSRF · CWE-89 SQLi · CWE-78/94 cmdi). One tested skeleton, three
// consumers — extracted at the rule-of-three (SSRF #799, SQLi #800, cmdi #801 each carried a near-identical copy).
//
// The engine owns the invariant machinery: a line-ordered scan; comment / minified-blob skipping; a per-function
// taint reset at a scope boundary (so a tainted var in fn A can't false-fire on a same-named param in fn B); a
// sanitizer sweep that clears any tainted var a validation/escaping line mentions; and the ONE assignment regex all
// three share, pre-parsed and handed to the consumer. Taint state is ONE Map<varName, tag> — the tag is an opaque
// label the consumer chooses (SSRF: "py"/"node"; SQLi: "user"/"sql"; cmdi: "t"), so SQLi's two logical sets collapse
// into one map with two tag values.
//
// Each consumer supplies only what genuinely varies, as two callbacks:
//   • checkSinks(line, taint, emit)             — does a tainted var reach a sink on this line? call emit(kind) if so.
//   • updateTaint(line, taint, simpleAssign)    — update taint state from this line. simpleAssign = {name, rhs} when
//     the line is a plain `name = rhs` (pre-parsed with the shared regex), else null; `line` is passed too so a
//     consumer can handle non-plain forms (e.g. destructuring `const { url } = req.query`).
// The consumer never sees the source line beyond these callbacks; the engine returns only [{line, kind}].

const DEFAULT_BOUNDARY = /\bdef\s|\bfunction\b|=>|\bclass\s|\bfunc\s/;
const ASSIGN_RE = /^\s*(?:(?:const|let|var)\s+)?([A-Za-z_$][\w$]*)\s*=\s*(?!=)(.+)$/;
const isComment = (l) => /^\s*(\/\/|\*|#|--|;|<!--)/.test(l);
export const escapeVar = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
/** Word-boundaried test for a bare identifier occurring in a line (used by consumers + the sanitizer sweep). */
export const mentions = (v, line) => new RegExp(`\\b${escapeVar(v)}\\b`).test(line);

/** The code part of a line : a trailing `// …`, `/* … *\/` or `# …` comment is cut, quoted text is kept. Expert-panel red
 *  team (2026-10-31) : `el.innerHTML = h; // sanitize` and `console.log(c); // validate` matched the sanitizer regex on the
 *  comment and cleared the taint. A `#` cuts only at the start or after a space and before a space or the line end, so a
 *  JS private field (`this.#x`) or a Ruby `"#{x}"` stays code. */
export function codeOnly(l) {
  let quote = null, out = "";
  for (let k = 0; k < l.length; k++) {
    const c = l[k];
    if (quote) {
      out += c;
      if (c === "\\") { out += l[k + 1] ?? ""; k++; } else if (c === quote) quote = null;
      continue;
    }
    if (c === '"' || c === "'" || c === "`") { quote = c; out += c; continue; }
    if (c === "/" && l[k + 1] === "/") break;
    if (c === "/" && l[k + 1] === "*") { const end = l.indexOf("*/", k + 2); if (end < 0) break; k = end + 1; out += " "; continue; }
    if (c === "#" && (k === 0 || /\s/.test(l[k - 1])) && (k + 1 >= l.length || /\s/.test(l[k + 1]))) break;
    out += c;
  }
  return out;
}

/**
 * Run the intra-function taint pass over a file's lines.
 * @param {string[]} lines
 * @param {{
 *   boundary?: RegExp,
 *   sanitizer?: RegExp,
 *   seed?: Iterable<[string, string]>,   // initial taint entries (used by the inter-procedural pass to pre-taint params)
 *   checkSinks: (line: string, taint: Map<string,string>, emit: (kind: string) => void) => void,
 *   updateTaint: (line: string, taint: Map<string,string>, simpleAssign: {name: string, rhs: string} | null) => void,
 * }} cfg
 * @returns {Array<{line: number, kind: string}>}
 */
export function runTaintPass(lines, cfg) {
  const boundary = cfg.boundary || DEFAULT_BOUNDARY;
  const taint = new Map(cfg.seed || []);   // optional seed (e.g. a function's params pre-tainted for inter-proc pass 1)
  const out = [];
  for (let i = 0; i < lines.length; i++) {
    if (lines[i].length > 4000 || isComment(lines[i])) continue;   // minified blob / a sink named in a comment is not live code
    const l = codeOnly(lines[i]);   // a trailing comment never decides a sink, a scope or a sanitizer

    // 1. Sink check — the consumer decides which tainted var reaching what sink counts (one hit per line).
    //    BEFORE the boundary reset : a sink line that also carries an inline callback (`exec(cmd, (e, out) => …)`)
    //    matches the `=>` boundary, and clearing first made every such sink invisible (release audit 2026-09-13,
    //    B-P1-6). The sink on this line still sees the taint of the enclosing function ; the reset applies to what
    //    FOLLOWS the new scope opener.
    let fired = false;
    cfg.checkSinks(l, taint, (kind) => { if (!fired) { out.push({ line: i + 1, kind }); fired = true; } });
    if (boundary.test(l)) taint.clear();
    // A route / tool handler declared here : the parameters its framework fills from the request start tainted
    // (sources.mjs paramSources ; Java methods match no boundary, so this runs on every line, not only after a reset).
    if (cfg.paramSources) for (const n of cfg.paramSources(lines, i)) taint.set(n, typeof cfg.paramTag === "function" ? cfg.paramTag(l) : cfg.paramTag);

    // 2. Sanitizer — by EFFECT, not by mention (sanitizerEffect below).
    const as = l.match(ASSIGN_RE);
    const effect = cfg.sanitizer ? sanitizerEffect(l, cfg.sanitizer, as, lines, i) : "none";
    if (effect === "clear") for (const v of [...taint.keys()]) if (mentions(v, l)) taint.delete(v);

    // 3. Assignment — pre-parse the shared simple-assign form, hand it (+ the raw line) to the consumer. For
    //    `s = escape(v)` the consumer sees the right-hand side WITHOUT the sanitizing calls, so its own rules decide :
    //    `s` is clean, `v` stays tainted, and `q = "…" + escape(id) + req.args.b` stays tainted through the raw part.
    const rhs = as ? (effect === "clean-target" ? stripSanitizerCalls(as[2], cfg.sanitizer) : as[2]) : null;
    cfg.updateTaint(as && effect === "clean-target" ? l.replace(as[2], rhs) : l, taint, as ? { name: as[1], rhs } : null);
  }
  return out;
}

// Expert panel 2026-10-31 (P0-4) : the old sweep cleared every tainted variable named on a sanitizer line, so
// `escape(id);` with its result thrown away, `el.textContent = h`, a bare `if (u) {` or `s = escapeHtml(h)` (which
// cleared `h` itself) all made a request value look safe. A sanitizer now acts by its effect :
//   · PURE transforms (escape*, sanitize*, quote*, encodeURI*, basename, realpath, .replace(…) …) return a new value —
//     they clean the variable they are ASSIGNED to, never their argument, and a call whose result is ignored does nothing ;
//   · VALIDATORS (valid*, check*, assert*, ensure*, verif*, allow-lists, parameter binding) clear the values they are
//     called on, in a guard or as a statement (they reject by throwing or by the guard) ;
//   · a bare guard (`if …`) with no sanitizer call clears only when it compares the value AND rejects right after.
const PURE_NAME = /^(?:escape\w*|sanitiz\w*|quote\w*|encodeURI\w*|DOMPurify|escapeshell\w*|shell[-_]?escape|basename|secure_filename|realpath|abspath|canonical\w*|safe_join|quote_ident|mogrify|textContent|innerText|createTextNode|replace|strip|lstrip|sub|htmlspecialchars|htmlentities|shlex\.quote|pipes\.quote|sql\.Identifier)$/i;
const GUARD_WORD = /^(?:if|elif|else\s+if|while|unless|assert|guard)$/i;
const GUARD_LINE = /^\s*(?:if|elif|else\s+if|while|unless|assert|guard)\b|\bif\s*\(/;
const REJECTS = /\b(?:return|throw|raise|abort|die|exit|continue|break|panic)\b|\bres\s*\.\s*status\s*\(\s*4|\bhttp\s*\.\s*Error\b|\bredirect\b/;
const PREDICATE_CALL = /\b[A-Za-z_$][\w$.]*\s*\(\s*[^)\s]/;
const COMPARES =/===?|!==?|\bin\b|\bnot\s+in\b|startsWith|endsWith|includes|\bmatch\w*\s*\(|\.test\s*\(|\bhas\s*\(|<|>/;

function sanitizerNames(code, re) {
  const g = new RegExp(re.source, re.flags.includes("g") ? re.flags : re.flags + "g");
  return [...code.matchAll(g)].map((m) => m[0].trim().replace(/^\./, ""));
}
/** The right-hand side with every sanitizing CALL removed (`escape(x)`, `x.replace(…)`), so what is left is raw. */
function stripSanitizerCalls(rhs, re) {
  let s = rhs;
  for (let guard = 0; guard < 20; guard++) {
    const g = new RegExp(re.source, re.flags.replace("g", ""));
    const m = g.exec(s);
    if (!m) break;
    let start = m.index, k = m.index + m[0].length;
    while (k < s.length && /\s/.test(s[k])) k++;
    if (s[k] !== "(") { s = s.slice(0, start) + " ".repeat(m[0].length) + s.slice(m.index + m[0].length); continue; }
    if (s[start] === "." || s[start - 1] === ".") {   // method form `recv.replace(…)` : the receiver is sanitized too
      let r = s[start] === "." ? start : start - 1;
      while (r > 0 && /[\w$.\])]/.test(s[r - 1])) r--;
      start = r;
    }
    let depth = 0, end = k;
    for (; end < s.length; end++) { if (s[end] === "(") depth++; else if (s[end] === ")" && --depth === 0) break; }
    s = s.slice(0, start) + " ".repeat(Math.max(0, end + 1 - start)) + s.slice(end + 1);
  }
  return s;
}
/** "clear" (clear the values this line names), "clean-target" (only the assigned variable is clean) or "none". */
export function sanitizerEffect(code, re, assign, lines, i) {
  if (!re.test(code)) return "none";
  const names = sanitizerNames(code, re);
  const calls = names.filter((n) => !GUARD_WORD.test(n));
  const pureOnly = calls.length > 0 && calls.every((n) => PURE_NAME.test(n));
  if (GUARD_LINE.test(code)) {
    if (calls.length && !pureOnly) return "clear";
    // `if not is_allowed(url): abort(403)` — a predicate CALL or a comparison, followed by a rejection, validates.
    // A bare truthiness test (`if (u) {`, `if (!u) return`) does neither and clears nothing.
    const after = [code, ...lines.slice(i + 1, i + 3).map(codeOnly)].join("\n");
    return (COMPARES.test(code) || PREDICATE_CALL.test(code)) && REJECTS.test(after) ? "clear" : "none";
  }
  if (assign) return pureOnly ? "clean-target" : calls.length ? "clear" : "none";
  return pureOnly || !calls.length ? "none" : "clear";
}
