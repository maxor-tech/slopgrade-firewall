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
    const l = lines[i];
    if (l.length > 4000 || isComment(l)) continue;   // minified blob / a sink named in a comment is not live code
    if (boundary.test(l)) taint.clear();

    // 1. Sink check — the consumer decides which tainted var reaching what sink counts (one hit per line).
    let fired = false;
    cfg.checkSinks(l, taint, (kind) => { if (!fired) { out.push({ line: i + 1, kind }); fired = true; } });

    // 2. Sanitizer sweep — a validation/escaping line clears every tainted var it references.
    if (cfg.sanitizer && cfg.sanitizer.test(l)) {
      for (const v of [...taint.keys()]) if (mentions(v, l)) taint.delete(v);
    }

    // 3. Assignment — pre-parse the shared simple-assign form, hand it (+ the raw line) to the consumer.
    const as = l.match(ASSIGN_RE);
    cfg.updateTaint(l, taint, as ? { name: as[1], rhs: as[2] } : null);
  }
  return out;
}
