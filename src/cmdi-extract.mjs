// Code / Command Injection (CWE-94 eval · CWE-78 OS command) — LANGUAGE-AGNOSTIC client fingerprint. Emit
// {file, line, kind} — NEVER the source line. User input flowing into an execution sink (eval/exec/os.system/shell/
// child_process.exec/Runtime.exec) is RCE.
//
// TWO detection layers, both computed client-side; only the {line, kind} egresses:
//   1. DIRECT (line-regex, unchanged) — a request value is the sink argument on the same line: os.system(request…).
//   2. TAINT (dataflow, new)          — intra-function: `cmd = "convert " + request.args['f']` … `os.system(cmd)`,
//      or `f = request.args['f']` … `os.system("convert " + f)`. A var becomes tainted from a user source (or by
//      combining one with string-building); a hit fires when it reaches a SHELL sink. Python + Node taint here;
//      PHP/Java/Ruby keep direct-only (next layer). Precision (low FP): subprocess only fires with
//      shell=True (a list-arg / shell=False call never shell-parses the value); `.exec` is scoped to child_process
//      (never a bare regexp.exec); taint clears on a function boundary, a shlex.quote/escape/sanitize call, or a
//      non-tainting reassignment.

const REQ = "request|req\\b|\\$_(?:GET|POST|REQUEST|COOKIE)";
const DIRECT_PATTERNS = [
  // (?<!\.) so a method call (myRegex.exec(req…) / obj.eval(req…)) never matches the Python eval/exec builtin.
  ["py-eval", new RegExp(`(?<!\\.)\\b(?:eval|exec)\\s*\\(\\s*(?:${REQ})`)],
  ["py-shell", new RegExp(`\\bos\\.(?:system|popen)\\s*\\([^)]*(?:${REQ})|\\bcommands\\.getoutput\\s*\\([^)]*(?:${REQ})|subprocess\\.[A-Za-z_]+\\([^)]*(?:${REQ})[^)]*shell\\s*=\\s*True|subprocess\\.[A-Za-z_]+\\([^)]*shell\\s*=\\s*True[^)]*(?:${REQ})`)],
  ["node-exec", /\beval\s*\(\s*(?:req|request)\b|child_process\s*\.\s*(?:exec|execSync)\s*\(\s*(?:req|request)\b|\bcp\s*\.\s*(?:exec|execSync)\s*\(\s*(?:req|request)\b|new\s+Function\s*\(\s*(?:req|request)\b/],
  ["php-exec", /\b(?:eval|assert|create_function|system|exec|passthru|shell_exec|popen|proc_open)\s*\(\s*[^;]*\$_(?:GET|POST|REQUEST|COOKIE)/],
  ["ruby-exec", /\b(?:eval|instance_eval|class_eval|system)\s*\(\s*params\b|`[^`]*#\{[^}]*params[^}]*\}[^`]*`/],
  ["java-exec", /Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\([^;]*\brequest\b|new\s+ProcessBuilder\s*\([^;]*\brequest\b/],
];

const isComment = (l) => /^\s*(\/\/|\*|#|--|;|<!--)/.test(l);

import { runTaintPass, mentions } from "./taint-core.mjs";
import { findSinkWrappers, interprocHit } from "./taint-interproc.mjs";

// ── Taint-pass vocabulary (Python + Node ; fed to the shared runTaintPass engine) ───────────────────────────────
// Source = a request-derived value on the RHS. `params` bare is DELIBERATELY absent (collides with regexp.exec /
// route params, per the direct pack's note) — property access only.
const SOURCE = /\brequest\s*\.\s*(?:args|form|values|GET|POST|json|data)\b|\breq(?:uest)?\s*\.\s*(?:query|body|params)\b/;
// A cheap file-level gate: no shell-sink token ⇒ skip the inter-procedural pass.
const HAS_SINK = /\bos\.(?:system|popen)|subprocess\.|(?<!\.)\b(?:eval|exec)\s*\(|(?:child_process|cp)\s*\.\s*(?:exec|execSync)|new\s+Function/;
// An escaping / quoting call on the value — assume it makes the argument shell-safe → clear taint.
const CMD_SANITIZE = /\b(?:shlex\.(?:quote|split)|pipes\.quote|escapeshell\w*|escape\w*|sanitiz\w*|quote\w*|shell[-_]?escape|allowlist|whitelist|valid\w*)\b/i;
const esc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
// A SHELL sink containing the tainted var: always-shell (os.system/os.popen/eval/exec/child_process.exec/execSync/
// new Function) OR subprocess WITH shell=True. `.exec` is scoped to child_process/cp — never a bare regexp.exec.
const sink = (v) => {
  const V = esc(v);
  return new RegExp(
    `\\bos\\.(?:system|popen)\\s*\\([^)]*\\b${V}\\b` +
    `|(?<!\\.)\\b(?:eval|exec)\\s*\\([^)]*\\b${V}\\b` +
    `|subprocess\\.[A-Za-z_]+\\s*\\([^)]*\\b${V}\\b[^)]*shell\\s*=\\s*True` +
    `|subprocess\\.[A-Za-z_]+\\s*\\([^)]*shell\\s*=\\s*True[^)]*\\b${V}\\b` +
    `|(?:child_process|cp)\\s*\\.\\s*(?:exec|execSync)\\s*\\([^)]*\\b${V}\\b` +
    `|new\\s+Function\\s*\\([^)]*\\b${V}\\b`
  );
};

const cmdiSinkTest = (l, v) => sink(v).test(l);
/** The cmdi wrapper config — shared by the walker's cross-file registry build. */
export const cmdiWrapperCfg = { sinkTest: cmdiSinkTest, sanitizer: CMD_SANITIZE, sourceTest: SOURCE, hasSink: HAS_SINK };

/** Command-injection taint pass — intra-function + inter-procedural + cross-file (a shell-sink wrapper imported from another module). */
function taintPass(lines, text, importedWrappers) {
  const wrappers = HAS_SINK.test(text)
    ? findSinkWrappers(lines, { sinkTest: cmdiSinkTest, sanitizer: CMD_SANITIZE, sourceTest: SOURCE })
    : new Map();
  const imported = importedWrappers instanceof Map ? importedWrappers : new Map();
  const dangerous = (taint) => (a) => SOURCE.test(a) || [...taint.keys()].some((v) => mentions(v, a));
  return runTaintPass(lines, {
    sanitizer: CMD_SANITIZE,
    checkSinks(l, taint, emit) {
      for (const v of taint.keys()) if (sink(v).test(l)) { emit("taint-cmd"); return; }
      // Inter-procedural: an inline user source OR a tainted var at a flowing arg of a LOCAL shell-sink wrapper.
      if (wrappers.size && interprocHit(l, wrappers, dangerous(taint))) { emit("taint-interproc"); return; }
      // Cross-file: same, into a shell-sink wrapper IMPORTED from another module.
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

/** Scan one file → [{line, kind}]. Direct regex + command-injection taint. Source line NEVER leaves this function. */
export function extractCmdi(text, importedWrappers) {
  const out = [];
  const lines = String(text).split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const l = lines[i];
    if (l.length > 4000) continue;   // minified blob — noise
    if (isComment(l)) continue;      // a sink named in a comment is documentation, not live code
    for (const [kind, re] of DIRECT_PATTERNS) {
      if (re.test(l)) out.push({ line: i + 1, kind });
    }
  }
  for (const h of taintPass(lines, text, importedWrappers)) out.push(h);
  return out;
}

/** The command-injection fingerprint for one file — locations + kinds, no source. */
export function extractCmdiFingerprint(text, file, importedWrappers) {
  return { file, hits: extractCmdi(text, importedWrappers) };
}
