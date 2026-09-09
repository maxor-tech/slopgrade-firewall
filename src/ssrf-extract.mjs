// SSRF — Server-Side Request Forgery (CWE-918) — LANGUAGE-AGNOSTIC client fingerprint. Emits {file, line, kind} —
// NEVER the source line. A request-derived value used as the URL of an OUTBOUND HTTP request lets an attacker make
// the server fetch internal endpoints — cloud metadata (169.254.169.254), internal admin APIs, localhost.
//
// TWO detection layers, both computed client-side; only the {line, kind} egresses:
//   1. DIRECT (line-regex)  — the user-input field IS the URL argument inline: requests.get(request.args['u']).
//   2. TAINT  (dataflow)    — intra-function source→sink: `u = request.args['u']` … `requests.get(u)`. The SAME var
//      must flow from a user source to an HTTP sink UNTOUCHED. Any function boundary, sanitizer/validation call,
//      conditional guard on the var, or non-source reassignment CLEARS the taint — so a validated URL never fires
//      (precision over recall = ~0 FP, "we don't cry wolf"). Python + Node taint here; PHP/Java/Ruby keep direct-only.
//
// We scope TIGHT to USER-INPUT sub-fields (request.args / req.query / params / $_GET) as the URL of an HTTP CLIENT —
// NOT req.url (the current request path, server-derived) and NOT file_get_contents on a superglobal (path-traversal's
// job). The direct patterns are unchanged; the taint pass is additive.

// ── Sink vocabulary (parametrised by the file's client group so `import requests as r` is tracked) ───────────────
const PY_BASE = "requests|httpx|session";                 // base Python HTTP clients (aliases appended per file)
const NODE_C = "fetch|axios|got|superagent|needle";       // Node HTTP clients
const VERBS = "get|post|put|delete|patch|head|request";   // HTTP verbs
const PY_SRC = "request\\s*\\.\\s*(?:args|form|values|json|GET|POST|data)";
const NODE_SRC = "req(?:uest)?\\s*\\.\\s*(?:query|body|params)";
// A leading HTTP-METHOD string arg — `needle('get', url)` and `requests.request('GET', url)` put the URL at arg 2.
// Scoped ONLY to needle (Node) and the `.request` verb (Python) — fetch/axios/got are url-FIRST, so consuming a
// leading quoted arg there would FP on `fetch('api', { body: req.x })`. `['"]\w+['"]` matches only a word-only method
// literal (get/post/…), never a quoted URL (which carries `:`//`/`).
const METH = "['\"]\\w+['\"]\\s*,\\s*";
const esc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/** Python `import requests as r` / `import httpx as hx` → the local aliases, so `r.get(...)` is tracked. */
function pyClientGroup(text) {
  const aliases = [];
  for (const m of String(text).matchAll(/^\s*import\s+(?:requests|httpx)\s+as\s+([A-Za-z_]\w*)/gm)) aliases.push(esc(m[1]));
  return aliases.length ? `${PY_BASE}|${aliases.join("|")}` : PY_BASE;
}

/** Direct inline-source patterns for one file's client group (aliases included). */
function directPatterns(pyClients) {
  return [
    // Python — requests/httpx/urlopen with a user-input request field inline as the URL (incl. an aliased client).
    ["py-requests", new RegExp(`\\b(?:${pyClients})\\s*\\.\\s*(?:${VERBS})\\s*\\(\\s*(?:${PY_SRC})\\b|urlopen\\s*\\(\\s*(?:${PY_SRC})\\b`)],
    // Concat/nested into the URL: the source appears in the FIRST arg (before any comma) of an HTTP client —
    // requests.get('https://' + request.args['h']). Bounded to the first arg so a header/param kwarg never fires.
    ["http-concat", new RegExp(`\\b(?:${pyClients})\\s*\\.\\s*(?:${VERBS})\\s*\\(\\s*[^,)]*\\b(?:${PY_SRC})\\b|\\b(?:${NODE_C})\\s*(?:\\.\\s*(?:${VERBS}))?\\s*\\(\\s*[^,)]*\\b(?:${NODE_SRC})\\b`)],
    // Node — fetch/axios/got/superagent/needle with a user-input request field inline as the URL.
    ["node-http", new RegExp(`\\b(?:${NODE_C})\\s*(?:\\.\\s*(?:${VERBS}))?\\s*\\(\\s*(?:${NODE_SRC})\\b|\\bhttps?\\s*\\.\\s*(?:get|request)\\s*\\(\\s*(?:${NODE_SRC})\\b`)],
    // Method-first sinks — the URL is arg 2: needle('get', req.query.u) / requests.request('GET', request.args['u']).
    ["py-request-methodfirst", new RegExp(`\\b(?:${pyClients})\\s*\\.\\s*request\\s*\\(\\s*${METH}[^,)]*\\b(?:${PY_SRC})\\b`)],
    ["node-needle-methodfirst", new RegExp(`\\bneedle\\s*\\(\\s*${METH}[^,)]*\\b(?:${NODE_SRC})\\b`)],
    // PHP — cURL URL set from a superglobal (Guzzle/HTTP clients too).
    ["php-curl", /curl_setopt\s*\([^;]*CURLOPT_URL\s*,\s*[^;]*\$_(?:GET|POST|REQUEST|COOKIE)|->\s*(?:get|post|request)\s*\(\s*\$_(?:GET|POST|REQUEST)/],
    // Java — new URL(request.getParameter(...)).openConnection / RestTemplate on a request value.
    ["java-url", /new\s+URL\s*\([^;]*request\s*\.\s*getParameter|restTemplate\s*\.\s*(?:getForObject|getForEntity|exchange)\s*\([^;]*request\s*\.\s*getParameter/],
    // Ruby — Net::HTTP / HTTParty / Faraday / open on params inline.
    ["ruby-http", /\b(?:Net::HTTP\s*\.\s*(?:get|post|get_response)|HTTParty\s*\.\s*(?:get|post)|Faraday\s*\.\s*(?:get|post)|open)\s*\(\s*params\b/],
  ];
}

import { runTaintPass, mentions } from "./taint-core.mjs";
import { findSinkWrappers, interprocHit } from "./taint-interproc.mjs";

const isComment = (l) => /^\s*(\/\/|\*|#|--|;|<!--)/.test(l);

// A cheap file-level gate: no HTTP-client token anywhere ⇒ no possible SSRF sink ⇒ skip the inter-procedural pass.
const HAS_SINK = /\b(?:requests|httpx|session|urlopen|fetch|axios|got|superagent|needle)\b|\bhttps?\s*\.\s*(?:get|request)/;

// ── Taint-pass vocabulary (fed to the shared runTaintPass engine) ────────────────────────────────────────────────
// A user-controlled source on the RHS of an assignment taints the LHS var.
const PY_SOURCE = new RegExp(PY_SRC);
const NODE_SOURCE = new RegExp(NODE_SRC);
// A validation/normalisation of the var, OR a conditional guard testing it — assume the URL is checked → clear taint.
const SSRF_SANITIZE = /\b(?:valid\w*|sanitiz\w*|allow\w*|whitelist|allowlist|check\w*|urlparse|urlsplit|parse_url|netloc|host_?name|ip_?address|resolve|assert\w*|ensure\w*|verif\w*|is_safe|ssrf|guard)\b|^\s*(?:if|elif|else\s+if|while|assert|unless)\b/i;

// A tainted var reaching a sink — matched ANYWHERE in the FIRST arg (bare `get(v)` OR concat `get('https://'+v)`),
// bounded before the next comma so a header/timeout kwarg never fires; plus the method-first URL-at-arg-2 forms.
const pySink = (clients) => (v) => new RegExp(
  `\\b(?:${clients})\\s*\\.\\s*(?:${VERBS})\\s*\\(\\s*[^,)]*\\b${esc(v)}\\b` +
  `|\\b(?:${clients})\\s*\\.\\s*request\\s*\\(\\s*${METH}[^,)]*\\b${esc(v)}\\b` +
  `|\\burlopen\\s*\\(\\s*[^,)]*\\b${esc(v)}\\b`);
const nodeSink = (v) => new RegExp(
  `\\b(?:${NODE_C})\\s*(?:\\.\\s*(?:${VERBS}))?\\s*\\(\\s*[^,)]*\\b${esc(v)}\\b` +
  `|\\bneedle\\s*\\(\\s*${METH}[^,)]*\\b${esc(v)}\\b` +
  `|\\bhttps?\\s*\\.\\s*(?:get|request)\\s*\\(\\s*[^,)]*\\b${esc(v)}\\b`);

// ── Inter-procedural pass (same-file, one level) — on the shared taint-interproc engine ─────────────────────────
// A user value passed to a LOCAL helper that reaches the sink (def fetch(u): requests.get(u) … fetch(request.args))
// is missed by the intra-function pass. findSinkWrappers finds helpers whose param reaches the SSRF sink (reusing
// SSRF_SANITIZE, so a validating helper is never a wrapper); interprocHit fires on a user value at a flowing arg.
// The wrapper cfg uses the BASE client group (cross-file alias tracking is a documented residual, not the common case).
const pySinkBase = pySink(PY_BASE);
const ssrfSinkTest = (l, v) => pySinkBase(v).test(l) || nodeSink(v).test(l);
const SSRF_SOURCE = new RegExp(`${PY_SOURCE.source}|${NODE_SOURCE.source}`);

/** The SSRF wrapper config — shared by the walker's cross-file registry build. */
export const ssrfWrapperCfg = { sinkTest: ssrfSinkTest, sanitizer: SSRF_SANITIZE, sourceTest: SSRF_SOURCE, hasSink: HAS_SINK };

/**
 * SSRF taint pass — intra-function (py/node) + inter-procedural (local sink-wrapper) + cross-file (a wrapper imported
 * from another module, via `importedWrappers` resolved by the walker's registry). Emits taint-interproc / taint-xfile.
 */
function taintPass(lines, text, importedWrappers) {
  const pySinkFile = pySink(pyClientGroup(text));   // alias-aware sink for THIS file's `import requests as r`
  const localSinkTest = (l, v) => pySinkFile(v).test(l) || nodeSink(v).test(l);
  const wrappers = HAS_SINK.test(text)
    ? findSinkWrappers(lines, { sinkTest: localSinkTest, sanitizer: SSRF_SANITIZE, sourceTest: SSRF_SOURCE })
    : new Map();
  const imported = importedWrappers instanceof Map ? importedWrappers : new Map();
  const dangerous = (taint) => (a) => SSRF_SOURCE.test(a) || [...taint.keys()].some((v) => mentions(v, a));
  return runTaintPass(lines, {
    sanitizer: SSRF_SANITIZE,
    checkSinks(l, taint, emit) {
      for (const [v, lang] of taint) {
        if ((lang === "py" ? pySinkFile(v) : nodeSink(v)).test(l)) { emit(lang === "py" ? "py-taint" : "node-taint"); return; }
      }
      // Inter-procedural: a tainted var OR an inline user source at a flowing arg position of a LOCAL sink-wrapper.
      if (wrappers.size && interprocHit(l, wrappers, dangerous(taint))) { emit("taint-interproc"); return; }
      // Cross-file: same, into a wrapper IMPORTED from another module.
      if (imported.size && interprocHit(l, imported, dangerous(taint))) { emit("taint-xfile"); return; }
    },
    updateTaint(l, taint, sa) {
      // Node destructuring source: const { a, b } = req.query  → taint a, b.
      const de = l.match(/\b(?:const|let|var)\s*\{([^}]*)\}\s*=\s*(.+)$/);
      if (de && NODE_SOURCE.test(de[2])) {
        for (const raw of de[1].split(",")) {
          const name = raw.trim().split(":").pop().trim();
          if (/^[A-Za-z_$][\w$]*$/.test(name)) taint.set(name, "node");
        }
        return;
      }
      if (!sa) return;
      if (PY_SOURCE.test(sa.rhs)) taint.set(sa.name, "py");
      else if (NODE_SOURCE.test(sa.rhs)) taint.set(sa.name, "node");
      else if (taint.has(sa.name)) taint.delete(sa.name);
    },
  });
}

/**
 * Scan one file → [{line, kind}]. Direct regex + taint dataflow. Source line NEVER leaves this function.
 * `importedWrappers` (optional) — a Map<localName, Set<flowingIdx>> resolved by the walker from the repo registry;
 * enables the cross-file layer. Omit it for a single-file scan (intra + local inter-procedural only).
 */
export function extractSsrf(text, importedWrappers) {
  const out = [];
  const lines = String(text).split(/\r?\n/);
  const patterns = directPatterns(pyClientGroup(text));   // per-file: client group includes `import requests as r`
  for (let i = 0; i < lines.length; i++) {
    const l = lines[i];
    if (l.length > 4000) continue;   // minified blob — noise
    if (isComment(l)) continue;      // a sink named in a comment is documentation, not live code
    for (const [kind, re] of patterns) {
      if (re.test(l)) out.push({ line: i + 1, kind });
    }
  }
  for (const h of taintPass(lines, text, importedWrappers)) out.push(h);
  return out;
}

/** The SSRF fingerprint for one file — locations + kinds, no source. `importedWrappers` enables the cross-file layer. */
export function extractSsrfFingerprint(text, file, importedWrappers) {
  return { file, hits: extractSsrf(text, importedWrappers) };
}
