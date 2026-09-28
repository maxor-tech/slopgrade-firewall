// heisen deep scan — OPT-IN (`deep-scan: true` / --deep-scan), paid repos only. PURE helpers; the network call is
// injected so every boundary here is unit-testable.
//
// THIS IS THE ONE PATH THAT SENDS SOURCE. The default Firewall run never does (structural fingerprint only). With the
// deep scan enabled, the CONTENTS of a bounded set of files are POSTed to the canonical slopGrade origin
// (/api/ci/heisen), which forwards them to the hosted heisen-slop taint engine and drops them (never logged, never
// persisted). Which files: those where the free extractors recorded a hit FIRST, then any other file that contains a
// marker of a class the engines model (SINK_HINTS) — the free extractors are intra-function, so a request→sink flow through a helper
// leaves NO hit, and that is exactly the flow the taint engine adds. A file with no sink marker is never sent. Capped
// at DEEP_MAX_UNITS files / DEEP_MAX_TOTAL_CHARS characters. `--print-payload` lists them.
//
// ADVISORY: the server returns `blocking: 0` while the engine is in its calibration window, so these findings annotate
// as warnings and never fail the check.

export const DEEP_SCAN_EXTS = /\.(py|js|jsx|mjs|cjs|ts|tsx|go|java|rb)$/i;
// 80 since 0.10.5 (was 40): measured on the 22-app walk, the file cap was the last coverage loss on large monorepos —
// 76% of the repo-wide findings were inside the sent files at 40 (v0.10.4), 85% with the tiered ranking, 91% at 80
// (Ghost 4 → 11 of 12). The route answers within its time budget (pretix, the heaviest: 40 units in 12 s, 5 s worst
// unit on the live detector) and stops dispatching past its deadline, so a larger set degrades to « partial », never a timeout.
export const DEEP_MAX_UNITS = 80;
export const DEEP_MAX_UNIT_CHARS = 200_000;
export const DEEP_MAX_TOTAL_CHARS = 2_000_000;
// A cheap lexical pre-filter, one entry per weakness family the hosted engines model (Python / JS-TS / Go / Java /
// Ruby — the same classes /api/ci/heisen asks for). Over-inclusive by design — it only decides what MAY be sent; the
// engine decides what is a finding. Until 0.10.3 this was a single injection-era regex: 93 of the 116 modelled
// (language × class) cells never matched it (Go `db.Query(`, Java `executeQuery(`, every config rule — TLS off, JWT
// none, weak crypto, CORS, cookies, XXE, CSRF…), so a file carrying only those never reached the engine.
// src/__tests__/fixtures/heisen-classes.json pins one engine-verified positive per cell; each must match.
export const SINK_HINTS = {
  command: /\b(?:os\.system|popen|Popen|subprocess|spawn|child_process|exec(?:Sync|File|ute|Command)?\s*\(|system\s*\(|Runtime\.getRuntime|ProcessBuilder|exec\.Command|Open3|%x[{(\[]|`[^`\n]*#\{)|\bopen\s*\(/,
  code: /\b(?:eval|exec|compile|instance_eval|class_eval|module_eval)\s*\(|\bnew Function\s*\(|\bFunction\s*\(|\bvm\.run|runInContext|DoString|\bgoja\b|\botto\b|Eval\.me|ScriptEngine|GroovyShell|parseExpression|\bOgnl|\bMVEL\b|constantize/,
  sql: /\b(?:query|Query|QueryRow|QueryContext|Exec|ExecContext|execute|executemany|executeQuery|executeUpdate|executeLargeUpdate|addBatch|prepareStatement|createQuery|createNativeQuery|createSQLQuery|raw|where|find_by_sql|select_all|order|joins|pluck|text)\s*\(|\bdb\.\w+\s*\(|\bcursor\b|sqlalchemy|knex|sequelize|\bsqlx\b|\bgorm\b/,
  nosql: /\$(?:where|expr|regex|function|accumulator|ne|gt)\b|\b(?:find|findOne|findOneAndUpdate|aggregate|updateOne|deleteMany|mapReduce)\s*\(|\bmongo|\bMongo|\bbson\b|\bFilters\./,
  ldap: /ldap|LDAP|Ldap/,
  xpath: /xpath|XPath|xpathEval|\bgoxpath\b|document\.evaluate|selectNodes|selectSingleNode/,
  path: /\b(?:readFile|readFileSync|createReadStream|createWriteStream|sendFile|send_file|send_from_directory|FileResponse|FileInputStream|FileOutputStream|FileReader|os\.Open|os\.ReadFile|ioutil\.ReadFile|ServeFile|plugin\.Open|Paths\.get|IO\.read|Pathname)\b|\bFiles\.|\bFile\s*[.(]|\bnew\s+(?:java\.io\.)?File\b|\bsend_?[fF]ile/,
  redirect: /redirect|Redirect|\bLocation\b/,
  ssrf: /\b(?:requests|httpx|aiohttp|urllib3?|urllib\.request)\b|urlopen|\baxios\b|\bfetch\s*\(|\bgot\s*\(|superagent|\bneedle\b|\bhttp\.(?:Get|Post|Head|NewRequest)|NewRequest|RestTemplate|WebClient|HttpClient|HttpGet|HttpPost|openStream|openConnection|\bnew\s+(?:java\.net\.)?(?:URL|Socket)\s*\(|OkHttp|Net::HTTP|HTTParty|Faraday|RestClient|open-uri/,
  template: /render_template_string|\bTemplate\s*\(|\bEnvironment\s*\(|jinja|Jinja|jinjava|Jinjava|\bmako\b|\bejs\b|\bpug\b|[Hh]andlebars|nunjucks|mustache|\b_\.template|Velocity|Pebble|[Ff]ree[Mm]arker|\bERB\b|Erubi|render\s+inline:|text\/template|html\/template|template\.New/,
  xss: /\b(?:Markup|mark_safe|SafeString|html_safe|raw|innerHTML|outerHTML|insertAdjacentHTML|dangerouslySetInnerHTML|document\.write|make_response|HttpResponse|getWriter|Fprint[fln]?|template\.HTML)\b|\bres\.(?:send|write|end)\s*\(|\.Write\s*\(|TEXT_HTML|text\/html/,
  deserialization: /\b(?:pickle|cPickle|marshal|dill|jsonpickle|shelve|joblib|torch\.load|unserialize|node-serialize|serialize-to-js|funcster|cryo|ObjectInputStream|readObject|readUnshared|XMLDecoder|XStream|fromXML|snakeyaml|SerializationUtils|Psych|Oj|gob)\b|\bya?ml\.(?:load|unsafe_load|load_all|full_load)|\bYAML\.(?:load|unsafe_load|load_stream)|\bMarshal\.(?:load|restore)|\bnew\s+(?:[\w.]+\.)?Yaml\s*\(/,
  prototypePollution: /__proto__|\bconstructor\.prototype|\b(?:merge|mergeWith|defaultsDeep|extend|assignIn|set|setWith|zipObjectDeep|unflatten|deepmerge|deepExtend)\s*\(|\bObject\.assign\s*\(/,
  redos: /\bre\.(?:compile|match|search|fullmatch|sub|subn|split|findall|finditer)\s*\(|\bRegExp\b|\bRegexp\b|regexp2|Pattern\.(?:compile|matches)|\.matches\s*\(|replaceAll\s*\(/,
  xxe: /XMLParser|resolve_entities|setFeature|external-general|external-parameter|\betree\b|\blxml\b|xml\.sax|xml\.dom|parseXml|parseXmlString|\bnoent\b|libxmljs|DocumentBuilderFactory|SAXParserFactory|SAXReader|SAXBuilder|XMLInputFactory|XMLReader|TransformerFactory|SchemaFactory|isSupportingExternalEntities|Nokogiri|REXML|LibXML/,
  zipSlip: /extractall|\bextract\s*\(|tarfile|zipfile|ZipFile|ZipInputStream|ZipEntry|getNextEntry|adm-zip|unzipper|archive\/zip|archive\/tar/,
  worldWritable: /chmod|Chmod|umask|\b0o?7[0-7]7\b|\b0o?666\b|setWritable|setReadable|setExecutable|PosixFilePermissions|\bmkdir\s*\(|MkdirAll/,
  tls: /verify\s*=\s*False|cert_reqs|CERT_NONE|_create_unverified_context|check_hostname|InsecureSkipVerify|rejectUnauthorized|NODE_TLS_REJECT_UNAUTHORIZED|VERIFY_NONE|verify_mode|NoopHostnameVerifier|ALLOW_ALL_HOSTNAME_VERIFIER|HostnameVerifier|TrustManager|TrustAll|trustAll|ssl_verify|verify_ssl/,
  transport: /insecure_channel|createInsecure|WithInsecure|insecure\.NewCredentials|usePlaintext|PLAINTEXT|this_channel_is_insecure|\bhttp:\/\/(?!localhost|127\.0\.0\.1)/,
  crypto: /\b(?:ARC4|RC4|rc4|RC2|DES|DES3|TripleDES|Blowfish|MD4|MD5|md5|SHA1|sha1|ECB|MODE_ECB|hashlib|createCipher|createCipheriv|createHash|KeyGenerator|MessageDigest|SecretKeyFactory)\b|Crypto\.Cipher|from Crypto\b|Cryptodome|cryptography\.hazmat|Cipher\.(?:getInstance|new)|OpenSSL::(?:Cipher|Digest)|crypto\/(?:md5|sha1|des|rc4)/,
  jwt: /jwt|JWT|Jwt|jsonwebtoken|\bjose\b|SigningMethod|SignedString|ParseWithClaims|Algorithm\.(?:HMAC|none)|parseUnsecured|jjwt/,
  cookie: /cookie|Cookie|COOKIE|\bsession\s*\(/,
  cors: /\bcors\b|\bCORS\b|Access-Control-Allow|CrossOrigin|AllowAllOrigins|AllowedOrigins|AllowOrigins|\borigins\b/,
  csrf: /csrf|CSRF|Csrf|forgery_protection|protect_from_forgery/,
  jndi: /InitialContext|InitialDirContext|JndiTemplate|\bDirContext\b|\.lookup\s*\(/,
  debug: /\bdebug\s*[=:]\s*(?:True|true)\b|\bDEBUG\s*=\s*True\b|DEBUG_PROPAGATE_EXCEPTIONS/,
};
/** Does this source carry at least one marker of a class the hosted engines model? */
export function hasSinkMarker(code) {
  for (const re of Object.values(SINK_HINTS)) if (re.test(code)) return true;
  return false;
}
// A request-value source (the other half of every taint class). A marker file that ALSO reads request input is the
// likeliest to hold a real flow, so it is sent before a marker-only file when the file cap bites on a large repo.
export const SOURCE_HINT = /\brequest\.(?:args|form|values|GET|POST|FILES|files|json|get_json|data|body|query_params|cookies|headers|params|query|url|path_info|META|match_info|rel_url|post|multipart)\b|\breq\.(?:query|body|params|headers|cookies|url|originalUrl|path|files?|get)\b|\bparams\[|\br\.(?:URL|FormValue|PostFormValue|Form|PostForm|Header|Body|Cookie|MultipartForm)\b|\bc\.(?:Query|Param|PostForm|FormValue|Bind\w*)\s*\(|\bget(?:Parameter|ParameterValues|Header|QueryString|InputStream|Reader|Cookies|RequestURI|PathInfo)\s*\(|@(?:RequestParam|PathVariable|RequestBody|RequestHeader|CookieValue|QueryParam|PathParam|FormParam|HeaderParam)\b|\b(?:location|document)\.(?:hash|search|href|URL|location|cookie|referrer)\b|\bprocess\.argv\b|\bsearchParams\b|@\w+\.(?:route|get|post|put|patch|delete)\s*\(/;

/** Paths (repo-relative) of every file a pack fingerprint recorded hits for — the sink-bearing files. Sorted. */
export function sinkFiles(packFingerprints) {
  const out = new Set();
  for (const fp of Object.values(packFingerprints || {})) {
    for (const f of Array.isArray(fp?.files) ? fp.files : []) {
      if (typeof f?.file === "string" && f.file && Array.isArray(f.hits) && f.hits.length) out.add(f.file);
    }
  }
  return [...out].sort();
}

const FULL_SHA = /^[0-9a-f]{40}$/;

/**
 * The paths THIS pull request changed, read LOCALLY from git (`base...head` = the PR's own changes since its merge-base),
 * so the deep scan can send the PR's files first on a repo larger than the file cap. No network and no token: the
 * same answer in `--print-payload` as in the real run, so the audit list stays the list that is sent. `git(args)` →
 * stdout, throwing on failure (injected). null when this is not a pull_request run, the event has no full SHAs, or git
 * cannot answer (shallow checkout without the base, pull_request_target on the base ref…) — the caller then keeps the
 * repo-wide order. Deleted files are left out (nothing to send).
 */
export function prChangedPaths(env, readEvent, git) {
  if (env.GITHUB_EVENT_NAME !== "pull_request" && env.GITHUB_EVENT_NAME !== "pull_request_target") return null;
  let ev = null;
  try { ev = readEvent(); } catch { return null; }
  const base = ev?.pull_request?.base?.sha, head = ev?.pull_request?.head?.sha;
  if (!FULL_SHA.test(base || "") || !FULL_SHA.test(head || "")) return null;
  try {
    const out = git(["diff", "--name-only", "--diff-filter=d", "-z", `${base}...${head}`]);
    return typeof out === "string" ? out.split("\0").filter(Boolean) : null;
  } catch { return null; }
}

// A config rule the engines report WITHOUT any request source, in its unambiguous shape (TLS verification off, CSRF
// off, debug on, JWT unverified, ECB / weak cipher, insecure cookie flag, world-writable mode, XXE-enabling parser
// option). Such a file never matches SOURCE_HINT, so on a large repo it sorted LAST and fell past the (then 40-)file cap:
// outline (942 candidates) sent none of its 4 `rejectUnauthorized: false` files, netbox missed its `@csrf_exempt`.
export const STRONG_PATTERN_HINT = /rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED|verify\s*=\s*False\b|CERT_NONE|_create_unverified_context|InsecureSkipVerify\s*[:=]\s*true|VERIFY_NONE|NoopHostnameVerifier|ALLOW_ALL_HOSTNAME_VERIFIER|@csrf_exempt|WTF_CSRF_ENABLED\s*=\s*False|csrf\(\)\s*\.\s*disable|skip_forgery_protection|\bdebug\s*=\s*True\b|\bDEBUG\s*=\s*True\b|algorithms?\s*[:=]\s*\[?\s*['"]none['"]|verify_signature['"]?\s*:\s*False|MODE_ECB|modes\.ECB|createCipher\s*\(|\b(?:secure|httpOnly|httponly)\s*[:=]\s*(?:false|False)\b|SESSION_COOKIE_SECURE\s*=\s*False|\b0o?777\b|\bnoent\s*:\s*true|resolve_entities\s*=\s*True/;
// An injection-grade sink (shell, eval, raw SQL string, redirect, outbound URL, template from string, unsafe
// deserializer). A file that reads a request value AND carries one of these is the likeliest real flow, so among
// request-reading files it goes first — payload (1 362 candidates) cut its `redirect(path)` preview routes by name order.
export const STRONG_TAINT_SINK = /\b(?:os\.system|subprocess|child_process|execSync|execFile|exec\.Command|Runtime\.getRuntime|ProcessBuilder)\b|\bexec\s*\(|\beval\s*\(|\bnew Function\s*\(|\b(?:execute|executeQuery|query|raw|Exec|QueryRow)\s*\(\s*[`'"f]?[^)]*?(?:\+|\$\{|%s|\{|format\()|\bredirect(?:_to)?\s*\(|sendRedirect|\bfetch\s*\(|\baxios\b|\brequests\.(?:get|post|put|request)|urlopen|render_template_string|\bpickle\.loads?|\bunserialize\s*\(|yaml\.load\s*\(|Marshal\.load|readObject\s*\(/;

// Dev-only locations (examples, scripts, tests, fixtures, benchmarks, docs). Never excluded — a flaw there is real — but
// inside a tier they go AFTER production code: on Ghost the 40 slots went to release/bench scripts while
// core/frontend/src/admin-auth/message-handler.js (6 SSRF) and web/middleware/admin-toolbar.js (open redirect) were cut.
export const DEV_PATH = /(?:^|\/)(?:examples?|samples?|demos?|scripts?|tools?|bench(?:marks?)?|tests?|__tests__|spec|specs|e2e|fixtures?|mocks?|docs?|stories)(?:\/|$)|\.(?:test|spec|stories)\.[cm]?[jt]sx?$|(?:^|\/)test_[^/]*\.py$|_test\.(?:go|py)$/i;

/** How many weakness families a source carries — a tie-breaker: a file touching more families goes first. */
function familyCount(code) {
  let n = 0;
  for (const re of Object.values(SINK_HINTS)) if (re.test(code)) n++;
  return n;
}

/**
 * The units to send, in priority order (each tier ranked by family count, then path):
 *   0 files THIS PR changed (`changedPaths`) · 1 extractor hits (`hitPaths`) · 2 an unambiguous config rule
 *   (STRONG_PATTERN_HINT) · 3 a request source AND an injection-grade sink (STRONG_TAINT_SINK) · 4 a request source ·
 *   5 any other sink marker.
 * A changed file is still sent only when it has a hit or a marker — being in the PR never widens egress, nor does any
 * tier (every tier is a subset of « has a sink marker »). Engine-modelled extensions only; read via `read(path)`
 * (null / throw = unreadable); empty / oversize files skipped; stops at the file and character caps. `skipped` counts
 * candidate files left out so the log can say the scan was bounded instead of implying full coverage; `fromPr` counts
 * the sent units the PR changed.
 */
export function selectDeepUnits(paths, read, hitPaths = [], changedPaths = []) {
  const hits = new Set(hitPaths);
  const changed = new Set(changedPaths);
  const cands = [];
  let skipped = 0;
  for (const path of [...new Set([...hitPaths, ...[...paths].sort()])]) {
    if (!DEEP_SCAN_EXTS.test(path)) continue;
    let code = null;
    try { code = read(path); } catch { code = null; }
    if (typeof code !== "string" || !code) { if (hits.has(path)) skipped++; continue; }
    const hit = hits.has(path);
    if (!hit && !hasSinkMarker(code)) continue; // no sink marker → never sent
    const sourced = SOURCE_HINT.test(code);
    const tier = changed.has(path) ? 0 : hit ? 1 : STRONG_PATTERN_HINT.test(code) ? 2
      : sourced && STRONG_TAINT_SINK.test(code) ? 3 : sourced ? 4 : 5;
    cands.push({ path, code, tier, dev: DEV_PATH.test(path) ? 1 : 0, fam: familyCount(code) });
  }
  cands.sort((a, b) => a.tier - b.tier || a.dev - b.dev || b.fam - a.fam || (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  const units = [];
  let total = 0, fromPr = 0;
  for (const c of cands) {
    const u = { path: c.path, code: c.code };
    if (units.length >= DEEP_MAX_UNITS || u.code.length > DEEP_MAX_UNIT_CHARS || total + u.code.length > DEEP_MAX_TOTAL_CHARS) { skipped++; continue; }
    total += u.code.length;
    units.push(u);
    if (changed.has(u.path)) fromPr++;
  }
  return { units, skipped, chars: total, fromPr };
}

// ── Library mode (0.10.6, opt-in `library-mode: "true"`) ─────────────────────────────────────────────────────────────
// For a PACKAGE the attack surface is its callers, so the detector's library tier (a public function's parameter
// reaching a sink) is worth a look. Measured on the full GHSA real-CVE set (paired: the vulnerable file flagged AND its
// fix not): JS 1.0% → 9.0%, Python 1.5% → 5.6%; ~2 of 3 candidate hits persist in the FIXED file, and a clean library
// like jinja yields a dozen by-design API flows — hence opt-in, and shown as « to triage », never as a finding.
const APP_DEPS_PY = /\b(?:django|flask|fastapi|starlette|aiohttp|tornado|pyramid|sanic|quart|falcon)\b/i;
const APP_ENTRY_PY = ["manage.py", "wsgi.py", "asgi.py", "app.py"];

/**
 * Is this checkout a PUBLISHED LIBRARY or an application? Deterministic, local, reads manifests only.
 *   JS  — package.json not private, with a published surface (files / exports / types) and no `start` script.
 *   Py  — no web-app entry point (manage.py / wsgi / asgi / app.py at the root or one level down), and a pyproject with
 *         [build-system] + a project name and no web-framework dependency, or a setup.py calling setup(name=…).
 * Measured: 22 of 22 real applications → app (0 false library), 9 of 10 real libraries → library (lodash's private root
 * manifest is a conservative miss). `read(rel)` → text | null, `dirs()` → top-level directory names (injected).
 */
export function repoKind(read, dirs = () => []) {
  const pj = read("package.json");
  if (pj !== null) {
    let p = null;
    try { p = JSON.parse(pj); } catch { p = null; }
    if (p && typeof p === "object") {
      const start = p.scripts && typeof p.scripts.start === "string";
      if (p.private !== true && typeof p.name === "string" && !start && (p.files || p.exports || p.types || p.typings)) return { kind: "library", why: "published package.json (files/exports/types, no start script)" };
      return { kind: "app", why: p.private === true ? "private package.json" : start ? "package.json has a start script" : "package.json declares no published surface" };
    }
  }
  const entry = APP_ENTRY_PY.some((f) => read(f) !== null) || dirs().some((d) => ["manage.py", "wsgi.py", "asgi.py"].some((f) => read(`${d}/${f}`) !== null));
  if (entry) return { kind: "app", why: "web-app entry point (manage.py / wsgi / asgi / app.py)" };
  const pp = read("pyproject.toml");
  if (pp !== null) {
    const named = /^\[project\][^[]*?^name\s*=/ms.test(pp) || /^\[tool\.poetry\][^[]*?^name\s*=/ms.test(pp);
    const deps = ((pp.match(/^\[project\][\s\S]*?^dependencies\s*=\s*\[([\s\S]*?)\]/m) || [])[1] || "") + ((pp.match(/^\[tool\.poetry\.dependencies\]([\s\S]*?)^\[/m) || [])[1] || "");
    if (/^\[build-system\]/m.test(pp) && named && !APP_DEPS_PY.test(deps) && !/package-mode\s*=\s*false/.test(pp)) return { kind: "library", why: "pyproject with build-system + project name" };
  }
  const sp = read("setup.py");
  if (sp !== null && /setup\s*\([\s\S]*?name\s*=/.test(sp) && !APP_DEPS_PY.test(sp)) return { kind: "library", why: "setup.py" };
  return { kind: "app", why: "no published-package manifest" };
}

/** Library-tier candidates → triage rows, only on paths THIS run sent; malformed rows dropped. Never feed/gate rows. */
export function libraryCandidates(candidates, sentPaths) {
  const sent = new Set(sentPaths);
  return (Array.isArray(candidates) ? candidates : [])
    .filter((c) => c && typeof c.path === "string" && sent.has(c.path) && typeof c.cwe === "string" && /^CWE-\d{1,5}$/.test(c.cwe) && typeof c.evidence === "string")
    .map((c) => ({ file: c.path, line: evidenceLine(c.evidence), rule: c.cwe, detail: c.evidence }));
}

/** Shape check of the server answer; anything else is treated as no answer (fail open). */
export function validHeisenResponse(j) {
  if (!j || typeof j !== "object" || j.ok !== true || !Array.isArray(j.findings)) return false;
  if (typeof j.scanned !== "number" || typeof j.unanswered !== "number") return false;
  return j.findings.every((f) => f && typeof f.path === "string" && typeof f.cwe === "string" && /^CWE-\d{1,5}$/.test(f.cwe)
    && typeof f.p === "number" && typeof f.evidence === "string");
}

/** The sink line from the engine evidence ("… reaches os.system() at line 7 …"), else the first source line, else 1. */
export function evidenceLine(evidence) {
  const m = /reaches .*? at line (\d+)/.exec(evidence) || /at line (\d+)/.exec(evidence);
  const n = m ? Number(m[1]) : 1;
  return Number.isInteger(n) && n > 0 ? n : 1;
}

/**
 * Findings → the normalized feed rows the log / PR review / SARIF already consume. Only paths THIS run sent are kept
 * (a server answer can never place an annotation on a file we did not scan). Severity "medium" = advisory: the feed
 * counts critical|high as blocking, and the deep scan never blocks while it is uncalibrated.
 */
export function heisenFeed(findings, sentPaths) {
  const sent = new Set(sentPaths);
  return findings.filter((f) => sent.has(f.path)).map((f) => ({
    file: f.path, line: evidenceLine(f.evidence), pack: "heisen", rule: f.cwe, detail: f.evidence, severity: "medium",
  }));
}

/**
 * Split deep-scan rows into the NEW ones (a location no other pack already reported) and the ones that only CONFIRM an
 * existing finding (same file:line). Confirmations are counted, not re-annotated — one sink, one annotation.
 */
export function splitAgainstFeed(rows, feed) {
  const seen = new Set(feed.map((f) => `${f.file}:${f.line}`));
  const fresh = [], confirmed = [];
  for (const r of rows) (seen.has(`${r.file}:${r.line}`) ? confirmed : fresh).push(r);
  return { fresh, confirmed };
}

/**
 * Is this repo on the PAID tier? The server's `gateLevel` ("paid" | "public" | "free-oss" | "none") is exact;
 * `gateEntitled` is also true for public and free-oss repos (they have the free gate but not the paid catalogue), so it
 * is only a fallback for a server that predates `gateLevel`.
 */
export function isPaidVerdict(v) {
  if (v && typeof v.gateLevel === "string") return v.gateLevel === "paid";
  return !!v && v.gateEntitled === true;
}

/**
 * The one-line invitation a PAID repo sees when it has not opted into the deep scan — in the CI log, where the owner
 * already looks (no new screen). Public / free-oss repos are never invited (the deep scan would answer them 402).
 * null = nothing to say.
 */
export function deepScanNudge({ deepScan, paid }) {
  if (deepScan || paid !== true) return null;
  return "Deep scan available on this paid repo: add `deep-scan: \"true\"` to follow request values across functions "
    + "(flows the packs above cannot see). Opt-in — the one mode that sends source; see the Action README.";
}

/**
 * POST the units; `post(url, body)` → {status, json()} is injected (timedFetch in the client). Returns
 * {state: "ok", response} | {state: "plan-required"} | {state: "unavailable", status?} — never throws.
 */
export async function requestDeepScan(post, origin, oidcToken, sha, units, library = false) {
  try {
    const res = await post(`${origin}/api/ci/heisen`, JSON.stringify({ oidcToken, sha, units, ...(library ? { library: true } : {}) }));
    if (res.status === 402) return { state: "plan-required" };
    if (res.status < 200 || res.status >= 300) return { state: "unavailable", status: res.status };
    const j = await res.json();
    return validHeisenResponse(j) ? { state: "ok", response: j } : { state: "unavailable", status: "malformed" };
  } catch {
    return { state: "unavailable", status: "network" };
  }
}
