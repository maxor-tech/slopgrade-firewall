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
export const DEEP_MAX_UNITS = 40;
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
// likeliest to hold a real flow, so it is sent before a marker-only file when the 40-file cap bites on a large repo.
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

/**
 * The units to send, in priority order: the `hitPaths` (extractor hits) first, then the other `paths` carrying a sink
 * marker AND a request source (SOURCE_HINT), then the marker-only ones. Engine-modelled extensions only; read via
 * `read(path)` (null / throw = unreadable); empty / oversize files skipped; stops at the file and character caps.
 * `skipped` counts candidate files left out so the log can say the scan was bounded instead of implying full coverage.
 */
export function selectDeepUnits(paths, read, hitPaths = []) {
  const hits = new Set(hitPaths);
  const first = [], sourced = [], markerOnly = [];
  let skipped = 0;
  for (const path of [...new Set([...hitPaths, ...[...paths].sort()])]) {
    if (!DEEP_SCAN_EXTS.test(path)) continue;
    let code = null;
    try { code = read(path); } catch { code = null; }
    if (typeof code !== "string" || !code) { if (hits.has(path)) skipped++; continue; }
    if (hits.has(path)) first.push({ path, code });
    else if (hasSinkMarker(code)) (SOURCE_HINT.test(code) ? sourced : markerOnly).push({ path, code });
    // no sink marker → never sent
  }
  const units = [];
  let total = 0;
  for (const u of [...first, ...sourced, ...markerOnly]) {
    if (units.length >= DEEP_MAX_UNITS || u.code.length > DEEP_MAX_UNIT_CHARS || total + u.code.length > DEEP_MAX_TOTAL_CHARS) { skipped++; continue; }
    total += u.code.length;
    units.push(u);
  }
  return { units, skipped, chars: total };
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
export async function requestDeepScan(post, origin, oidcToken, sha, units) {
  try {
    const res = await post(`${origin}/api/ci/heisen`, JSON.stringify({ oidcToken, sha, units }));
    if (res.status === 402) return { state: "plan-required" };
    if (res.status < 200 || res.status >= 300) return { state: "unavailable", status: res.status };
    const j = await res.json();
    return validHeisenResponse(j) ? { state: "ok", response: j } : { state: "unavailable", status: "malformed" };
  } catch {
    return { state: "unavailable", status: "network" };
  }
}
