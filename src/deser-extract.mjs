// Insecure deserialization (CWE-502 / OWASP A08) — LANGUAGE-AGNOSTIC client fingerprint. Mirror of
// crypto-extract: emit {file, line, kind, high, srcCtx} — NEVER the source line. The SUPPRESSION DECISION
// (which kinds fire, and gated kinds only near an untrusted source) is hosted server-side, not shipped in this client.
//
// Two tiers, like weak-crypto's HIGH vs gated:
//   • HIGH — an RCE-gadget API with (near-)no safe use: BinaryFormatter, ObjectInputStream.readObject, XMLDecoder,
//     yaml.load WITHOUT a safe loader, yaml.unsafe_load, Json.NET TypeNameHandling.All/Auto/Objects,
//     node-serialize unserialize, PHP unserialize on a request superglobal. → always fire.
//   • GATED (dangerous-on-untrusted) — pickle/cPickle/dill/marshal loads, Ruby Marshal.load / YAML.load, PHP
//     unserialize on a variable. Legitimate for TRUSTED internal data (a cache, an ML model) → fire ONLY when an
//     untrusted-source keyword (request/input/body/socket/$_GET…) sits within SRC_WINDOW lines (srcCtx=true).

const HIGH = [
  // Python — yaml.load with no safe loader is RCE; the safe forms (safe_load / Loader=SafeLoader/CSafeLoader) are
  // excluded by requiring the call to NOT carry a Safe loader on the same line. A real sink also LOADS something, so
  // the parens must hold a non-empty argument (`\(\s*[^\s)]`): this drops a security scanner's own reminder PROSE
  // that names the API with empty parens — `yaml.load() / yaml.unsafe_load() execute arbitrary Python` — as a false
  // HIGH (a real-code false positive: security-guidance prose that names the API with no argument). Zero TP loss: a bare
  // `yaml.load()` with no stream is a TypeError, never a real deserialization sink.
  // The safe-Loader lookahead scans the whole LINE (`[^\n]*`), not just to the first `)` — otherwise a nested paren
  // in the first arg hides the loader: `yaml.load(path.read_text(...), Loader=yaml.CSafeLoader)` (a real-code
  // sample) stopped the old `[^)]*Loader` scan at read_text's `)` and false-fired. The redundant `(?![^)]*safe)`
  // lookahead was dropped (SafeLoader is already caught by the Loader lookahead, and `[^)]*safe` matched "unsafe").
  ["py-yaml-unsafe", /\byaml\.unsafe_load\s*\(\s*[^\s)]|\byaml\.load\s*\(\s*(?![^\n]*(?:Safe|CSafe|Base|Full)?Loader)[^\s)]/],
  // Java — the classic gadget sinks. The bare `.readObject()` (a 2-line ObjectInputStream, receiver on another
  // line) is NOT here: it is receiver-agnostic and false-positives on ASN1InputStream.readObject() (BouncyCastle
  // ASN.1) and PEMParser.readObject() (PEM) — crypto PARSING, not Java deserialization. It is handled below with a
  // file-level ObjectInputStream guard (an ASN.1/PEM parser file never mentions ObjectInputStream).
  ["java-readobject", /\bObjectInputStream\b[^;]{0,120}\.readObject\s*\(|new\s+XMLDecoder\s*\(|new\s+XStream\s*\([^)]*\)\s*\.fromXML|new\s+Yaml\s*\(\s*\)\s*\.load\s*\(/],
  // .NET — Microsoft-deprecated insecure formatters + Json.NET unsafe type handling.
  ["dotnet-binaryformatter", /\bBinaryFormatter\b[^;]{0,60}\.Deserialize\s*\(|\bNetDataContractSerializer\b|\bLosFormatter\b|\bObjectStateFormatter\b|\bSoapFormatter\b|TypeNameHandling\s*\.\s*(?:All|Auto|Objects|Arrays)/],
  // Node — the node-serialize RCE.
  ["node-serialize", /require\(\s*['"]node-serialize['"]\s*\)|\bnodeserialize\b|serialize\.unserialize\s*\(/],
  // PHP — unserialize directly on a request superglobal (unambiguously attacker-controlled).
  ["php-unserialize-super", /\bunserialize\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE|FILES)\b/],
];

const GATED = [
  ["py-pickle", /\b(?:c?[Pp]ickle|dill|jsonpickle)\.(?:loads?|decode)\s*\(|\bmarshal\.loads?\s*\(/],
  ["ruby-marshal", /\bMarshal\.load\s*\(|\bYAML\.load\s*\(|\bOj\.load\s*\(/],
  ["php-unserialize", /\bunserialize\s*\(\s*\$/],
];

// A GATED sink (pickle/marshal/unserialize-on-a-var) is a vuln ONLY on ATTACKER-CONTROLLED input. Frameworks
// deserialize their OWN cache/queue/session payloads constantly (trusted) — so a nearby "cache"/"cookie"/"body"
// keyword is NOT enough (it false-positives on Laravel's cache stores, Django's redis backend, …). We require a
// DIRECT untrusted-source reference ON THE SINK LINE ITSELF (request.body / $_GET / params[…] / getParameter):
// `pickle.loads(request.body)` fires; `unserialize($cachedValue)` (framework) does not. Precision over recall = ~0 FP.
const DIRECT_SRC = /\brequest\.|\breq\.(?:body|data|params|query|json|files|form)|\$_(?:GET|POST|REQUEST|COOKIE|FILES)\b|\bparams\[|\.get_json\(|getParameter\s*\(|Input::(?:get|all)|\binput\(\s*['"]/i;
const isComment = (l) => /^\s*(\/\/|\*|#|--|;|<!--)/.test(l);
// A bare `.readObject()` (empty parens, receiver declared on another line) is Java deserialization ONLY when the file
// uses ObjectInputStream. An ASN.1/PEM parser file (ASN1InputStream / PEMParser) never mentions ObjectInputStream, so
// its `asn1In.readObject()` / `pemParser.readObject()` is crypto PARSING, not a deser sink — the guard drops it.
const BARE_READOBJECT = /\.readObject\s*\(\s*\)/;

/** Scan one file → [{line, kind, high, srcCtx}]. Source line NEVER leaves this function. */
export function extractDeser(text) {
  const out = [];
  const s = String(text);
  const hasOIS = /\bObjectInputStream\b/.test(s);   // file-level: is real Java deserialization even in play here?
  const lines = s.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const l = lines[i];
    if (l.length > 4000) continue;   // minified blob — noise
    if (isComment(l)) continue;      // a sink named in a comment is documentation, not live code
    for (const [kind, re] of HIGH) {
      if (re.test(l)) out.push({ line: i + 1, kind, high: true, srcCtx: true });
    }
    // bare ObjectInputStream deserialization (receiver on another line) — only when the file uses ObjectInputStream.
    if (hasOIS && BARE_READOBJECT.test(l) && !/\bObjectInputStream\b/.test(l)) {
      out.push({ line: i + 1, kind: "java-readobject", high: true, srcCtx: true });
    }
    for (const [kind, re] of GATED) {
      if (!re.test(l)) continue;
      const srcCtx = DIRECT_SRC.test(l);   // untrusted source DIRECTLY on the sink line — not a nearby keyword
      out.push({ line: i + 1, kind, high: false, srcCtx });
    }
  }
  return out;
}

/** The insecure-deserialization fingerprint for one file — locations + kinds + tier flags, no source. */
export function extractDeserFingerprint(text, file) {
  return { file, hits: extractDeser(text) };
}
