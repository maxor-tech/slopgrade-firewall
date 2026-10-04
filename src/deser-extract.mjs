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
  // HIGH (holistic FP audit 2026-09-08: anthropics_claude-code security-guidance patterns.py). Zero TP loss: a bare
  // `yaml.load()` with no stream is a TypeError, never a real deserialization sink.
  // The safe-Loader lookahead scans the whole LINE (`[^\n]*`), not just to the first `)` — otherwise a nested paren
  // in the first arg hides the loader: `yaml.load(path.read_text(...), Loader=yaml.CSafeLoader)` (a real project, (real-code corpus)
  // audit) stopped the old `[^)]*Loader` scan at read_text's `)` and false-fired. The redundant `(?![^)]*safe)`
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

// Real-code corpus FPs (2026-10-01) — three narrow recognitions, each a provably-not-untrusted shape:
//   • ruamel.yaml — `yaml = YAML()` / `ruamel.yaml.YAML(typ="safe")` binds `yaml` to a ruamel instance whose `load`
//     is the round-trip/safe loader (no arbitrary Python objects). Only typ="unsafe" reconstructs objects. So in a
//     file that binds `yaml` to a ruamel YAML(...) (not unsafe) and never imports PyYAML as `yaml`, `yaml.load(f)` is
//     not the PyYAML RCE. `yaml.unsafe_load` is still judged below.
//   • A LOCAL-FILE stream — `yaml.unsafe_load(path.read_text())` / `ObjectInputStream(FileInputStream(file))`
//     deserializes a file on the app's own disk: the same trusted-data case the GATED tier already drops for
//     `pickle.load(open(...))`. Demoted to GATED (fires only with a direct request source on the line). A network /
//     caller-supplied stream (`ObjectInputStream(socket.getInputStream())`, a stream parameter) stays HIGH.
//   • A Json.NET MEMBER attribute `[JsonProperty(ItemTypeNameHandling = TypeNameHandling.Auto)]` on a member typed as
//     an app's own class: Json.NET rejects a `$type` not assignable to the declared type, so the gadget classes
//     (ObjectDataProvider, …) cannot land there. It stays HIGH when the member is `object`/`dynamic` or a BCL
//     interface every gadget implements (IEnumerable, IDisposable, ISerializable, …). Settings-level
//     `TypeNameHandling = TypeNameHandling.Auto` (root object, declared types unknown) always stays HIGH.
const RUAMEL_BIND = /\byaml\s*=\s*(?:ruamel\.yaml\.)?YAML\s*\(/;
const RUAMEL_UNSAFE = /\bYAML\s*\([^)\n]*typ\s*=\s*\[?\s*['"]unsafe/;
const PYYAML_IMPORT = /^\s*(?:import\s+yaml\b(?!\s*\.)|from\s+yaml\s+import\b)/m;
const LOCAL_FILE_ARG = /\byaml\.unsafe_load\s*\(\s*(?:open\s*\(|[\w.]+\.read_(?:text|bytes)\s*\()/;
const OIS_CTOR = /\bObjectInputStream\s*\(/;
const OIS_LOCAL_FILE = /\bObjectInputStream\s*\(\s*(?:new\s+)?(?:Buffered(?:Input)?Stream\s*\(\s*(?:new\s+)?)?FileInputStream\s*\(/;
const TNH_ATTR = /^\s*\[\s*JsonProperty\s*\([^\]]*TypeNameHandling\s*=\s*TypeNameHandling\./;
const TNH_DANGEROUS_TYPE = /^(?:object|Object|dynamic|System\.Object|I(?:Enumerable|List|Collection|Dictionary|Disposable|Serializable|Comparable|Convertible|Formattable|ReadOnlyList|ReadOnlyCollection|ReadOnlyDictionary))$/;
// Declared (element) type of the member a C# attribute decorates: the next non-attribute line, innermost generic arg.
function memberElementType(lines, i) {
  for (let j = i + 1; j < Math.min(lines.length, i + 4); j++) {
    const d = lines[j].trim();
    if (!d || d.startsWith("[")) continue;
    const m = /^(?:(?:public|private|protected|internal|static|readonly|virtual|override|new|required)\s+)*([\w.]+(?:<[^=;{]*>)?(?:\[\])?\??)\s+\w+\s*(?:[{;=]|$)/.exec(d);
    if (!m) return null;
    const g = /<\s*(?:[^<>]*,\s*)?([\w.]+)\??\s*>\s*(?:\[\])?\??$/.exec(m[1]);
    return (g ? g[1] : m[1].replace(/(?:\[\])?\??$/, ""));
  }
  return null;
}

/** Scan one file → [{line, kind, high, srcCtx}]. Source line NEVER leaves this function. */
export function extractDeser(text) {
  const out = [];
  const s = String(text);
  const hasOIS = /\bObjectInputStream\b/.test(s);   // file-level: is real Java deserialization even in play here?
  const ruamelSafe = RUAMEL_BIND.test(s) && !RUAMEL_UNSAFE.test(s) && !PYYAML_IMPORT.test(s);
  const lines = s.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const l = lines[i];
    if (l.length > 4000) continue;   // minified blob — noise
    if (isComment(l)) continue;      // a sink named in a comment is documentation, not live code
    for (const [kind, re] of HIGH) {
      if (!re.test(l)) continue;
      if (kind === "py-yaml-unsafe" && ruamelSafe && !/\byaml\.unsafe_load\b/.test(l)) continue; // ruamel safe/rt load
      if (kind === "dotnet-binaryformatter" && TNH_ATTR.test(l) && !/\bBinaryFormatter\b|Formatter\b|NetDataContractSerializer/.test(l)) {
        const t = memberElementType(lines, i);
        if (t && !TNH_DANGEROUS_TYPE.test(t)) continue;   // member typed as an app class → $type must be assignable to it
      }
      const local = (kind === "py-yaml-unsafe" && LOCAL_FILE_ARG.test(l)) || (kind === "java-readobject" && OIS_LOCAL_FILE.test(l));
      if (local) { out.push({ line: i + 1, kind, high: false, srcCtx: DIRECT_SRC.test(l) }); continue; } // local-file stream → gated
      out.push({ line: i + 1, kind, high: true, srcCtx: true });
    }
    // bare ObjectInputStream deserialization (receiver on another line) — only when the file uses ObjectInputStream,
    // and not on a line the inline java-readobject pattern already matched (avoid a double count on the same line).
    if (hasOIS && BARE_READOBJECT.test(l) && !/\bObjectInputStream\b/.test(l)) {
      // the nearest ObjectInputStream construction within 3 lines above: a local FileInputStream → gated (trusted disk)
      let ctor = null;
      for (let j = i - 1; j >= Math.max(0, i - 3); j--) if (OIS_CTOR.test(lines[j])) { ctor = lines[j]; break; }
      if (ctor && OIS_LOCAL_FILE.test(ctor)) out.push({ line: i + 1, kind: "java-readobject", high: false, srcCtx: DIRECT_SRC.test(l) });
      else out.push({ line: i + 1, kind: "java-readobject", high: true, srcCtx: true });
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
