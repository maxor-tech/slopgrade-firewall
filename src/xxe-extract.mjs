// XXE — XML External Entity injection (CWE-611 / OWASP A05) — LANGUAGE-AGNOSTIC client fingerprint. Mirror of
// jwt-extract: emit {file, line, kind} — NEVER the source line. Every kind here is an EXPLICIT enabling of
// external-entity / DTD processing — modern XML parsers are secure BY DEFAULT, so you only write these to turn the
// protection OFF. No safe use → all HIGH, no gated tier. The only suppression is test/vendored/comment (xxe-brain).
//
// XXE lets an attacker read local files (file:///etc/passwd), reach internal services (SSRF), or exfiltrate data
// via a crafted DOCTYPE — the classic `<!ENTITY xxe SYSTEM "file:///…">` payload the parser then resolves.

const PATTERNS = [
  // PHP — libxml: NOENT substitutes entities; disable_entity_loader(false) re-enables the external loader.
  ["php-libxml", /\bLIBXML_NOENT\b|libxml_disable_entity_loader\s*\(\s*false\s*\)/],
  // Python — lxml: resolve_entities=True (or no_network=False) on an XMLParser is the XXE switch.
  ["py-lxml", /resolve_entities\s*=\s*True|\bno_network\s*=\s*False\b/],
  // Java — SAX/DOM/StAX: expand entity refs, or the SAX feature flags flipped ON, or StAX external-entity support.
  ["java-entities", /setExpandEntityReferences\s*\(\s*true\s*\)|setFeature\s*\(\s*["'][^"']*external-(?:general|parameter)-entities["']\s*,\s*true\s*\)|IS_SUPPORTING_EXTERNAL_ENTITIES\s*,\s*(?:true|Boolean\.TRUE)|SUPPORT_DTD\s*,\s*(?:true|Boolean\.TRUE)/],
  // .NET — DtdProcessing.Parse (allows a DOCTYPE) especially with an XmlUrlResolver (fetches the external DTD).
  ["dotnet-dtd", /DtdProcessing\s*=\s*DtdProcessing\.Parse|XmlResolver\s*=\s*new\s+XmlUrlResolver/],
  // Ruby — Nokogiri with the NOENT parse option enables entity substitution.
  ["ruby-noent", /Nokogiri::XML::ParseOptions::NOENT|\.noent\b/],
];

const isComment = (l) => /^\s*(\/\/|\*|#|--|;|<!--)/.test(l);

/** Scan one file → [{line, kind}]. Source line NEVER leaves this function. */
export function extractXxe(text) {
  const out = [];
  const lines = String(text).split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const l = lines[i];
    if (l.length > 4000) continue;   // minified blob — noise
    if (isComment(l)) continue;      // an XXE switch named in a comment is documentation, not live code
    for (const [kind, re] of PATTERNS) {
      if (re.test(l)) out.push({ line: i + 1, kind });
    }
  }
  return out;
}

/** The XXE fingerprint for one file — locations + kinds, no source. */
export function extractXxeFingerprint(text, file) {
  return { file, hits: extractXxe(text) };
}
