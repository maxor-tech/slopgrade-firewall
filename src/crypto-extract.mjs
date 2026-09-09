// Weak-crypto (CWE-327 broken/risky algorithm · CWE-328 weak hash) — LANGUAGE-AGNOSTIC client fingerprint.
// Mirror of transport-extract: emit {file, line, kind, severityHint, secCtx} — NEVER the source line. The
// SUPPRESSION DECISION (which kinds fire, MD5/SHA1 only in a security context) is the moat, server-side
// (crypto-brain.mjs). No-egress: only line numbers + a fixed kind id + two booleans leave the client.
//
// Two tiers, exactly like transport's HIGH vs opt-in-gated:
//   • HIGH kinds (DES/3DES/RC4/RC2/ECB-mode/mcrypt) — a BROKEN cipher with no legitimate modern use → always fire.
//   • WEAK-HASH kinds (MD5/SHA1) — fine for a checksum/ETag/cache key, a real defect only for a password/token/
//     signature. So a weak hash fires ONLY when a security keyword sits within SEC_WINDOW lines (secCtx=true).

// HIGH — broken ciphers / modes. Distinctive literals that only name a weak primitive (near-zero base-rate FP).
const HIGH = [
  // DES / 3DES (single-DES strength) / RC4 / RC2 — named across ecosystems. The DES token must be in a USE context
  // (a constructor/call/keyspec/getInstance/provider), NOT a bare mention: `import …symmetric.DES`,
  // `algorithm.startsWith("DES")` and an error string `"…is not a DES algorithm"` are NOT uses of DES (a real-code
  // false positive: a name check / error string, not a call). So the bare `\bDES\b` alternative was replaced by use-forms.
  ["des-cipher",   /\bdes\.NewCipher\b|Cipher\.getInstance\(\s*["'](?:DESede|DES)(?:\/|["'])|OpenSSL::Cipher(?:::|\.new\(\s*['"])(?:DES|des)|DESCryptoServiceProvider|TripleDESCryptoServiceProvider|MCRYPT_(?:3?DES|TRIPLEDES)|['"]des-(?:ede-)?(?:cbc|ecb)['"]|\bnew\s+(?:DESede|TripleDES|DES)\b|\b(?:DESede|TripleDES|3DES|DES)\s*(?:\.\s*new\b|\()|\balgorithms\s*\.\s*(?:TripleDES|DES)\b|\bDESK(?:ey)?Spec\b|\bcreateCipher(?:iv)?\s*\(\s*["']des\b|\bDES3\s*(?:\.\s*new\b|\()/],
  // RC4 / RC2 — like DES above, the bare `\bRC4\b`/`\bRC2\b` was a real-code false positive: it
  // matched "RC2"/"RC4" as radio-control channels/servos, a `/** RC4 */` doc comment, and a
  // `case 0x…:/* RC2 */` archive/runtime format table. A real cipher always appears via an API call or a lower-case
  // quoted cipher name — never a bare/upper-case word — so the bare alternative is dropped.
  ["rc4-cipher",   /\brc4\.NewCipher\b|\bARC4\b|Cipher\.getInstance\(\s*["']RC4|OpenSSL::Cipher(?:::|\.new\(\s*['"])(?:RC4|rc4)|MCRYPT_ARCFOUR|\bcreateCipher(?:iv)?\s*\(\s*["']rc4\b|['"](?:rc4|arcfour)['"]/],
  ["rc2-cipher",   /Cipher\.getInstance\(\s*["']RC2|RC2CryptoServiceProvider|MCRYPT_RC2|\bcreateCipher(?:iv)?\s*\(\s*["']rc2\b|['"]rc2['"]/],
];

// WEAK-HASH — MD5 / SHA-1. Gated on a nearby security keyword (secCtx).
const HASH = [
  ["md5-hash",  /\bcreateHash\(\s*['"]md5['"]|hashlib\.md5\s*\(|\bMD5\.new\s*\(|MessageDigest\.getInstance\(\s*["']MD5["']|\bmd5\.(?:New|Sum)\b|Digest::MD5|new\s+MD5CryptoServiceProvider|MD5\.Create\s*\(|\bMd5::new\b|\bmd5\s*\(|hashlib\.new\s*\(\s*["']md5["']|\bDigestUtils\.md5Hex\b|\bCryptoJS\.MD5\b/],
  ["sha1-hash", /\bcreateHash\(\s*['"]sha1['"]|hashlib\.sha1\s*\(|\bSHA1?\.new\s*\(|MessageDigest\.getInstance\(\s*["']SHA-?1["']|\bsha1\.(?:New|Sum)\b|Digest::SHA1|new\s+SHA1CryptoServiceProvider|SHA1\.Create\s*\(|\bSha1::new\b|\bsha1\s*\(|hashlib\.new\s*\(\s*["']sha-?1["']|\bDigestUtils\.sha1Hex\b|\bCryptoJS\.SHA1\b/],
];

// A weak HASH (MD5/SHA1) is an UNAMBIGUOUS defect only for PASSWORD hashing — collision-broken hashes are still
// safe inside HMAC (HMAC-SHA1 is fine — it does not rely on collision resistance) and for checksums/ETags/cache
// keys. So a weak hash fires ONLY when a password keyword sits within SEC_WINDOW lines (secCtx=true) AND no
// SAFE marker (HMAC / a proper KDF / a signer digest_method) is nearby. This precision-over-recall choice keeps
// the FP rate ~0 (the moat); broad recall is carried by the HIGH tier (DES/RC4/RC2/ECB, which have no safe use).
const PW_CTX = /password|passwd|\bpwd\b|user_?pass|pass_?(?:word|hash|phrase)/i;
const SAFE_CTX = /\bhmac\b|digest_?method|digestmod|\bbcrypt\b|\bscrypt\b|argon2?|pbkdf|createHmac|OpenSSL::HMAC|Mac\.getInstance|itsdangerous/i;
const SEC_WINDOW = 4; // lines above + below the hit to inspect
const isComment = (l) => /^\s*(\/\/|\*|#|--|;|<!--)/.test(l);
// An import/using/package line NAMES a crypto type, it never USES it (the real use fires on a later line). Java
// `import a.b.DES;` / `from Crypto.Cipher import DES` / C# `using X.DES;` are documentation of a dependency, not a
// weak-crypto call (a real-code false positive: an `import …DESKeySpec;` names the type, does not use it). Skipped like a comment.
const isImport = (l) => /^\s*(?:import\s+[\w.]|from\s+[\w.]+\s+import\s|using\s+[\w.]+\s*;|package\s+[\w.]+\s*;)/.test(l);

/** Scan one file → [{line, kind, high, secCtx}]. Source line NEVER leaves this function. */
export function extractCrypto(text) {
  const out = [];
  const lines = String(text).split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const l = lines[i];
    if (l.length > 4000) continue;   // minified/one-line blob — noise
    if (isComment(l)) continue;      // a weak-algo name in a comment is documentation, not live code
    if (isImport(l)) continue;       // an import/using line names a crypto type, it does not use it
    for (const [kind, re] of HIGH) {
      if (re.test(l)) out.push({ line: i + 1, kind, high: true, secCtx: true });
    }
    for (const [kind, re] of HASH) {
      if (!re.test(l)) continue;
      const from = Math.max(0, i - SEC_WINDOW), to = Math.min(lines.length, i + SEC_WINDOW + 1);
      const win = lines.slice(from, to).join("\n");
      const secCtx = PW_CTX.test(win) && !SAFE_CTX.test(win);   // password hashing, and NOT an HMAC/KDF/signer use
      out.push({ line: i + 1, kind, high: false, secCtx });
    }
  }
  return out;
}

/** The weak-crypto fingerprint for one file — locations + kinds + tier flags, no source. */
export function extractCryptoFingerprint(text, file) {
  return { file, hits: extractCrypto(text) };
}
