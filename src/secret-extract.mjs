// SECRETS pack — the CLIENT half (commodity). Scans file text for credential-shaped literals and emits, per match,
// ONLY {file, line, kind, entropy, placeholder} — NEVER the secret value. The value is read locally to compute its
// Shannon entropy and to test if it's an obvious placeholder, then discarded. That is the no-egress guarantee for
// secrets: the server learns WHERE and WHAT KIND, never the credential itself. The confidence tuning that turns
// candidates into findings lives server-side, in the hosted product — never shipped in this client.

// HIGH-CONFIDENCE provider credential shapes only — a specific prefix + fixed body ≈ near-certainty, low base-rate
// FP. Noisier heuristics (a generic `secret = "…"` assignment; a bare JWT or a lone `-----BEGIN PRIVATE KEY-----`
// header) are intentionally omitted here: they collide with design tokens, form fields, i18n strings and
// PEM-handling code, so they need context a static line-scan can't give. The hosted product handles those.
const PATTERNS = [
  ["aws-access-key", /\bAKIA[0-9A-Z]{16}\b/],
  ["github-token", /\bgh[pousr]_[A-Za-z0-9]{36,}\b/],
  ["stripe-secret", /\bsk_live_[A-Za-z0-9]{20,}\b/],
  ["slack-token", /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/],
  // google-api-key (AIza…) was REJECTED: it is the Firebase/Maps WEB key, public-by-design (ships in
  // google-services.json / client bundles / deploy config) — flagging it is a false positive, not a leak.
];

// Shannon entropy (bits/char) of a string — high entropy ≈ random ≈ a real secret; low ≈ a word/placeholder.
export function entropy(s) {
  if (!s) return 0;
  const freq = {};
  for (const c of s) freq[c] = (freq[c] || 0) + 1;
  let h = 0;
  for (const c in freq) { const p = freq[c] / s.length; h -= p * Math.log2(p); }
  return h;
}
// Obvious non-secrets: placeholders, examples, templated refs. Kept OUT of the fingerprint entirely (never a value).
const PLACEHOLDER = /^(?:x{4,}|\.{3,}|)$|your[_-]?|example|sample|changeme|placeholder|dummy|redacted|<[^>]*>|\$\{|process\.env|import\.meta|getenv|os\.environ|secrets?\.|vault|todo|fixme|xxxx|0000|1234|abcd|test[_-]?(?:key|secret|token)/i;
const isPlaceholder = (v) => PLACEHOLDER.test(v);

/** Scan one file's text → [{line, kind, entropy, placeholder}]. The matched VALUE never leaves this function. */
export function extractSecrets(text) {
  const out = [];
  const lines = String(text).split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const l = lines[i];
    if (l.length > 4000) continue; // skip minified/one-line blobs (noise)
    // Skip comment lines: a key that appears in a `//`, `#`, `*`, `--` comment is overwhelmingly a documentation
    // EXAMPLE (event-payload docs, README snippets), not a committed live credential. A real leak lives in code.
    if (/^\s*(\/\/|\*|#|--|;)/.test(l)) continue;
    // A pre-signed S3 URL carries the access-key-ID as a shareable query param (X-Amz-Credential=AKIA…) — that ID is
    // meant to be public and is not a secret. Such lines (common in webhook fixtures/logs) are not credential leaks.
    const presigned = /X-Amz-(?:Credential|Signature|Security-Token)|[?&](?:AWSAccessKeyId|Signature)=/i.test(l);
    for (const [kind, re] of PATTERNS) {
      const m = re.exec(l);
      // Even a prefixed match can be a documented EXAMPLE (AWS's AKIAIOSFODNN7EXAMPLE is in countless repos) or a
      // pre-signed-URL key-ID → the placeholder flag covers both, so the server drops them.
      if (m) out.push({ line: i + 1, kind, entropy: Math.round(entropy(m[0]) * 100) / 100, placeholder: isPlaceholder(m[0]) || presigned });
    }
  }
  return out;
}

/** The secrets fingerprint for one file — locations + kinds + entropies, no values. */
export function extractSecretFingerprint(text, file) {
  return { file, hits: extractSecrets(text) };
}
