// Language scope for the DIRECT (line-regex) rules of the injection extractors (sqli · cmdi · xss · path traversal).
// Those rules are named after the language they were written for (`php-exec`, `ruby-exec`, `py-open`, `java-sql` …) but
// they match text, so they also fired on files of another language — the PR-replay benchmark (run2, re-checked on the
// current extractors 2026-10-31) showed `ruby-exec` on a Java `eval(params, map)` template helper and on a Python
// `self.input.eval(params)` method call, and `py-open` on a Java `open(request.uri(), …)`. A rule now applies only to
// the files of its language. An unknown file (no name passed) keeps every rule, as before.
const FAMILY = [
  [/^php-/, /\.(?:php\d?|phtml|inc|module)$/i],
  [/^(?:ruby|rails)-/, /\.(?:rb|erb|rake|ru|haml|slim)$/i],
  [/^py-/, /\.(?:py|pyw)$/i],
  [/^(?:node|react)-/, /\.(?:[cm]?[jt]sx?|vue|svelte|astro)$/i],
  [/^java-/, /\.(?:java|kt|kts|groovy|scala|jsp)$/i],
];

// A PACKED source file — a vendored single-file tool or a build output whose statements are joined into very long
// lines (Adminer's adminer-5.0.4-*.php : average line 181-184 characters, 6.6-6.8 % of lines over 500). Measured on
// the benchmark's labelled files (2026-10-31) : every file holding a true finding averages <= 70 characters with
// <= 1.8 % of lines over 500. The injection extractors already skip a single line over 4,000 characters ; this is the
// same rule for a whole file whose author is upstream, not the pull request.
const PACKED_MIN_LINES = 50, PACKED_AVG = 150, PACKED_LONG = 500, PACKED_LONG_SHARE = 0.05;
export function isPackedSource(text) {
  const lines = String(text).split(/\r?\n/);
  if (lines.length < PACKED_MIN_LINES) return false;
  const avg = String(text).length / lines.length;
  const long = lines.filter((l) => l.length > PACKED_LONG).length / lines.length;
  return avg > PACKED_AVG && long >= PACKED_LONG_SHARE;
}

/** May a DIRECT rule named `kind` fire in `file` ? Rules without a language prefix apply everywhere. */
export function kindAppliesToFile(kind, file) {
  if (!file) return true;
  for (const [prefix, ext] of FAMILY) if (prefix.test(kind)) return ext.test(String(file));
  return true;
}
