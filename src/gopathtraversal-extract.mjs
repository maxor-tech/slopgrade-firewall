// Go path traversal / LFI (CWE-22) — a request value is used DIRECTLY as a filesystem path by the Go stdlib —
// SERVER fingerprint. Emit {file, line, kind} — never source. Go-specific: os.Open / os.OpenFile / os.ReadFile /
// ioutil.ReadFile open a file by name; when that name is derived from a net/http request accessor (r.FormValue /
// r.PostFormValue / r.URL / r.Header), an attacker supplies `../../etc/passwd` → arbitrary file read (filepath.Join
// does NOT stop `..` — only filepath.Base strips the directory components). Scoped to the file-read sink with a request
// accessor INLINE → ~0 FP; a constant/config path never fires. EXTENDS path traversal to Go — DISTINCT from
// pathTraversal #23 (Python/Node/PHP/Java/Ruby, no Go), goSsrf #77 (http sink) and goSqli #79 (SQL string).

const PATTERNS = [
  // os.Open / os.OpenFile / os.ReadFile / ioutil.ReadFile whose argument region carries a net/http request accessor —
  // the request value IS (or builds) the path. `[^)]*` keeps the match on the same call.
  ["go-file-read", /\b(?:os\s*\.\s*(?:Open|OpenFile|ReadFile)|ioutil\s*\.\s*ReadFile)\s*\([^)]*\b(?:r|req|request)\s*\.\s*(?:FormValue|PostFormValue|URL|Header)\b/],
];
const isComment = (l) => /^\s*(\/\/|\*|#|--|<!--|;)/.test(l);
// The canonical sanitizer strips the directory components, so a request value wrapped in it can't traverse — exclude
// it on the same line (the safe boundary is the arg), exactly as pathTraversal #23 excludes safe_join / path.resolve.
const isSanitized = (l) => /\b(?:filepath|path)\s*\.\s*Base\s*\(/.test(l);

/** Scan one file → [{line, kind}]. */
export function extractGoPathTraversal(text) {
  const out = [];
  const lines = String(text).split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const l = lines[i];
    if (l.length > 4000) continue;
    if (isComment(l)) continue;
    if (isSanitized(l)) continue;
    for (const [kind, re] of PATTERNS) {
      if (re.test(l)) { out.push({ line: i + 1, kind }); break; }
    }
  }
  return out;
}

/** The Go-path-traversal fingerprint for one file. */
export function extractGoPathTraversalFingerprint(text, file) {
  return { file, hits: extractGoPathTraversal(text) };
}
