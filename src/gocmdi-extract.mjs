// Go command injection (CWE-78) — an HTTP request value is executed as an OS command by the Go `os/exec` package —
// SERVER fingerprint. Emit {file, line, kind} — never source. Go-specific: exec.Command / exec.CommandContext spawn a
// process; when an argument is derived from a net/http request accessor (r.FormValue / r.PostFormValue / r.URL(.Query)
// / r.Header(.Get)), an attacker injects the command or its arguments → RCE (classically exec.Command("sh","-c", userInput)).
// There is no safe use for spawning a process from raw request input (the XXE model — a constant exec.Command("ls","-la")
// has no request accessor and never fires), so this is ungated. Scoped to a net/http request accessor INLINE in the
// exec.Command / exec.CommandContext call → ~0 FP. DISTINCT from cmdi #22 (Python/Node/PHP/Ruby/Java sinks — no Go).

const PATTERNS = [
  // exec.Command(...) / exec.CommandContext(...) whose argument region carries a net/http request accessor. `[^)]*`
  // keeps the match on the same call. The accessors are unambiguously *http.Request fields (FormValue/PostFormValue/
  // URL/Header) — a DB `db.Query` or a gin `c.Query` (ambiguous) is deliberately NOT matched.
  ["go-exec-request", /\bexec\s*\.\s*Command(?:Context)?\s*\([^)]*\b(?:r|req|request)\s*\.\s*(?:FormValue|PostFormValue|Header|URL)\b/],
];
const isComment = (l) => /^\s*(\/\/|\*|#|--|<!--|;)/.test(l);

/** Scan one file → [{line, kind}]. */
export function extractGoCmdi(text) {
  const out = [];
  const lines = String(text).split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const l = lines[i];
    if (l.length > 4000) continue;
    if (isComment(l)) continue;
    for (const [kind, re] of PATTERNS) {
      if (re.test(l)) { out.push({ line: i + 1, kind }); break; }
    }
  }
  return out;
}

/** The Go-command-injection fingerprint for one file. */
export function extractGoCmdiFingerprint(text, file) {
  return { file, hits: extractGoCmdi(text) };
}
