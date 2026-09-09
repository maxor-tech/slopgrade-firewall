// .NET command injection (CWE-78) — an HTTP request value is executed as an OS command by System.Diagnostics.Process —
// SERVER fingerprint. Emit {file, line, kind} — never source. .NET-specific: Process.Start / new ProcessStartInfo spawn
// a process; when an argument is derived from an ASP.NET request accessor (Request[...] / Request.QueryString /
// Request.Form / Request.Params / Request.Query / Request.Headers), an attacker injects the command → RCE. There is no
// safe use for spawning a process from raw request input (the XXE model — a constant Process.Start("notepad.exe") has no
// request accessor and never fires), so this is ungated. Scoped to an ASP.NET request accessor INLINE in the Process.Start
// / new ProcessStartInfo call → ~0 FP. DISTINCT from cmdi #22 (Python/Node/PHP/Ruby/Java sinks — no .NET) and goCmdi #75.

const PATTERNS = [
  // Process.Start(...) / new ProcessStartInfo(...) whose argument region carries an ASP.NET request accessor: either a
  // property (Request.QueryString/Form/Params/Query/Headers) or an indexer (Request[...]). `[^)]*` keeps it on the call.
  ["dotnet-process-request", /(?:\bProcess\s*\.\s*Start|new\s+ProcessStartInfo)\s*\([^)]*\bRequest\s*(?:\.\s*(?:QueryString|Form|Params|Query|Headers)\b|\[)/],
];
const isComment = (l) => /^\s*(\/\/|\*|#|--|<!--|;)/.test(l);

/** Scan one file → [{line, kind}]. */
export function extractDotnetCmdi(text) {
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

/** The .NET-command-injection fingerprint for one file. */
export function extractDotnetCmdiFingerprint(text, file) {
  return { file, hits: extractDotnetCmdi(text) };
}
