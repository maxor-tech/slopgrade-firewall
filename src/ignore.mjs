// `.slopgradeignore` — paths the client never scans (docs that SHOW vulnerable code, generated files, fixtures the
// default exclusions miss). One pattern per line, gitignore-style subset:
//   # comment · `dir/` (a directory, anywhere) · `docs/examples/` (anchored when it contains a `/`)
//   `*` (within a segment) · `**` (across segments) · `?` (one char)
// SELF-EXEMPTION GUARD: on a pull request the file is read from the BASE branch, never from the PR head — a PR that
// adds `src/` to the ignore list cannot hide its own findings; the new entry applies once it is merged. A pattern that
// would exclude everything (`*`, `**`, `/`…) is refused, on every run.
export const IGNORE_FILE = ".slopgradeignore";
export const MAX_IGNORE_PATTERNS = 200;
const MAX_PATTERN_LEN = 200;
// Linear check (no nested quantifier): once the slashes are gone, only stars or a lone dot left ⇒ it matches everything.
const matchesAll = (p) => { const bare = p.replace(/\//g, ""); return bare === "" || bare === "." || /^\*+$/.test(bare); };

/** Glob → RegExp over a repo-relative POSIX path (a match on the path OR any parent directory of it). */
function globToRegExp(glob) {
  const anchored = glob.startsWith("/") || glob.replace(/\/$/, "").includes("/");
  const body = glob.replace(/^\//, "").replace(/\/$/, "");
  let re = "";
  for (let i = 0; i < body.length; i++) {
    const c = body[i];
    if (c === "*" && body[i + 1] === "*") {
      if (body[i + 2] === "/") { re += "(?:.*/)?"; i += 2; } // `**/` = zero or more directories
      else { re += ".*"; i++; }
    }
    else if (c === "*") re += "[^/]*";
    else if (c === "?") re += "[^/]";
    else re += c.replace(/[.+^${}()|[\]\\]/g, "\\$&");
  }
  return new RegExp(`${anchored ? "^" : "(^|/)"}${re}(/|$)`);
}

/** Parse the file. Returns { patterns: RegExp[], kept: string[], refused: string[] }. Pure. */
export function parseIgnore(text) {
  const kept = [], refused = [], patterns = [];
  for (const raw of String(text ?? "").split(/\r?\n/)) {
    const p = raw.trim();
    if (!p || p.startsWith("#")) continue;
    if (p.startsWith("!") || p.length > MAX_PATTERN_LEN || matchesAll(p) || kept.length >= MAX_IGNORE_PATTERNS) { refused.push(p); continue; }
    kept.push(p);
    patterns.push(globToRegExp(p));
  }
  return { patterns, kept, refused };
}

/** A predicate over repo-relative paths. */
export const ignoreMatcher = (patterns) => (relPath) => patterns.some((re) => re.test(String(relPath).replace(/\\/g, "/")));

/**
 * Read the ignore file for this run. On a pull request (GITHUB_BASE_REF set) it comes from the BASE branch via git —
 * the PR head's copy is never trusted. Otherwise from the checkout. Missing / unreadable ⇒ null (scan everything).
 * `git(args)` returns stdout or throws ; `readFile(rel)` returns text or throws.
 */
export function readIgnoreText(env, git, readFile) {
  const base = env.GITHUB_BASE_REF;
  if (base) {
    if (!/^[A-Za-z0-9._/-]+$/.test(base) || base.startsWith("-") || base.includes("..")) return { text: null, source: "base" };
    try { return { text: git(["show", `origin/${base}:${IGNORE_FILE}`]), source: "base" }; } catch { return { text: null, source: "base" }; }
  }
  try { return { text: readFile(IGNORE_FILE), source: "checkout" }; } catch { return { text: null, source: "checkout" }; }
}
