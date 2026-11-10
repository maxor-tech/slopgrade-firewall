// Dependency CVE matching, layer 1 (P3): parse an npm package-lock.json into exact resolved versions, and diff two of
// them into the versions a pull request INTRODUCES. Deterministic, no network. What leaves the runner later is only
// {ecosystem, name, version} of introduced packages — public registry coordinates, never source.
//
// Covers lockfileVersion 1 (`dependencies`, nested) and 2 / 3 (`packages`, keyed by install path). pnpm-lock.yaml,
// yarn.lock, poetry.lock and the others are later layers. PURE and total: malformed input gives [], never a throw.

// a matchable version: semver-ish, no URL, path or tag (those cannot be matched against advisories)
const VERSION = /^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.+-]*)?$/;

// Only packages from the PUBLIC npm registry are ever matched (and so ever sent to an advisory database): a package
// resolved from a private registry, a git URL or a tarball elsewhere may carry an internal name.
const PUBLIC = /^https:\/\/registry\.npmjs\.org\//;
const isPublic = (resolved) => resolved === undefined || (typeof resolved === "string" && PUBLIC.test(resolved));

const add = (out, seen, name, version, dev, resolved) => {
  if (typeof name !== "string" || !name || typeof version !== "string" || !VERSION.test(version) || !isPublic(resolved)) return;
  const k = `${name}@${version}`;
  if (seen.has(k)) return;
  seen.add(k);
  out.push({ eco: "npm", name, version, ...(dev ? { dev: true } : {}) });
};

/** package-lock.json text -> [{ eco: "npm", name, version, dev? }], each name@version once. */
export function parsePackageLock(text) {
  let lock;
  try { lock = JSON.parse(text); } catch { return []; }
  if (!lock || typeof lock !== "object" || Array.isArray(lock)) return [];
  const out = [], seen = new Set();
  if (lock.packages && typeof lock.packages === "object" && !Array.isArray(lock.packages)) {
    for (const [path, e] of Object.entries(lock.packages)) {
      if (!path || !e || typeof e !== "object" || e.link) continue;
      const at = path.lastIndexOf("node_modules/");
      if (at < 0) continue;                                    // a workspace folder, not an installed package
      const name = typeof e.name === "string" && e.name ? e.name : path.slice(at + "node_modules/".length);
      add(out, seen, name, e.version, e.dev === true, e.resolved);
    }
    return out;
  }
  const walk = (deps, depth) => {
    if (!deps || typeof deps !== "object" || depth > 64) return;
    for (const [name, e] of Object.entries(deps)) {
      if (!e || typeof e !== "object" || e.bundled) continue;
      add(out, seen, name, e.version, e.dev === true, e.resolved);
      walk(e.dependencies, depth + 1);
    }
  };
  walk(lock.dependencies, 0);
  return out;
}

// go.sum: "<module> <version> <hash>" = the module's code was downloaded (it is built); "<module> <version>/go.mod
// <hash>" alone = only its go.mod was read to resolve the graph, the code is never built — such a version is skipped.
const GO_LINE = /^(\S+)\s+(v\d+\.\d+\.\d+[0-9A-Za-z.+-]*?)\s+h1:\S+$/;

/**
 * go.sum text -> [{ eco: "Go", name, version }], each module version once. A module under the repository's OWN GitHub
 * owner (`ctx.owner`, case-insensitive) is never kept: it is most often a private module whose path would leak.
 */
export function parseGoSum(text, ctx = {}) {
  const own = typeof ctx.owner === "string" && ctx.owner ? `github.com/${ctx.owner.toLowerCase()}/` : null;
  const out = [], seen = new Set();
  for (const raw of String(text ?? "").split(/\r?\n/)) {
    const m = GO_LINE.exec(raw.trim());
    if (!m) continue;
    const [, name, version] = m;
    if (own && name.toLowerCase().startsWith(own)) continue;
    const k = `${name}@${version}`;
    if (seen.has(k)) continue;
    seen.add(k);
    out.push({ eco: "Go", name, version });
  }
  return out;
}

const RUBYGEMS = /^https?:\/\/rubygems\.org\/?$/;
const GEM_SPEC = /^ {4}([A-Za-z0-9_.-]+) \(([0-9][0-9A-Za-z.]*)(?:-[A-Za-z0-9_-]+)?\)$/;

/** Gemfile.lock text -> [{ eco: "RubyGems", name, version }] — top-level specs of a GEM section on rubygems.org only. */
export function parseGemfileLock(text) {
  const out = [], seen = new Set();
  let section = null, publicGem = false, inSpecs = false;
  for (const raw of String(text ?? "").split(/\r?\n/)) {
    const line = raw.replace(/\s+$/, "");
    if (/^[A-Z][A-Z ]*$/.test(line)) { section = line; publicGem = false; inSpecs = false; continue; }
    if (section !== "GEM") continue;
    const remote = /^ {2}remote: (\S+)$/.exec(line);
    if (remote) { publicGem = RUBYGEMS.test(remote[1]); continue; }
    if (line === "  specs:") { inSpecs = true; continue; }
    if (!inSpecs || !publicGem) continue;
    const m = GEM_SPEC.exec(line);
    if (!m) continue;
    const k = `${m[1]}@${m[2]}`;
    if (seen.has(k)) continue;
    seen.add(k);
    out.push({ eco: "RubyGems", name: m[1], version: m[2] });
  }
  return out;
}

/** The lockfile names this module reads, and their parser. */
const PARSERS = [
  [/(^|\/)package-lock\.json$/, (t) => parsePackageLock(t)],
  [/(^|\/)go\.sum$/, (t, ctx) => parseGoSum(t, ctx)],
  [/(^|\/)Gemfile\.lock$/, (t) => parseGemfileLock(t)],
];
export const LOCKFILE_PATHSPEC = [":(glob)**/package-lock.json", ":(glob)**/go.sum", ":(glob)**/Gemfile.lock"];

/** Any supported lockfile -> its entries; an unsupported name gives []. PURE. */
export function parseLockfile(path, text, ctx = {}) {
  const p = PARSERS.find(([re]) => re.test(String(path ?? "")));
  return p ? p[1](text, ctx) : [];
}

/**
 * The supported lockfiles this PR adds or changes -> [{ path, introduced }]. `git(args)` runs git in the checkout
 * (string or null on failure), `read(path)` reads the head file. A lockfile git cannot show at the base is new: every
 * version in it is introduced. `ctx.owner` = the repository owner (go.sum own-module rule). Never throws.
 */
export function prLockfileChanges(git, read, baseSha, ctx = {}) {
  let names;
  try { names = git(["-c", "core.quotepath=off", "diff", "--name-only", "--diff-filter=AM", baseSha, "--", ...LOCKFILE_PATHSPEC]); } catch { return []; }
  if (typeof names !== "string") return [];
  const out = [];
  for (const path of names.split("\n").map((s) => s.trim()).filter((p) => PARSERS.some(([re]) => re.test(p)))) {
    let head = null, base = null;
    try { head = read(path); } catch { head = null; }
    if (typeof head !== "string") continue;
    try { base = git(["show", `${baseSha}:${path}`]); } catch { base = null; }
    const H = parseLockfile(path, head, ctx);
    out.push({ path, introduced: introducedDeps(typeof base === "string" ? parseLockfile(path, base, ctx) : null, H) });
  }
  return out;
}

/**
 * Every tracked supported lockfile with ALL its pinned versions -> [{ path, deps }] — the scheduled monitor (a run that is
 * not a pull request): an advisory published after a merge is found on the next scheduled run. Never throws.
 */
export function repoLockfiles(git, read, ctx = {}) {
  let names;
  try { names = git(["ls-files", "-z", "--", ...LOCKFILE_PATHSPEC]); } catch { return []; }
  if (typeof names !== "string") return [];
  const out = [];
  for (const path of names.split(/[\0\n]/).map((s) => s.trim()).filter((p) => PARSERS.some(([re]) => re.test(p)))) {
    let text = null;
    try { text = read(path); } catch { text = null; }
    if (typeof text !== "string") continue;
    out.push({ path, deps: parseLockfile(path, text, ctx) });
  }
  return out;
}

/** The {eco, name, version} entries of `head` that `base` did not have. A null base (new lockfile) = all of head. */
export function introducedDeps(base, head) {
  const had = new Set((Array.isArray(base) ? base : []).map((d) => `${d.eco}\u0000${d.name}\u0000${d.version}`));
  return (Array.isArray(head) ? head : []).filter((d) => !had.has(`${d.eco}\u0000${d.name}\u0000${d.version}`));
}
