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

/**
 * The package-lock.json files this PR adds or changes -> [{ path, introduced }]. `git(args)` runs git in the checkout
 * (string or null on failure), `read(path)` reads the head file. A lockfile git cannot show at the base is new: every
 * version in it is introduced. Never throws.
 */
export function prLockfileChanges(git, read, baseSha) {
  let names;
  try { names = git(["-c", "core.quotepath=off", "diff", "--name-only", "--diff-filter=AM", baseSha, "--", ":(glob)**/package-lock.json"]); } catch { return []; }
  if (typeof names !== "string") return [];
  const out = [];
  for (const path of names.split("\n").map((s) => s.trim()).filter((p) => /(^|\/)package-lock\.json$/.test(p))) {
    let head = null, base = null;
    try { head = read(path); } catch { head = null; }
    if (typeof head !== "string") continue;
    try { base = git(["show", `${baseSha}:${path}`]); } catch { base = null; }
    const H = parsePackageLock(head);
    out.push({ path, introduced: introducedDeps(typeof base === "string" ? parsePackageLock(base) : null, H) });
  }
  return out;
}

/** The {eco, name, version} entries of `head` that `base` did not have. A null base (new lockfile) = all of head. */
export function introducedDeps(base, head) {
  const had = new Set((Array.isArray(base) ? base : []).map((d) => `${d.eco}\u0000${d.name}\u0000${d.version}`));
  return (Array.isArray(head) ? head : []).filter((d) => !had.has(`${d.eco}\u0000${d.name}\u0000${d.version}`));
}
