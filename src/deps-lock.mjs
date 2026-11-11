// Dependency CVE matching, layer 1 (P3): parse an npm package-lock.json into exact resolved versions, and diff two of
// them into the versions a pull request INTRODUCES. Deterministic, no network. What leaves the runner later is only
// {ecosystem, name, version} of introduced packages — public registry coordinates, never source.
//
// npm package-lock.json covers lockfileVersion 1 (`dependencies`, nested) and 2 / 3 (`packages`, keyed by install path).
// Later layers: go.sum, Gemfile.lock, then pnpm-lock.yaml, yarn.lock (v1 and Berry), poetry.lock, uv.lock,
// Pipfile.lock, Cargo.lock and composer.lock. Every parser is PURE and total: malformed input gives [], never a throw.

// a matchable version: semver-ish, no URL, path or tag (those cannot be matched against advisories)
const VERSION = /^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.+-]*)?$/;

// Only packages from the PUBLIC npm registry are ever matched (and so ever sent to an advisory database): a package
// resolved from a private registry, a git URL or a tarball elsewhere may carry an internal name. The well-known public
// mirrors of that registry (Yarn, npmmirror / taobao, cnpm, Tencent) serve the same packages under the same names; a
// company registry (Nexus, Artifactory, an `-inc` host) is never on this list.
const NPM_PUBLIC = /^https?:\/\/(?:registry\.npmjs\.org|registry\.yarnpkg\.com|registry\.npmmirror\.com|registry\.npm\.taobao\.org|r\.cnpmjs\.org|mirrors\.(?:cloud\.)?tencent\.com\/npm)\//;
const isPublic = (resolved) => resolved === undefined || (typeof resolved === "string" && NPM_PUBLIC.test(resolved));

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

// ── pnpm, yarn, Python, Rust, PHP ─────────────────────────────────────────────────────────────────────────────────
// pnpm-lock.yaml and a Yarn Berry yarn.lock do not record the registry a package came from. A package under the
// repository's OWN npm scope (`@<owner>/`, case-insensitive) is most often private: it is never kept (same rule as go.sum).

const collector = (eco, valid) => {
  const out = [], seen = new Set();
  const push = (name, version, dev) => {
    if (typeof name !== "string" || !name || typeof version !== "string" || !valid.test(version)) return;
    const k = `${name}@${version}`;
    if (seen.has(k)) return;
    seen.add(k);
    out.push({ eco, name, version, ...(dev ? { dev: true } : {}) });
  };
  return { out, push };
};
const ownScope = (ctx) => (typeof ctx.owner === "string" && ctx.owner ? `@${ctx.owner.toLowerCase()}/` : null);
const isOwn = (own, name) => own !== null && name.toLowerCase().startsWith(own);

// pnpm package keys: v9 `name@1.2.3`, v6 `/name@1.2.3`, v5 `/name/1.2.3` ; a peer suffix `(peer@x)` (v6, v9) or
// `_peer` (v5) is not part of the version.
const PNPM_AT = /^(@[^/]+\/[^/@]+|[^/@]+)@([^/]+)$/;
const PNPM_SLASH = /^(@[^/]+\/[^/]+|[^/@]+)\/([^/]+)$/;
// The key indent is read from the file (pnpm writes 2 spaces; a formatter may have rewritten it with 4).
const PNPM_KEY = /^(?:'([^']+)'|"([^"]+)"|([^\s'"#][^\s]*?)):(?:\s+\{\})?\s*$/;
// a resolution that is not a registry integrity: a tarball URL, a git commit, a local directory
const PNPM_NOT_REGISTRY = /\b(?:tarball|type|directory|repo|commit|path):/;

/** pnpm-lock.yaml (v5, v6, v9) text -> [{ eco: "npm", name, version, dev? }] — the `packages:` entries from a registry. */
export function parsePnpmLock(text, ctx = {}) {
  const own = ownScope(ctx);
  const { out, push } = collector("npm", VERSION);
  // keyIndent: indent of the package keys in this `packages:` section ; cur.field: indent of that package's fields ;
  // cur.inRes: inside a block-style `resolution:` mapping (a reformatted file), whose keys are read like the flow style
  let inPackages = false, cur = null, keyIndent = null;
  const flush = () => {
    if (!cur || cur.skip) { cur = null; return; }
    let key = cur.key.replace(/^\//, "");
    const paren = key.indexOf("(");
    if (paren > 0) key = key.slice(0, paren);
    let m = PNPM_AT.exec(key), name, version;
    if (m) [, name, version] = m;
    else if ((m = PNPM_SLASH.exec(key))) { name = m[1]; version = m[2].split("_")[0]; }
    if (name && !isOwn(own, name)) push(name, version, cur.dev);
    cur = null;
  };
  for (const raw of String(text ?? "").split(/\r?\n/)) {
    const line = raw.replace(/\s+$/, "");
    if (!line || /^\s*#/.test(line)) continue;
    if (/^\S/.test(line)) { flush(); inPackages = line === "packages:"; keyIndent = null; continue; }
    if (!inPackages) continue;
    const indent = line.length - line.trimStart().length, body = line.trimStart();
    if (keyIndent === null) keyIndent = indent;
    if (indent <= keyIndent) {
      flush();
      const k = indent === keyIndent ? PNPM_KEY.exec(body) : null;
      if (k) cur = { key: k[1] ?? k[2] ?? k[3], skip: false, dev: false, field: null, inRes: false };
      continue;
    }
    if (!cur) continue;
    if (cur.field === null) cur.field = indent;
    if (indent === cur.field) {
      cur.inRes = body === "resolution:";
      if (/^resolution:/.test(body) && PNPM_NOT_REGISTRY.test(body)) cur.skip = true;
      else if (body === "dev: true") cur.dev = true;
    } else if (cur.inRes && PNPM_NOT_REGISTRY.test(body)) cur.skip = true;
  }
  flush();
  return out;
}

const unquote = (s) => s.trim().replace(/^"(.*)"$/, "$1");

/**
 * yarn.lock text -> [{ eco: "npm", name, version }]. Yarn v1: the `resolved` URL must be the public registry (a block
 * with no `resolved` is kept, like package-lock). Yarn Berry (`__metadata:`): only `name@npm:1.2.3` resolutions — a
 * workspace, patch, git, file or link resolution is never kept — and never the repository's own npm scope.
 */
export function parseYarnLock(text, ctx = {}) {
  const lines = String(text ?? "").split(/\r?\n/);
  const { out, push } = collector("npm", VERSION);
  if (lines.some((l) => l === "__metadata:")) {
    const own = ownScope(ctx);
    for (const line of lines) {
      const m = /^ +resolution: (.+)$/.exec(line);
      if (!m) continue;
      const res = unquote(m[1]);
      const at = res.indexOf("@npm:", 1);
      if (at < 0) continue;
      const name = res.slice(0, at);
      if (!isOwn(own, name)) push(name, res.slice(at + 5));
    }
    return out;
  }
  let cur = null;
  const flush = () => {
    if (cur && cur.name && isPublic(cur.resolved)) push(cur.name, cur.version);
    cur = null;
  };
  for (const line of lines) {
    if (/^[^\s#].*:$/.test(line)) {
      flush();
      // the name ends at the first "@" after a leading scope "@": "@scope/name@^1.0.0", "name@git+ssh://git@host/x" ;
      // an old yarn v1 writes a bare `name:` (no range) for a `*` dependency
      const spec = unquote(line.slice(0, -1).split(/,\s*/)[0]);
      const at = spec.indexOf("@", 1);
      let name = at > 0 ? spec.slice(0, at) : spec;
      const range = at > 0 ? spec.slice(at + 1) : "";
      if (range.startsWith("npm:")) {               // an alias: "my-alias@npm:real-name@^1.0.0"
        const real = range.slice(4), ra = real.indexOf("@", 1);
        name = ra > 0 ? real.slice(0, ra) : real;
      }
      cur = { name };
      continue;
    }
    if (!cur) continue;
    const v = /^ {2}version "?([^"\s]+)"?$/.exec(line);
    if (v) { cur.version = v[1]; continue; }
    const r = /^ {2}resolved "?([^"\s]+)"?$/.exec(line);
    if (r) cur.resolved = r[1];
  }
  flush();
  return out;
}

// A minimal reader for the TOML lockfiles (poetry.lock, uv.lock, Cargo.lock): each `[[package]]` table's top-level
// `key = value` lines, plus a `[package.source]` sub-table. Any other header closes the keys of the current package.
function tomlPackages(text) {
  const out = [];
  let cur = null, target = null;
  for (const raw of String(text ?? "").split(/\r?\n/)) {
    const line = raw.replace(/\s+$/, "");
    if (line === "[[package]]") { cur = {}; out.push(cur); target = cur; continue; }
    if (/^\[/.test(line)) {
      if (line === "[package.source]" && cur) target = cur.sourceTable = {};
      else { target = null; if (!/^\[\[?package\./.test(line)) cur = null; }
      continue;
    }
    const kv = /^([A-Za-z0-9_-]+)\s*=\s*(.+)$/.exec(line);
    if (!kv || !target) continue;
    const s = /^"((?:[^"\\]|\\.)*)"$/.exec(kv[2]);
    target[kv[1]] = s ? s[1] : kv[2];
  }
  return out;
}

// PEP 440 versions (an epoch, pre / post / dev releases, a local label) ; names are compared in PEP 503 form.
const PY_VERSION = /^(?:\d+!)?\d+(?:\.\d+)*(?:[-_.]?(?:a|b|c|rc|alpha|beta|pre|preview|post|rev|r|dev)[-_.]?\d*)*(?:\+[A-Za-z0-9.]+)?$/i;
const pyName = (n) => String(n).toLowerCase().replace(/[-_.]+/g, "-");
const PYPI = /^https:\/\/pypi\.org\/simple\/?$/;

/** poetry.lock text -> [{ eco: "PyPI", name, version }] — a package with a `[package.source]` (git, path, a private index) is skipped. */
export function parsePoetryLock(text) {
  const { out, push } = collector("PyPI", PY_VERSION);
  for (const p of tomlPackages(text)) {
    if (p.sourceTable && !PYPI.test(p.sourceTable.url ?? "")) continue;
    push(pyName(p.name ?? ""), p.version);
  }
  return out;
}

/** uv.lock text -> [{ eco: "PyPI", name, version }] — only `source = { registry = "https://pypi.org/simple" }`. */
export function parseUvLock(text) {
  const { out, push } = collector("PyPI", PY_VERSION);
  for (const p of tomlPackages(text)) {
    const reg = /^\{\s*registry\s*=\s*"([^"]+)"\s*\}$/.exec(p.source ?? "");
    if (reg && PYPI.test(reg[1])) push(pyName(p.name ?? ""), p.version);
  }
  return out;
}

/**
 * Pipfile.lock text -> [{ eco: "PyPI", name, version, dev? }] — `==` pins whose index (the named `index`, else the
 * first source) is pypi.org. A git, path, file or editable entry is skipped.
 */
export function parsePipfileLock(text) {
  let lock;
  try { lock = JSON.parse(text); } catch { return []; }
  if (!lock || typeof lock !== "object" || Array.isArray(lock)) return [];
  const sources = Array.isArray(lock._meta?.sources) ? lock._meta.sources : [];
  const publicIndex = new Map(sources.map((s) => [s?.name, PYPI.test(String(s?.url ?? ""))]));
  const defaultPublic = sources.length ? publicIndex.get(sources[0]?.name) === true : true;
  const { out, push } = collector("PyPI", PY_VERSION);
  for (const [section, dev] of [["default", false], ["develop", true]]) {
    const deps = lock[section];
    if (!deps || typeof deps !== "object" || Array.isArray(deps)) continue;
    for (const [name, e] of Object.entries(deps)) {
      if (!e || typeof e !== "object" || e.git || e.path || e.file || e.editable) continue;
      const pin = /^==([^=].*)$/.exec(typeof e.version === "string" ? e.version : "");
      const isPublic = typeof e.index === "string" ? publicIndex.get(e.index) === true : defaultPublic;
      if (pin && isPublic) push(pyName(name), pin[1], dev);
    }
  }
  return out;
}

const CRATES_IO = new Set(["registry+https://github.com/rust-lang/crates.io-index", "sparse+https://index.crates.io/"]);

/** Cargo.lock text -> [{ eco: "crates.io", name, version }] — crates.io packages only (no workspace, git or other registry). */
export function parseCargoLock(text) {
  const { out, push } = collector("crates.io", VERSION);
  for (const p of tomlPackages(text)) if (CRATES_IO.has(p.source)) push(p.name, p.version);
  return out;
}

const PACKAGIST_VERSION = /^\d+(?:\.\d+){0,3}(?:-[0-9A-Za-z.]+)?$/;

/** composer.lock text -> [{ eco: "Packagist", name, version, dev? }] — packages published on packagist.org only. */
export function parseComposerLock(text) {
  let lock;
  try { lock = JSON.parse(text); } catch { return []; }
  if (!lock || typeof lock !== "object" || Array.isArray(lock)) return [];
  const { out, push } = collector("Packagist", PACKAGIST_VERSION);
  for (const [section, dev] of [["packages", false], ["packages-dev", true]]) {
    if (!Array.isArray(lock[section])) continue;
    for (const e of lock[section]) {
      if (!e || typeof e !== "object" || e["notification-url"] !== "https://packagist.org/downloads/") continue;
      if (typeof e.name === "string" && typeof e.version === "string") push(e.name.toLowerCase(), e.version.replace(/^v/, ""), dev);
    }
  }
  return out;
}

/** The lockfile names this module reads, and their parser. */
const PARSERS = [
  [/(^|\/)package-lock\.json$/, (t) => parsePackageLock(t)],
  [/(^|\/)go\.sum$/, (t, ctx) => parseGoSum(t, ctx)],
  [/(^|\/)Gemfile\.lock$/, (t) => parseGemfileLock(t)],
  [/(^|\/)pnpm-lock\.yaml$/, (t, ctx) => parsePnpmLock(t, ctx)],
  [/(^|\/)yarn\.lock$/, (t, ctx) => parseYarnLock(t, ctx)],
  [/(^|\/)poetry\.lock$/, (t) => parsePoetryLock(t)],
  [/(^|\/)uv\.lock$/, (t) => parseUvLock(t)],
  [/(^|\/)Pipfile\.lock$/, (t) => parsePipfileLock(t)],
  [/(^|\/)Cargo\.lock$/, (t) => parseCargoLock(t)],
  [/(^|\/)composer\.lock$/, (t) => parseComposerLock(t)],
];
export const LOCKFILE_PATHSPEC = ["package-lock.json", "go.sum", "Gemfile.lock", "pnpm-lock.yaml", "yarn.lock", "poetry.lock",
  "uv.lock", "Pipfile.lock", "Cargo.lock", "composer.lock"].map((n) => `:(glob)**/${n}`);

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
