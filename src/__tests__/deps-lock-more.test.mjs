// Lockfile parsing, layer 3: pnpm, yarn (v1 and Berry), poetry, uv, Pipfile, Cargo, composer. Fixtures are trimmed
// copies of real lockfiles (vite, react, berry, poetry, pydantic, pipenv, ripgrep, composer) plus the private cases.
import { test } from "node:test";
import assert from "node:assert/strict";
import { parsePnpmLock, parseYarnLock, parsePoetryLock, parseUvLock, parsePipfileLock, parseCargoLock, parseComposerLock,
  parseLockfile, prLockfileChanges, LOCKFILE_PATHSPEC } from "../deps-lock.mjs";

const ids = (list) => list.map((d) => `${d.eco}:${d.name}@${d.version}${d.dev ? ":dev" : ""}`).sort();

test("pnpm v9: quoted and bare keys, peer suffix dropped, snapshots ignored, tarball / git / directory skipped, own scope never kept", () => {
  const lock = [
    "lockfileVersion: '9.0'", "", "importers:", "", "  .:", "    dependencies:", "      lodash:", "        specifier: ^4.17.0", "        version: 4.17.15", "",
    "packages:", "",
    "  '@babel/core@7.29.13':", "    resolution: {integrity: sha512-j1nv==}", "    engines: {node: '>=6.9.0'}", "",
    "  autoprefixer@10.6.2(postcss@8.5.32):", "    resolution: {integrity: sha512-a==}", "",
    "  lodash@4.17.15:", "    resolution: {integrity: sha512-b==}", "",
    "  '@acme/internal@1.2.3':", "    resolution: {integrity: sha512-c==}", "",
    "  tar-dep@https://codeload.github.com/x/y/tar.gz/abc:", "    resolution: {tarball: https://codeload.github.com/x/y/tar.gz/abc}", "    version: 1.0.0", "",
    "  gitdep@1.0.0:", "    resolution: {commit: abc, repo: https://github.com/x/gitdep, type: git}", "",
    "snapshots:", "", "  ghost@9.9.9: {}", "",
  ].join("\n");
  assert.deepEqual(ids(parsePnpmLock(lock, { owner: "ACME" })), ["npm:@babel/core@7.29.13", "npm:autoprefixer@10.6.2", "npm:lodash@4.17.15"]);
  assert.equal(parsePnpmLock(lock, {}).length, 4, "without an owner the @acme package is kept");
});

test("pnpm v6 (/name@v(peer)) and v5.4 (/name/v_peer, /@scope/name/v) keys, `dev: true` carried", () => {
  const v6 = ["lockfileVersion: '6.0'", "packages:", "  /react-dom@18.2.0(react@18.2.0):", "    resolution: {integrity: sha512-x==}", "    dev: true", "",
    "  /@types/node@20.1.0:", "    resolution: {integrity: sha512-y==}", "    dev: false", ""].join("\n");
  assert.deepEqual(ids(parsePnpmLock(v6)), ["npm:@types/node@20.1.0", "npm:react-dom@18.2.0:dev"]);
  const v5 = ["lockfileVersion: 5.4", "packages:", "  /@babel/core/7.18.6:", "    resolution: {integrity: sha512-x==}", "",
    "  /babel-loader/8.2.5_@babel+core@7.18.6:", "    resolution: {integrity: sha512-y==}", "",
    "  /file-dep/0.0.0:", "    resolution: {directory: packages/file-dep, type: directory}", ""].join("\n");
  assert.deepEqual(ids(parsePnpmLock(v5)), ["npm:@babel/core@7.18.6", "npm:babel-loader@8.2.5"]);
});

test("pnpm reformatted with 4 spaces (prettier) reads the same packages; a block-style tarball resolution is still skipped", () => {
  const lock = [
    "lockfileVersion: '9.0'", "", "settings:", "    autoInstallPeers: true", "", "packages:",
    "    '@babel/code-frame@7.29.7':", "        resolution: {integrity: sha512-a==}", "        engines: {node: '>=6.9.0'}", "",
    "    lodash@4.17.15:", "        resolution:", "            integrity: sha512-b==", "        dev: true", "",
    "    tar-dep@1.0.0:", "        resolution:", "            tarball: https://codeload.github.com/x/y/tar.gz/abc", "",
    "snapshots:", "    ghost@9.9.9: {}",
  ].join("\n");
  assert.deepEqual(ids(parsePnpmLock(lock)), ["npm:@babel/code-frame@7.29.7", "npm:lodash@4.17.15:dev"]);
  assert.deepEqual(ids(parsePnpmLock(lock.replace(/\n/g, "\r\n"))), ["npm:@babel/code-frame@7.29.7", "npm:lodash@4.17.15:dev"], "CRLF too");
});

test("yarn v1: a bare `name:` header (old yarn, `*` range) is a package ; CRLF line endings read the same", () => {
  const lock = ["# yarn lockfile v1", "", "redux-thunk:", "  version \"2.2.0\"", "  resolved \"https://registry.yarnpkg.com/redux-thunk/-/redux-thunk-2.2.0.tgz#e6\"", "",
    "tslint-config-standard@^4.0.0:", "  version \"4.0.0\"", ""].join("\r\n");
  assert.deepEqual(ids(parseYarnLock(lock)), ["npm:redux-thunk@2.2.0", "npm:tslint-config-standard@4.0.0"]);
});

test("yarn v1: first spec names the block, npm alias resolved to the real name, a private `resolved` URL is never kept", () => {
  const lock = [
    "# yarn lockfile v1", "",
    "\"@ampproject/remapping@^2.1.0\", \"@ampproject/remapping@^2.2.0\":", "  version \"2.3.0\"",
    "  resolved \"https://registry.yarnpkg.com/@ampproject/remapping/-/remapping-2.3.0.tgz#ed44\"", "  dependencies:", "    \"@jridgewell/gen-mapping\" \"^0.3.5\"", "",
    "lodash@^4.17.15:", "  version \"4.17.15\"", "  resolved \"https://registry.npmjs.org/lodash/-/lodash-4.17.15.tgz\"", "",
    "my-alias@npm:minimist@^1.2.0:", "  version \"1.2.0\"", "  resolved \"https://registry.yarnpkg.com/minimist/-/minimist-1.2.0.tgz\"", "",
    "\"@acme/secret@^1.0.0\":", "  version \"1.0.0\"", "  resolved \"https://npm.acme.corp/@acme/secret/-/secret-1.0.0.tgz\"", "",
    "gitdep@git+https://github.com/x/gitdep.git:", "  version \"0.0.1\"", "  resolved \"git+https://github.com/x/gitdep.git#abc\"", "",
  ].join("\n");
  assert.deepEqual(ids(parseYarnLock(lock)), ["npm:@ampproject/remapping@2.3.0", "npm:lodash@4.17.15", "npm:minimist@1.2.0"]);
});

test("yarn Berry: only `@npm:` resolutions (workspace / patch / git skipped), the real name of an alias, own scope never kept", () => {
  const lock = [
    "__metadata:", "  version: 10", "  cacheKey: 10", "",
    "\"@actions/core@npm:^1.2.6\":", "  version: 1.2.6", "  resolution: \"@actions/core@npm:1.2.6\"", "  languageName: node", "",
    "\"my-alias@npm:minimist@^1.2.0\":", "  version: 1.2.0", "  resolution: \"minimist@npm:1.2.0\"", "",
    "\"@yarnpkg/cli@workspace:packages/yarnpkg-cli\":", "  version: 0.0.0-use.local", "  resolution: \"@yarnpkg/cli@workspace:packages/yarnpkg-cli\"", "",
    "\"resolve@patch:resolve@npm%3A1.22.8#~builtin<compat/resolve>\":", "  version: 1.22.8", "  resolution: \"resolve@patch:resolve@npm%3A1.22.8#~builtin<compat/resolve>::version=1.22.8\"", "",
    "\"@acme/ui@npm:^2.0.0\":", "  version: 2.0.0", "  resolution: \"@acme/ui@npm:2.0.0\"", "",
  ].join("\n");
  assert.deepEqual(ids(parseYarnLock(lock, { owner: "acme" })), ["npm:@actions/core@1.2.6", "npm:minimist@1.2.0"]);
});

test("poetry.lock: PyPI packages, PEP 503 names, a git / path / private-index package ([package.source]) skipped", () => {
  const lock = [
    "[[package]]", "name = \"Typing_Extensions\"", "version = \"4.12.2\"", "files = [", "    {file = \"x.whl\", hash = \"sha256:a\"},", "]", "",
    "[package.dependencies]", "idna = \">=2.8\"", "version = \"9.9.9\"", "",
    "[[package]]", "name = \"internal-lib\"", "version = \"0.3.0\"", "", "[package.source]", "type = \"legacy\"", "url = \"https://pypi.acme.corp/simple\"", "reference = \"acme\"", "",
    "[[package]]", "name = \"from-git\"", "version = \"1.0.0\"", "", "[package.source]", "type = \"git\"", "url = \"https://github.com/x/y.git\"", "",
    "[[package]]", "name = \"django\"", "version = \"4.2.0rc1\"", "",
    "[metadata]", "lock-version = \"2.1\"", "name = \"not-a-package\"", "version = \"1.0.0\"",
  ].join("\n");
  assert.deepEqual(ids(parsePoetryLock(lock)), ["PyPI:django@4.2.0rc1", "PyPI:typing-extensions@4.12.2"]);
});

test("uv.lock: only `source = { registry = \"https://pypi.org/simple\" }` — editable, git and other indexes skipped", () => {
  const lock = [
    "version = 1", "requires-python = \">=3.11\"", "",
    "[[package]]", "name = \"aiohttp\"", "version = \"3.14.5\"", "source = { registry = \"https://pypi.org/simple\" }", "",
    "[[package]]", "name = \"pydantic\"", "version = \"2.9.0\"", "source = { editable = \".\" }", "",
    "[[package]]", "name = \"docs\"", "version = \"0.1.0\"", "source = { git = \"https://github.com/x/docs#abc\" }", "",
    "[[package]]", "name = \"torch\"", "version = \"2.4.0+cpu\"", "source = { registry = \"https://download.pytorch.org/whl/cpu\" }", "",
  ].join("\n");
  assert.deepEqual(ids(parseUvLock(lock)), ["PyPI:aiohttp@3.14.5"]);
});

test("Pipfile.lock: `==` pins from a pypi.org index, `develop` marked dev, git / editable / private-index entries skipped", () => {
  const lock = JSON.stringify({
    _meta: { sources: [{ name: "pypi", url: "https://pypi.org/simple", verify_ssl: true }, { name: "acme", url: "https://pypi.acme.corp/simple" }] },
    default: { requests: { version: "==2.19.0", index: "pypi" }, distlib: { version: "==0.4.4" }, internal: { version: "==1.0.0", index: "acme" },
      mylib: { editable: true, path: "." }, gitdep: { git: "https://github.com/x/y.git", ref: "abc" } },
    develop: { pytest: { version: "==8.0.0", index: "pypi" } },
  });
  assert.deepEqual(ids(parsePipfileLock(lock)), ["PyPI:distlib@0.4.4", "PyPI:pytest@8.0.0:dev", "PyPI:requests@2.19.0"]);
  const privateFirst = JSON.stringify({ _meta: { sources: [{ name: "acme", url: "https://pypi.acme.corp/simple" }] }, default: { secret: { version: "==1.0.0" } } });
  assert.deepEqual(parsePipfileLock(privateFirst), [], "no index named: the first source decides, here a private one");
});

test("Cargo.lock: crates.io (git index or sparse) only — workspace crates, git and other registries skipped", () => {
  const lock = [
    "version = 4", "",
    "[[package]]", "name = \"aho-corasick\"", "version = \"1.1.5\"", "source = \"registry+https://github.com/rust-lang/crates.io-index\"", "checksum = \"c98\"", "dependencies = [", " \"memchr\",", "]", "",
    "[[package]]", "name = \"memchr\"", "version = \"2.7.4\"", "source = \"sparse+https://index.crates.io/\"", "",
    "[[package]]", "name = \"ripgrep\"", "version = \"14.1.1\"", "",
    "[[package]]", "name = \"forked\"", "version = \"0.1.0\"", "source = \"git+https://github.com/x/forked#abc\"", "",
    "[[package]]", "name = \"secret\"", "version = \"1.0.0\"", "source = \"registry+https://crates.acme.corp/index\"", "",
  ].join("\n");
  assert.deepEqual(ids(parseCargoLock(lock)), ["crates.io:aho-corasick@1.1.5", "crates.io:memchr@2.7.4"]);
});

test("composer.lock: packagist.org packages only, `v` prefix dropped, dev branches and private repositories skipped", () => {
  const pk = (name, version, n = "https://packagist.org/downloads/") => ({ name, version, ...(n ? { "notification-url": n } : {}) });
  const lock = JSON.stringify({
    packages: [pk("symfony/console", "v5.4.55"), pk("Composer/CA-Bundle", "1.6.1"), pk("acme/private", "1.0.0", null), pk("x/dev", "dev-master")],
    "packages-dev": [pk("phpunit/phpunit", "9.6.0")],
  });
  assert.deepEqual(ids(parseComposerLock(lock)), ["Packagist:composer/ca-bundle@1.6.1", "Packagist:phpunit/phpunit@9.6.0:dev", "Packagist:symfony/console@5.4.55"]);
});

test("every new parser is total: empty, garbage, wrong JSON shape and binary-ish input give [] and never throw", () => {
  const junk = ["", "{", "null", "[]", "\u0000\u0001", "packages:\n  :\n", "[[package]]\nname = \n", JSON.stringify({ packages: "x", default: 7 })];
  for (const f of [parsePnpmLock, parseYarnLock, parsePoetryLock, parseUvLock, parsePipfileLock, parseCargoLock, parseComposerLock]) {
    for (const t of [...junk, undefined, null]) assert.deepEqual(f(t, {}), [], `${f.name}(${JSON.stringify(t)})`);
  }
});

test("dispatch and pathspec cover the 10 names; a PR that bumps a pnpm lockfile introduces only the bumped version", () => {
  for (const n of ["package-lock.json", "go.sum", "Gemfile.lock", "pnpm-lock.yaml", "yarn.lock", "poetry.lock", "uv.lock", "Pipfile.lock", "Cargo.lock", "composer.lock"]) {
    assert.ok(LOCKFILE_PATHSPEC.includes(`:(glob)**/${n}`), n);
  }
  assert.equal(parseLockfile("rust/Cargo.lock", "[[package]]\nname = \"a\"\nversion = \"1.0.0\"\nsource = \"sparse+https://index.crates.io/\"\n")[0].eco, "crates.io");
  const pnpm = (v) => `lockfileVersion: '9.0'\npackages:\n  lodash@${v}:\n    resolution: {integrity: sha512-a==}\n  qs@6.5.1:\n    resolution: {integrity: sha512-b==}\n`;
  const git = (args) => (args[0].startsWith("-c") ? "web/pnpm-lock.yaml\nREADME.md\n" : args[0] === "show" ? pnpm("4.17.21") : null);
  const out = prLockfileChanges(git, () => pnpm("4.17.15"), "base", {});
  assert.deepEqual(out.map((x) => [x.path, ids(x.introduced)]), [["web/pnpm-lock.yaml", ["npm:lodash@4.17.15"]]]);
});
