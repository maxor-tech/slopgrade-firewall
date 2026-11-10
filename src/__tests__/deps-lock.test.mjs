// Lockfile parsing for dependency CVE matching (P3, layer 1: npm package-lock.json v1 / v2 / v3).
import { test } from "node:test";
import assert from "node:assert/strict";
import { parsePackageLock, parseGoSum, parseGemfileLock, parseLockfile, introducedDeps, repoLockfiles } from "../deps-lock.mjs";

const keys = (list) => list.map((d) => `${d.name}@${d.version}`).sort();

test("v2/v3 `packages`: root skipped, scoped names, nested copies, alias real name, links and version-less skipped", () => {
  const lock = JSON.stringify({ lockfileVersion: 3, packages: {
    "": { name: "app", version: "1.0.0" },
    "node_modules/lodash": { version: "4.17.15" },
    "node_modules/@babel/core": { version: "7.1.0", dev: true },
    "node_modules/a/node_modules/lodash": { version: "4.17.21" },
    "node_modules/my-alias": { name: "minimist", version: "1.2.0" },
    "node_modules/local-pkg": { resolved: "packages/local", link: true },
    "packages/local": { version: "0.0.1" },
    "node_modules/no-version": {},
  } });
  assert.deepEqual(keys(parsePackageLock(lock)), ["@babel/core@7.1.0", "lodash@4.17.15", "lodash@4.17.21", "minimist@1.2.0"]);
  assert.equal(parsePackageLock(lock).find((d) => d.name === "@babel/core").dev, true);
  assert.ok(parsePackageLock(lock).every((d) => d.eco === "npm"));
});

test("v1 `dependencies`: recursive, duplicates kept once, bundled and version-less skipped", () => {
  const lock = JSON.stringify({ lockfileVersion: 1, dependencies: {
    lodash: { version: "4.17.15" },
    express: { version: "4.16.0", dependencies: { qs: { version: "6.5.1" }, lodash: { version: "4.17.15" } } },
    "file-dep": { version: "file:../x" },
    bundled: { version: "1.0.0", bundled: true },
  } });
  assert.deepEqual(keys(parsePackageLock(lock)), ["express@4.16.0", "lodash@4.17.15", "qs@6.5.1"]);
});

test("malformed, empty or hostile input gives [] and never throws", () => {
  for (const t of ["", "{", "null", "[]", JSON.stringify({ packages: "x" }), JSON.stringify({ packages: { "node_modules/a": { version: 7 } } })]) {
    assert.deepEqual(parsePackageLock(t), [], t);
  }
  // a version string that is not a semver-ish token (a URL, a path) is not matchable: skipped
  assert.deepEqual(parsePackageLock(JSON.stringify({ packages: { "node_modules/a": { version: "git+https://x/y.git#abc" } } })), []);
});

test("only public-registry packages are kept: a private registry, git or other tarball is never matched or sent", () => {
  const lock = JSON.stringify({ lockfileVersion: 3, packages: {
    "node_modules/lodash": { version: "4.17.15", resolved: "https://registry.npmjs.org/lodash/-/lodash-4.17.15.tgz" },
    "node_modules/@acme/internal": { version: "1.2.3", resolved: "https://npm.acme.corp/@acme/internal/-/internal-1.2.3.tgz" },
    "node_modules/gitdep": { version: "1.0.0", resolved: "git+ssh://git@github.com/acme/gitdep.git#abc" },
    "node_modules/noresolved": { version: "2.0.0" },
  } });
  assert.deepEqual(keys(parsePackageLock(lock)), ["lodash@4.17.15", "noresolved@2.0.0"]);
});

test("go.sum: built module versions only (a /go.mod-only line is graph resolution, never built), own-owner modules never sent", () => {
  const sum = [
    "github.com/gin-gonic/gin v1.6.0 h1:abc=",
    "github.com/gin-gonic/gin v1.6.0/go.mod h1:def=",
    "golang.org/x/net v0.0.0-20190404232315-eb5bcb51f2a3 h1:x=",
    "golang.org/x/text v0.3.0/go.mod h1:only-graph=",
    "github.com/acme/internal-lib v1.2.3 h1:y=",
    "github.com/ACME/other v0.1.0 h1:z=",
    "garbage line",
    "",
  ].join("\n");
  const out = parseGoSum(sum, { owner: "acme" });
  assert.deepEqual(out.map((d) => `${d.eco}:${d.name}@${d.version}`).sort(),
    ["Go:github.com/gin-gonic/gin@v1.6.0", "Go:golang.org/x/net@v0.0.0-20190404232315-eb5bcb51f2a3"]);
  assert.equal(parseGoSum(sum, {}).length, 4, "without an owner, every built module is kept; the /go.mod-only x/text never");
});

test("Gemfile.lock: rubygems.org specs only (top level), platform suffix stripped, GIT / PATH / private sources skipped", () => {
  const lock = [
    "GIT", "  remote: https://github.com/acme/private-gem.git", "  revision: abc", "  specs:", "    private-gem (0.1.0)", "",
    "GEM", "  remote: https://rubygems.org/", "  specs:", "    rails (5.2.0)", "      actionpack (= 5.2.0)", "    nokogiri (1.10.0-x86_64-linux)", "    rack (2.0.7)", "",
    "GEM", "  remote: https://gems.acme.corp/", "  specs:", "    acme-secret (3.0.0)", "",
    "PLATFORMS", "  ruby", "",
  ].join("\n");
  assert.deepEqual(parseGemfileLock(lock).map((d) => `${d.eco}:${d.name}@${d.version}`).sort(),
    ["RubyGems:nokogiri@1.10.0", "RubyGems:rack@2.0.7", "RubyGems:rails@5.2.0"]);
});

test("parseLockfile dispatches on the file name; an unknown name gives []", () => {
  assert.equal(parseLockfile("a/go.sum", "github.com/x/y v1.0.0 h1:a=", {})[0].eco, "Go");
  assert.equal(parseLockfile("Gemfile.lock", "GEM\n  remote: https://rubygems.org/\n  specs:\n    rack (2.0.7)\n", {})[0].eco, "RubyGems");
  assert.equal(parseLockfile("web/package-lock.json", JSON.stringify({ packages: { "node_modules/a": { version: "1.0.0" } } }), {})[0].eco, "npm");
  assert.deepEqual(parseLockfile("yarn.lock", "x", {}), []);
});

test("repoLockfiles: every tracked supported lockfile with all its pinned versions (the scheduled monitor)", () => {
  const files = {
    "package-lock.json": JSON.stringify({ packages: { "node_modules/lodash": { version: "4.17.15" } } }),
    "svc/go.sum": "github.com/gin-gonic/gin v1.6.0 h1:a=\n",
    "README.md": "x",
  };
  const git = (args) => (args[0] === "ls-files" ? "package-lock.json\nsvc/go.sum\nREADME.md\n" : null);
  const out = repoLockfiles(git, (p) => files[p], {});
  assert.deepEqual(out.map((x) => [x.path, x.deps.map((d) => `${d.eco}:${d.name}@${d.version}`)]),
    [["package-lock.json", ["npm:lodash@4.17.15"]], ["svc/go.sum", ["Go:github.com/gin-gonic/gin@v1.6.0"]]]);
  assert.deepEqual(repoLockfiles(() => null, () => "", {}), [], "git failure: nothing, never a throw");
  assert.deepEqual(repoLockfiles(() => { throw new Error("x"); }, () => "", {}), []);
});

test("introducedDeps: versions in head that base did not have (a bump, a new package), never a removal", () => {
  const base = [{ eco: "npm", name: "lodash", version: "4.17.21" }, { eco: "npm", name: "qs", version: "6.5.1" }];
  const head = [{ eco: "npm", name: "lodash", version: "4.17.15" }, { eco: "npm", name: "qs", version: "6.5.1" }, { eco: "npm", name: "minimist", version: "1.2.0" }];
  assert.deepEqual(keys(introducedDeps(base, head)), ["lodash@4.17.15", "minimist@1.2.0"]);
  assert.deepEqual(introducedDeps(head, base), [{ eco: "npm", name: "lodash", version: "4.17.21" }], "the reverse diff introduces only the other lodash");
  assert.deepEqual(keys(introducedDeps(null, head)), ["lodash@4.17.15", "minimist@1.2.0", "qs@6.5.1"], "no base lockfile: everything is new");
});
