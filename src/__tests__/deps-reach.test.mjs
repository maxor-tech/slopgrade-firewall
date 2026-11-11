// Go reachability, import level (READ-DEPS-6): the import scanner, the OSV affected-path reader, the marker, and the
// end-to-end label on a REAL pull-request checkout (OSV stubbed).
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { goImports, goImportSpecs, goDefaultName, affectedGoImports, affectedGoPaths, markGoImported, isOwnGoFile } from "../deps-reach.mjs";
import { annotated, depsOutput } from "../deps-osv.mjs";
import { main } from "../../isolation-gate.mjs";

test("goImports: block (aliases, dot, blank, comments) and single forms; strings elsewhere are not imports", () => {
  const src = [
    "package main", "", "import (", '\t"fmt"', '\th2 "golang.org/x/net/http2"', '\t. "strings"', '\t_ "net/http/pprof"',
    '\t// "golang.org/x/commented/out"', ")", 'import yaml "gopkg.in/yaml.v2"', 'import "os"', "",
    'func main() { s := "golang.org/x/text"; fmt.Println(s) }',
  ].join("\n");
  assert.deepEqual([...goImports(src)].sort(), ["fmt", "golang.org/x/net/http2", "gopkg.in/yaml.v2", "net/http/pprof", "os", "strings"]);
  assert.deepEqual([...goImports(null)], []);
});

test("affectedGoPaths: the advisory's import paths for THIS module only; no import data gives []", () => {
  const rec = { affected: [
    { package: { ecosystem: "Go", name: "stdlib" }, ecosystem_specific: { imports: [{ path: "net/http" }] } },
    { package: { ecosystem: "Go", name: "golang.org/x/net" }, ecosystem_specific: { imports: [{ path: "golang.org/x/net/http2", symbols: ["Server.ServeConn"] }] } },
    { package: { ecosystem: "Go", name: "golang.org/x/text" } },
  ] };
  assert.deepEqual(affectedGoPaths(rec, "golang.org/x/net"), ["golang.org/x/net/http2"]);
  assert.deepEqual(affectedGoPaths(rec, "golang.org/x/text"), []);
  assert.deepEqual(affectedGoPaths(undefined, "x"), []);
});

test("isOwnGoFile: vendor/, testdata/ and _test.go are not your code", () => {
  assert.deepEqual(["main.go", "cmd/a/b.go", "vendor/x/y.go", "pkg/testdata/z.go", "a_test.go", "README.md"].filter(isOwnGoFile), ["main.go", "cmd/a/b.go"]);
});

test("markGoImported: labels only the versions whose affected package your code imports, sorts after KEV, never removes one", () => {
  const r = { vulnerable: [
    { eco: "Go", name: "golang.org/x/text", version: "v0.3.0", ids: ["GO-1"], goPaths: ["golang.org/x/text/language"] },
    { eco: "Go", name: "golang.org/x/net", version: "v0.0.1", ids: ["GO-2"], goPaths: ["golang.org/x/net/http2"] },
    { eco: "Go", name: "github.com/a/b", version: "v1.0.0", ids: ["GO-3"], kev: ["CVE-1"] },
  ], checked: 3, skipped: 0 };
  const files = { "main.go": 'package main\nimport h2 "golang.org/x/net/http2"\n', "vendor/golang.org/x/text/language/x.go": 'import "golang.org/x/text/language"' };
  const out = markGoImported(r, () => Object.keys(files), (p) => files[p]);
  assert.deepEqual(out.vulnerable.map((v) => [v.name, v.imported ?? null]),
    [["github.com/a/b", null], ["golang.org/x/net", ["golang.org/x/net/http2"]], ["golang.org/x/text", null]], "vendor import does not count");
  assert.equal(out.vulnerable.length, 3);
  assert.equal(annotated({ severity: "LOW", imported: ["p"] }), true, "imported is always annotated");
  assert.equal(annotated({ severity: "LOW", dev: true, imported: ["p"] }), true);
  // failure paths: a file list that throws keeps every finding and says so; nothing to look for = untouched
  const failed = markGoImported(r, () => { throw new Error("git"); }, () => "");
  assert.equal(failed.vulnerable.length, 3);
  assert.match(failed.scanNote, /skipped/);
  const none = { vulnerable: [{ eco: "npm", name: "lodash", version: "1.0.0", ids: ["GHSA-x"] }], checked: 1, skipped: 0 };
  assert.equal(markGoImported(none, () => { throw new Error("never called"); }, () => ""), none);
});

test("depsOutput: an imported version gets its own title and says which package your code imports", () => {
  const out = depsOutput("go.sum", { vulnerable: [{ eco: "Go", name: "golang.org/x/net", version: "v0.0.1", ids: ["GO-2023-2102"], severity: "MODERATE", imported: ["golang.org/x/net/http2"] }], checked: 4, skipped: 0 });
  assert.equal(out.notices.length, 1, "MODERATE but imported: annotated");
  assert.match(out.notices[0], /title=slopGrade dependency scan — imported by your code::golang\.org\/x\/net@v0\.0\.1 has 1 published advisory \(MODERATE\): GO-2023-2102 — your code imports golang\.org\/x\/net\/http2/);
  assert.match(out.lines[1], /imported: golang\.org\/x\/net\/http2$/);
});

test("goDefaultName: last element without /vN, gopkg.in .vN, go- prefix, -go/.go suffix", () => {
  assert.deepEqual(["golang.org/x/net/http2", "gopkg.in/yaml.v2", "github.com/go-redis/redis/v8", "github.com/mattn/go-sqlite3",
    "github.com/a/client-go", "github.com/a/b.go", "v2"].map(goDefaultName), ["http2", "yaml", "redis", "sqlite3", "client", "b", "v2"]);
});

test("goImportSpecs: the alias is kept (named, dot, blank) or null", () => {
  assert.deepEqual(goImportSpecs('import (\n\th2 "golang.org/x/net/http2"\n\t. "strings"\n\t"fmt"\n)\nimport _ "net/http/pprof"\n'),
    [["h2", "golang.org/x/net/http2"], [".", "strings"], [null, "fmt"], ["_", "net/http/pprof"]]);
});

test("affectedGoImports: symbols per path, invalid symbol strings dropped, no symbols = []", () => {
  const rec = { affected: [{ package: { ecosystem: "Go", name: "m" }, ecosystem_specific: { imports: [
    { path: "m/a", symbols: ["Parse", "Server.ServeConn", "bad(", 3] }, { path: "m/b" }] } }] };
  assert.deepEqual(affectedGoImports(rec, "m"), [{ path: "m/a", symbols: ["Parse", "Server.ServeConn"] }, { path: "m/b", symbols: [] }]);
  assert.deepEqual(affectedGoPaths(rec, "m"), ["m/a", "m/b"]);
});

test("markGoImported, call level: name.Func / name.Type with the alias in use; dot import and other names stay import level", () => {
  const mk = () => ({ vulnerable: [
    { eco: "Go", name: "golang.org/x/net", version: "v1", ids: ["GO-2"], goPaths: ["golang.org/x/net/http2"], goSymbols: { "golang.org/x/net/http2": ["Server.ServeConn", "ConfigureTransport"] } },
    { eco: "Go", name: "golang.org/x/text", version: "v2", ids: ["GO-1"], goPaths: ["golang.org/x/text/language"], goSymbols: { "golang.org/x/text/language": ["Parse"] } },
  ], checked: 2, skipped: 0 });
  const run = (files) => markGoImported(mk(), () => Object.keys(files), (p) => files[p]).vulnerable.map((v) => [v.name, v.imported ?? null, v.named ?? null]);
  // aliased import: h2.Server names Server.ServeConn; « language.Parse » is not named (it says lang.Parse)
  assert.deepEqual(run({ "a.go": 'import (\n\th2 "golang.org/x/net/http2"\n\tlang "golang.org/x/text/language"\n)\nvar s h2.Server\nvar _ = lang.Make("x")\n' }),
    [["golang.org/x/net", ["golang.org/x/net/http2"], ["http2.Server (affected: Server.ServeConn)"]], ["golang.org/x/text", ["golang.org/x/text/language"], null]]);
  // default name; « http2.ServerX » and « xhttp2.Server » are not « http2.Server »; named sorts first
  assert.deepEqual(run({ "a.go": 'import "golang.org/x/net/http2"\nimport "golang.org/x/text/language"\nvar _ = http2.ServerX\nvar _ = xhttp2.Server\nvar _ = language.Parse\n' }),
    [["golang.org/x/text", ["golang.org/x/text/language"], ["language.Parse"]], ["golang.org/x/net", ["golang.org/x/net/http2"], null]]);
  // a dot import gives no qualified name: import level only
  assert.deepEqual(run({ "a.go": 'import . "golang.org/x/text/language"\nvar _ = Parse\n' }).find((x) => x[0] === "golang.org/x/text"),
    ["golang.org/x/text", ["golang.org/x/text/language"], null]);
  // a name in a file that does NOT import the package does not count
  assert.deepEqual(run({ "a.go": 'import "golang.org/x/text/language"\n', "b.go": "var _ = http2.Server{}\n" }).find((x) => x[0] === "golang.org/x/net"),
    ["golang.org/x/net", null, null]);
});

test("depsOutput: a named version gets the call-level title and says which function", () => {
  const out = depsOutput("go.sum", { vulnerable: [{ eco: "Go", name: "golang.org/x/net", version: "v1", ids: ["GO-2"], severity: "LOW",
    imported: ["golang.org/x/net/http2"], named: ["http2.Server (affected: Server.ServeConn)", "http2.ConfigureServer"] }], checked: 1, skipped: 0 });
  assert.equal(out.notices.length, 1);
  assert.match(out.notices[0], /title=slopGrade dependency scan — affected symbol referenced by your code::golang\.org\/x\/net@v1 has 1 published advisory \(LOW\): GO-2 — your code imports golang\.org\/x\/net\/http2 and references http2\.Server \(affected: Server\.ServeConn\), http2\.ConfigureServer — https/);
  assert.match(out.lines[1], /imported: golang\.org\/x\/net\/http2  references: http2\.Server \(affected: Server\.ServeConn\); http2\.ConfigureServer$/);
});

const sh = (cwd, ...args) => execFileSync("git", args, { cwd, encoding: "utf8" });
test("end to end: a PR that bumps x/net in go.sum, with main.go importing the affected package → the imported label", async () => {
  const dir = mkdtempSync(join(tmpdir(), "fw-go-reach-"));
  sh(dir, "init", "-q", "-b", "main"); sh(dir, "config", "user.email", "t@example.com"); sh(dir, "config", "user.name", "t"); sh(dir, "config", "core.autocrlf", "false");
  const sum = (v) => `golang.org/x/net ${v} h1:a=\ngolang.org/x/net ${v}/go.mod h1:b=\n`;
  writeFileSync(join(dir, "go.sum"), sum("v0.17.0"));
  writeFileSync(join(dir, "main.go"), 'package main\n\nimport (\n\t"golang.org/x/net/http2"\n)\n\nvar _ = http2.Server{}\n');
  mkdirSync(join(dir, "vendor"), { recursive: true });
  sh(dir, "add", "."); sh(dir, "commit", "-qm", "base");
  const base = sh(dir, "rev-parse", "HEAD").trim();
  writeFileSync(join(dir, "go.sum"), sum("v0.0.0-20230101000000-abcdefabcdef"));
  sh(dir, "commit", "-qam", "bump");
  const head = sh(dir, "rev-parse", "HEAD").trim();
  const ev = join(dir, "..", `${dir.split(/[\\/]/).pop()}-event.json`);
  writeFileSync(ev, JSON.stringify({ pull_request: { base: { sha: base }, head: { sha: head } } }));
  const env = { GITHUB_ACTIONS: "true", ACTIONS_ID_TOKEN_REQUEST_URL: "https://oidc.example/token?api-version=2", ACTIONS_ID_TOKEN_REQUEST_TOKEN: "rt",
    GITHUB_SHA: head, GITHUB_WORKSPACE: dir, GITHUB_EVENT_NAME: "pull_request", GITHUB_EVENT_PATH: ev };
  const realFetch = globalThis.fetch, realLog = console.log, out = [];
  globalThis.fetch = async (url, opts) => {
    const u = String(url);
    if (u.startsWith("https://oidc.example/")) return { ok: true, status: 200, json: async () => ({ value: "eyJ.oidc.token" }) };
    if (u === "https://api.osv.dev/v1/querybatch") return { ok: true, status: 200, json: async () => ({ results: JSON.parse(opts.body).queries.map(() => ({ vulns: [{ id: "GO-2023-2102" }] })) }) };
    if (u === "https://api.osv.dev/v1/vulns/GO-2023-2102") return { ok: true, status: 200, json: async () => ({ id: "GO-2023-2102", aliases: ["CVE-2023-39325"],
      affected: [{ package: { ecosystem: "Go", name: "golang.org/x/net" }, ecosystem_specific: { imports: [{ path: "golang.org/x/net/http2", symbols: ["Server.ServeConn"] }] } }] }) };
    if (u.endsWith("/api/ci/pro-extractors")) return { ok: false, status: 402, json: async () => ({ error: "plan-required" }) };
    return { ok: true, status: 200, json: async () => ({ gateEntitled: false, gateLevel: "none", packBlocking: 0, pattern: "none", conformancePct: null, hardLeaks: 0, reliable: true, leaks: [] }) };
  };
  console.log = (...a) => out.push(a.join(" "));
  try {
    const code = await main(["--dependency-scan"], env);
    const text = out.join("\n");
    assert.equal(code, 0);
    assert.match(text, /::warning file=go\.sum,line=1,title=slopGrade dependency scan — affected symbol referenced by your code::golang\.org\/x\/net@v0\.0\.0-20230101000000-abcdefabcdef has 1 published advisory: GO-2023-2102 — your code imports golang\.org\/x\/net\/http2 and references http2\.Server \(affected: Server\.ServeConn\)/);
    assert.match(text, /references: http2\.Server \(affected: Server\.ServeConn\)/);
  } finally {
    globalThis.fetch = realFetch; console.log = realLog;
    rmSync(dir, { recursive: true, force: true });
  }
});
