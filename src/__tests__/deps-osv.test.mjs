// Dependency scan (0.18.0): the versions a PR introduces, matched against OSV from the runner. Fetch is the only double.
import { test } from "node:test";
import assert from "node:assert/strict";
import { queryOsv, depsOutput, addKev, annotated, KEV_URL, OSV_BATCH, OSV_MAX_QUERIES } from "../deps-osv.mjs";

const dep = (name, version) => ({ eco: "npm", name, version });

test("queryOsv batches, sends only {name, ecosystem, version}, maps advisories back, keeps clean versions out", async () => {
  const sent = [];
  const fetchImpl = async (url, init) => {
    assert.equal(url, "https://api.osv.dev/v1/querybatch");
    const b = JSON.parse(init.body);
    sent.push(b.queries);
    return { ok: true, status: 200, json: async () => ({ results: b.queries.map((q) => (q.package.name === "lodash" ? { vulns: [{ id: "GHSA-35jh-r3h4-6jhm" }] } : {})) }) };
  };
  const deps = [dep("lodash", "4.17.15"), ...Array.from({ length: OSV_BATCH }, (_, i) => dep(`p${i}`, "1.0.0"))];
  const r = await queryOsv(deps, { fetchImpl });
  assert.equal(sent.length, 2, "1,001 queries go in two batches");
  assert.deepEqual(sent[0][0], { package: { name: "lodash", ecosystem: "npm" }, version: "4.17.15" });
  assert.deepEqual(r.vulnerable, [{ eco: "npm", name: "lodash", version: "4.17.15", ids: ["GHSA-35jh-r3h4-6jhm"] }]);
  assert.equal(r.checked, OSV_BATCH + 1);
});

test("queryOsv sends each entry's own OSV ecosystem (Go, RubyGems, npm)", async () => {
  let q = null;
  const fetchImpl = async (_u, init) => { q = JSON.parse(init.body).queries; return { ok: true, status: 200, json: async () => ({ results: q.map(() => ({})) }) }; };
  await queryOsv([{ eco: "Go", name: "github.com/gin-gonic/gin", version: "v1.6.0" }, { eco: "RubyGems", name: "rack", version: "2.0.7" }, dep("a", "1.0.0")], { fetchImpl });
  assert.deepEqual(q.map((x) => x.package.ecosystem), ["Go", "RubyGems", "npm"]);
});

test("queryOsv caps the queries and says so ; any failure is an error, never « no advisory »", async () => {
  const many = Array.from({ length: OSV_MAX_QUERIES + 5 }, (_, i) => dep(`p${i}`, "1.0.0"));
  const ok = async (_u, init) => ({ ok: true, status: 200, json: async () => ({ results: JSON.parse(init.body).queries.map(() => ({})) }) });
  const r = await queryOsv(many, { fetchImpl: ok });
  assert.equal(r.checked, OSV_MAX_QUERIES);
  assert.equal(r.skipped, 5);
  assert.match((await queryOsv([dep("a", "1.0.0")], { fetchImpl: async () => ({ ok: false, status: 503, json: async () => ({}) }) })).error, /HTTP 503/);
  assert.match((await queryOsv([dep("a", "1.0.0")], { fetchImpl: async () => { throw new Error("ECONNRESET"); } })).error, /ECONNRESET/);
  assert.match((await queryOsv([dep("a", "1.0.0")], { fetchImpl: async () => ({ ok: true, status: 200, json: async () => ({ results: [] }) }) })).error, /malformed/);
  assert.deepEqual(await queryOsv([], { fetchImpl: ok }), { vulnerable: [], checked: 0, skipped: 0 });
});

test("addKev: an advisory whose CVE alias is on CISA KEV marks the version, first in the list; failures drop only the priority", async () => {
  const r = { vulnerable: [{ name: "a", version: "1.0.0", ids: ["GHSA-aaaa"] }, { name: "log4j", version: "2.14.1", ids: ["GHSA-jfh8", "GHSA-other"] }], checked: 2, skipped: 0 };
  const fetchImpl = async (url) => {
    if (url === KEV_URL) return { ok: true, status: 200, json: async () => ({ vulnerabilities: [{ cveID: "CVE-2021-44228" }, { cveID: "CVE-2000-0001" }] }) };
    if (url.endsWith("/GHSA-jfh8")) return { ok: true, status: 200, json: async () => ({ id: "GHSA-jfh8", aliases: ["CVE-2021-44228"] }) };
    return { ok: true, status: 200, json: async () => ({ id: "x", aliases: ["CVE-2099-0001"] }) };
  };
  const out = await addKev(r, { fetchImpl });
  assert.deepEqual(out.vulnerable.map((v) => [v.name, v.kev || []]), [["log4j", ["CVE-2021-44228"]], ["a", []]]);
  const failing = await addKev(r, { fetchImpl: async () => ({ ok: false, status: 500, json: async () => ({}) }) });
  assert.equal(failing.kevError, "CISA KEV list unavailable (HTTP 500)");
  assert.deepEqual(failing.vulnerable.map((v) => v.name), ["a", "log4j"], "without KEV the order and findings are unchanged");
  assert.deepEqual(await addKev({ error: "x" }, { fetchImpl }), { error: "x" });
});

test("depsOutput scope repo (scheduled monitor): says « pinned in this lockfile », not « this PR adds »", () => {
  const out = depsOutput("go.sum", { vulnerable: [], checked: 40, skipped: 0 }, { scope: "repo" });
  assert.match(out.lines[0], /0 of 40 version\(s\) pinned in this lockfile have published advisories/);
});

test("depsOutput: a KEV version gets its own title and leads the list", () => {
  const out = depsOutput("package-lock.json", { vulnerable: [{ name: "log4j", version: "2.14.1", ids: ["GHSA-jfh8"], kev: ["CVE-2021-44228"] }], checked: 1, skipped: 0 });
  assert.match(out.notices[0], /title=slopGrade dependency scan — actively exploited \(CISA KEV\)::log4j@2\.14\.1 has 1 published advisory: GHSA-jfh8 — exploited in the wild: CVE-2021-44228/);
  assert.match(out.lines[0], /1 of them actively exploited \(CISA KEV\)/);
});

test("depsOutput: one notice per vulnerable version on its lockfile, a link per advisory, nothing blocks", () => {
  const out = depsOutput("web/package-lock.json", { vulnerable: [{ name: "lodash", version: "4.17.15", ids: ["GHSA-35jh-r3h4-6jhm", "GHSA-p6mc-m468-83gw"] }], checked: 12, skipped: 0 });
  assert.deepEqual(out.notices, ["::warning file=web/package-lock.json,line=1,title=slopGrade dependency scan::lodash@4.17.15 has 2 published advisories: GHSA-35jh-r3h4-6jhm, GHSA-p6mc-m468-83gw — https://osv.dev/vulnerability/GHSA-35jh-r3h4-6jhm"]);
  assert.match(out.lines[0], /dependency scan: web\/package-lock\.json — 1 of 12 version\(s\) this PR adds have published advisories \(OSV\)\. Warnings only, never blocking\./);
  const clean = depsOutput("package-lock.json", { vulnerable: [], checked: 3, skipped: 0 });
  assert.deepEqual(clean.notices, []);
  assert.match(clean.lines[0], /0 of 3 version\(s\)/);
  const err = depsOutput("package-lock.json", { error: "OSV HTTP 503" });
  assert.equal(err.warn, true);
  assert.match(err.lines[0], /unavailable: OSV HTTP 503 — verdict unaffected/);
});

test("queryOsv keeps the parser's dev flag on a vulnerable version", async () => {
  const fetchImpl = async (_u, init) => ({ ok: true, status: 200, json: async () => ({ results: JSON.parse(init.body).queries.map(() => ({ vulns: [{ id: "GHSA-x" }] })) }) });
  const r = await queryOsv([{ eco: "npm", name: "jest", version: "1.0.0", dev: true }, dep("lodash", "4.17.15")], { fetchImpl });
  assert.deepEqual(r.vulnerable.map((v) => [v.name, v.dev === true]), [["jest", true], ["lodash", false]]);
});

test("addKev reads each advisory's GitHub severity (highest wins); a record failure leaves the version unrated", async () => {
  const sev = { "GHSA-low": "LOW", "GHSA-high": "HIGH", "GHSA-mod": "MODERATE" };
  const fetchImpl = async (url) => {
    if (url === KEV_URL) return { ok: true, status: 200, json: async () => ({ vulnerabilities: [] }) };
    const id = url.split("/").pop();
    if (id === "GHSA-down") return { ok: false, status: 500, json: async () => ({}) };
    return { ok: true, status: 200, json: async () => ({ id, aliases: [], database_specific: { severity: sev[id] } }) };
  };
  const r = { vulnerable: [{ name: "a", version: "1", ids: ["GHSA-low", "GHSA-high"] }, { name: "b", version: "1", ids: ["GHSA-mod"] }, { name: "c", version: "1", ids: ["GHSA-down"] }], checked: 3, skipped: 0 };
  const out = await addKev(r, { fetchImpl });
  assert.deepEqual(out.vulnerable.map((v) => [v.name, v.severity ?? null]), [["a", "HIGH"], ["b", "MODERATE"], ["c", null]]);
  const noKev = await addKev(r, { fetchImpl: async (url) => (url === KEV_URL ? { ok: false, status: 503, json: async () => ({}) } : fetchImpl(url)) });
  assert.equal(noKev.kevError, "CISA KEV list unavailable (HTTP 503)");
  assert.equal(noKev.vulnerable[0].severity, "HIGH", "a KEV failure keeps the severities read");
});

test("annotated: KEV always; dev-only never (unless KEV); HIGH / CRITICAL / unrated yes; LOW / MODERATE no; all = every version", () => {
  const cases = [
    [{ severity: "CRITICAL" }, true], [{ severity: "HIGH" }, true], [{}, true], [{ severity: "MODERATE" }, false], [{ severity: "LOW" }, false],
    [{ severity: "CRITICAL", dev: true }, false], [{ severity: "LOW", kev: ["CVE-1"] }, true], [{ dev: true, kev: ["CVE-1"] }, true],
  ];
  for (const [v, want] of cases) assert.equal(annotated(v), want, JSON.stringify(v));
  for (const [v] of cases) assert.equal(annotated(v, { all: true }), true);
});

test("depsOutput default: a MODERATE and a dev-only version are listed and counted, not annotated; `all` annotates them", () => {
  const r = { vulnerable: [
    { name: "minimist", version: "1.2.0", ids: ["GHSA-a"], severity: "CRITICAL" },
    { name: "qs", version: "6.5.1", ids: ["GHSA-b"], severity: "MODERATE" },
    { name: "jest", version: "26.0.0", ids: ["GHSA-c"], severity: "HIGH", dev: true },
  ], checked: 40, skipped: 0 };
  const out = depsOutput("package-lock.json", r);
  assert.equal(out.notices.length, 1);
  assert.match(out.notices[0], /minimist@1\.2\.0 has 1 published advisory \(CRITICAL\): GHSA-a/);
  assert.match(out.lines[0], /3 of 40 version\(s\) this PR adds have published advisories \(OSV\)\. Warnings only, never blocking\. 2 of them below HIGH or dev-only: listed here, not annotated/);
  assert.deepEqual(out.lines.slice(1), ["    - minimist@1.2.0  GHSA-a  CRITICAL", "    - qs@6.5.1  GHSA-b  MODERATE", "    - jest@26.0.0 (dev)  GHSA-c  HIGH"]);
  const all = depsOutput("package-lock.json", r, { all: true });
  assert.equal(all.notices.length, 3);
  assert.match(all.notices[2], /jest@26\.0\.0 \(dev\) has 1 published advisory \(HIGH\)/);
  assert.doesNotMatch(all.lines[0], /not annotated/);
});
