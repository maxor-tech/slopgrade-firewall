// Dependency scan (0.18.0): match the package versions a pull request ADDS (deps-lock.mjs) against OSV
// (https://osv.dev, the open advisory database behind GitHub, PyPI and npm advisories). The call goes from the runner
// to api.osv.dev; slopGrade sees nothing. What is sent: {ecosystem, name, version} of public-registry packages only.
//
// Measured (slopGrade release run, ledger READ-DEPS-1 as amended, READ-DEPS-3, READ-DEPS-4): 363 of 1,750 pull requests
// that changed a package-lock.json (20.7 %) added a version whose advisory was ALREADY published when the PR was made;
// 920 of 5,242 lockfile changes across the 10 formats. Of those, 63 % carry a GitHub severity of HIGH or CRITICAL, and
// where dev packages are recorded half of the warnings are dev-only — so by default only a version that is actively
// exploited (CISA KEV), or HIGH+ (or unrated) and not dev-only, is annotated; the others are counted in the run log.
// Warnings to triage, never blocking; any failure prints one warning and the gate goes on (fail open, everything shown).

import { affectedGoPaths } from "./deps-reach.mjs";

export const OSV_URL = "https://api.osv.dev/v1/querybatch";
export const OSV_BATCH = 1000;          // OSV's querybatch limit
export const OSV_MAX_QUERIES = 5000;    // per run: a new monorepo lockfile is ~300 versions (median), the largest few thousand
export const OSV_TIMEOUT_MS = 30_000;

/**
 * deps ([{eco, name, version, dev?}]) -> { vulnerable: [{name, version, ids, dev?}], checked, skipped } or { error }.
 * Never throws. A malformed or failed answer is an error, never « no advisory ».
 */
export async function queryOsv(deps, { fetchImpl = fetch, timeoutMs = OSV_TIMEOUT_MS } = {}) {
  const all = Array.isArray(deps) ? deps : [];
  const list = all.slice(0, OSV_MAX_QUERIES);
  const vulnerable = [];
  try {
    for (let i = 0; i < list.length; i += OSV_BATCH) {
      const chunk = list.slice(i, i + OSV_BATCH);
      const res = await fetchImpl(OSV_URL, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ queries: chunk.map((d) => ({ package: { name: d.name, ecosystem: d.eco || "npm" }, version: d.version })) }),
        signal: AbortSignal.timeout(timeoutMs),
      });
      if (!res.ok) return { error: `OSV HTTP ${res.status}` };
      const body = await res.json().catch(() => null);
      if (!body || !Array.isArray(body.results) || body.results.length !== chunk.length) return { error: "malformed answer from OSV" };
      chunk.forEach((d, k) => {
        const ids = (body.results[k]?.vulns || []).map((v) => v?.id).filter((x) => typeof x === "string").slice(0, 20);
        if (ids.length) vulnerable.push({ eco: d.eco || "npm", name: d.name, version: d.version, ids, ...(d.dev === true ? { dev: true } : {}) });
      });
    }
  } catch (e) {
    return { error: e?.name === "TimeoutError" ? "OSV did not answer in time" : `OSV call failed (${e?.message || e})` };
  }
  return { vulnerable, checked: list.length, skipped: all.length - list.length };
}

const ghProp = (s) => String(s).replace(/[\r\n]/g, " ").replace(/%/g, "%25").replace(/:/g, "%3A").replace(/,/g, "%2C");
const ghMsg = (s) => String(s).replace(/%/g, "%25").replace(/[\r\n]+/g, " ");

// CISA Known Exploited Vulnerabilities: the CVEs attacked in the wild (public JSON, nothing is sent to fetch it).
export const KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
const OSV_VULN_URL = "https://api.osv.dev/v1/vulns/";
export const KEV_MAX_LOOKUPS = 100;   // advisory records read per run (CVE aliases for KEV, GitHub severity)

// GitHub advisory severity (`database_specific.severity` of an OSV record), as a rank; 0 = unrated.
export const SEVERITY_RANK = { LOW: 1, MODERATE: 2, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };
const RANK_NAME = ["", "LOW", "MODERATE", "HIGH", "CRITICAL"];

/**
 * Read each advisory's OSV record once: mark the versions whose advisory is on CISA KEV (`kev: [CVE ids]`, put first)
 * and give each version the highest GitHub severity of its advisories (`severity: "HIGH"`, absent when unrated). Never
 * throws. A record failure leaves `severity` absent (the version stays shown); a KEV failure sets `kevError`.
 */
export async function addKev(r, { fetchImpl = fetch, timeoutMs = OSV_TIMEOUT_MS } = {}) {
  if (!r || r.error || !r.vulnerable?.length) return r;
  const get = async (url) => {
    const res = await fetchImpl(url, { signal: AbortSignal.timeout(timeoutMs) });
    return { status: res.status, ok: res.ok, body: res.ok ? await res.json().catch(() => null) : null };
  };
  const aliases = new Map(), rank = new Map(), goRec = new Map();
  try {
    for (const id of [...new Set(r.vulnerable.flatMap((v) => v.ids))].slice(0, KEV_MAX_LOOKUPS)) {
      if (id.startsWith("CVE-")) { aliases.set(id, [id]); continue; }
      const rec = await get(OSV_VULN_URL + encodeURIComponent(id));
      aliases.set(id, [id, ...(Array.isArray(rec.body?.aliases) ? rec.body.aliases : [])]);
      const s = SEVERITY_RANK[String(rec.body?.database_specific?.severity ?? "").toUpperCase()];
      if (s) rank.set(id, s);
      if (id.startsWith("GO-") && rec.body) goRec.set(id, rec.body);   // affected import paths (deps-reach.mjs)
    }
  } catch { /* records are best effort: a version without a severity is shown */ }
  const rated = r.vulnerable.map((v) => {
    const s = Math.max(0, ...v.ids.map((id) => rank.get(id) || 0));
    const goPaths = v.eco === "Go" ? [...new Set(v.ids.flatMap((id) => affectedGoPaths(goRec.get(id), v.name)))] : [];
    return { ...v, ...(s ? { severity: RANK_NAME[s] } : {}), ...(goPaths.length ? { goPaths } : {}) };
  });
  try {
    const kev = await get(KEV_URL);
    if (!kev.ok || !Array.isArray(kev.body?.vulnerabilities)) return { ...r, vulnerable: rated, kevError: `CISA KEV list unavailable (HTTP ${kev.status})` };
    const kevSet = new Set(kev.body.vulnerabilities.map((v) => v?.cveID).filter((x) => typeof x === "string"));
    const vulnerable = rated.map((v) => {
      const hit = [...new Set(v.ids.flatMap((id) => (aliases.get(id) || [])).filter((a) => kevSet.has(a)))];
      return hit.length ? { ...v, kev: hit } : v;
    });
    vulnerable.sort((a, b) => (b.kev ? 1 : 0) - (a.kev ? 1 : 0));
    return { ...r, vulnerable };
  } catch (e) {
    return { ...r, vulnerable: rated, kevError: `CISA KEV check failed (${e?.message || e})` };
  }
}

/**
 * The default annotation rule (READ-DEPS-4): a version is annotated when it is on CISA KEV, or when it is not dev-only
 * and its advisories are HIGH / CRITICAL or carry no GitHub severity (unrated is never hidden). `all` annotates everything.
 */
export function annotated(v, { all = false } = {}) {
  if (all || v.kev || v.imported?.length) return true;   // imported by your own Go code (READ-DEPS-6): always annotated
  if (v.dev) return false;
  const s = SEVERITY_RANK[v.severity] || 0;
  return s === 0 || s >= SEVERITY_RANK.HIGH;
}

/** queryOsv's result for one lockfile -> run-log lines and workflow warnings. PURE, so the wording is tested. */
export function depsOutput(lockPath, r, { scope = "pr", all = false } = {}) {
  if (r?.error) return { lines: [`slopGrade Firewall — dependency scan unavailable: ${r.error} — verdict unaffected.`], notices: [], warn: true };
  const skipped = r.skipped ? ` · ${r.skipped} more not checked (cap ${OSV_MAX_QUERIES.toLocaleString("en-US")})` : "";
  const nKev = r.vulnerable.filter((v) => v.kev).length;
  const kevNote = nKev ? `, ${nKev} of them actively exploited (CISA KEV)` : "";
  const what = scope === "repo" ? "version(s) pinned in this lockfile" : "version(s) this PR adds";
  const hidden = r.vulnerable.filter((v) => !annotated(v, { all })).length;
  const hiddenNote = hidden ? ` ${hidden} of them below HIGH or dev-only: listed here, not annotated (dependency-severity: "all" annotates them).` : "";
  const lines = [`slopGrade Firewall — dependency scan: ${lockPath} — ${r.vulnerable.length} of ${r.checked} ${what} have published advisories (OSV)${kevNote}${skipped}. Warnings only, never blocking.${hiddenNote}`];
  if (r.kevError) lines.push(`  (${r.kevError} — advisories shown without the exploited-in-the-wild priority)`);
  if (r.scanNote) lines.push(`  (${r.scanNote})`);
  const notices = [];
  for (const v of r.vulnerable) {
    const n = v.ids.length;
    const sev = v.severity ? ` (${v.severity})` : "";
    const imp = v.imported?.length ? ` — your code imports ${v.imported.join(", ")}` : "";
    if (annotated(v, { all })) {
      const title = v.kev ? "slopGrade dependency scan — actively exploited (CISA KEV)"
        : imp ? "slopGrade dependency scan — imported by your code" : "slopGrade dependency scan";
      const kev = v.kev ? ` — exploited in the wild: ${v.kev.join(", ")}` : "";
      notices.push(`::warning file=${ghProp(lockPath)},line=1,title=${title}::${ghMsg(`${v.name}@${v.version}${v.dev ? " (dev)" : ""} has ${n} published advisor${n === 1 ? "y" : "ies"}${sev}: ${v.ids.join(", ")}${kev}${imp} — https://osv.dev/vulnerability/${v.ids[0]}`)}`);
    }
    lines.push(`    - ${v.name}@${v.version}${v.dev ? " (dev)" : ""}  ${v.ids.join(" ")}${v.severity ? `  ${v.severity}` : ""}${v.kev ? `  KEV ${v.kev.join(" ")}` : ""}${v.imported?.length ? `  imported: ${v.imported.join(" ")}` : ""}`);
  }
  return { lines, notices, warn: false };
}
