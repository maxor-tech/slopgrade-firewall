// Dependency scan (0.18.0): match the package versions a pull request ADDS (deps-lock.mjs) against OSV
// (https://osv.dev, the open advisory database behind GitHub, PyPI and npm advisories). The call goes from the runner
// to api.osv.dev; slopGrade sees nothing. What is sent: {ecosystem, name, version} of public-registry packages only.
//
// Measured (slopGrade release run, PREREG-DEPS-1, ledger READ-DEPS-1): 1,750 of 52,534 replayed pull requests changed a
// package-lock.json; 366 of them (20.9 %) added a version whose advisory was ALREADY published when the PR was made
// (13.5 % of lockfile bumps, 65.5 % of new lockfiles). Warnings to triage, never blocking; any failure prints one
// warning and the gate goes on (fail open).

export const OSV_URL = "https://api.osv.dev/v1/querybatch";
export const OSV_BATCH = 1000;          // OSV's querybatch limit
export const OSV_MAX_QUERIES = 5000;    // per run: a new monorepo lockfile is ~300 versions (median), the largest few thousand
export const OSV_TIMEOUT_MS = 30_000;

/**
 * deps ([{eco, name, version}]) -> { vulnerable: [{name, version, ids}], checked, skipped } or { error }. Never throws.
 * A malformed or failed answer is an error, never « no advisory ».
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
        body: JSON.stringify({ queries: chunk.map((d) => ({ package: { name: d.name, ecosystem: "npm" }, version: d.version })) }),
        signal: AbortSignal.timeout(timeoutMs),
      });
      if (!res.ok) return { error: `OSV HTTP ${res.status}` };
      const body = await res.json().catch(() => null);
      if (!body || !Array.isArray(body.results) || body.results.length !== chunk.length) return { error: "malformed answer from OSV" };
      chunk.forEach((d, k) => {
        const ids = (body.results[k]?.vulns || []).map((v) => v?.id).filter((x) => typeof x === "string").slice(0, 20);
        if (ids.length) vulnerable.push({ name: d.name, version: d.version, ids });
      });
    }
  } catch (e) {
    return { error: e?.name === "TimeoutError" ? "OSV did not answer in time" : `OSV call failed (${e?.message || e})` };
  }
  return { vulnerable, checked: list.length, skipped: all.length - list.length };
}

const ghProp = (s) => String(s).replace(/[\r\n]/g, " ").replace(/%/g, "%25").replace(/:/g, "%3A").replace(/,/g, "%2C");
const ghMsg = (s) => String(s).replace(/%/g, "%25").replace(/[\r\n]+/g, " ");

/** queryOsv's result for one lockfile -> run-log lines and workflow warnings. PURE, so the wording is tested. */
export function depsOutput(lockPath, r) {
  if (r?.error) return { lines: [`slopGrade Firewall — dependency scan unavailable: ${r.error} — verdict unaffected.`], notices: [], warn: true };
  const skipped = r.skipped ? ` · ${r.skipped} more not checked (cap ${OSV_MAX_QUERIES.toLocaleString("en-US")})` : "";
  const lines = [`slopGrade Firewall — dependency scan: ${lockPath} — ${r.vulnerable.length} of ${r.checked} version(s) this PR adds have published advisories (OSV)${skipped}. Warnings only, never blocking.`];
  const notices = [];
  for (const v of r.vulnerable) {
    const n = v.ids.length;
    notices.push(`::warning file=${ghProp(lockPath)},line=1,title=slopGrade dependency scan::${ghMsg(`${v.name}@${v.version} has ${n} published advisor${n === 1 ? "y" : "ies"}: ${v.ids.join(", ")} — https://osv.dev/vulnerability/${v.ids[0]}`)}`);
    lines.push(`    - ${v.name}@${v.version}  ${v.ids.join(" ")}`);
  }
  return { lines, notices, warn: false };
}
