// heisen deep scan — OPT-IN (`deep-scan: true` / --deep-scan), paid repos only. PURE helpers; the network call is
// injected so every boundary here is unit-testable.
//
// THIS IS THE ONE PATH THAT SENDS SOURCE. The default Firewall run never does (structural fingerprint only). With the
// deep scan enabled, the CONTENTS of a bounded set of files are POSTed to the canonical slopGrade origin
// (/api/ci/heisen), which forwards them to the hosted heisen-slop taint engine and drops them (never logged, never
// persisted). Which files: only those where the free extractors already saw a security sink — the files a request→sink
// flow can live in — capped at DEEP_MAX_UNITS files / DEEP_MAX_TOTAL_CHARS characters. `--print-payload` lists them.
//
// ADVISORY: the server returns `blocking: 0` while the engine is in its calibration window, so these findings annotate
// as warnings and never fail the check.

export const DEEP_SCAN_EXTS = /\.(py|js|jsx|mjs|cjs|ts|tsx|go|java|rb)$/i;
export const DEEP_MAX_UNITS = 40;
export const DEEP_MAX_UNIT_CHARS = 200_000;
export const DEEP_MAX_TOTAL_CHARS = 2_000_000;

/** Paths (repo-relative) of every file a pack fingerprint recorded hits for — the sink-bearing files. Sorted. */
export function sinkFiles(packFingerprints) {
  const out = new Set();
  for (const fp of Object.values(packFingerprints || {})) {
    for (const f of Array.isArray(fp?.files) ? fp.files : []) {
      if (typeof f?.file === "string" && f.file && Array.isArray(f.hits) && f.hits.length) out.add(f.file);
    }
  }
  return [...out].sort();
}

/**
 * The units to send: sink-bearing files with an engine-modelled extension, read via `read(path)` (null = unreadable),
 * skipping empty / oversize files, stopping at the file and character caps. `skipped` counts the files left out so the
 * log can say the scan was bounded instead of implying full coverage.
 */
export function selectDeepUnits(paths, read) {
  const units = [];
  let total = 0, skipped = 0;
  for (const path of paths) {
    if (!DEEP_SCAN_EXTS.test(path)) continue;
    if (units.length >= DEEP_MAX_UNITS) { skipped++; continue; }
    let code = null;
    try { code = read(path); } catch { code = null; }
    if (typeof code !== "string" || !code || code.length > DEEP_MAX_UNIT_CHARS || total + code.length > DEEP_MAX_TOTAL_CHARS) { skipped++; continue; }
    total += code.length;
    units.push({ path, code });
  }
  return { units, skipped, chars: total };
}

/** Shape check of the server answer; anything else is treated as no answer (fail open). */
export function validHeisenResponse(j) {
  if (!j || typeof j !== "object" || j.ok !== true || !Array.isArray(j.findings)) return false;
  if (typeof j.scanned !== "number" || typeof j.unanswered !== "number") return false;
  return j.findings.every((f) => f && typeof f.path === "string" && typeof f.cwe === "string" && /^CWE-\d{1,5}$/.test(f.cwe)
    && typeof f.p === "number" && typeof f.evidence === "string");
}

/** The sink line from the engine evidence ("… reaches os.system() at line 7 …"), else the first source line, else 1. */
export function evidenceLine(evidence) {
  const m = /reaches .*? at line (\d+)/.exec(evidence) || /at line (\d+)/.exec(evidence);
  const n = m ? Number(m[1]) : 1;
  return Number.isInteger(n) && n > 0 ? n : 1;
}

/**
 * Findings → the normalized feed rows the log / PR review / SARIF already consume. Only paths THIS run sent are kept
 * (a server answer can never place an annotation on a file we did not scan). Severity "medium" = advisory: the feed
 * counts critical|high as blocking, and the deep scan never blocks while it is uncalibrated.
 */
export function heisenFeed(findings, sentPaths) {
  const sent = new Set(sentPaths);
  return findings.filter((f) => sent.has(f.path)).map((f) => ({
    file: f.path, line: evidenceLine(f.evidence), pack: "heisen", rule: f.cwe, detail: f.evidence, severity: "medium",
  }));
}

/**
 * POST the units; `post(url, body)` → {status, json()} is injected (timedFetch in the client). Returns
 * {state: "ok", response} | {state: "plan-required"} | {state: "unavailable", status?} — never throws.
 */
export async function requestDeepScan(post, origin, oidcToken, sha, units) {
  try {
    const res = await post(`${origin}/api/ci/heisen`, JSON.stringify({ oidcToken, sha, units }));
    if (res.status === 402) return { state: "plan-required" };
    if (res.status < 200 || res.status >= 300) return { state: "unavailable", status: res.status };
    const j = await res.json();
    return validHeisenResponse(j) ? { state: "ok", response: j } : { state: "unavailable", status: "malformed" };
  } catch {
    return { state: "unavailable", status: "network" };
  }
}
