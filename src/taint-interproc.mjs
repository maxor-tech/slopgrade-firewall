// SHIM — OSS edition. API-compatible with the hosted product's inter-procedural
// engine, but WITHOUT the interprocedural/cross-file pass: every function returns
// an "empty" result of the correct shape, so the flagship detectors
// (sqli/cmdi/xss/ssrf/pathtraversal) run in INTRA-FUNCTION mode only
// (via taint-core.mjs, which stays OSS). This is the free tier's "shallow but working":
//   • findSinkWrappers → empty Map     ⇒ the detector's inter-proc branch is skipped
//   • interprocHit     → false         ⇒ no inter-proc/cross-file hit
//   • buildWrapperRegistries → {}      ⇒ no cross-file registry is built by the harness
//   • resolveImportedWrappers → empty Map ⇒ the detector's cross-file branch is skipped
//
// Cross-function + cross-file detection (the craft) is the paid value: the hosted
// edition runs the SAME detectors through the real taint-interproc. No thresholds,
// no corpus, no calibration method is present here.
//
// The parsing helpers (parseParams/splitArgs/splitFunctions/resolveModuleSpec/
// parseImports) are provided as minimal implementations: in the OSS build they only
// feed the inter-proc pass — disabled here — so their output is never consumed. They
// keep an honest signature rather than throwing, so any existing import resolves
// without error.

/** @returns {string[]} parameter names (best-effort, unused by the OSS pass). */
export function parseParams(s) {
  if (typeof s !== "string" || !s.trim()) return [];
  return s.split(",").map((p) => p.trim().split(/[:\s=]/)[0]).filter(Boolean);
}

/** @returns {string[]} call arguments (best-effort, unused by the OSS pass). */
export function splitArgs(s) {
  if (typeof s !== "string" || !s.trim()) return [];
  return s.split(",").map((a) => a.trim()).filter(Boolean);
}

/** @returns {Array} no functions extracted (no inter-proc pass in OSS). */
export function splitFunctions(_lines) {
  return [];
}

/** Local sink wrappers — OSS: none ⇒ the detector's inter-proc branch is inert.
 *  @returns {Map<string, Set<number>>} */
export function findSinkWrappers(_lines, _cfg) {
  return new Map();
}

/** Inter-proc/cross-file hit — OSS: never (intra-function only).
 *  @returns {boolean} */
export function interprocHit(_line, _wrappers, _argIsDangerous) {
  return false;
}

/** @returns {string|null} module resolution — OSS: unresolved (no cross-file). */
export function resolveModuleSpec(_fromFile, _spec, _lang) {
  return null;
}

/** @returns {Array<{spec:string, names:string[]}>} imports — OSS: ignored. */
export function parseImports(_text) {
  return [];
}

/** @returns {Map<string, Map<string, Set<number>>>} registry — OSS: empty. */
export function buildWrapperRegistry(_files, _cfg) {
  return new Map();
}

/** @returns {Record<string, Map<string, Map<string, Set<number>>>>} per-gate registries — OSS: {}.
 *  resolveImportedWrappers tolerates an absent/undefined registry and returns an empty Map. */
export function buildWrapperRegistries(_files, _cfgs) {
  return {};
}

/** @returns {Map<string, Set<number>>} resolved imported wrappers — OSS: always empty,
 *  whatever the registry (including undefined coming from buildWrapperRegistries → {}). */
export function resolveImportedWrappers(_text, _fromFile, _registry) {
  return new Map();
}
