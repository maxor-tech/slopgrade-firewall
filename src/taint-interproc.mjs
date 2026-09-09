// SHIM — OSS édition. API-compatible avec le moteur inter-procédural du produit
// hébergé, mais SANS la passe interprocédurale/cross-file : chaque
// fonction retourne un résultat "vide" de la bonne forme, si bien que les détecteurs
// phares (sqli/cmdi/xss/ssrf/pathtraversal) tournent en mode INTRA-FONCTION uniquement
// (via taint-core.mjs, qui reste OSS). C'est le "shallow but working" du tier gratuit :
//   • findSinkWrappers → Map vide      ⇒ la branche inter-proc du détecteur est sautée
//   • interprocHit     → false         ⇒ aucun hit inter-proc/cross-file
//   • buildWrapperRegistries → {}      ⇒ aucun registre cross-file construit par le harnais
//   • resolveImportedWrappers → Map vide ⇒ la branche cross-file du détecteur est sautée
//
// La détection cross-fonction + cross-fichier (le craft) est la valeur payante : l'édition
// hébergée passe les MÊMES détecteurs à travers le vrai taint-interproc. Aucun seuil,
// aucun corpus, aucune méthode de calibration n'est présent ici.
//
// Les helpers de parsing (parseParams/splitArgs/splitFunctions/resolveModuleSpec/
// parseImports) sont fournis en implémentations minimales : ils ne servent, dans la suite
// OSS, qu'à alimenter la passe inter-proc — désactivée ici — donc leur sortie n'est jamais
// consommée. Ils gardent une signature honnête plutôt qu'un throw, pour que tout import
// existant résolve sans erreur.

/** @returns {string[]} noms de paramètres (best-effort, non utilisé par la passe OSS). */
export function parseParams(s) {
  if (typeof s !== "string" || !s.trim()) return [];
  return s.split(",").map((p) => p.trim().split(/[:\s=]/)[0]).filter(Boolean);
}

/** @returns {string[]} arguments d'appel (best-effort, non utilisé par la passe OSS). */
export function splitArgs(s) {
  if (typeof s !== "string" || !s.trim()) return [];
  return s.split(",").map((a) => a.trim()).filter(Boolean);
}

/** @returns {Array} aucune fonction extraite (pas de passe inter-proc en OSS). */
export function splitFunctions(_lines) {
  return [];
}

/** Wrappers de sink locaux — OSS : aucun ⇒ la branche inter-proc du détecteur est inerte.
 *  @returns {Map<string, Set<number>>} */
export function findSinkWrappers(_lines, _cfg) {
  return new Map();
}

/** Hit inter-proc/cross-file — OSS : jamais (intra-fonction seulement).
 *  @returns {boolean} */
export function interprocHit(_line, _wrappers, _argIsDangerous) {
  return false;
}

/** @returns {string|null} résolution de module — OSS : non résolu (pas de cross-file). */
export function resolveModuleSpec(_fromFile, _spec, _lang) {
  return null;
}

/** @returns {Array<{spec:string, names:string[]}>} imports — OSS : ignorés. */
export function parseImports(_text) {
  return [];
}

/** @returns {Map<string, Map<string, Set<number>>>} registre — OSS : vide. */
export function buildWrapperRegistry(_files, _cfg) {
  return new Map();
}

/** @returns {Record<string, Map<string, Map<string, Set<number>>>>} registres par gate — OSS : {}.
 *  resolveImportedWrappers tolère un registre absent/undefined et rend une Map vide. */
export function buildWrapperRegistries(_files, _cfgs) {
  return {};
}

/** @returns {Map<string, Set<number>>} wrappers importés résolus — OSS : toujours vide,
 *  quel que soit le registre (y compris undefined venant de buildWrapperRegistries → {}). */
export function resolveImportedWrappers(_text, _fromFile, _registry) {
  return new Map();
}
