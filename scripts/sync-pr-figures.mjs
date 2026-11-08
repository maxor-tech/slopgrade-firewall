#!/usr/bin/env node
// Rewrite the Deep Scan PR-replay sentence in every surface from benchmark-figures.json (the slopgrade harness export),
// and check that README.md / action.yml state what really blocks (benchmark-figures.json `blocking`, copied from the
// live catalog). Both are generated or checked, never typed : src/__tests__/deep-scan.test.mjs and
// src/__tests__/blocking-truth.test.mjs fail when a surface drifts from the file.
//   node scripts/sync-pr-figures.mjs            rewrite the PR-replay sentence in place, check the blocking phrases
//   node scripts/sync-pr-figures.mjs --check    exit 1 when a surface differs (no write)
//   node scripts/sync-pr-figures.mjs --catalog  refresh `blocking` from the live catalog, then run as above
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
export const SURFACES = ["README.md", "action.yml", "isolation-gate.mjs", ".github/workflows/slop-gate.yml"];
/** The surfaces that state who blocks on what (the free allocation and the paid slot). */
export const BLOCKING_SURFACES = ["README.md", "action.yml"];
const SENTENCE_RE = /\d[\d,]* ordinary open-source pull requests it blocked \d[\d,]*, \d[\d,]* of them for a real flaw/g;
/** Claims withdrawn on 2026-11-08 : the free allocation never blocked on 22 classes, a paid slot never on « every » class. */
export const STALE_BLOCKING_RE = /block[^.\n|]{0,80}the 22 OSS classes|the 22 OSS classes \*\*block|every calibrated class/i;
const CATALOG_URL = "https://app.slopgrade.ai/api/catalog";

/** Plain-English name of each blocking class (and kind) the catalog can return. A class missing here throws, so a
 *  catalog change forces a copy decision instead of a silent gap. */
const CLASS_NAMES = {
  accessControl: () => "cross-tenant",
  xss: (kinds) => {
    if (!kinds) return "XSS";
    if (kinds.length === 1 && kinds[0] === "php-echo") return "XSS in PHP output";
    throw new Error(`no copy for xss kinds ${kinds.join(",")}`);
  },
  timingUnsafeCompare: () => "timing-unsafe signature checks",
};

/** PURE. The sentence every surface carries, from the figures file. */
export function prSentence(f) {
  const n = (x) => Number(x).toLocaleString("en-US");
  return `${n(f.deep.replayedPrs)} ordinary open-source pull requests it blocked ${n(f.deep.blockedPrs)}, ${n(f.deep.justified)} of them for a real flaw`;
}

/** PURE. « cross-tenant + XSS in PHP output » from a blocking list ({key, kinds?}[]), in catalog order. */
export function blockingPhrase(list) {
  if (!Array.isArray(list) || !list.length) throw new Error("empty blocking list");
  return list.map(({ key, kinds }) => {
    const name = CLASS_NAMES[key];
    if (!name) throw new Error(`no copy for blocking class ${key} — add it to CLASS_NAMES`);
    return name(kinds);
  }).join(" + ");
}

/** PURE. The free and paid blocking lists from a catalog response ({classes:[{key, free, blocks, kinds?}]}). */
export function blockingFromCatalog(cat) {
  const pick = (c) => (c.kinds ? { key: c.key, kinds: c.kinds } : { key: c.key });
  const blocking = (cat?.classes ?? []).filter((c) => c.blocks);
  return { free: blocking.filter((c) => c.free).map(pick), paid: blocking.map(pick) };
}

/** PURE. Problems with one surface's blocking copy : missing phrases, or a withdrawn claim. */
export function blockingProblems(text, f) {
  const out = [];
  for (const [tier, list] of [["free", f.blocking.free], ["paid", f.blocking.paid]]) {
    const phrase = blockingPhrase(list);
    if (!text.includes(phrase)) out.push(`missing the ${tier} blocking phrase « ${phrase} »`);
  }
  const stale = text.match(STALE_BLOCKING_RE);
  if (stale) out.push(`withdrawn claim « ${stale[0]} »`);
  return out;
}

export function loadFigures() {
  return JSON.parse(readFileSync(join(ROOT, "benchmark-figures.json"), "utf8"));
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const check = process.argv.includes("--check");
  if (process.argv.includes("--catalog")) {
    const res = await fetch(CATALOG_URL);
    if (!res.ok) throw new Error(`${CATALOG_URL}: HTTP ${res.status}`);
    const figures = loadFigures();
    const next = blockingFromCatalog(await res.json());
    if (JSON.stringify(next) !== JSON.stringify({ free: figures.blocking.free, paid: figures.blocking.paid })) {
      figures.blocking = { ...figures.blocking, ...next, checked: new Date().toISOString().slice(0, 10) };
      writeFileSync(join(ROOT, "benchmark-figures.json"), JSON.stringify(figures, null, 2) + "\n");
      console.log("benchmark-figures.json: blocking lists refreshed from the catalog — update the copy if --check fails");
    }
  }
  const figures = loadFigures();
  const want = prSentence(figures);
  let drift = 0;
  for (const p of SURFACES) {
    const file = join(ROOT, p);
    const s = readFileSync(file, "utf8");
    const hits = s.match(SENTENCE_RE) ?? [];
    if (!hits.length) { console.error(`${p}: no PR-replay sentence found`); drift++; continue; }
    const out = s.replace(SENTENCE_RE, want);
    if (out !== s) {
      drift++;
      if (!check) writeFileSync(file, out);
      console.log(`${check ? "drift" : "updated"} ${p}`);
    }
  }
  // The blocking copy is prose around generated phrases : checked, never rewritten (a human words the sentence), so a
  // problem fails in both modes.
  let wrong = 0;
  for (const p of BLOCKING_SURFACES) {
    for (const problem of blockingProblems(readFileSync(join(ROOT, p), "utf8"), figures)) {
      console.error(`${p}: ${problem}`);
      wrong++;
    }
  }
  if (wrong || (check && drift)) process.exitCode = 1;
  else console.log(`PR-replay sentence: « ${want} » · free blocks on « ${blockingPhrase(figures.blocking.free)} »`);
}
