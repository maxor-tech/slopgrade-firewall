#!/usr/bin/env node
// Rewrite the Deep Scan PR-replay sentence in every surface from benchmark-figures.json (the slopgrade harness export).
// The sentence is generated, never typed : src/__tests__/deep-scan.test.mjs fails when a surface drifts from the file.
//   node scripts/sync-pr-figures.mjs          rewrite in place
//   node scripts/sync-pr-figures.mjs --check  exit 1 when a surface differs (no write)
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
export const SURFACES = ["README.md", "action.yml", "isolation-gate.mjs", ".github/workflows/slop-gate.yml"];
const SENTENCE_RE = /\d[\d,]* ordinary open-source pull requests it blocked \d[\d,]*, \d[\d,]* of them for a real flaw/g;

/** PURE. The sentence every surface carries, from the figures file. */
export function prSentence(f) {
  const n = (x) => Number(x).toLocaleString("en-US");
  return `${n(f.deep.replayedPrs)} ordinary open-source pull requests it blocked ${n(f.deep.blockedPrs)}, ${n(f.deep.justified)} of them for a real flaw`;
}

export function loadFigures() {
  return JSON.parse(readFileSync(join(ROOT, "benchmark-figures.json"), "utf8"));
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const want = prSentence(loadFigures());
  const check = process.argv.includes("--check");
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
  if (check && drift) process.exitCode = 1;
  else console.log(`PR-replay sentence: « ${want} »`);
}
