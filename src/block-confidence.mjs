import { readFileSync } from "node:fs";
import { join } from "node:path";

export const BLOCK_CONFIDENCE_SCHEMA = "heisen-block-confidence/v2";
export const BLOCK_CONFIDENCE_EXTRACTOR = "repo-aggregates/1";

// Verbatim training patterns. Python re.I uses Unicode word boundaries/digits and
// matches a dot against everything except LF; JavaScript's built-ins differ.
const OFF = String.raw`exploit|payload|webshell|shell|pentest|red.?team|scanner|recon|osint|c2\b|rat\b|backdoor|bypass|poc\b|cve|attack|ctf|hack|fuzz|brute`;
const TEACH = String.raw`course|tutorial|lesson|homework|assignment|exercise|student|bootcamp|learn|workshop|lab\d|week\d|day\d|example|demo|sample|practice`;
const offPattern = new RegExp(OFF.replaceAll(String.raw`\b`, String.raw`(?![\p{L}\p{N}_])`).replace(".?", "[^\\n]?"), "giu");
const teachPattern = new RegExp(TEACH.replaceAll(String.raw`\d`, String.raw`\p{Nd}`), "giu");

/** Pure training boundary: repoString is owner__name, README lengths are code points. */
export function extractRepoAggregates(repoString, readme = "") {
  const chars = [];
  for (const char of readme) {
    if (chars.length === 20_000) break;
    chars.push(char);
  }
  // Python also folds dotted/dotless I to ASCII i; JS /iu already handles long s and Kelvin K.
  const context = `${repoString} ${chars.slice(0, 3_000).join("")}`.replace(/[\u0130\u0131]/gu, "i");
  return {
    repo_off: [...context.matchAll(offPattern)].length,
    repo_teach: [...context.matchAll(teachPattern)].length,
    readme_len: Math.log1p(chars.length),
  };
}

/** Read the scanned working tree, not the base branch used by repo-purpose. */
export function readRepoAggregates(root, repository, read = readFileSync) {
  if (typeof repository !== "string" || !/^[^/\s]+\/[^/\s]+$/.test(repository)) {
    throw new Error("GITHUB_REPOSITORY must be owner/name");
  }
  let readme = "";
  for (const name of ["README.md", "readme.md", "README.rst", "README"]) {
    try {
      readme = read(join(root, name), "utf8");
      break; // The first existing file wins, including an empty README.
    } catch (error) {
      if (error?.code !== "ENOENT") throw error;
    }
  }
  return extractRepoAggregates(repository.replace("/", "__"), readme);
}

/** True only for an acknowledged v2 advisory score; malformed/skewed metadata keeps legacy blocking. */
export function applyBlockConfidence(row) {
  if (!row || typeof row !== "object") return false;
  const camel = Object.hasOwn(row, "blockConfidence"), snake = Object.hasOwn(row, "block_confidence");
  // Two competing acknowledgments are ambiguous, even if one would permit demotion.
  if (camel === snake) return false;
  const meta = camel ? row.blockConfidence : row.block_confidence;
  return !!meta && typeof meta === "object" && !Array.isArray(meta)
    && meta.schema === BLOCK_CONFIDENCE_SCHEMA
    && typeof meta.model === "string" && meta.model.trim().length > 0
    && meta.disposition === "ADVISORY"
    && Number.isFinite(meta.score) && meta.score >= 0 && meta.score <= 1
    && Number.isFinite(meta.tau) && meta.tau >= 0 && meta.tau <= 1
    && meta.score < meta.tau;
}
