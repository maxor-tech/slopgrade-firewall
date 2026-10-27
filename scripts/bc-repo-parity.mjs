#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { extractRepoAggregates } from "../src/block-confidence.mjs";

try {
  if (process.argv.length !== 3) throw new Error("Usage: node scripts/bc-repo-parity.mjs <fixture.json>");
  const rows = JSON.parse(readFileSync(process.argv[2], "utf8"));
  if (!Array.isArray(rows) || !rows.length) throw new Error("Fixture must be a nonempty array");
  let passed = 0;
  for (const [index, row] of rows.entries()) {
    if (!row || typeof row.repo_string !== "string" || typeof row.readme !== "string") {
      throw new Error("Malformed fixture row " + (index + 1));
    }
    const actual = extractRepoAggregates(row.repo_string, row.readme);
    const matches = actual.repo_off === row.repo_off && actual.repo_teach === row.repo_teach
      && Number.isFinite(row.readme_len) && Math.abs(actual.readme_len - row.readme_len) <= 1e-9;
    if (matches) passed++;
    else console.error("Mismatch row " + (index + 1) + ": expected " + JSON.stringify({ repo_off: row.repo_off, repo_teach: row.repo_teach, readme_len: row.readme_len }) + "; got " + JSON.stringify(actual));
  }
  console.log(passed + "/" + rows.length + " exact (repo_off/repo_teach exact; readme_len tolerance 1e-9)");
  process.exitCode = passed === rows.length ? 0 : 1;
} catch (error) {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
}
