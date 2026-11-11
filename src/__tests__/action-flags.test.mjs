// Every flag the Action passes to the CLI (action.yml, `ARGS+=(…)`) is a flag the CLI knows. `--dependency-scan` was
// added to the Action without it, so every default run printed « unknown flag --dependency-scan ignored (see --help) ».
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { main } from "../../isolation-gate.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const actionFlags = () => [...new Set([...readFileSync(join(ROOT, "action.yml"), "utf8").matchAll(/ARGS\+=\(([^)]*)\)/g)].flatMap((m) => m[1].split(/\s+/).filter((t) => /^--[a-z-]+$/.test(t))))];

/** Outside CI, `--print-payload` scans the (empty) directory, prints the payload and returns: no network. */
async function cliOutput(flags) {
  const dir = mkdtempSync(join(tmpdir(), "fw-flags-"));
  const realLog = console.log; const out = [];
  console.log = (...a) => out.push(a.join(" "));
  try { await main([...flags, "--print-payload"], { GITHUB_WORKSPACE: dir }); } finally { console.log = realLog; rmSync(dir, { recursive: true, force: true }); }
  return out.join("\n");
}

test("the Action passes flags, and the list is read from action.yml", () => {
  const flags = actionFlags();
  for (const f of ["--gate", "--deep-scan", "--ai-review", "--dependency-scan"]) assert.ok(flags.includes(f), `${f} is passed by action.yml`);
  assert.ok(flags.length >= 12, `expected the full flag list, got ${flags.length}`);
});

test("no flag the Action passes is reported as unknown", async () => {
  const text = await cliOutput(actionFlags().filter((f) => f !== "--sarif"));
  assert.doesNotMatch(text, /unknown flag/);
});

test("control: a flag that does not exist is still named", async () => {
  assert.match(await cliOutput(["--no-such-flag"]), /unknown flag --no-such-flag ignored \(see --help\)/);
});

test("--help lists every flag the Action passes", async () => {
  const realLog = console.log; const out = [];
  console.log = (...a) => out.push(a.join(" "));
  try { await main(["--help"], {}); } finally { console.log = realLog; }
  const help = out.join("\n");
  for (const f of actionFlags()) assert.ok(help.includes(f), `${f} is missing from --help`);
});
