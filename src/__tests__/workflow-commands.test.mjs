// GitHub workflow commands separate properties with COMMAS : `::warning file=a.py,line=8,title=T::msg`. A space before
// `title=` made GitHub read `line` as « 8 title=T » → every annotation landed on line 0 with no title, so none showed
// inline on the diff (e2e 2026-10-27, slopgrade-gate-e2e#9 : app/files.py#L0). These tests keep it from coming back.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { parseWorkflowCommand } from "./_workflow-command.mjs";

test("parseWorkflowCommand reads a well-formed command and flags the space-separated one", () => {
  assert.deepEqual(parseWorkflowCommand("::warning file=a.py,line=8,title=slopGrade Firewall::x"),
    { level: "warning", props: { file: "a.py", line: "8", title: "slopGrade Firewall" } });
  // The old shape : `line` swallows the title, so it is not an integer.
  assert.equal(parseWorkflowCommand("::warning file=a.py,line=8 title=slopGrade Firewall::x").props.line, "8 title=slopGrade Firewall");
});

test("every file+line annotation in isolation-gate.mjs separates its properties with commas", () => {
  const src = readFileSync(new URL("../../isolation-gate.mjs", import.meta.url), "utf8");
  const sites = src.match(/::\$\{[^}]+\}[^`]*?file=\$\{[^}]+\},line=\$\{[^}]+\}[ ,]title=|::(?:error|warning|notice) file=\$\{[^}]+\},line=\$\{[^}]+\}[ ,]title=/g) ?? [];
  assert.equal(sites.length, 5, "the five file+line annotation sites (cross-tenant, pack, deep scan, library, change review)");
  for (const s of sites) assert.ok(s.endsWith(",title="), `space-separated title in: ${s}`);
});
