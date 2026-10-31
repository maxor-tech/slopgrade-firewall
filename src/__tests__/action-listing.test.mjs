// The GitHub Marketplace listing is built from action.yml (name, description, branding) and the README. It is a public
// claim : the description must fit the Marketplace limit (125 characters) and must say « by default » — the opt-in
// deep scan sends source, so an unqualified « source never leaves your runner » is false.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const action = readFileSync(new URL("../../action.yml", import.meta.url), "utf8");
const readme = readFileSync(new URL("../../README.md", import.meta.url), "utf8");

test("action.yml carries what the Marketplace listing needs", () => {
  assert.match(action, /^name: "slopGrade Firewall"$/m);
  assert.match(action, /^author: "Maxor Global LLC"$/m);
  assert.match(action, /^branding: \{ icon: "shield", color: "green" \}$/m);
});

test("the listing description fits 125 characters and qualifies the source claim with « by default »", () => {
  const description = /^description: "([^"]*)"$/m.exec(action)?.[1];
  assert.equal(description, "Blocks cross-tenant leaks, injection and secrets a pull request introduces. By default, source never leaves your runner.");
  assert.ok(description.length <= 125, `${description.length} characters`);
});

test("the README's link to the site is attributed to the Marketplace listing", () => {
  assert.ok(readme.includes("https://www.slopgrade.ai/firewall?utm_source=github-marketplace&utm_medium=listing&utm_campaign=launch-v3"));
  assert.doesNotMatch(readme.split("\n").slice(0, 8).join("\n"), /(?<!By default, your )source code and file contents never leave/);
});
