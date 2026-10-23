// 0.11.1 — the README is the GitHub Marketplace listing page : its Quick start is the snippet people copy first. It must
// pin the CURRENT release (a release that forgets the README fails here), use a real ref (never the `<sha>` placeholder),
// and carry the one permission the client cannot run without (`id-token: write` — the OIDC proof of the repo).
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const readme = readFileSync(new URL("../../README.md", import.meta.url), "utf8");
const pkg = JSON.parse(readFileSync(new URL("../../package.json", import.meta.url), "utf8"));
const start = readme.indexOf("## Quick start");
const quick = readme.slice(start, readme.indexOf("\n## ", start + 1));

test("Quick start pins the current release and is copy-paste runnable", () => {
  assert.ok(start > 0, "the README has a Quick start section");
  assert.ok(start < readme.indexOf("## Add it to your repo"), "Quick start comes before the full options");
  assert.match(quick, new RegExp(`uses: maxor-tech/slopgrade-firewall@v${pkg.version.replace(/\./g, "\\.")}\\n`));
  assert.doesNotMatch(quick, /<sha>/, "a placeholder ref fails on copy-paste");
  assert.match(quick, /id-token: write/);
  assert.match(quick, /on: \{ pull_request: \{\} \}/);
});

test("links to slopgrade.ai from the listing carry UTM tags (Plausible attributes the channel, no pixel)", () => {
  const head = readme.slice(0, start);
  for (const url of head.match(/https:\/\/www\.slopgrade\.ai\/pricing[^)\s]*/g) ?? []) {
    assert.match(url, /utm_source=github&utm_medium=readme&utm_campaign=firewall-action/);
  }
});
