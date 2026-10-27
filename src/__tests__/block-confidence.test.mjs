import { test } from "node:test";
import assert from "node:assert/strict";
import { basename, join } from "node:path";
import { mkdtempSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { extractRepoAggregates, readRepoAggregates, applyBlockConfidence, BLOCK_CONFIDENCE_SCHEMA } from "../block-confidence.mjs";

test("aggregate counts are case-insensitive, non-overlapping, and retain trailing newlines", () => {
  assert.deepEqual(extractRepoAggregates("o__service", "WEBshell payload tutorial lab2\n"), {
    repo_off: 2, repo_teach: 2, readme_len: Math.log1p(31),
  });
  assert.deepEqual(extractRepoAggregates("o__service"), { repo_off: 0, repo_teach: 0, readme_len: 0 });
});

test("owner__name preserves the training word boundary, including Unicode alphanumerics", () => {
  assert.equal(extractRepoAggregates("poc__service").repo_off, 0);
  assert.equal(extractRepoAggregates("poc/service").repo_off, 1);
  assert.equal(extractRepoAggregates("o__poc").repo_off, 1);
  assert.equal(extractRepoAggregates("", "pocé rat中 c2² poc_ poc! rat- c2.").repo_off, 3);
  assert.equal(extractRepoAggregates("", "poc\u0301").repo_off, 1, "Python combining marks are not word characters");
});

test("Python Unicode digits, case folding and dot semantics survive the JS port", () => {
  assert.equal(extractRepoAggregates("", "lab٣ week４ day2").repo_teach, 3);
  assert.equal(extractRepoAggregates("", "OＳINT").repo_off, 0, "fullwidth letters are not ASCII case folds");
  assert.equal(extractRepoAggregates("", "OSİNT oſınt hacK").repo_off, 3);
  assert.equal(extractRepoAggregates("", "red\rteam red\u2028team red\nteam").repo_off, 2);
});

test("README slices count code points at both 3000 and 20000, never UTF-16 units", () => {
  const readme = "😀".repeat(2995) + "shell" + " tutorial" + "😀".repeat(20000);
  assert.deepEqual(extractRepoAggregates("o__r", readme), { repo_off: 1, repo_teach: 0, readme_len: Math.log1p(20000) });
  assert.equal(extractRepoAggregates("o__r", "😀\n").readme_len, Math.log1p(2));
  assert.equal(extractRepoAggregates("", " ".repeat(2998) + "shell").repo_off, 0);
});

test("README lookup uses the first existing file, even empty; missing files mean empty text", () => {
  const order = ["README.md", "readme.md", "README.rst", "README"];
  for (let first = 0; first <= order.length; first++) {
    const calls = [];
    const read = (path, encoding) => {
      assert.equal(encoding, "utf8");
      const name = basename(path); calls.push(name);
      if (order.indexOf(name) < first) throw Object.assign(new Error("absent"), { code: "ENOENT" });
      return name === order[first] ? "" : "shell tutorial";
    };
    assert.deepEqual(readRepoAggregates("checkout", "poc/service", read), { repo_off: 0, repo_teach: 0, readme_len: 0 });
    assert.deepEqual(calls, order.slice(0, Math.min(first + 1, 4)));
  }
  assert.throws(() => readRepoAggregates(".", "bad"), /owner\/name/);
  assert.throws(() => readRepoAggregates(".", "o/r", () => { throw Object.assign(new Error("denied"), { code: "EACCES" }); }), /denied/);
});

test("working-tree README is decoded as UTF-8 with replacement and read without newline translation", () => {
  const root = mkdtempSync(join(tmpdir(), "sg-bc-readme-"));
  writeFileSync(join(root, "README.rst"), Buffer.concat([Buffer.from("shell\r\n😀"), Buffer.from([0xff])]));
  assert.deepEqual(readRepoAggregates(root, "o/r"), { repo_off: 1, repo_teach: 0, readme_len: Math.log1p(9) });
});

const advisory = { schema: BLOCK_CONFIDENCE_SCHEMA, model: "synthetic-v2", disposition: "ADVISORY", score: 0.2, tau: 0.45 };
test("only valid ADVISORY metadata below tau demotes; aliases work and ambiguity fails closed", () => {
  for (const key of ["blockConfidence", "block_confidence"]) {
    assert.equal(applyBlockConfidence({ [key]: advisory }), true);
    for (const bad of [null, [], "ADVISORY", {}, { ...advisory, schema: "v1" }, { ...advisory, model: "" },
      { ...advisory, model: null }, { ...advisory, disposition: "BLOCKING" }, { ...advisory, disposition: "advisory" },
      ...[-1, 1.01, NaN, Infinity, "0.2", null, undefined, 0.45, 0.7].map((score) => ({ ...advisory, score })),
      ...[-1, 1.01, NaN, Infinity, "0.45", null, undefined].map((tau) => ({ ...advisory, tau }))]) {
      assert.equal(applyBlockConfidence({ [key]: bad }), false, JSON.stringify(bad));
    }
  }
  for (const row of [null, {}, { blockConfidence: advisory, block_confidence: advisory },
    { blockConfidence: null, block_confidence: advisory }]) assert.equal(applyBlockConfidence(row), false);
});

test("Action wires block-confidence as an ON-by-default input and CLI flag", () => {
  const action = readFileSync(new URL("../../action.yml", import.meta.url), "utf8");
  assert.match(action, /  block-confidence:\r?\n(?:.*\r?\n){2}    default: "true"/);
  assert.ok(action.includes("FW_BLOCK_CONFIDENCE: $" + "{{ inputs.block-confidence }}"));
  assert.ok(action.includes('[ "$' + '{FW_BLOCK_CONFIDENCE}" = "true" ] && ARGS+=(--block-confidence)'));
});
