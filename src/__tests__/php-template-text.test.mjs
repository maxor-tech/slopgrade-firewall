// A .php file is template text with <?php … ?> code blocks. The PHP direct rules read only the code (lang-scope.mjs
// phpCodeLines) : CSS `expression(eval(…))` around a PHP echo is not a PHP eval (PR-replay labels 2026-10-31 :
// phpMyAdmin archived themes theme_right.css.php, 3 wrong cmdi blocks). Each case pairs the removed wrong block with
// the true finding that must keep firing.
import { test } from "node:test";
import assert from "node:assert/strict";
import { phpCodeLines } from "../lang-scope.mjs";
import { extractCmdi } from "../cmdi-extract.mjs";

const kindsAt = (src, file, line) => extractCmdi(src, new Map(), file).filter((h) => h.line === line).map((h) => h.kind);

test("CSS eval() around a PHP echo of a superglobal is not a PHP eval", () => {
  const src = [
    "<?php header('Content-Type: text/css'); ?>",
    "#frame {",
    "  top: expression(eval(document.documentElement.scrollTop<?php echo (stristr($_GET['type'], 'querywin') ? '' : '+27'); ?>));",
    "}",
  ].join("\n");
  assert.deepEqual(kindsAt(src, "themes/x/css/theme_right.css.php", 3), []);
});

test("CONTROL : a real sink inside an inline block of an HTML line still fires", () => {
  const src = ["<html><body>", "<div><?php system($_GET['cmd']); ?></div>", "</body></html>"].join("\n");
  assert.deepEqual(kindsAt(src, "page.php", 2), ["php-exec"]);
});

test("CONTROL : a ?> inside a quoted string does not close the block", () => {
  const src = ["<?php", "echo \"<?xml version='1.0'?>\"; shell_exec($_POST['c']);"].join("\n");
  assert.deepEqual(kindsAt(src, "feed.php", 2), ["php-exec"]);
});

test("CONTROL : a sink in a multi-line block keeps firing", () => {
  const src = ["<p>title</p>", "<?php", "$x = 1;", "eval($_REQUEST['code']);", "?>", "<p>end</p>"].join("\n");
  assert.deepEqual(kindsAt(src, "run.php", 4), ["php-exec"]);
});

test("phpCodeLines keeps the line count and columns, and leaves a file with no opener unchanged", () => {
  const lines = ["a <?php b(); ?> c", "d"];
  const code = phpCodeLines(lines);
  assert.equal(code.length, 2);
  assert.equal(code[0].length, lines[0].length);
  assert.equal(code[0], "  <?php b(); ?>  ");
  assert.equal(code[1], " ");
  assert.equal(phpCodeLines(["eval($x);"])[0], "eval($x);");
});
