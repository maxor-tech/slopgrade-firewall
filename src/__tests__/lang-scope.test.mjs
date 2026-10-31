// Precision fixes from the PR-replay benchmark (run2 labels re-checked on the current extractors, 2026-10-31) :
//   · a language rule fires only on its own files (lang-scope.mjs kindAppliesToFile) ;
//   · a packed / vendored single-file build is skipped (isPackedSource) ;
//   · a superglobal only COMPARED in a literal ternary is not echoed (xss) ;
//   · an http(s) fetch is not a local path, and a constant first argument is not a tainted path (path traversal).
// Each case pairs the wrong block that was removed with the true finding that must keep firing.
import { test } from "node:test";
import assert from "node:assert/strict";
import { isPackedSource, kindAppliesToFile } from "../lang-scope.mjs";
import { extractCmdi } from "../cmdi-extract.mjs";
import { extractPathTraversal } from "../pathtraversal-extract.mjs";
import { extractSqli } from "../sqli-extract.mjs";
import { extractXss } from "../xss-extract.mjs";

const kinds = (fn, src, file) => fn(src, new Map(), file).map((h) => h.kind);

test("a language rule applies only to its own file types; unknown files keep every rule", () => {
  assert.equal(kindAppliesToFile("ruby-exec", "app/models/user.rb"), true);
  assert.equal(kindAppliesToFile("ruby-exec", "src/ExcelExportOfTemplateUtil.java"), false);
  // JS / TS keep ruby-exec : `eval(params.code)` in a Next.js route handler reads the URL segments (server cmdi.test.ts)
  assert.equal(kindAppliesToFile("ruby-exec", "app/api/[code]/route.ts"), true);
  assert.equal(kindAppliesToFile("ruby-exec", "routes/x.js"), true);
  assert.equal(kindAppliesToFile("ruby-exec", "Templates/Eval.cs"), false);
  assert.equal(kindAppliesToFile("ruby-exec", "tmpl/eval.go"), false);
  assert.equal(kindAppliesToFile("ruby-exec", "x.javats"), false);   // a dot is required before the extension
  assert.equal(kindAppliesToFile("py-open", "maven/ParquetPhysicalReader.java"), false);
  assert.equal(kindAppliesToFile("php-echo", "views/index.phtml"), true);
  assert.equal(kindAppliesToFile("node-exec", "src/server.mts"), true);
  assert.equal(kindAppliesToFile("java-sql", "Repo.kt"), true);
  assert.equal(kindAppliesToFile("concat-sql", "anything.go"), true);   // no language prefix
  assert.equal(kindAppliesToFile("ruby-exec", undefined), true);         // no file name : unchanged behaviour
});

test("ruby-exec no longer fires on a Java template helper or a Python method call; Ruby still fires", () => {
  assert.deepEqual(kinds(extractCmdi, "    Object value = eval(params, map);", "ExcelExportOfTemplateUtil.java"), []);
  assert.deepEqual(kinds(extractCmdi, "        imesh = self.input.eval(params)", "normal.py"), []);
  assert.deepEqual(kinds(extractCmdi, "  result = eval(params[:expr])", "app/controllers/calc_controller.rb"), ["ruby-exec"]);
});

test("py-open no longer fires on Java; Python open(request…) still fires", () => {
  assert.deepEqual(kinds(extractPathTraversal, "            fileReader = open(request.uri(), new ParquetInputFile(inputFile));", "ParquetPhysicalReader.java"), []);
  assert.ok(kinds(extractPathTraversal, "    data = open(request.args['f']).read()", "app.py").includes("py-open"));
});

test("a packed single-file build is skipped; ordinary code with one long line is not", () => {
  const long = "x".repeat(600);
  const packed = Array.from({ length: 60 }, (_, i) => (i % 10 === 0 ? `$f->query("SELECT * FROM t WHERE id=".$_GET["id"]);${long}` : "a".repeat(170))).join("\n");
  assert.equal(isPackedSource(packed), true);
  assert.deepEqual(kinds(extractSqli, packed, "resources/adminer-5.0.4-en.php"), []);
  const normal = Array.from({ length: 60 }, (_, i) => (i === 5 ? `$r = mysqli_query($c, "SELECT * FROM t WHERE id=" . $_GET["id"]); // ${long}` : "$a = 1;")).join("\n");
  assert.equal(isPackedSource(normal), false);
  assert.ok(kinds(extractSqli, normal, "signin.php").length > 0);
  assert.equal(isPackedSource("a".repeat(5000)), false);   // too few lines to judge
});

test("an echoed superglobal that is only compared in a literal ternary is not XSS; a tainted branch still is", () => {
  assert.deepEqual(kinds(extractXss, 'echo $_GET["t"] == "d" ? "folder" : "file";', "shell.php"), []);
  assert.deepEqual(kinds(extractXss, "print $_POST['a'] === 1 ? 'y' : 'n';", "x.php"), []);
  assert.deepEqual(kinds(extractXss, 'echo $_GET["t"];', "x.php"), ["php-echo"]);
  assert.deepEqual(kinds(extractXss, 'echo $_GET["t"] == "d" ? $_GET["x"] : "file";', "x.php"), ["php-echo"]);
});

test("an http(s) fetch is not a local path; include of a URL and a local read still fire", () => {
  assert.deepEqual(kinds(extractPathTraversal, "$v = file_get_contents('https://hcaptcha.com/siteverify?secret=' . $s . '&response=' . $_POST['h']);", "functions.php"), []);
  assert.deepEqual(kinds(extractPathTraversal, "include('http://x.example/' . $_GET['p']);", "f.php"), ["php-include"]);
  assert.deepEqual(kinds(extractPathTraversal, "$c = file_get_contents($_GET['f']);", "f.php"), ["php-include"]);
});

test("a constant first argument is not a tainted path; a tainted, template or concatenated path still fires", () => {
  const wrap = (body) => `app.post('/q', (req, res) => {\n  ${body.join("\n  ")}\n});`;
  assert.deepEqual(kinds(extractPathTraversal, wrap(["const QRcode = req.body.code;", "fs.writeFile('views/code.txt', QRcode, (e) => {});"]), "server.js"), []);
  for (const call of ["fs.writeFile(p, 'x', (e) => {});", "fs.writeFile(`up/${p}`, 'x', (e) => {});", "fs.writeFile('up/' + p, 'x', (e) => {});"]) {
    assert.deepEqual(kinds(extractPathTraversal, wrap(["const p = req.body.path;", call]), "server.js"), ["taint-path"], call);
  }
});
