// Benchmark 2026-10-24 (dev split): a prepared statement's `->execute([...])` binds VALUES — a superglobal there is not SQL text.
import { test } from "node:test";
import assert from "node:assert/strict";
import { extractSqli } from "../sqli-extract.mjs";

const kinds = (src) => extractSqli(src).map((h) => h.kind);

test("->execute([...]) / ->execute(array(...)) with a superglobal value is a bound parameter", () => {
  assert.deepEqual(kinds("\t\t\t$stmt->execute([$type, $time, $U['nickname'], $_POST['text']]);"), []);
  assert.deepEqual(kinds("$stmt->execute(array($id, $_GET['name']));"), []);
});

test("a superglobal inside SQL text still fires on every PHP sink form", () => {
  assert.deepEqual(kinds(`$db->exec("DELETE FROM notes WHERE id = '$_GET[id]'");`), ["php-inline-sql"]);
  assert.deepEqual(kinds(`$r = $db->query("SELECT * FROM u WHERE id = $_GET[id]");`), ["php-inline-sql"]);
  assert.deepEqual(kinds(`mysqli_query($c, "SELECT * FROM u WHERE id = $_GET[id]");`), ["php-inline-sql"]);
});
