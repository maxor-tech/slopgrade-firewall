// An in-memory deep clone deserializes bytes the method itself just wrote (PR-replay labels 2026-10-31 : DataCloneLib
// BaseParentBean / CloneDataUtils, azkaban SlaOption). The hit is demoted to the gated tier : it fires only with a
// direct request source on the line. Every other ObjectInputStream source keeps the HIGH tier.
import { test } from "node:test";
import assert from "node:assert/strict";
import { extractDeser } from "../deser-extract.mjs";

const at = (src, line) => extractDeser(src).filter((h) => h.line === line);

const CLONE_BYTES_VAR = [
  "public <T> T deepCopy() {",
  "  ByteArrayOutputStream bos = new ByteArrayOutputStream();",
  "  ObjectOutputStream out = new ObjectOutputStream(bos);",
  "  out.writeObject(this);",
  "  out.close();",
  "  byte[] bytes = bos.toByteArray();",
  "  ByteArrayInputStream inputStream = new ByteArrayInputStream(bytes);",
  "  ObjectInputStream in = new ObjectInputStream(inputStream);",
  "  return (T) in.readObject();",
  "}",
].join("\n");

const CLONE_INLINE = [
  "public SlaOption deepClone() {",
  "  bos = new ByteArrayOutputStream();",
  "  oos = new ObjectOutputStream(bos);",
  "  oos.writeObject(this);",
  "  bis = new ByteArrayInputStream(bos.toByteArray());",
  "  ois = new ObjectInputStream(bis);",
  "  return (SlaOption) ois.readObject();",
  "}",
].join("\n");

test("a deep clone through a byte-array variable is gated, not HIGH", () => {
  assert.deepEqual(at(CLONE_BYTES_VAR, 9), [{ line: 9, kind: "java-readobject", high: false, srcCtx: false }]);
});

test("a deep clone that wraps bos.toByteArray() inline is gated, not HIGH", () => {
  assert.deepEqual(at(CLONE_INLINE, 7), [{ line: 7, kind: "java-readobject", high: false, srcCtx: false }]);
});

test("CONTROL : an ObjectInputStream over a socket stays HIGH", () => {
  const src = [
    "void handle(Socket s) throws Exception {",
    "  ObjectInputStream in = new ObjectInputStream(s.getInputStream());",
    "  Object o = in.readObject();",
    "}",
  ].join("\n");
  assert.deepEqual(at(src, 3), [{ line: 3, kind: "java-readobject", high: true, srcCtx: true }]);
});

test("CONTROL : request bytes written raw into the buffer break the clone chain and stay HIGH", () => {
  const src = [
    "Object read(HttpServletRequest req) throws Exception {",
    "  ByteArrayOutputStream bos = new ByteArrayOutputStream();",
    "  ObjectOutputStream out = new ObjectOutputStream(bos);",
    "  out.writeObject(marker);",
    "  bos.write(req.getInputStream().readAllBytes());",
    "  ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(bos.toByteArray()));",
    "  return in.readObject();",
    "}",
  ].join("\n");
  assert.equal(at(src, 7)[0].high, true);
});

test("CONTROL : a ByteArrayInputStream over caller bytes (not the clone buffer) stays HIGH", () => {
  const src = [
    "Object decode(byte[] payload) throws Exception {",
    "  ByteArrayOutputStream bos = new ByteArrayOutputStream();",
    "  ObjectOutputStream out = new ObjectOutputStream(bos);",
    "  out.writeObject(header);",
    "  ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(payload));",
    "  return in.readObject();",
    "}",
  ].join("\n");
  assert.equal(at(src, 6)[0].high, true);
});
