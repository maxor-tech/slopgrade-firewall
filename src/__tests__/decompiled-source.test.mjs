// A decompiled source file is a decompiler's output, not the pull request author's code (PR-replay labels 2026-10-31 :
// a decompiled Android malware sample, 5 files / 7 DESIGN blocks, no true finding). The markers are the fixed lines a
// decompiler writes above the first class. A file that only MENTIONS a decompiler deeper down, or uses the same cipher
// in its own code, still fires.
import { test } from "node:test";
import assert from "node:assert/strict";
import { isDecompiledSource } from "../lang-scope.mjs";
import { extractCrypto } from "../crypto-extract.mjs";
import { extractDeser } from "../deser-extract.mjs";
import { extractSqli } from "../sqli-extract.mjs";
import { extractCmdi } from "../cmdi-extract.mjs";

const JADX = [
  "package com.unia.y;",
  "",
  "import javax.crypto.Cipher;",
  "import javax.crypto.spec.DESKeySpec;",
  "/* loaded from: /mnt/shared/apks/menSe7ni.dex */",
  "public class as {",
  "    /* renamed from: a  reason: collision with root package name */",
  '    private static final String f487a = "DES";',
  '    Cipher c = Cipher.getInstance("DES/ECB/PKCS5Padding");',
  "}",
].join("\n");
const OWN = JADX.replace("/* loaded from: /mnt/shared/apks/menSe7ni.dex */\n", "");

test("decompiler headers are recognised (JADX, CFR, Procyon, FernFlower, JD, JetBrains)", () => {
  assert.equal(isDecompiledSource(JADX, "as.java"), true);
  assert.equal(isDecompiledSource("package x;\n/* compiled from: GFW */\npublic final class n {}", "n.java"), true);
  assert.equal(isDecompiledSource("/*\n * Decompiled with CFR 0.152.\n */\npackage a;", "A.java"), true);
  assert.equal(isDecompiledSource("// Decompiled by Procyon v0.6.0\npackage a;", "A.java"), true);
  assert.equal(isDecompiledSource("// Source code recreated from a .class file by IntelliJ IDEA\n// (powered by FernFlower decompiler)\npackage a;", "A.kt"), true);
  assert.equal(isDecompiledSource("// Decompiled with JetBrains decompiler\nnamespace A {}", "A.cs"), true);
});

test("CONTROL : the author's own code, or a decompiler named in prose or below the header, is not decompiled", () => {
  assert.equal(isDecompiledSource(OWN, "as.java"), false);
  assert.equal(isDecompiledSource('String help = "loaded from: the cache";\nclass A {}', "A.java"), false);
  assert.equal(isDecompiledSource("int x = 1;\n".repeat(80) + "// Decompiled with CFR", "A.java"), false);
});

test("EVASION (expert-panel red team) : a decompiler marker in a non-JVM file, out of place, or with no file name never skips", () => {
  assert.equal(isDecompiledSource("// Decompiled with CFR\nconst c = req.query.cmd;", "r.js"), false);
  assert.equal(isDecompiledSource("# Decompiled with CFR\nimport os", "r.py"), false);
  assert.equal(isDecompiledSource("package a;\n" + "int x = 1;\n".repeat(6) + "// Decompiled with CFR\nclass A {}", "A.java"), false);
  assert.equal(isDecompiledSource('/* loaded from: x.dex */\nString s = req.getParameter("q");', "A.java"), false);
  assert.equal(isDecompiledSource(JADX), false);
  const cmd = "const cp = require('child_process');\napp.get('/r', (req, res) => {\n  const c = req.query.cmd;\n  cp.exec(c);\n});";
  assert.ok(extractCmdi("// Decompiled with CFR\n" + cmd, new Map(), "r.js").length > 0);
});

test("a decompiled file is skipped by the crypto, deser and injection extractors ; the same code written by hand fires", () => {
  assert.deepEqual(extractCrypto(JADX, "as.java"), []);
  assert.ok(extractCrypto(OWN, "as.java").length > 0);
  const ois = "/* loaded from: classes.dex */\npublic class a {\n  Object r(java.io.InputStream s) throws Exception { return new java.io.ObjectInputStream(s).readObject(); }\n}";
  assert.deepEqual(extractDeser(ois, "a.java"), []);
  assert.ok(extractDeser(ois.replace("/* loaded from: classes.dex */\n", ""), "a.java").length > 0);
  const sql = '/* loaded from: classes.dex */\nclass q { void r(String id) { st.executeQuery("SELECT * FROM t WHERE id=" + request.getParameter("id")); } }';
  assert.deepEqual(extractSqli(sql, new Map(), "q.java"), []);
});
