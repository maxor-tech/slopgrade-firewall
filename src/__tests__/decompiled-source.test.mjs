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
  assert.equal(isDecompiledSource(JADX), true);
  assert.equal(isDecompiledSource("package x;\n/* compiled from: GFW */\npublic final class n {}"), true);
  assert.equal(isDecompiledSource("/*\n * Decompiled with CFR 0.152.\n */\npackage a;"), true);
  assert.equal(isDecompiledSource("// Decompiled by Procyon v0.6.0\npackage a;"), true);
  assert.equal(isDecompiledSource("// Source code recreated from a .class file by IntelliJ IDEA\n// (powered by FernFlower decompiler)\npackage a;"), true);
  assert.equal(isDecompiledSource("// Decompiled with JetBrains decompiler\nnamespace A {}"), true);
});

test("CONTROL : the author's own code, or a decompiler named in prose or below the header, is not decompiled", () => {
  assert.equal(isDecompiledSource(OWN), false);
  assert.equal(isDecompiledSource('const help = "loaded from: the cache";\nconsole.log(help);'), false);
  assert.equal(isDecompiledSource("x = 1\n".repeat(80) + "# Decompiled with CFR"), false);
});

test("a decompiled file is skipped by the crypto, deser and injection extractors ; the same code written by hand fires", () => {
  assert.deepEqual(extractCrypto(JADX, "as.java"), []);
  assert.ok(extractCrypto(OWN, "as.java").length > 0);
  const ois = "/* loaded from: classes.dex */\npublic class a {\n  Object r(java.io.InputStream s) throws Exception { return new java.io.ObjectInputStream(s).readObject(); }\n}";
  assert.deepEqual(extractDeser(ois), []);
  assert.ok(extractDeser(ois.replace("/* loaded from: classes.dex */\n", "")).length > 0);
  const sql = '/* loaded from: classes.dex */\nclass q { void r(String id) { st.executeQuery("SELECT * FROM t WHERE id=" + request.getParameter("id")); } }';
  assert.deepEqual(extractSqli(sql, new Map(), "q.java"), []);
});
