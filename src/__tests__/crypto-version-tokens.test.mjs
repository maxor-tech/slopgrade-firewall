// P8 (benchmark 2026-10-24): a bare "rc4"/"rc2" literal that is a release tag is not a cipher. Real cipher uses still fire.
import { test } from "node:test";
import assert from "node:assert/strict";
import { extractCrypto, extractCryptoFingerprint } from "../crypto-extract.mjs";

const kinds = (src, file) => extractCrypto(src, file).map((h) => h.kind);

test("net-ssh style PRE = \"rc4\" is a version token, not RC4", () => {
  assert.deepEqual(kinds('module Net; module SSH; class Version\n  PRE = "rc4"\nend; end; end'), []);
  assert.deepEqual(kinds("pre = 'rc2'"), []);
  assert.deepEqual(kinds('  PRERELEASE = "rc4"'), []);
  assert.deepEqual(kinds('const version = "rc2"'), []);
});

test("a release-stage list beside alpha/beta/rc1/snapshot is not RC2", () => {
  const go = 'var stages = []string{\n  "alpha", "beta", "rc1", "rc2", "snapshot",\n}';
  assert.deepEqual(kinds(go), []);
  assert.deepEqual(kinds('  "alpha",\n  "beta",\n  "rc2",\n  "rc3",'), []);
});

test("a version file never reports a bare rc token", () => {
  assert.deepEqual(extractCryptoFingerprint('X = "rc4"', "lib/net/ssh/version.rb").hits, []);
  assert.deepEqual(extractCryptoFingerprint('x := "rc2"', "pkg/gen/libnamegenerator/version.go").hits, []);
});

test("real RC4 / RC2 cipher uses keep firing", () => {
  const rc4 = [
    "c = ARC4.new(key)",
    'Cipher c = Cipher.getInstance("RC4");',
    "crypto.createCipheriv('rc4', key, iv)",
    "c, _ := rc4.NewCipher(key)",
    "x = new RC4(key)",
    "$c = OpenSSL::Cipher.new('rc4')",
  ];
  for (const s of rc4) assert.deepEqual(kinds(s), ["rc4-cipher"], s);
  assert.deepEqual(kinds('Cipher.getInstance("RC2/CBC/PKCS5Padding")'), ["rc2-cipher"]);
  assert.deepEqual(kinds("crypto.createCipheriv('rc2', k, iv)"), ["rc2-cipher"]);
});

test("an import-path table naming the rc4 / rc2 package is not a cipher (benchmark 2026-10-24, dev split)", () => {
  assert.deepEqual(kinds('var hints = map[string]string{\n\t"crypto/rc4":                         "rc4",\n}'), []);
  assert.deepEqual(kinds("  'golang.org/x/crypto/rc2': 'rc2',"), []);
  // failure pre-conditions : an API use on such a line, or a config key that is not an import path, still fires
  assert.deepEqual(kinds('\t"crypto/rc4": rc4.NewCipher,'), ["rc4-cipher"]);
  assert.deepEqual(kinds('{ "cipher": "rc4", "key": k }'), ["rc4-cipher"]);
});

test("a bare cipher-name literal with no version context still fires, even in a version-named assignment elsewhere", () => {
  assert.deepEqual(kinds('const opts = { algorithm: "rc4" }'), ["rc4-cipher"]);
  assert.deepEqual(kinds('ciphers = ["rc2", "rc4"]'), ["rc4-cipher", "rc2-cipher"]);   // two ciphers, no release-stage sibling
  assert.deepEqual(kinds('  "rc4",\n  "arcfour",'), ["rc4-cipher", "rc4-cipher"]);
  assert.deepEqual(kinds("crypto.createCipheriv('rc4', key, iv) // version = 1"), ["rc4-cipher"]);
  // a real use stays real even inside a version-named file (API context beats the filename)
  assert.deepEqual(extractCryptoFingerprint("c = ARC4.new(key)", "lib/version.py").hits.map((h) => h.kind), ["rc4-cipher"]);
});

test("a hash-identifier catalog literal and a DESKeySpec signature are not DES uses (benchmark 2026-10-26, dev split)", () => {
  assert.deepEqual(kinds('    HashInfo(name="DES(Unix)", hashcat=1500, john="descrypt"),'), []);
  assert.deepEqual(kinds('  Prototype("DES(Oracle)", [HashInfo(...)])'), []);
  assert.deepEqual(kinds("    private static DESKeySpec getDesKeySpec(String key) throws Exception {"), []);
  assert.deepEqual(kinds("        DESKeySpec spec = getDesKeySpec(key);"), []);
  // the real uses on the same file shape keep firing
  for (const s of ["        DESKeySpec spec = new DESKeySpec(key.getBytes());", "    boolean ok = DESKeySpec.isParityAdjusted(k, 0);",
                   '    Cipher c = Cipher.getInstance("DES/ECB/PKCS5Padding");', "    from Crypto.Cipher import DES\n    c = DES.new(k, DES.MODE_ECB)"]) {
    assert.ok(kinds(s).includes("des-cipher"), s);
  }
});

test("a name list, a trailing comment and an enum constant are not cipher uses (benchmark 2026-10-24 re-checked 2026-10-31)", () => {
  // the six labelled wrong blocks still firing on main, as they appear in the replayed files
  assert.deepEqual(kinds('        "base64decode", "rot13", "rc4", "aes", "des",'), []);
  assert.deepEqual(kinds('  "stringArrayEncoding": ["rc4", "base64"]'), []);
  assert.deepEqual(kinds("    stringArrayEncoding: ['base64'],           // 'none','base64','rc4'"), []);
  assert.deepEqual(kinds('  "components": ["core", "x64-core", "enc-base64", "md5", "sha1", "aes", "tripledes", "rc4", "rabbit"],'), []);
  assert.deepEqual(kinds('    DES("6", "DES加密"),'), []);
  assert.deepEqual(kinds("    DES(6);"), []);
  // failure pre-conditions : a cipher list, a single selection, an object value and a real call keep firing
  assert.deepEqual(kinds('ciphers = ["rc2", "rc4"]'), ["rc4-cipher", "rc2-cipher"]);
  assert.deepEqual(kinds('  stringArrayEncoding: ["rc4"]'), ["rc4-cipher"]);
  assert.deepEqual(kinds('{ "cipher": "rc4", "key": k }'), ["rc4-cipher"]);
  assert.deepEqual(kinds("$out = openssl_encrypt($data, 'rc4', $key); // legacy"), ["rc4-cipher"]);
  assert.deepEqual(kinds("    Cipher c = DES(key);"), ["des-cipher"]);
  assert.deepEqual(kinds("    DES(keyBytes),"), ["des-cipher"]);
});
