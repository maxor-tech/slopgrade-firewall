// False-positive classes found by the independent test set v1 (178 shipped findings on 600 unseen repos, labelled
// blind ; maxor-tech/slopgrade bench/independent/v1.json). Each fix carries its control.
import { test } from "node:test";
import assert from "node:assert/strict";
import { extractPathTraversal } from "../pathtraversal-extract.mjs";
import { extractCrypto } from "../crypto-extract.mjs";

const pt = (code, file = "app/api.py") => extractPathTraversal(code, new Map(), file).length;
const rc = (code, file = "src/lib.js") => extractCrypto(code, file).filter((h) => /rc4|rc2/.test(h.kind)).length;

test("path traversal : an uploaded in-memory stream opened by Image / pdfplumber is not a path", () => {
  assert.equal(pt(`@app.post("/predict")\nasync def predict(file: UploadFile = File(...)):\n    contents = await file.read()\n    with pdfplumber.open(BytesIO(contents)) as pdf:\n        return pdf.pages\n`), 0);
  assert.equal(pt(`@app.post("/predict")\nasync def predict(file: UploadFile = File(...)):\n    image = Image.open(file.file)\n    return image.size\n`), 0);
});

test("CONTROL : the same open on a request-chosen path still fires", () => {
  assert.ok(pt(`@app.get("/img")\ndef img():\n    name = request.args["name"]\n    image = Image.open(name)\n    return image.size\n`) > 0);
});

test("weakCrypto : an rc4 module key, module metadata or a label map is not a cipher in use", () => {
  assert.equal(rc(`module.exports = {\n    rc4: {\n      name: "rc4",\n      folder: "libs",\n    },\n};\n`, "modules.conf.js"), 0);
  assert.equal(rc(`modularize: {\n  "rc4": {\n    "exports": "CryptoJS.RC4",\n  },\n}\n`, "grunt/config/modularize.js"), 0);
  assert.equal(rc(`const lang = {\n  'plain': 'Plain',\n  'arc4': 'ARC4',\n};\n`, "src/config/defaultLanguage.js"), 0);
});

test("CONTROL : a cipher setting, a ternary-selected rc4 and an API use still fire", () => {
  assert.equal(rc(`const opts = {\n  cipher: "rc4",\n};\n`), 1);
  assert.equal(rc(`c = createCipheriv(legacy ? "rc4" : "aes-256-gcm", k, iv)`), 1);
  assert.equal(rc(`const c = crypto.createCipheriv('rc4', key, '');\n`), 1);
});
