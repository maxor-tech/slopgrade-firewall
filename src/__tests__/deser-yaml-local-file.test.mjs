// A YAML load of a file the code opens from its own disk is the trusted local-file case (PR-replay labels 2026-10-31,
// 7 wrong blocks). The hit is demoted to the gated tier : it fires only with a direct request source. A string, a
// parameter, a request-chosen path or a variable reassigned after the open keeps the HIGH tier.
import { test } from "node:test";
import assert from "node:assert/strict";
import { extractDeser } from "../deser-extract.mjs";

const tier = (src) => extractDeser(src).map((h) => (h.high ? "high" : h.srcCtx ? "gated+src" : "gated"));

test("a yaml.load of a file opened in the lines above is gated", () => {
  assert.deepEqual(tier(`with open(path_to_yaml) as f:\n    di2s = yaml.load(f)`), ["gated"]);
  assert.deepEqual(tier(`with open('data/semantic-kitti.yaml', 'r') as f:\n    inv = yaml.load(f.read())['map']`), ["gated"]);
  assert.deepEqual(tier(`data = yaml.load(open(file_path, 'r'), **kwargs)`), ["gated"]);
  assert.deepEqual(tier(`InputStream inputStream = new FileInputStream(file);\nYaml yaml = new Yaml();\ndata = yaml.load(inputStream);`), ["gated"]);
  assert.deepEqual(tier(`try (FileInputStream fis = new FileInputStream(file)) {\n    List<Map<String, Object>> d = yaml.load(fis);`), ["gated"]);
});

test("CONTROL : a string, a parameter or a reassigned variable stays HIGH ; a request-chosen path keeps its source", () => {
  assert.deepEqual(tier(`Yaml yaml = new Yaml();\ndata = yaml.load(str);`), ["high"]);
  assert.deepEqual(tier(`def load_from_fileobj(self, file, **kwargs):\n    return yaml.load(file, **kwargs)`), ["high"]);
  assert.deepEqual(tier(`f = open("conf.yaml")\nf = request.files["cfg"]\nc = yaml.load(f)`), ["high"]);
  assert.deepEqual(tier(`with open(request.args["f"]) as f:\n    c = yaml.load(f)`), ["gated+src"]);
});
