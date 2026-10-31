// XXE (src/xxe-extract.mjs) — PR-replay labels 2026-10-31 : `setExpandEntityReferences(true)` on a
// factory that already turns the DOCTYPE, or both external entity kinds, off loads no external entity. Shape taken from
// the labelled file (craftercms SecuredConf). A factory with only one kind off, or none, still fires.
import { test } from "node:test";
import assert from "node:assert/strict";
import { extractXxe } from "../xxe-extract.mjs";

const lines = (src) => extractXxe(src).map((h) => h.line);

test("expand-entity-references on a hardened factory is not XXE", () => {
  assert.deepEqual(lines(`factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);\nfactory.setFeature(EXTERNAL_GENERAL_ENTITIES, false);\nfactory.setFeature(EXTERNAL_PARAMETER_ENTITIES, false);\nfactory.setFeature(LOAD_EXTERNAL_DTD, false);\nfactory.setExpandEntityReferences(true);`), []);
  assert.deepEqual(lines(`dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);\ndbf.setExpandEntityReferences(true);`), []);
  assert.deepEqual(lines(`dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);\ndbf.setFeature("http://xml.org/sax/features/external-parameter-entities", Boolean.FALSE);\ndbf.setExpandEntityReferences(true);`), []);
});

test("the labelled shape : expansion turned on 13 lines below the hardening, in the same factory method", () => {
  const src = [
    "factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);",
    "factory.setFeature(EXTERNAL_GENERAL_ENTITIES, false);",
    "factory.setFeature(EXTERNAL_PARAMETER_ENTITIES, false);",
    "factory.setFeature(LOAD_EXTERNAL_DTD, false);",
    'factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");',
    'factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");',
    "factory.setAttribute(ENTITY_EXPANSION_LIMIT, MAX_ENTITY_EXPANSIONS);",
    "factory.setValidating(false);",
    "factory.setNamespaceAware(true);",
    "factory.setIgnoringComments(true);",
    "factory.setXIncludeAware(false);",
    "// Tuckey reads only the first text child of <from> and <to>.",
    "// External entities stay disabled by the features above.",
    "factory.setExpandEntityReferences(true);",
  ].join("\n");
  assert.deepEqual(lines(src), []);
});

test("CONTROL : no hardening, one entity kind only, or a feature turned ON still fires", () => {
  assert.deepEqual(lines(`dbf.setExpandEntityReferences(true);`), [1]);
  assert.deepEqual(lines(`dbf.setFeature(EXTERNAL_GENERAL_ENTITIES, false);\ndbf.setExpandEntityReferences(true);`), [2]);
  assert.deepEqual(lines(`dbf.setFeature("http://xml.org/sax/features/external-general-entities", true);\ndbf.setFeature(EXTERNAL_PARAMETER_ENTITIES, false);\ndbf.setExpandEntityReferences(true);`), [1, 3]);
  assert.deepEqual(lines(`dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", false);\ndbf.setExpandEntityReferences(true);`), [2]);
});
