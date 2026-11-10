// Deterministic Deep Scan guards (0.16.0) — mined once from the reasons an AI verifier gave when it rejected a blocking
// finding on the 61k replay, then kept only where the frozen labels show 0 true positives removed. Each case below is a
// real labeled finding (repo in the comment) ; each rule has a control that must keep blocking.
import { test } from "node:test";
import assert from "node:assert/strict";
import { deepGuard } from "../deep-guard.mjs";

const files = (map) => (p) => (Object.hasOwn(map, p) ? map[p] : null);
const row = (file, line, rule, detail) => ({ file, line, rule, detail, pack: "heisen" });

test("deepGuard: a command-line argument is not attacker input (microsoft/TRELLIS.2, DESIGN)", () => {
  const read = files({ "data_toolkit/build_metadata.py": "import sys\nimport importlib\n\n" + "x = 1\n".repeat(46) + "mod = importlib.import_module(f'datasets.{sys.argv[1]}')\n" });
  const r = row("data_toolkit/build_metadata.py", 50, "CWE-94", "ast-taint: the request value read at line 50 reaches importlib.import_module() at line 50 (CWE-94)");
  assert.equal(deepGuard(r, read), "command-line input");
  // control: the same sink fed by a request parameter keeps blocking
  const read2 = files({ "app.py": "x\n".repeat(49) + "mod = importlib.import_module(request.args.get('m'))\n" });
  assert.equal(deepGuard(row("app.py", 50, "CWE-94", "ast-taint: the request value read at line 50 reaches importlib.import_module() at line 50 (CWE-94)"), read2), null);
});

test("deepGuard: the source can sit in another file (evidence names path:line)", () => {
  const read = files({ "tasks/cgb.js": "x\n".repeat(95) + "const name = process.argv[2];\n", "tasks/run.js": "" });
  const r = row("tasks/run.js", 10, "CWE-78", "ast-taint: the request value read at tasks/cgb.js:96 reaches child_process.execSync() at tasks/cgb.js:105 (called at line 10) (CWE-78)");
  assert.equal(deepGuard(r, read), "command-line input");
});

test("deepGuard: posture classes (cleartext gRPC, wildcard CORS, file permissions) report but never block", () => {
  const none = files({});
  assert.equal(deepGuard(row("Loon.java", 144, "CWE-732", "ast-pattern: .setReadable(true, false) (permission widened to everyone) at line 144 (CWE-732)"), none), "configuration finding");
  assert.equal(deepGuard(row("srv.py", 37, "CWE-732", "ast-pattern: os.open() with a world-writable mode 0o666 at line 37 (CWE-732)"), none), "configuration finding");
  assert.equal(deepGuard(row("c.go", 29, "CWE-319", "ast-pattern: grpc.WithInsecure() (gRPC channel over cleartext, no TLS) at line 29 (CWE-319)"), none), "configuration finding");
  assert.equal(deepGuard(row("app.py", 17, "CWE-942", "ast-pattern: CORS(origins='*' + supports_credentials=True) at line 17 (CWE-942)"), none), "configuration finding");
  // controls: posture classes that DO carry labeled true positives keep blocking (weak crypto, TLS off, CSRF off)
  assert.equal(deepGuard(row("EncriptUtil.java", 28, "CWE-327", "ast-pattern: DES cipher at line 28 (CWE-327)"), none), null);
  assert.equal(deepGuard(row("tcp_conn.go", 47, "CWE-295", "ast-pattern: InsecureSkipVerify = true at line 47 (CWE-295)"), none), null);
  assert.equal(deepGuard(row("WebSecurityConfigurer.java", 23, "CWE-352", "ast-pattern: csrf().disable() at line 23 (CWE-352)"), none), null);
});

test("deepGuard: vendored third-party code (a committed venv, a bundled Workbox) never blocks", () => {
  const none = files({});
  const ev = "ast-taint: the request value read at line 496 reaches os.path.isdir() at line 69 (CWE-22)";
  assert.equal(deepGuard(row("venv/Lib/site-packages/debugpy/_vendored/pydevd/_pydevd_bundle/x.py", 69, "CWE-22", ev), none), "vendored code");
  assert.equal(deepGuard(row("static/workbox-v4.3.1/workbox-precaching.dev.js", 715, "CWE-918", "ast-taint: a request value reaches an outgoing HTTP request at line 715 (CWE-918)"), none), "vendored code");
  assert.equal(deepGuard(row("public/js/jquery.min.js", 3, "CWE-79", "ast-taint: x (CWE-79)"), none), "vendored code");
  // control: a first-party directory whose name only contains "vendor" keeps blocking
  assert.equal(deepGuard(row("src/vendors/routes.js", 69, "CWE-22", ev), none), null);
});

test("deepGuard: test files the tooling rule misses (root test.js, testapp/, *-tests/, calibration corpus)", () => {
  const none = files({});
  const ev = "ast-taint: the request value read at line 689 reaches res.end() at line 690 (CWE-79)";
  assert.equal(deepGuard(row("test.js", 690, "CWE-79", ev), none), "test code");
  assert.equal(deepGuard(row("apm-agent-plugins/testapp/WebFluxConfig.java", 1, "CWE-79", ev), none), "test code");
  assert.equal(deepGuard(row("oidc-conformance-tests/configure_is.py", 1, "CWE-79", ev), none), "test code");
  assert.equal(deepGuard(row("search/corpus/calibration/security-rules/server.ts", 1, "CWE-79", ev), none), "test code");
  // controls
  assert.equal(deepGuard(row("src/latest.js", 690, "CWE-79", ev), none), null);
  assert.equal(deepGuard(row("contests/server.js", 690, "CWE-79", ev), none), null);
});

test("deepGuard: a redirect built from the page's own location.href stays same-origin (smart-medicine, FP)", () => {
  const read = files({ "static/custom.js": "x\n".repeat(225) + "var href = window.location.href;\n" });
  const ev = "ast-taint: the request value read at line 226 reaches an assignment to the page location at line 228 (CWE-601)";
  assert.equal(deepGuard(row("static/custom.js", 228, "CWE-601", ev), read), "same-page URL");
  // control: the query string or hash of the URL is attacker-chosen
  const read2 = files({ "static/custom.js": "x\n".repeat(225) + "var next = new URLSearchParams(location.search).get('next');\n" });
  assert.equal(deepGuard(row("static/custom.js", 228, "CWE-601", ev), read2), null);
});

test("deepGuard: SSRF in browser-side code is the visitor's own browser fetching (GraphvizOnline, FP)", () => {
  const ev = "ast-taint: the request value read at line 488 reaches an outgoing HTTP request at line 531 (CWE-918)";
  const read = files({ "main.js": "const editor = document.getElementById('e');\nfetch(url);\n" });
  assert.equal(deepGuard(row("main.js", 531, "CWE-918", ev), read), "browser-side request");
  // controls: server code, and a non-JS file
  const read2 = files({ "main.js": "const app = require('express')();\napp.get('/p', (req, res) => fetch(req.query.u));\n// document.title\n" });
  assert.equal(deepGuard(row("main.js", 531, "CWE-918", ev), read2), null);
  const read3 = files({ "main.py": "document = 1\nrequests.get(url)\n" });
  assert.equal(deepGuard(row("main.py", 531, "CWE-918", ev), read3), null);
});

test("deepGuard: location.hash given to jQuery $() is a selector, not HTML (disable-comments, FP)", () => {
  const ev = "ast-taint: the request value read at line 151 reaches jQuery $() with an HTML string at line 159 (CWE-79)";
  const read = files({ "a.js": "x\n".repeat(150) + "var target = window.location.hash;\n" });
  assert.equal(deepGuard(row("a.js", 159, "CWE-79", ev), read), "jQuery selector");
  // control: location.hash into innerHTML is DOM XSS and keeps blocking
  const ev2 = "ast-taint: the request value read at line 151 reaches innerHTML at line 159 (CWE-79)";
  assert.equal(deepGuard(row("a.js", 159, "CWE-79", ev2), read), null);
});

test("deepGuard: an unreadable file never clears a finding that needs the file", () => {
  const ev = "ast-taint: the request value read at line 50 reaches importlib.import_module() at line 50 (CWE-94)";
  assert.equal(deepGuard(row("gone.py", 50, "CWE-94", ev), files({})), null);
  assert.equal(deepGuard(row("gone.py", 50, "CWE-94", ev), () => { throw new Error("EACCES"); }), null);
  assert.equal(deepGuard({}, files({})), null);
});

test("deepGuard: an evidence path outside the repo is never read", () => {
  const asked = [];
  const read = (p) => { asked.push(p); return "x = sys.argv[1]\n"; };
  for (const p of ["../../etc/passwd", "/etc/passwd", "C:/Windows/win.ini", "a/../../b.py", "..\\b.py"]) {
    const r = row("app.py", 9, "CWE-78", `ast-taint: the request value read at ${p}:1 reaches os.system() at line 9 (CWE-78)`);
    assert.equal(deepGuard(r, read), null, p);
  }
  assert.deepEqual(asked, []);
});
