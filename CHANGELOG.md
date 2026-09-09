# Changelog

All notable changes to the open-source slopGrade Firewall client are documented here. This project adheres to
[Semantic Versioning](https://semver.org/) and [Keep a Changelog](https://keepachangelog.com/).

## [0.5.0] — 2026-09-08

First public release of the open-source client — the **free tier**: the 10 highest-severity classes, run 100%
locally with zero source egress.

### Added
- **10 flagship detection classes** across JS/TS, Python, Go and .NET: SQL injection, command injection, XSS,
  SSRF, XXE, insecure deserialization, path traversal, hardcoded secrets, broken/weak crypto, and CORS
  reflected-origin. Each emits only `{file, line, kind}` — for hardcoded secrets, the value is discarded in the
  extractor and never leaves the runner.
- **Zero source egress**: the client posts only a structural fingerprint (file paths + `{file, line, kind}`).
  `--print-payload` prints the exact payload and exits, so you can audit what would be sent.
- **Zero-secret auth**: a short-lived GitHub OIDC token, audience-bound to the server origin. No PAT, nothing stored.
- **`--gate`** (block on a reliable hard leak in an entitled repo) · **`--strict`** (fail closed when no verdict) ·
  **`--sarif <path>`** (SARIF + inline PR annotations) · **`--help`**. Default is advisory (never blocks).
- Fail-open everywhere: a missing token, a 20s timeout, a network/server error never breaks your build.
- Origin-override guard: a custom `SLOPGRADE_ORIGIN` runs dry unless `SLOPGRADE_ALLOW_CUSTOM_ORIGIN=1`.
- Zero npm dependencies (only `node:*`). Node >= 22.

### Notes
- Detectors run **intra-function**. Cross-function / cross-file dataflow, the additional security classes, and the
  calibrated false-positive suppression are part of the hosted product at https://www.slopgrade.ai.
- Pin the commit **SHA** (`@<sha40>`) to freeze the exact code that runs in your CI.
