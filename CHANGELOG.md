# Changelog

All notable changes to the open-source slopGrade Firewall client are documented here. This project adheres to
[Semantic Versioning](https://semver.org/) and [Keep a Changelog](https://keepachangelog.com/).

## [0.6.0] — 2026-09-10

Feed + default-gate release — the firewall now reports like a reviewer and defaults to blocking.

### Added
- **Inline PR comment feed**: every finding (cross-tenant leak *and* detector-pack finding) posts as an inline
  review comment on the exact `file:line`, plus a single summary comment updated in place. The feed is deduped
  (one marker per location) and capped at 30 comments. It posts only when the caller grants
  `permissions: pull-requests: write` and uses the caller's OWN `GITHUB_TOKEN` — findings post to the caller's PR
  and never reach slopGrade. No-op off-PR.
- **`packBlocking`** exit source: in gate mode, a blocking detector finding (critical|high — injection / crypto /
  secrets…) blocks the check on its own. The count is server-paywalled to 0 unless the repo is entitled, so the
  free tier is never blocked by it. Defaults to 0 — an older server response (no field) is unchanged.

### Security
- **Detector fingerprints now egress by whitelist** (`sanitizePackFingerprints`), matching the cross-tenant
  fingerprint. Every pack hit is rebuilt at the POST boundary to only `{file, line, kind}` plus the known scalar
  tags (`entropy`, `placeholder`, `high`, `secCtx`, `srcCtx`) — any other field is dropped before it can leave the
  runner, so a future extractor bug can never grow a source-bearing field that rides to the server. `--print-payload`
  shows exactly what is POSTed, byte-for-byte.

### Changed
- **`firewall-mode` default is now `gate`** (was `advisory`). A non-entitled repo in gate mode still stays
  advisory (the paywall fails open), so the default flip never blocks a free repo; it does surface the gate for
  entitled repos without an explicit opt-in. Set `firewall-mode: advisory` to restore report-only behavior.
- The block message now names the reason (the cross-tenant leak count and/or the blocking security-finding count).

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
