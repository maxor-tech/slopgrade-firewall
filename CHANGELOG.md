# Changelog

All notable changes to the open-source slopGrade Firewall client are documented here. This project adheres to
[Semantic Versioning](https://semver.org/) and [Keep a Changelog](https://keepachangelog.com/).

## [0.7.6] — 2026-09-19

Hardening from an adversarial review of the v0.7.2–0.7.5 GitHub-native work.

### Fixed
- **The SARIF result cap no longer drops the most critical findings.** When a repo exceeds the 25 000-result limit,
  results are now sorted by severity before truncating, so `error`-level findings (SQLi, crypto, secrets…) are kept and
  only the lowest-severity ones are dropped — previously the cap kept insertion order, so criticals (built last) were
  sliced off first while low-severity notes survived.
- **Code Scanning upload retries on 429 (rate limit), not just 5xx**, and honors a `Retry-After` header — the most
  transient, most-retryable status was previously treated as a permanent failure.
- **The SARIF `uri` is now sanitized** (control characters stripped, like `message.text` already was), so a
  server-controlled path can't carry control bytes into the consumer's Security tab. `ident()` is control-stripped too.
- **`--strict --gate` no-verdict runs now emit outputs.** A fail-closed run (exit 1) with no server verdict used to
  write nothing to `$GITHUB_OUTPUT`, so a downstream `if: outputs.blocked == 'true'` read an empty string and could
  deploy anyway. A `verdict=no-verdict` / `blocked` sentinel is now emitted before every no-verdict early return.
- **The truncation warning is precise** — it fires only on genuine overflow (counting real candidates) and names the
  true count, instead of false-firing at exactly the cap.

### Changed
- The 403 message no longer assumes a missing permission: it notes the scope may already be granted and GitHub could be
  rate-limiting.

## [0.7.5] — 2026-09-18

### Changed
- **A SARIF result cap is now visible, not silent.** When a repo is large enough to hit the 25 000-result cap, the run
  logs a clear warning that Code Scanning shows only the first N and the rest are in the log + PR feed — closing the
  one remaining rough edge of the cap (the findings were never lost, but the truncation was previously unannounced).

### Added
- **A README badge snippet** consumers can add to show the diff is checked by the slopGrade Firewall.

## [0.7.4] — 2026-09-18

Consume the verdict in your own workflow, and harden the Code Scanning upload for huge repos and flaky networks.

### Added
- **Action outputs.** The step now surfaces `verdict` (advisory / gate-blocked / gate-unpaid / gate-pass), `blocked`,
  `hard-leaks`, `blocking-findings`, `conformance`, `entitled`, and `sarif-uploaded` (via `$GITHUB_OUTPUT`) — so a
  downstream step can act on the result (post to Slack, gate another job, render a badge) without re-parsing logs.

### Changed
- **The Code Scanning upload retries once on a transient 5xx / network error** (with a short backoff, mirroring the
  verdict POST) — a flaky moment no longer silently drops the upload. A 403 (missing scope) and other 4xx stay
  no-retry: they're permanent states, not transient.
- **The SARIF is capped at 25 000 results** (`MAX_SARIF_RESULTS`) so a very large repo never exceeds GitHub's per-run
  SARIF limit and 413s the upload; the truncated findings still appear in the log and the PR feed.

## [0.7.3] — 2026-09-18

Findings now land in GitHub's own Security tab — inline on the PR, tracked across commits, dismissible — with one permission line and no extra workflow step.

### Added
- **Automatic upload to GitHub Code Scanning.** The gate now posts its SARIF to the repo's Security tab itself
  (`uploadSarifToCodeScanning` → `POST /code-scanning/sarifs`), so findings also appear **inline on the PR "Files
  changed" tab**, tracked across commits and dismissible — GitHub's native security surface, **free on public repos**.
  It uses the caller's own `GITHUB_TOKEN` against their own repo (nothing new leaves the runner; slopGrade is never
  contacted for it), needs `permissions: security-events: write`, and requires **no** `codeql-action/upload-sarif` step
  and **no** action SHA to pin. Default on; `upload-sarif: "false"` opts out. A clean run uploads an empty report so
  fixed alerts auto-resolve.
- **The SARIF now carries every detector pack**, not just the cross-tenant and access-control findings — the same
  normalized feed the inline PR comments use, so the log, the PR review and Code Scanning all show the same findings.

### Changed
- `sarif-file` is now purely optional (write the SARIF to a file for a build artifact or a manual upload step); the
  Code Scanning upload runs whether or not a file path is set.

### Notes
- Fail-soft, as ever: without `security-events: write` (or on a private repo without GitHub Advanced Security) the
  upload quietly no-ops with a one-line hint — never a warning annotation, never a broken build, verdict unchanged.

## [0.7.2] — 2026-09-18

A rendered report on every run page — including push runs, where PR comments never appear — with every leak a one-click jump to the exact line.

### Added
- **A GitHub Step Summary is written on every run.** The gate now renders a markdown report to `$GITHUB_STEP_SUMMARY`
  (`stepSummaryMarkdown` + `emitStepSummary`): a verdict banner (✅ clean / ⚠️ advisory / ❌ blocked), the pattern +
  tenant key + conformance facts, the blocking-pack count, and the leak list — visible on the run page for **push runs
  too**, not just PRs (the inline review + sticky comment channels only fire when there's a PR to comment on).
- **Every `file:line` leak is a clickable link** to the exact line at the run's head SHA
  (`githubBlobBase` + `fileLink` → `<server>/<repo>/blob/<sha>/<file>#L<n>`). Off CI (no repo/SHA in the env) it
  degrades to plain code text — never a broken link. A paid repo's advisory report links straight to the offending line.

### Notes
- Purely additive and display-only: the gate's verdict and exit code are **unchanged**. The Step Summary is fail-soft
  (a write error is swallowed) and a no-op off CI, so it can never break a build.

## [0.7.1] — 2026-09-14

One PR notification instead of dozens, and a loud signal when a paid repo isn't getting its full catalogue.

### Changed
- **The finding feed posts as ONE PR review, not one comment per finding.** A findings-heavy PR used to email the
  author once per inline comment (~40 emails on a busy PR). The feed now posts a single review (`POST /pulls/N/reviews`,
  event `COMMENT`) carrying the summary in its body + every on-diff finding inline — one notification. A review rejects
  the whole batch if any comment is off-diff, so findings are first filtered to the PR diff (`parseAddedLines`); the
  off-diff ones remain fully listed in the summary body. Dedup + the 30-comment cap are unchanged; on a review-API
  refusal it falls back to a single summary comment (fail-open).

### Fixed
- **A paid repo no longer downgrades to the free tier silently.** `loadProPacks` returns quietly on a `402` (correct
  for a genuinely-free repo). But when the server verdict says the repo *is* entitled (`gateEntitled`) while the pro
  bundle didn't load, the entitlement chain broke (livemode drift / an unassigned slot / an unlinked repo) and a paying
  customer was getting only the 22 free packs with no signal. The client now warns loudly in that case, pointing at the
  repo's plan + slot at `/ci`.

## [0.7.0] — 2026-09-13

Paid repos now run the **full detector catalogue** — in your runner, with the same zero-egress contract.

### Added
- **Pro extractors for paid repos.** The hosted product judges ~120 detector packs ; this client ships the extractors
  for 22. A repo whose gate is paid now asks `POST /api/ci/pro-extractors` (with its OIDC token) for the closed-source
  extractors of the other ~100 packs, verifies the bundle (size-bounded, sha256-checked), loads it from a temp file
  and runs it **locally** — your source still never leaves the runner ; only fingerprints do. A free repo gets 402 and
  keeps its 22 packs. Every failure path (network, 5xx, hash mismatch, load error) falls back to the free packs with a
  warning — a pro hiccup never costs the verdict.
- **Egress boundary for the pro packs** (`sanitizeProFingerprints`) : a recursive, bounded scrub that keeps numbers,
  booleans and short strings under identifier-like keys and DROPS every key that could name source (`text`, `snippet`,
  `content`, `raw`, `value`, `secret`, `sql`, …). `--print-payload` inside CI now performs the pro ask too, so the
  printed payload stays byte-for-byte what is POSTed on the paid tier.
- **A coverage line on every run** — `slopGrade Firewall: N detector packs (free tier | paid · pro extractors <v>) ·
  M files scanned.` — a clean run is now distinguishable from a run that scanned nothing.
- The POST carries `proVersion` when pro packs ran (server-side diagnostics).

### Changed
- `--print-payload` in CI mints the OIDC token (to ask for the pro bundle) ; it still never POSTs the payload.

## [0.6.2] — 2026-09-13

Release-audit fixes (independent-repo install probe, 2026-09-13). No change to what leaves the runner.

### Fixed
- **All detector classes are now rendered.** The report loop iterated a hardcoded list of six legacy pack keys and
  silently dropped the server's `sqli / cmdi / xss / ssrf / xxe / insecureDeser / pathTraversal / weakCrypto / cors`
  blocks from the CI log, the inline PR feed and the SARIF — only `secrets` ever showed. The loop is now data-driven
  (`collectPackBlocks`: every pack object with a `count`), with one SARIF rule per pack (`buildSarif` `findings`).
- **Free-tier sample is no longer an empty annotation.** A withheld finding (rule `gated`, empty detail) now prints the
  class, the location and where to unlock, instead of `##[error][gated] `.
- **`--strict` fails closed on a blocked custom origin** (`SLOPGRADE_ORIGIN` without the opt-in is a no-verdict path).
- `CLIENT_VERSION` was stuck at `0.6.0`; it now tracks `package.json` (pinned by a test).
- `vendor/` is excluded from the scan (Go/PHP vendored deps, or a vendored copy of this client, no longer
  self-fingerprint).
- Workflow-command `file=` arguments are sanitized like every other server string.

### Changed
- README workflow: the job is named `slop` (the check name that « Protect main » in the app requires — a different job
  name left the protected branch waiting on a check that never runs) ; the free-vs-hosted table now states what the
  free tier actually shows (count + one located sample per class).

## [0.6.1] — 2026-09-11

Pre-publish hardening. No behavior change to detection or the exit boundary; the test suite is unchanged and green.

### Security
- **The composite action passes argv as an array** (`action.yml`), never a word-split string — a consumer who wires
  an untrusted value into `sarif-file` can no longer shell-inject in their own runner.

### Changed
- **Docs/comment hygiene for public release**: internal calibration-corpus references were removed from source
  comments. The free/paid boundary is now stated in the README ("Free vs hosted" + a price anchor), and the
  gate-unpaid CLI nudge names the price and the 14-day, no-card trial.

### Packaging
- `files` now ships `SECURITY.md` + `CHANGELOG.md`. Added a CI workflow (`node --test` on Node 22) and a
  `CONTRIBUTING.md`.

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
