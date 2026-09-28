# Changelog

All notable changes to the open-source slopGrade Firewall client are documented here. This project adheres to
[Semantic Versioning](https://semver.org/) and [Keep a Changelog](https://keepachangelog.com/).

## [0.10.7] — 2026-09-28

### Added
- **Library mode: what became of the last run's candidates.** When the server compares this run's library candidates with
  the previous library run's (slopgrade `candidateOutcomes`), the triage section prints one line: resolved (gone, file
  scanned again, no `heisen-ignore` at the sink) · dismissed (the sink line is marked `heisen-ignore`) · still open · new
  · not re-scanned. Nothing is printed on a first library run, a partial scan or an older server.
- The triage section now says how to quiet a reviewed candidate: a `heisen-ignore: <reason>` comment on the sink line (or
  on a comment line just above) — the engine honours it on candidates since heisen-slop `aea8aa9`, like on findings.

### Changed
- A candidate's annotation line is the detector's own sink line when it sends one (one candidate per sink line since
  heisen-slop `aea8aa9`; before, one per class), else read from the evidence as before.

## [0.10.6] — 2026-09-28

### Added
- **Library mode** (`library-mode: "true"`, opt-in, with `deep-scan`). For a repo recognised as a **published package**
  (from its manifest, locally — applications are never affected and the log says so), the deep scan also lists the taint
  engine's **library-tier candidates** — a public function's parameter reaching a sink — as `::notice` annotations to
  triage. They are never findings: not in the gate, the PR review count or SARIF. Measured on real CVEs (paired: the
  vulnerable file flagged AND its fix not): recall about 1% → 9% (JavaScript), 1.5% → 5.6% (Python); about 2 in 3
  candidates remain after the fix. Package detection on a 32-repo check: 22 of 22 applications stay applications, 9 of 10
  libraries are recognised (a private monorepo root is conservatively treated as an application).

## [0.10.5] — 2026-09-28

### Changed
- **Deep scan: the files most likely to hold a flaw are sent first, and up to 80 of them.** On a large repo the file cap
  decided coverage, and ordering was by name inside two coarse groups. Measured on a 22-repo walk (repo-wide findings
  that fall inside the sent files): **76% → 91%**. Now, in order: this PR's files · files an extractor already flagged ·
  an unambiguous config rule (TLS verification off, `@csrf_exempt`, debug on, JWT unverified, ECB / weak cipher,
  insecure cookie flag, world-writable mode, XXE-enabling parser option) · a request value AND an injection-grade sink
  in the same file · a request value · any other marker. Inside each group, production code goes before dev-only paths
  (examples, scripts, tests, fixtures, benchmarks, docs) — never excluded, only ranked later. Examples: outline's four
  `rejectUnauthorized: false` files (of 942 candidates) and Ghost's admin SSRF handler were previously cut.
- Cap raised from 40 to **80 files** (2M characters unchanged). The slopGrade route stops dispatching past its time
  budget, so a large set degrades to « partial » in the log, never to a missing result. A file with no security marker
  is still never sent.

## [0.10.4] — 2026-09-28

### Changed
- **Deep scan: on a pull request, the files it changed are sent first.** The deep scan sends at most 40 files; on a
  large repo the PR's own code could fall past the cap (a 313-candidate repo sent a new request→shell helper 36th — one
  more request-reading file and it was never analysed). The PR's changed files are now read **locally from git**
  (`base...head` from the event — no network, no token), so `--print-payload` still lists exactly what is sent. A changed
  file is still sent only when it carries a security marker or an extractor hit — being in the PR never widens egress.
  Shallow checkouts or runs where git cannot answer keep the previous order. The log says how many analysed files the
  PR changed.

## [0.10.3] — 2026-09-28

### Fixed
- **Deep scan now reaches every detector the hosted engine runs.** The lexical pre-filter that decides which files MAY
  be sent (`deep-scan: "true"`) only knew the injection-era sinks, so 93 of the 116 (language × class) cells the hosted
  engines model could never be reached from a file without a free-extractor hit — Go `db.Query(`, Java `executeQuery(`,
  and every configuration rule (TLS verification off, JWT `none`, weak crypto, permissive CORS, insecure cookies, XXE,
  CSRF off, debug mode, world-writable modes, JNDI, LDAP, XPath, NoSQL, ReDoS, prototype pollution, SSTI…). The
  pre-filter is now one marker family per modelled class, pinned by a test that feeds one engine-verified positive per
  cell (`src/__tests__/fixtures/heisen-classes.json`). A file with no security marker is still never sent, and the caps
  (40 files / 2M characters) are unchanged.
- **Under the 40-file cap, files that read request input go first.** After the extractor-hit files, a marker file that
  also reads a request value (Flask/Django/aiohttp `request.*`, Express `req.*`, Rails `params[`, Go `r.*`, servlet
  `getParameter`, Spring `@RequestParam`…) is sent before a marker-only one — the likeliest place for a real flow.

## [0.10.2] — 2026-09-27

### Changed
- **Honest precision for `deep-scan-block`.** The README, the `deep-scan-block` input description and `--help` quoted
  only the benchmark number (~94%, « about 1 false block in 17 »). Measured on real-world CVE code — GitHub advisory
  files in their vulnerable and fixed versions, 49 blocks adjudicated one by one — the taint engine's blocks are right
  69–73% of the time (about 1 false block in 3–4), mostly because a project's own validation function is not
  recognised. Both numbers are now stated. No behavior change: the deep scan stays advisory by default and blocking
  stays opt-in.

## [0.10.1] — 2026-09-27

### Added
- **One-click fixes.** A finding with a deterministic, line-local secure rewrite — TLS verification off (`verify=False`,
  `rejectUnauthorized: false`, `NODE_TLS_REJECT_UNAUTHORIZED=0`, `InsecureSkipVerify: true`, `danger_accept_invalid_…(true)`),
  debug on in production (`app.run(debug=True)`, `<compilation debug="true">`) or `yaml.load` — gets a GitHub
  « Commit suggestion » inside its inline PR comment. Computed and **verified in your runner** (the finding's own detector
  no longer matches the rewritten line, and only a short span of the line changes) ; nothing leaves. New input
  `fix: suggest` (default) | `off`. The slopGrade /ci page already promised « N of these findings have a verified fix » —
  this is the client half it was pointing at.
- **Server kill switch for the PR-scoped gate.** The « clean as you code » rule lives in the Action and users pin tags,
  so a bad rule used to need a new release every user adopts. The server can now answer `gateScope: "repo"` to put
  every client ≥ 0.10.1 back on whole-repo counts at once (the introduced / debt split is still shown, and the review
  says the gate is temporarily judging the whole repo). Absent / any other value keeps the PR scope.

### Changed
- `action.yml` description shortened to fit the GitHub Marketplace listing (was ~280 chars) ; the `firewall-mode`
  input now says that on a pull request only what the PR introduces counts.

## [0.10.0] — 2026-09-26

Found by running slopGrade on its own repo : a 6-file PR got the repo's whole backlog — 26 findings, none on its own
lines, zero inline — and in gate mode would have been blocked by findings nobody in the PR touched.

### Changed
- **Clean as you code — the gate judges a pull request on what it introduced.** On a PR the client reads the diff
  and splits every finding into **introduced** (on a line the PR added or changed), **already in a file it changed**,
  and **existing debt elsewhere**. The blocking counts are scoped to the introduced part (`scopedBlocking`): pre-existing
  debt is reported, never blocks the PR. Push runs, and a PR whose diff can't be read (e.g. a private repo without
  `pull-requests: read`), keep the whole-repo counts and say so. Fail-closed where it matters: a blocking finding the
  client can't locate counts against the PR — except unlocated cross-tenant leaks (the server locates at most 20) on a
  PR that touches no schema file, which would otherwise block every PR of a repo with a leak backlog.
- **The PR review leads with the PR.** « This PR introduces N findings » (inline on its lines), then the ones already in
  the files it changed, then the debt as one count + a link — instead of « 26 finding(s) located ».
- **Step Summary** says what the gate counted on a PR (« Blocked — 1 blocking finding introduced by this PR »), plus the
  pre-existing blocking count, never the repo-wide totals it did not block on.

### Added
- Outputs `new-findings` and `preexisting-blocking` (empty off-PR). `blocking-findings` is now what the decision
  counted (PR-scoped on a pull request).
- The PR diff is read across all pages (GitHub's 3000-file cap), not the first 100 files, and once per run — the
  inline feed reuses it.

## [0.9.3] — 2026-09-26

Found by running slopGrade on its own repo.

### Fixed
- **Server-only tables were reported as cross-tenant hard leaks on the free tier.** The client never extracted the
  client-role `GRANT … TO anon|authenticated|public` / `REVOKE … FROM …` facts, and the egress boundary
  (`sanitizeFingerprint`) dropped `rls.granted` / `rls.revoked` anyway — so the server could never tell a REVOKE'd,
  server-only table from a client-reachable one. Both are now extracted (table names only, the same metadata class as
  `rls.on` / `rls.policy`) and whitelisted through the boundary with the same coercion.
- **Located cross-tenant leaks vanished from annotations, SARIF, the PR review and the Step Summary.** The server
  sends leaks as objects `{kind, table, file, line}`; the client parsed them as strings, so the log printed
  `[object Object]` and no leak ever got a location. `parseLeak` / `leakText` now read the object form (the legacy
  string form still works).

## [0.9.2] — 2026-09-26

### Fixed
- **Wrong price in the CI log and the README.** Both said « $8–29/repo/mo (volume pricing) »; the price is graduated —
  $24/repo/mo for repos 1–4, $15 for 5–10, $11 for 11–20 (20 repos = $296/mo) — or Team $299/mo flat for unlimited
  repos (source: slopgrade `lib/pricing.ts` FIREWALL_TIERS / TEAM_FLAT). 14-day free trial, no card, unchanged.

## [0.9.1] — 2026-09-26

### Fixed
- **Public and free-private repos were told « this repo is PAID … the pro extractors did not load » on every run.**
  The guard keyed on `gateEntitled`, which is also true for public and free-oss repos (they have the free gate, never the
  paid catalogue). It now keys on the server's exact `gateLevel === "paid"` (falls back to `gateEntitled` for a server
  that predates it).
- README / action.yml: the free tier **does** block — on public repos and on your first private repo (cross-tenant +
  the 22 OSS classes). The previous text said private repos never block.

### Added
- A paid repo that has not opted into the deep scan gets one `::notice` in the CI log saying how to enable it. Public
  and free-oss repos are never invited (the deep scan would answer them `402`).

## [0.9.0] — 2026-09-26

Blocking on the deep scan — your choice, with the cost stated.

### Added
- **`deep-scan-block` input / `--deep-scan-block` flag (default `false`).** With `deep-scan: "true"` and
  `firewall-mode: gate`, a **new** deep-scan finding (a `file:line` no detector pack reported) fails the check: it
  annotates as an error, counts in the `blocking-findings` output, and the block message names it. Measured block
  precision of the taint engine on held-out labeled code: 68/72 (~94%); 17/21 on the strictest slice (CodeQL Python).
- A finding that only confirms a line a pack already reported never counts twice.

### Unchanged
- Default behavior: the deep scan stays advisory; without `deep-scan`, no source leaves the runner. `--deep-scan-block`
  without `--deep-scan` is ignored with a warning. Advisory mode never blocks.

## [0.8.0] — 2026-09-26

The hosted taint engine, as an opt-in: cross-function flows the intra-function packs cannot see.

### Added
- **`deep-scan` input / `--deep-scan` flag (default `false`, paid repos).** Sends the source of a bounded set of
  sink-bearing files (≤ 40 files / 2M chars — extractor-hit files first, then files with a sink marker; a file with no
  sink marker is never sent) to `https://app.slopgrade.ai/api/ci/heisen`, which forwards it to the heisen taint engine
  and drops it (never logged, never stored). Findings follow a request value to its sink **across functions**.
  Measured on a paid sandbox with all 122 packs loaded: a request → helper → `check_output(shell=True)` flow reported
  by no pack is found by the deep scan.
- `--print-payload` lists the files the deep scan would send (`deepScan.files`), so the audit promise covers it.

### Security
- **The one mode that sends code is off unless you turn it on**, goes only to the canonical origin (never a custom
  `SLOPGRADE_ORIGIN`), and a server answer can only annotate a file this run actually sent. README, action and package
  descriptions now say « no source egress **by default** ».

### Behavior
- Advisory: deep-scan findings annotate as warnings and never fail the check (calibration window). A finding on a line
  another pack already reported is counted as a confirmation, not annotated twice. `402` (not paid), 5xx, network or a
  malformed answer are warnings — the verdict and exit code are never affected.

## [0.7.9] — 2026-09-19

The primary control for the paid pro-extractor path: cryptographic authenticity, not just integrity.

### Security
- **The pro bundle is verified against a pinned Ed25519 public key before it is ever written or executed.** The sha256
  check only proves the bytes weren't corrupted — the server supplies both the bundle and its hash, so a compromised
  server or a CA-valid MITM could match its own hash. A signature verified against a key the client *ships*
  (`PRO_BUNDLE_PUBKEY`) cannot be forged by whoever controls the response. An unsigned/invalid bundle is **never run** —
  the client degrades to the free packs. (`verifyBundleSig`, Ed25519 via `node:crypto`.)
- Ships **inert** until the public key is pinned: with `PRO_BUNDLE_PUBKEY` empty the check is skipped (unchanged
  behavior). Activation is a coordinated rollout — the server signs first (env private key), then this key is pinned.

## [0.7.8] — 2026-09-19

Runner-safety hardening of the paid pro-extractor path, from a wider adversarial security review.

### Security
- **The closed-source pro bundle is fetched ONLY from the canonical origin.** A custom `SLOPGRADE_ORIGIN` (staging, or
  an attacker who set `SLOPGRADE_ALLOW_CUSTOM_ORIGIN`) now falls back to the free packs instead of downloading and
  executing code from that origin — closing an RCE-via-custom-origin path.
- **The pro response is size-capped before parsing.** The body is read through a bounded reader (and a `content-length`
  pre-check) so an oversized/compromised response can no longer OOM the runner (`res.json()` was unbounded).
- **The bundle is written to a private (0700) unique temp dir with an exclusive (`wx`) flag and removed after import**,
  closing the predictable-filename symlink/TOCTOU race on shared self-hosted runners.

### Notes
- These reduce the blast radius of the pro path; the primary control — an Ed25519 signature over the bundle with a
  pinned public key (so a compromised server / MITM can't ship runnable code at all) — is tracked as the next step.

## [0.7.7] — 2026-09-19

### Fixed
- **Access-control / db-safety findings now land on their real file, with their own rule, in every channel.** These
  packs put a *DB table name* in `table` (not a `file:line`) and the real path in a separate `file` field. The old code
  located them via `table` — producing a bogus path like `orders:1`, mislabeling them as `cross-tenant-isolation-leak`
  in the SARIF, and dropping them from the inline PR feed entirely. A new `findingLocation()` resolves location from
  `file` when `table` isn't a `file:line`, and the redundant, wrongly-labeled SARIF path was removed — so the log, the
  PR review, and Code Scanning all show these findings on the right file under their own pack rule (`accessControl`,
  `dbSafety`, …), once each.

### Docs
- README documents that fork PRs get a read-only `GITHUB_TOKEN`, so the PR feed + Code Scanning upload are skipped
  fail-soft on external-contributor runs (the gate still runs).

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
