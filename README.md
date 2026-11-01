# slopGrade Firewall — CI security-leak detection

The **open-source client** of the [slopGrade Firewall](https://www.slopgrade.ai/firewall?utm_source=github-marketplace&utm_medium=listing&utm_campaign=launch-v3). It runs in your CI,
detects high-severity security leaks in the diff. **By default, your source code and file contents never leave your
runner** — only a structural fingerprint (table/column names + `{file, line, kind}` locations, no code) is posted for
classification. The one exception is the opt-in [`deep-scan`](#deep-scan--opt-in-paid-the-one-mode-that-sends-code)
(off unless you turn it on). This repository is the exact code that runs in your runner: **audit every line before you pin it.**

**What it catches in a pull request, before it merges:** cross-tenant data access (a query that forgets the tenant
filter), SQL and command injection, SSRF, XSS, path traversal and secrets in code — the 10 open-source classes
(22 detector packs) on JS/TS and Python; Go and .NET cover six of them.

- **Free where it matters first.** It blocks on public repos and on your first private repo. Other private repos get
  the full report and are never blocked; the [Team plan](https://www.slopgrade.ai/pricing?utm_source=github&utm_medium=readme&utm_campaign=firewall-action) blocks on 50 of them.
- **Your code stays on your runner.** Only a structural fingerprint is sent. Print it with `--print-payload`.
- **No secret to store.** GitHub's OIDC token proves which repo is calling.
- **Only what the pull request adds can block it.** Existing findings are reported, never block the PR.

## Quick start

```yaml
# .github/workflows/slop-gate.yml
name: slop-gate
on: { pull_request: {} }
jobs:
  slop:
    runs-on: ubuntu-latest
    permissions: { contents: read, id-token: write, pull-requests: write }
    steps:
      - uses: actions/checkout@v7
        with: { fetch-depth: 0 }
      - uses: maxor-tech/slopgrade-firewall@v0.12.2
```

`id-token: write` is required (it is how the repo proves itself). `pull-requests: write` posts the findings on the PR.

## Add it to your repo (all options)

```yaml
# .github/workflows/slop-gate.yml
name: slop-gate
on: { pull_request: {} }
jobs:
  slop:                          # keep this job name: "Protect main" in app.slopgrade.ai requires the check named `slop`
    runs-on: ubuntu-latest
    permissions:
      contents: read
      id-token: write            # zero secret: GitHub proves your repo by OIDC (no PAT, nothing to store)
      pull-requests: write       # optional: post the inline finding feed on the PR (omit to skip the feed)
      security-events: write     # optional: send findings to the Security tab (Code Scanning) — free on public repos
    steps:
      - uses: actions/checkout@v7
        with: { fetch-depth: 0 }
      - uses: maxor-tech/slopgrade-firewall@<sha>   # pin the commit SHA (a tag can be re-pointed; a SHA cannot)
        with:
          # firewall-mode: "gate"      # DEFAULT — block on a hard leak or a blocking finding. Free: public repos and your
          #                              FIRST private repo block on cross-tenant + the 22 OSS classes; other repos
          #                              without a paid slot stay advisory, never blocked
          # firewall-mode: "advisory"  # opt into report-only: report leaks, never block
          # firewall-mode: "off"       # disable
          # strict: "true"             # with gate: fail the build if no verdict is available (default: fail open)
          # upload-sarif: "false"          # opt out of the Code Scanning upload (default: true — needs security-events: write)
          # sarif-file: "firewall.sarif"   # ALSO write the SARIF to a file (for a build artifact); upload runs regardless
          # deep-scan: "true"              # OPT-IN, paid: ALSO send the source of sink-bearing files to the hosted taint
          #                                  engine (cross-function flows). Default false — see "Deep scan" below
          # deep-scan-block: "true"        # with deep-scan + gate: a NEW deep-scan finding fails the check (default false)
          # block-confidence: "false"      # opt out of advisory demotion below the engine threshold (ON by default)
          # fix: "off"                     # one-click « Commit suggestion » fixes on the PR (default: suggest)
```

Or run it directly: `node isolation-gate.mjs --print-payload` (audit exactly what would leave the runner).

## Outputs

The step exposes the verdict so a later step can act on it (post to Slack, gate another job, render a badge):

| Output | Example | Meaning |
|---|---|---|
| `verdict` | `gate-blocked` | `advisory` · `gate-blocked` · `gate-unpaid` · `gate-pass` |
| `blocked` | `true` | did the gate fail the build? |
| `hard-leaks` | `2` | count of hard cross-tenant leaks |
| `blocking-findings` | `3` | count of blocking (critical/high) findings the gate counted — on a PR, only those it introduced |
| `new-findings` | `1` | on a PR: findings on the lines this PR added or changed (empty off-PR) |
| `preexisting-blocking` | `12` | on a PR: blocking findings that were already there — reported, never block the PR (empty off-PR) |
| `conformance` | `94.2` | tenant-scoping conformance %, or empty |
| `entitled` | `true` | the gate is active: public repo, your free private repo, or a paid slot |
| `sarif-uploaded` | `true` | were findings sent to Code Scanning this run? |

```yaml
      - uses: maxor-tech/slopgrade-firewall@<sha>
        id: firewall
      - if: ${{ steps.firewall.outputs.blocked == 'true' }}
        run: echo "blocked on ${{ steps.firewall.outputs.hard-leaks }} leak(s)"
```

## What it detects (free tier — the 10 highest-severity classes)

All ten classes run across **JavaScript/TypeScript** and **Python**. **Go** and **.NET** cover the six
marked ✓ (the four unmarked — XXE, insecure deserialization, hardcoded secrets, broken crypto — are JS/TS + Python only):

| Class | CWE | | Go / .NET |
|---|---|---|---|
| SQL injection | CWE-89 | RCE / data exfiltration | ✓ |
| Command injection | CWE-78 | remote code execution | ✓ |
| Cross-site scripting (XSS) | CWE-79 | session theft | ✓ |
| Server-side request forgery (SSRF) | CWE-918 | incl. cloud-metadata theft | ✓ |
| XML external entity (XXE) | CWE-611 | file read + SSRF | |
| Insecure deserialization | CWE-502 | RCE | |
| Path traversal | CWE-22 | file disclosure | ✓ |
| Hardcoded secrets | CWE-798 | credential leak (the value never leaves this client) | |
| Broken / weak crypto | CWE-327 | md5 · sha1 · ECB on secrets | |
| CORS reflected-origin | CWE-942 | cross-origin data leak | ✓ |

## How it works — no source-code egress

1. **Local, in your runner** — the client walks your tree and builds a **structural fingerprint**: file paths and
   `{file, line, kind}` per finding. **Your source code, and the contents of your files, never leave the machine.**
   Only the fingerprint is posted. Hardcoded-secret matches emit the *location and kind* — never the value.
2. **Server verdict** — the fingerprint is posted to `https://app.slopgrade.ai/api/ci/isolation`, which classifies
   and measures, then returns the verdict. The classification heuristics run **server-side** and are intentionally
   **not** in this repository.
3. **Feed — judged on the PR, not on your backlog** — on a pull request the client reads the PR's diff and splits every
   finding into **introduced** (on a line this PR added or changed), **already in a file you changed**, and
   **existing debt elsewhere**. The review leads with what the PR introduced (inline on those lines); the debt is a
   count and a link, not a wall. With `pull-requests: write`, it is posted as ONE review (one notification), deduped on
   re-runs. It posts with your **own** `GITHUB_TOKEN`, to your own PR — findings never reach slopGrade. Omit the
   permission to skip the feed. Reading the diff of a **private** repo needs `pull-requests: read` (or `write`);
   without it the run says so and judges the whole repo, as before.
4. **Code Scanning** — when the workflow grants `security-events: write`, the same findings are uploaded to your
   repo's **Security tab** as a SARIF report, so they also appear **inline on the PR "Files changed" tab**, tracked
   across commits and dismissible — GitHub's native security surface, **free on public repos**. No extra step to wire
   and no action SHA to pin: the upload uses your own `GITHUB_TOKEN`, to your own repo (nothing reaches slopGrade). A
   clean run uploads an empty report, so fixed alerts auto-resolve. Omit the permission (or `upload-sarif: "false"`)
   to skip it — the upload quietly no-ops, never breaking the build.
5. **Exit** — `advisory` always exits 0 (reports only). `gate` (the default) blocks (exit 1) **only** on a `reliable`
   cross-tenant hard leak in an entitled repo, **or** a blocking (critical/high) detector finding the server counted
   for this repo, **or** (opt-in `deep-scan-block`) a new deep-scan finding. **Entitled** = a public repo, your **first
   private repo** (the free allocation — both block on cross-tenant + the 22 OSS classes), or a paid slot (every
   calibrated class). Any other repo in `gate` mode stays advisory — the paywall fails open, it is never blocked. The
   whole decision is the pure, tested [`firewallVerdict`](./src/gate-verdict.mjs).
   **Clean as you code:** on a pull request those counts are **scoped to what the PR introduced** — pre-existing debt
   is reported but never blocks the PR, so adopting the gate on a repo with a backlog doesn't block its next PR on
   findings nobody touched. Push runs, and a PR whose diff can't be read, keep the whole-repo counts. A blocking
   finding the client can't locate is counted against the PR (never assumed old), except unlocated cross-tenant leaks
   on a PR that touches no schema file (SQL / migration / ORM schema) — [`scopedBlocking`](./src/pr-suggest.mjs).

> **Fork PRs (external contributors):** GitHub gives the `pull_request` event a **read-only** `GITHUB_TOKEN` on runs
> from a fork, whatever `permissions:` you declare. The gate still runs (verdict + exit code are unaffected), but the
> PR feed (step 3) and Code Scanning upload (step 4) can't write and are **skipped fail-soft** — so an external-contributor
> PR gets the log + Step Summary, not inline comments or Security-tab alerts. This is inherent to GitHub's fork model;
> teams that want those surfaces on fork PRs use a separate `workflow_run`/`pull_request_target` workflow (with its own
> security trade-offs), which is out of scope for this action.

Detectors run **intra-function**. Cross-function / cross-file dataflow, the other security classes, and the
calibrated (corpus-tuned) false-positive suppression are part of the hosted product — see **[slopgrade.ai/firewall](https://www.slopgrade.ai/firewall)**.

### Paid repos — the full catalogue, still in your runner

When the repo's gate is paid, the client (≥ 0.7.0) asks `https://app.slopgrade.ai/api/ci/pro-extractors` — with the
same OIDC proof — for the **closed-source extractors** of the other ~100 detector packs, verifies the bundle
(size-bounded, sha256-checked), and runs it **locally**, then posts ~120 fingerprints instead of 22. Nothing else
changes: your file contents still never leave, the classification still runs server-side, and a free repo simply
gets `402` and keeps its 22 packs. The pro output goes through a second, shape-agnostic egress boundary
(`sanitizeProFingerprints`: numbers, booleans and short strings under identifier-like keys — every source-bearing key
is dropped). `--print-payload` inside CI performs the same ask, so what it prints is byte-for-byte what is posted on
the paid tier. Every run prints a coverage line — `N detector packs (free tier | paid) · M files scanned` — so a
clean run is never mistaken for a run that scanned nothing.

### Deep scan — opt-in, paid, the one mode that sends code

`deep-scan: "true"` (client ≥ 0.8.0, default **false**) adds slopGrade's hosted **taint engine** (heisen): it follows a
request value from the line it is read to the line it reaches a sink, **across functions** — the flows the
intra-function packs above cannot see (e.g. a request parameter passed to a helper that runs `check_output(…,
shell=True)`). It is the **only** mode in which file contents leave your runner, so it is off unless you set it:

- **What is sent** — the source of at most **80 files / 2M characters**: first the files where an extractor already
  found a sink, then any Python / JS-TS / Go / Java / Ruby / PHP file containing a sink marker (shell, eval, SQL, file,
  redirect, outbound request, template, unsafe deserializer). A file with no sink marker is never sent.
  `--print-payload` lists the exact files (under `deepScan.files`) before anything is sent.
- **On a pull request, the PR's code first — and only the code it changed** (client ≥ 0.10.11). The files the PR
  changed are sent first. Each one also carries the **line ranges** the PR changed, read locally with `git diff -U0`
  against the base commit (line numbers only, never more source). The engine then analyses the functions those lines
  touch and every function of the file that calls them, not the whole file again. A new file, or a change outside any
  function the engine can place, is analysed whole.
  - A PR-scoped run is never read as « fixed »: on the run's page an untouched function's earlier findings are neither
    resolved nor compared.
  - Measured on real CVE fixes (OSV PyPI, each side scoped to the lines its fix changed): no vulnerable file that the
    whole-file analysis caught was lost; held-out pairs caught rose 59 → 65; files flagged on both sides of a fix fell
    76 → 54; engine time fell about a quarter.
  - Push runs to the default branch stay whole-file. `--print-payload` shows how many files are sent PR-scoped
    (`deepScan.scopedToPrLines`).
- **Where** — only to the canonical `https://app.slopgrade.ai/api/ci/heisen` (never to a custom origin), with the same
  OIDC proof. Server-side the code is forwarded to the engine and **dropped** — never logged, never stored; only
  `file:line`, the CWE and the engine's one-line evidence are kept for your `/ci` history.
- **Who** — paid repos. A non-paid repo gets `402`: a warning, nothing is analysed, the run is unaffected.
- **Advisory by default, blocking if you choose** — findings annotate as **warnings** (log, PR review, SARIF) and never
  fail the check. Set `deep-scan-block: "true"` (with `firewall-mode: gate`) to make a **new** deep-scan finding — one no
  detector pack reported — **fail the check**. What that costs depends on the code, so here are both numbers:
  on labeled **benchmark** code the engine was not tuned on, its blocks are right **68 of 72 (~94%)**; on **real-world
  CVE code** (GitHub advisories, the vulnerable and the fixed version of the same file — held-out split, 2026-10-22)
  they are right **at least 78% (25 of 32)** — roughly **one false block in four to five**; but **on 52,089 ordinary open-source pull requests it blocked 245, 46 of them for a real flaw** (benchmark of 2026-10-24), so ordinary code sees far more false blocks than the CVE figure suggests. The CVE figure is a floor: every block on
  the fixed version counts as false, even where a real flow remains after the fix. Most false blocks come from a project's
  own validation function (`validateId(x)`, `isPathAllowed(x)`) that the engine does not recognise. That is why it is off by default: enable it where a false block is cheaper than a missed flow. A finding on a line another pack already reported is counted as a confirmation, not annotated or
  counted twice. Any failure (timeout, 5xx, malformed answer) is a warning — the verdict is never affected.
- **Block confidence — ON by default in the GitHub Action** (requires `deep-scan`). Set
  `block-confidence: "false"` to opt out. Direct CLI use remains opt-in with `--block-confidence` (default OFF).
  With `deep-scan-block` and gate mode, a fresh finding stays a warning only when its
  `blockConfidence` (or `block_confidence`) object has schema `heisen-block-confidence/v2`, a nonempty model
  identifier, disposition `ADVISORY`, and finite scores in [0, 1] satisfying **score < tau**. Equality still blocks.
  The engine owns tau and the model; the Action cannot override either. The hosted operator switch
  `SLOPGRADE_BLOCK_CONFIDENCE` must also be ON on the hosted side for scoring.
  Findings remain in the report; independent pack findings and cross-tenant leaks retain their gate rules.
  - **Additional egress: three numbers**, `repo_off`, `repo_teach`, `readme_len`, plus schema and extractor
    (`repo-aggregates/1`) identifiers, in the existing SHA/OIDC-bound Deep Scan request. README text never leaves the runner; no author
    information is added. These numbers reveal limited repository characteristics.
  - Locally, `owner/name` from `GITHUB_REPOSITORY` becomes `owner__name`. The first existing `README.md`,
    `readme.md`, `README.rst`, or `README` in the scanned working tree is decoded as UTF-8 (invalid bytes replaced),
    capped at 20,000 Unicode code points; its first 3,000 feed the keyword counts. `readme_len` is
    `log1p` of the capped length. Missing README means empty text; an empty existing file wins.
    The caller must check out the scanned commit, just as for the source units.
  - **Fallback:** OFF adds no request fields. An unreadable context, missing repository identity, old server,
    absent/malformed metadata, unsupported schema, or ambiguous aliases retains existing Deep Scan blocking.
    Disable the input to roll back; the hosted operator can also stop returning confidence metadata.
  - **Measured on a fresh sample of 104 blocked pull requests:** PR-block precision rose **21.0% → 41.7%**,
    and blocked PRs fell **104 → 49**. One justified PR lost its block; **37 of 41 true-positive findings**
    remained blocking. **Caveat:** one blind labeler, labels not adjudicated; the 95% confidence interval for
    the resulting precision is **29–56%**. These sample results are not a guarantee for other repositories.
    Activation requires a compatible hosted app/engine model. README-derived inputs are caller assertions and can be manipulated.
- **Library mode — opt-in, packages only** (`library-mode: "true"`, client ≥ 0.10.6). For a repo that is a **published
  package**, the attack surface is its callers, so the engine can also report **library-tier candidates**: a public
  function's parameter reaching a sink. The package is recognised from its manifest, locally (npm: not private, publishes
  `files`/`exports`/`types`, no `start` script; Python: a `pyproject.toml`/`setup.py` package without `manage.py`/`wsgi`/`asgi`/
  `app.py` or a web-framework dependency) — an application is never affected, the log says so. Candidates are **notices to
  triage**, never findings: not in the gate, the PR review count or SARIF. Honest numbers, measured on real CVEs (GitHub
  advisories, the vulnerable file flagged AND its fix not): paired recall rises from about **1% to 9%** (JavaScript) and
  **1.5% to 5.6%** (Python) — but about **2 in 3 candidates remain after the fix**, and a clean library can show a few
  by-design flows (a template engine rendering what it is given). Use it to review a package's public API, not as a gate.
  A candidate you reviewed is quieted with a `heisen-ignore: <reason>` comment on its sink line (client ≥ 0.10.7 also prints
  what became of the previous run's candidates: resolved · dismissed · still open · new; the run's page in
  [app.slopgrade.ai/ci](https://app.slopgrade.ai/ci) lists them with a link to each line).
- **Compared with semgrep, on the CVEs a taint tool is built for.** Most real CVEs are validation-logic bugs no taint
  engine sees, so the comparison uses a denominator fixed **before** running either tool: an advisory pair counts when
  its fix changes a line that calls a sink API of its class (`os.system`, `subprocess.*`, `eval`, `.execute(`, `fs.*`,
  `fetch(`, `innerHTML`, `pickle.load`, …) — about 17% of pairs. Both tools then run on the same files; a pair is found
  when the vulnerable file is flagged **and** its fix is not; « both sides » counts pairs flagged on the fix too (noise).
  Held-out OSV advisories, semgrep 1.178.0 `p/default` per file, heisen measured 2026-09-28:

  | held-out pairs | heisen, requests only | **heisen + library** | semgrep, taint rules | semgrep, + audit rules |
  |---|---:|---:|---:|---:|
  | npm, 174 | 1.1% | **24.1%** (both sides 41) | 6.9% (9) | 4.6% (55) |
  | PyPI, 123 | 4.1% | **19.5%** (both sides 20) | 8.1% (16) | 24.4% (42) |

  In **JavaScript** the library tier finds about **3×** what semgrep finds, and a smaller GitHub-advisory sample (93
  pairs: 35.5% vs 12.9%) agrees. In **Python** it finds more than semgrep's taint rules but **fewer than its audit
  rules**, which also flag the fixed file about twice as often. Go is not claimed (the sink list names Python / JS APIs).
  Both library tier and audit rules are triage tiers, not blocks; the requests-only tier is what `deep-scan-block` can
  block on: on the fixed files it blocked 1 in the PyPI set above and 0 in the GitHub-advisory sample.

## Excluding paths — `.slopgradeignore`

Tests, fixtures, `vendor/`, `dist/` and example folders are already skipped. For anything else that is not your running
code — docs or marketing copy that *shows* vulnerable snippets, generated files — add a `.slopgradeignore` at the repo
root, one pattern per line (gitignore-style subset):

```gitignore
# pages that display intentionally vulnerable examples
content/examples/
lib/gate-pages.ts
*.snap
src/**/generated-*.ts
```

A pattern without `/` matches a file or directory at any depth; with a `/` it is anchored at the repo root. `*` stays
within a path segment, `**` spans segments. Ignored files are never read, so they produce no finding and no fingerprint.

**A pull request cannot exempt itself:** on a `pull_request` run the file is read from the **base branch** (`git show
origin/<base>:.slopgradeignore`, needs `fetch-depth: 0`), never from the PR — a new entry applies once it is merged.
Patterns that would exclude everything (`*`, `**`, `/`), negations (`!`) and over-long lines are refused with a warning.
The log says how many patterns applied and how many files were skipped.

## Accepting one finding for a time — `.slopgrade-exceptions`

`.slopgradeignore` hides whole paths for good. To accept **one** finding you have reviewed — a protocol that mandates a
cipher, a query you have proven safe — add an entry to `.slopgrade-exceptions` with an owner, a reason and an end date:

```text
# <pack-or-rule> <path>[:<line>] until=YYYY-MM-DD owner=<who> reason=<why>
weakCrypto src/legacy/ntlm.ts:88 until=2026-12-31 owner=@sec-team reason=NTLM interop, removed with the v2 auth
taint-sql db/report.py until=2026-11-30 owner=dana reason="read-only reporting replica"
```

The finding is still reported — annotation, PR review and SARIF say `excepted until … by …` — but it no longer blocks.
On its `until` date the entry stops applying: the finding blocks again and the log names the expired entry. `until`
(at most 180 days ahead), `owner` and a reason of at least 10 characters are required; a glob path and a cross-tenant
leak are refused. Like `.slopgradeignore`, the file is read from the **base branch** on a pull request, so a PR cannot
accept its own finding.

## Courses, labs and offensive tools — repository purpose

In a course, a tutorial, a deliberately vulnerable lab, a CTF or an offensive tool, the vulnerable code *is* the content. With `--gate`, a repo that **reads as one of those** gets its pack and Deep Scan blocks as **advisory warnings** (same findings, no failed check), and the log says why:

```
slopGrade Firewall: this repo reads as a teaching repository (README title "Node.js Bootcamp Course" mentions course, bootcamp) — findings are advisory. Set `purpose: product` in .slopgrade.yml to block.
```

The decision is local and deterministic (no network): README title and first paragraph, `package.json` / `pyproject.toml` / `composer.json` description and keywords, top-level directory names (`week-1`, `lesson_01`, `exercises/`, `payloads/`…) and the repository name. One strong signal (title, first paragraph) or two weaker ones are needed; a library that only links a tutorial stays a product. Cross-tenant hard leaks are **never** affected.

- **Override** — put `purpose: product` in `.slopgrade.yml` at the repo root to keep blocking on.
- **Opt-in** — `SLOPGRADE_PURPOSE_CLASSIFIER=on` in the step `env:` enables the classifier (default `off` while it is calibrated).
- **A pull request cannot reclassify its own repo:** on a `pull_request` run the README, manifests, directory list and `.slopgrade.yml` are read from the **base branch** (`origin/<base>`, needs `fetch-depth: 0`), like `.slopgradeignore`. An unreadable base means `product` (blocking unchanged).
- **Threat note** — a product can still dodge the gate by merging a course-like README to its default branch. That change is a visible commit on the base branch, and every demoted run prints the classification and the override line. The classifier only lowers pack and Deep Scan *blocks*; findings stay in the log, the PR review and the Security tab.

## Fail-open, always

A missing OIDC token, a timeout (each call bounded at 20s), a network failure, or a server error **never** breaks
your build. The only `exit 1` is a real finding in `gate` mode on an entitled repo (step 5 above). For teams that
would rather the control not silently self-disable, `strict: "true"` fails **closed** when no verdict is available.

## What leaves your runner (and what does not)

- **File contents never leave — unless you opt into `deep-scan`.** By default the client reads files locally and emits
  only source-derived **metadata**: file paths and `{file, line, kind}` — never the code, never a secret value. With
  `deep-scan: "true"` the source of the bounded, listed set of sink-bearing files is sent (see *Deep scan* above). Audit it: `node isolation-gate.mjs
  --print-payload` prints the exact payload that would be posted, then exits without contacting the server.
- **No stored secret.** Identity is a short-lived, GitHub-signed OIDC token, audience-bound to the server origin.
- **Endpoint is fixed.** A custom `SLOPGRADE_ORIGIN` is refused (the run goes dry) unless you explicitly set
  `SLOPGRADE_ALLOW_CUSTOM_ORIGIN=1` for a self-hosted server.
- **$0 · local · deterministic.** Zero npm dependencies (only `node:*`). Pin the **SHA** to freeze the exact code.

## Free vs hosted

The free tier is a real, standalone control — 10 classes, intra-function, your code never leaves (only the fingerprint above is sent) — and it **blocks for free** on
public repos and on your first private repo. The **hosted** [slopGrade Firewall](https://www.slopgrade.ai/firewall) adds what a local client cannot:

| | Free (this repo) | Hosted |
|---|---|---|
| Detection classes | the 10 highest-severity (22 packs) | the full detector catalog (~120 packs) — the extra extractors stream to **your runner** at run time (client ≥ 0.7.0) ; your code still never leaves |
| Dataflow | intra-function | cross-function + cross-file (interprocedural taint) |
| False-positive suppression | commodity context checks | calibrated on a large private corpus |
| Findings shown | the 22 OSS classes : every finding ; the other classes : the **count** + **one located sample** (`file:line`, rule name withheld) | every finding, rule name + detail |
| **Public** repos | cross-tenant gate + the 22 OSS classes **block, free** | blocking gate on every calibrated class |
| **Your first private repo** | cross-tenant gate + the 22 OSS classes **block, free** (one per account) | blocking gate on every calibrated class |
| **Other private repos** | **advisory only** — never blocked | **blocking gate** on every calibrated class |
| Verified auto-fix + inline PR feed | feed : the located sample per class | full feed + verified auto-fix |

Your **first private repo** blocks for free on the same classes as a public repo. **Further** private repos run
advisory-only: for each class you see how many findings there are and one located sample, and the build is never
blocked. Every class, the full list, the rule names and the block on them are the hosted gate, on the **Team** plan:
**$299/mo flat for 50 private repos**, then $4 per extra repo up to 100 and $3 beyond — **14-day free trial, no card**.
Users unlimited, never billed per seat. Larger fleets: **Enterprise**. → **[slopgrade.ai/pricing](https://www.slopgrade.ai/pricing)**

When a private repo runs advisory, the run summary, the PR comment and the log say **why** and **who acts** (client
≥ 0.11.0, from the server's answer — this client hard-codes no price): a **Team member** whose repo is outside the
Team pool gets a link to ask the owner to cover it; an account on the free plan gets the Team plan.

## Show it in your README

Once the gate runs on your repo, add the badge so contributors know the diff is checked:

```markdown
[![slopGrade Firewall](https://img.shields.io/badge/security-slopGrade%20Firewall-36D399?logo=github)](https://www.slopgrade.ai/firewall)
```

[![slopGrade Firewall](https://img.shields.io/badge/security-slopGrade%20Firewall-36D399?logo=github)](https://www.slopgrade.ai/firewall)

## Development

```bash
node --test src/__tests__/*.test.mjs        # the exit boundary + the extractor behavior
node isolation-gate.mjs --print-payload      # print the EXACT wire payload and exit
node isolation-gate.mjs --help               # flags + exit-code semantics
```

Security policy: [`SECURITY.md`](./SECURITY.md) · Changes: [`CHANGELOG.md`](./CHANGELOG.md).

MIT © Maxor Global LLC. See [LICENSE](./LICENSE).
