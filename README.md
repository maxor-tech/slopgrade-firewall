# slopGrade Firewall — CI security-leak detection

The **open-source client** of the [slopGrade Firewall](https://www.slopgrade.ai/firewall). It runs in your CI,
detects high-severity security leaks in the diff. **Your source code and file contents never leave your runner** —
only a structural fingerprint (table/column names + `{file, line, kind}` locations, no code) is posted for
classification. This repository is the exact code that runs in your runner: **audit every line before you pin it.**

## Add it to your repo

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
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }
      - uses: maxor-tech/slopgrade-firewall@<sha>   # pin the commit SHA (a tag can be re-pointed; a SHA cannot)
        with:
          # firewall-mode: "gate"      # DEFAULT — block on a hard leak or a blocking finding (public repos are gated
          #                              free on cross-tenant leaks; a non-entitled repo stays advisory, never blocked)
          # firewall-mode: "advisory"  # opt into report-only: report leaks, never block
          # firewall-mode: "off"       # disable
          # strict: "true"             # with gate: fail the build if no verdict is available (default: fail open)
          # sarif-file: "firewall.sarif"   # also write SARIF, then upload it to see leaks on the PR diff
```

Or run it directly: `node isolation-gate.mjs --print-payload` (audit exactly what would leave the runner).

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
3. **Feed** — when the run is on a PR and the workflow grants `pull-requests: write`, every finding is posted as an
   **inline review comment** on its exact `file:line`, plus one summary comment updated in place (deduped, so a re-run
   updates instead of spamming). It posts with your **own** `GITHUB_TOKEN`, to your own PR — findings never reach
   slopGrade. Omit the permission to skip the feed.
4. **Exit** — `advisory` always exits 0 (reports only). `gate` (the default) blocks (exit 1) **only** on a `reliable`
   cross-tenant hard leak in an entitled repo, **or** a blocking (critical/high) detector finding. A non-entitled repo
   in `gate` mode stays advisory — the paywall fails open, so a free repo is never blocked. The whole decision is the
   pure, tested [`firewallVerdict`](./src/gate-verdict.mjs).

Detectors run **intra-function**. Cross-function / cross-file dataflow, the other security classes, and the
calibrated (corpus-tuned) false-positive suppression are part of the hosted product — see **[slopgrade.ai/firewall](https://www.slopgrade.ai/firewall)**.

## Fail-open, always

A missing OIDC token, a timeout (each call bounded at 20s), a network failure, or a server error **never** breaks
your build. The only `exit 1` is a real, `reliable`, hard leak in `gate` mode on an entitled repo. For teams that
would rather the control not silently self-disable, `strict: "true"` fails **closed** when no verdict is available.

## What leaves your runner (and what does not)

- **File contents never leave.** The client reads files locally and emits only source-derived **metadata**: file
  paths and `{file, line, kind}` — never the code, never a secret value. Audit it: `node isolation-gate.mjs
  --print-payload` prints the exact payload that would be posted, then exits without contacting the server.
- **No stored secret.** Identity is a short-lived, GitHub-signed OIDC token, audience-bound to the server origin.
- **Endpoint is fixed.** A custom `SLOPGRADE_ORIGIN` is refused (the run goes dry) unless you explicitly set
  `SLOPGRADE_ALLOW_CUSTOM_ORIGIN=1` for a self-hosted server.
- **$0 · local · deterministic.** Zero npm dependencies (only `node:*`). Pin the **SHA** to freeze the exact code.

## Free vs hosted

The free tier is a real, standalone control — 10 classes, intra-function, zero-egress, and it never blocks a free
repo. The **hosted** [slopGrade Firewall](https://www.slopgrade.ai/firewall) adds what a local client cannot:

| | Free (this repo) | Hosted |
|---|---|---|
| Detection classes | the 10 highest-severity | the full detector catalog |
| Dataflow | intra-function | cross-function + cross-file (interprocedural taint) |
| False-positive suppression | commodity context checks | calibrated on a large private corpus |
| Findings shown | per class : the **count** + **one located sample** (`file:line`, rule name withheld) | every finding, rule name + detail |
| **Private** repos | **advisory only** — never blocked | **blocking gate** |
| **Public** repos | cross-tenant gate blocks, free ; detector classes advisory (count + sample) | blocking gate on every class |
| Verified auto-fix + inline PR feed | feed : the located sample per class | full feed + verified auto-fix |

On a **private** repo the free tier runs advisory-only: for each class you see how many findings there are and one
located sample, and the build is never blocked. The full list, the rule names and the block are the hosted gate:
**$8–29/repo/mo** (volume pricing) — **14-day free trial, no card**. Users unlimited; billed per repo, never per
seat. → **[slopgrade.ai/firewall](https://www.slopgrade.ai/firewall)**

## Development

```bash
node --test src/__tests__/*.test.mjs        # the exit boundary + the extractor behavior
node isolation-gate.mjs --print-payload      # print the EXACT wire payload and exit
node isolation-gate.mjs --help               # flags + exit-code semantics
```

Security policy: [`SECURITY.md`](./SECURITY.md) · Changes: [`CHANGELOG.md`](./CHANGELOG.md).

MIT © Maxor Global LLC. See [LICENSE](./LICENSE).
