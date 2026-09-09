# slopGrade Firewall — CI security-leak detection

The **open-source client** of the [slopGrade Firewall](https://www.slopgrade.ai). It runs in your CI,
detects high-severity security leaks in the diff, and — 100% locally — never sends your source anywhere.
This repository is the exact code that runs in your runner: **audit every line before you pin it.**

## Add it to your repo

```yaml
# .github/workflows/firewall.yml
on: { pull_request: {} }
jobs:
  firewall:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      id-token: write            # zero secret: GitHub proves your repo by OIDC (no PAT, nothing to store)
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }
      - uses: maxor-tech/slopgrade-firewall@<sha>   # pin the commit SHA (a tag can be re-pointed; a SHA cannot)
        with:
          firewall-mode: "advisory"   # default: report leaks, never block
          # firewall-mode: "gate"     # block on a hard leak (free for public repos)
          # firewall-mode: "off"      # disable
          # strict: "true"            # with gate: fail the build if no verdict is available (default: fail open)
          # sarif-file: "firewall.sarif"   # also write SARIF, then upload it to see leaks on the PR diff
```

Or run it directly: `node isolation-gate.mjs --print-payload` (audit exactly what would leave the runner).

## What it detects (free tier — the 10 highest-severity classes)

Across JavaScript/TypeScript, Python, **Go** and **.NET**:

| Class | CWE | |
|---|---|---|
| SQL injection | CWE-89 | RCE / data exfiltration |
| Command injection | CWE-78 | remote code execution |
| Cross-site scripting (XSS) | CWE-79 | session theft |
| Server-side request forgery (SSRF) | CWE-918 | incl. cloud-metadata theft |
| XML external entity (XXE) | CWE-611 | file read + SSRF |
| Insecure deserialization | CWE-502 | RCE |
| Path traversal | CWE-22 | file disclosure |
| Hardcoded secrets | CWE-798 | credential leak (the value never leaves this client) |
| Broken / weak crypto | CWE-327 | md5 · sha1 · ECB on secrets |
| CORS reflected-origin | CWE-942 | cross-origin data leak |

## How it works — zero source egress

1. **Local, in your runner** — the client walks your tree and builds a **structural fingerprint**: file paths and
   `{file, line, kind}` per finding. **Your source code, and the contents of your files, never leave the machine.**
   Only the fingerprint is posted. Hardcoded-secret matches emit the *location and kind* — never the value.
2. **Server verdict** — the fingerprint is posted to `https://app.slopgrade.ai/api/ci/isolation`, which classifies
   and measures, then returns the verdict. The classification heuristics run **server-side** and are intentionally
   **not** in this repository.
3. **Exit** — `advisory` always exits 0 (reports only). `gate` blocks (exit 1) **only** on a `reliable` verdict with
   a hard leak, **and** only if the repo is entitled. This decision is the pure, tested
   [`firewallVerdict`](./src/gate-verdict.mjs).

Detectors run **intra-function**. Cross-function / cross-file dataflow, the other security classes, and the
calibrated false-positive suppression are part of the hosted product — see **[slopgrade.ai](https://www.slopgrade.ai)**.

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

## Development

```bash
node --test src/__tests__/*.test.mjs        # the exit boundary + the extractor behavior
node isolation-gate.mjs --print-payload      # print the EXACT wire payload and exit
node isolation-gate.mjs --help               # flags + exit-code semantics
```

Security policy: [`SECURITY.md`](./SECURITY.md) · Changes: [`CHANGELOG.md`](./CHANGELOG.md).

MIT © Maxor Global LLC. See [LICENSE](./LICENSE).
