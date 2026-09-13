# Security Policy

## Reporting a vulnerability

If you find a security issue in the slopGrade Firewall client, please report it privately — **do not open a public
issue**.

- Email: **security@maxor-global.com**
- Or use GitHub's [private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
  on this repository (Security → Report a vulnerability).

Please include: the affected version or commit SHA, a description, and a reproduction if possible.

**Response targets:** acknowledgement within 3 business days; a remediation plan within 10 business days for a
confirmed issue. We will credit reporters who wish to be named once a fix ships.

## Scope

This repository is the **open-source client** that runs in your CI. Its security-relevant surface:

- **What leaves your runner:** only a structural fingerprint (table/column names, file paths, abstract query
  shapes) plus a short-lived GitHub OIDC token. File contents never leave. Audit exactly what would be sent with
  `node isolation-gate.mjs --print-payload`.
- **Paid repos (client ≥ 0.7.0) — the pro extractors:** a repo whose gate is paid receives the closed-source extractors
  for the rest of the detector catalogue from `app.slopgrade.ai/api/ci/pro-extractors` (proved by its OIDC token) and
  runs them in the runner. The bundle is size-bounded and sha256-verified before it is evaluated ; its output goes
  through a second, shape-agnostic egress boundary (`sanitizeProFingerprints` — numbers, booleans, short strings under
  identifier-like keys ; every source-bearing key is dropped). File contents still never leave. `--print-payload`
  inside CI shows the paid-tier payload byte-for-byte.
- **Fail-open by design:** a network/server/OIDC failure never breaks your build (exit 0). `--strict` fails closed.
- **Endpoint is fixed** to `https://app.slopgrade.ai`; a custom `SLOPGRADE_ORIGIN` runs dry unless
  `SLOPGRADE_ALLOW_CUSTOM_ORIGIN=1` is set and the origin is https.
- **The PR feed uses your own token, safely:** when the workflow grants `pull-requests: write`, findings post to
  your own PR with your own `GITHUB_TOKEN` (never to slopGrade). The client only *reads* the checked-out tree with
  regexes and never executes scanned content, so a malicious PR cannot achieve code execution through it — but as a
  general rule, do not add other steps that check out and run untrusted PR head under `pull_request_target`.

The hosted analysis service (the classification engine) is out of scope for this repository; report issues with it
to the same address.

## Supported versions

The latest published tag is supported. Pin the Action by full commit **SHA** to freeze the exact code that runs.
