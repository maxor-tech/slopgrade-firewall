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
- **Fail-open by design:** a network/server/OIDC failure never breaks your build (exit 0). `--strict` fails closed.
- **Endpoint is fixed** to `https://app.slopgrade.ai`; a custom `SLOPGRADE_ORIGIN` runs dry unless
  `SLOPGRADE_ALLOW_CUSTOM_ORIGIN=1` is set and the origin is https.

The hosted analysis service (the classification engine) is out of scope for this repository; report issues with it
to the same address.

## Supported versions

The latest published tag is supported. Pin the Action by full commit **SHA** to freeze the exact code that runs.
