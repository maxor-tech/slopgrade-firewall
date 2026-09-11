# Contributing

Thanks for looking at the slopGrade Firewall client. This repo is intentionally small, dependency-free, and
auditable — please keep it that way.

## Ground rules

- **Zero runtime dependencies.** Only `node:*` builtins and relative imports. A PR that adds a dependency will not
  be merged.
- **Nothing but a structural fingerprint may leave the runner.** Detectors emit `{file, line, kind}` (plus a few
  fixed scalar tags). Never add a field that carries a source snippet, a matched string, or a secret value — the
  egress boundary (`src/client-lib.mjs`) rebuilds the payload by whitelist, and `node isolation-gate.mjs
  --print-payload` must stay the exact wire content.
- **Node >= 22.**

## Develop

```bash
node --test src/__tests__/*.test.mjs   # the exit boundary + extractor behavior (must stay green)
node isolation-gate.mjs --print-payload # audit the exact payload
node isolation-gate.mjs --help
```

## Pull requests

- Add or update a test for any behavior change (`src/__tests__/`).
- Keep detectors **intra-function**. Cross-function / cross-file dataflow and calibrated false-positive suppression
  are part of the hosted product and are deliberately not in this repository — please don't add them here.
- Describe the false-positive / false-negative impact of any detector change.

## Security

Please report vulnerabilities privately — see [SECURITY.md](./SECURITY.md). Do not open a public issue for a
security problem.

## License

By contributing you agree your contributions are licensed under the [MIT License](./LICENSE).
