# Contributing

This repository is a security library in its design phase. Keep changes focused, explain architectural and security effects, and update the authoritative documentation when a decision changes.

Before proposing production protocol code, the protocol specification and its security rationale must be reviewed. Do not add custom cryptographic primitives or parallel production cryptography in a language binding. Security-relevant behavior will need tests and, once a protocol is selected, deterministic interoperability vectors.

Pull requests should complete the [pull request template](.github/pull_request_template.md). For suspected vulnerabilities, follow [SECURITY.md](SECURITY.md) instead of opening a public issue.

## Branches and releases

`main` is the authoritative branch for accepted, reviewed work. Use short-lived work branches such as `feature/...`, `security/...`, `docs/...`, `fix/...`, `refactor/...`, and `chore/...` (for example, `security/p1-threat-model` or `feature/dart-wrapper`). Review normal changes before merging into `main`; security and protocol changes need especially careful review. Do not commit production protocol or security changes directly to `main`.

Stable and pre-release versions will eventually be tagged from accepted commits on `main`. There is no `dev` or long-lived release branch; add an integration branch only if future project scale justifies it.
