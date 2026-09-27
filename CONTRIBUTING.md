# Contributing

This repository is a security library in its design phase. Keep changes focused, explain architectural and security effects, and update the authoritative documentation when a decision changes.

Before proposing production protocol code, the protocol specification and its security rationale must be reviewed. Do not add custom cryptographic primitives or parallel production cryptography in a language binding. Security-relevant behavior will need tests and, once a protocol is selected, deterministic interoperability vectors.

Pull requests should complete the [pull request template](.github/pull_request_template.md). For suspected vulnerabilities, follow [SECURITY.md](SECURITY.md) instead of opening a public issue.
