# Security policy

## Current status

The owner has authorized experimental implementation of the selected vodozemac-based remote profile. Security research and adversarial review have been AI-assisted. The owner waived the qualified independent human-review gate for experimental development; no professional audit, formal verification, or independent security certification has been completed or is claimed. The argument remains conditional on documented assumptions, and implementation/integration add risks. This project provides no production security guarantee. **Do not use it to protect production systems.** Any eventual public release must disclose these assurance limitations.

## Reporting a vulnerability

Please do not discuss suspected vulnerabilities in public issues or unrelated discussions. Use GitHub's private vulnerability reporting for this repository if it is enabled. If it is unavailable, contact the repository owner through an appropriate private channel. No security email address is currently provided.

## Security-sensitive changes

Cryptographic changes require unusually strict review and a clear written rationale with supporting references. Custom cryptographic primitives are strongly discouraged. Do not introduce custom elliptic-curve arithmetic; prefer published constructions and maintained implementations of established primitives. Interoperability alone does not demonstrate cryptographic security.

The experimental selection and owner waiver do not grant production approval or decide final release readiness. Production-readiness claims remain subject to applicable independent implementation/security review, required remediation, and evidence that the release meets its stated requirements. Tests and vectors alone are insufficient.
