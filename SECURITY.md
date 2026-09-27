# Security policy

## Current status

This project is experimental and has not been independently audited. It provides no production security guarantee. **Do not use it to protect production systems yet.**

## Reporting a vulnerability

Please do not discuss suspected vulnerabilities in public issues or unrelated discussions. Use GitHub's private vulnerability reporting for this repository if it is enabled. If it is unavailable, contact the repository owner through an appropriate private channel. No security email address is currently provided.

## Security-sensitive changes

Cryptographic changes require unusually strict review and a clear written rationale with supporting references. Custom cryptographic primitives are strongly discouraged. Do not introduce custom elliptic-curve arithmetic; prefer published constructions and maintained implementations of established primitives. Interoperability alone does not demonstrate cryptographic security.

Until a protocol is selected, reviewed, implemented, and independently assessed, no implementation in this project should be treated as suitable for production security.
