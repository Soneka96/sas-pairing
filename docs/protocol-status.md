# Protocol status

## NO PRODUCTION PROTOCOL SELECTED

The protocol is not implemented. This repository is pre-alpha and not suitable for production use.

Pasini–Vaudenay SAS-based authenticated key agreement is the current leading academic candidate for further study. Shortcake upstream is useful implementation research, but it is not currently accepted as the production security core. These are research directions, not protocol decisions or endorsements.

All of the following remain gates before production implementation:

- exact construction and security rationale
- concrete key agreement or KEM
- commitment mechanism
- application-context binding
- SAS derivation and encoding
- retry and security bound
- canonical wire format and state machine
- deterministic test vectors
- independent external review

A future candidate user experience is approximately a 40-bit SAS rendered as eight Crockford Base32 characters, for example `7K3-M2Q8D`. This is **not frozen** and carries no security claim.
