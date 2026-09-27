# Protocol status

## NO PRODUCTION PROTOCOL SELECTED

The protocol is not implemented. This repository is pre-alpha and not suitable for production use.

Pasini–Vaudenay SAS-based authenticated key agreement is the current leading academic candidate for further study. Shortcake upstream is useful implementation research, but it is not currently accepted as the production security core. These are research directions, not protocol decisions or endorsements.

P2 outcome: **RESEARCH CONTINUES**. The [construction mapping](construction-selection.md) records the paper-level result, assumptions, Shortcake differences, and blocking questions. P2 remains current; P3 is still gated.

All of the following remain gates before production implementation:

- exact construction and security rationale
- concrete key agreement or KEM
- commitment mechanism
- application-context binding
- SAS derivation and encoding
- protocol-required attempt, cooldown, ceremony, lifetime, and persistent-counter constraints needed for the security bound; exact values and enforcement integration
- canonical wire format and state machine
- deterministic test vectors
- independent external review

A future candidate user experience is approximately a 40-bit SAS rendered as eight Crockford Base32 characters, for example `7K3-M2Q8D`. This is a UX candidate only: no alphabet, length, grouping, or entropy value is selected, and no security claim depends on the example. The profile must account for partial comparison, confusing glyphs, accidental approval, accessibility, localization, display conditions, and repeated-mismatch fatigue. Retry constraints needed for a security bound belong to the protocol/security contract; consumers may enforce stricter product policy but may not bypass required constraints while claiming the same bound.
