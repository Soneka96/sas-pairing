# Protocol status

## NO PRODUCTION PROTOCOL SELECTED

The protocol is not implemented. This repository is pre-alpha and not suitable for production use.

Three constructions have been evaluated in P2. Pasini–Vaudenay (PKC 2006) is a generic SAS-AKE composition; Beskorovajnov–Müller-Quade (ACNS 2026 / IACR ePrint 2025/1598) prove SAS authentication composed into one-shot secure message transfer; Jarecki–Saxena (SCN 2010) directly prove a three-round SAS-AKA with a fresh shared key and a concurrent-session bound, assuming a non-malleable commitment and SS-CCA public-key encryption. Candidate C’s Enc-MCA authenticates arbitrary strings, but its Enc-AKA Theorem 2 covers only `m_i = null`, `m_j = K`; the source does not prove application-context binding to that key or bilateral terminal application success under delayed or dropped SAS messages. Its static long-term encryption-key reuse is not forward-secret. No construction is selected. Shortcake upstream remains implementation research, not the production security core.

P2 outcome: **RESEARCH CONTINUES**. The [construction mapping](construction-selection.md) records the focused result: **NEW PROOF REQUIRED** for context-to-key composition, and **CONSTRUCTION-LEVEL PROOF REQUIRED** for P1-compatible terminal results. The single remaining proof-level blocker is an established result covering both participants’ generic context inputs, the same fresh key, and compatible terminal outcomes under delayed or dropped messages while preserving key authentication/secrecy and the concurrent-session guarantees. P2 remains current; P3 is gated.

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
