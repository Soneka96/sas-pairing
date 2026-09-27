# Protocol status

## NO PRODUCTION PROTOCOL SELECTED

The protocol is not implemented. This repository is pre-alpha and not suitable for production use.

Four constructions have been evaluated in P2. Pasini–Vaudenay (PKC 2006) is a generic SAS-AKE composition; Beskorovajnov–Müller-Quade (ACNS 2026 / IACR ePrint 2025/1598) prove UC mutual SAS authentication of peer messages and compose it into one-shot sender-to-receiver secure message transfer; Jarecki–Saxena (SCN 2010; full proof in the 2012 version) directly prove a three-round SAS-AKA with a fresh shared key and a concurrent-session bound, assuming a non-malleable commitment and SS-CCA public-key encryption; and Čagalj–Čapkun–Hubaux (Proceedings of the IEEE 2006) prove authentication of DH public parameters and identifiers under an ideal commitment and one active session per party. DH-SC’s session limit could fit a serial profile only if P1’s coexistence clause is clarified and the protocol rejects attacker-created overlapping instances; the ideal-commitment assumption remains a serious blocker.

The current P1 audit finds the shared-key requirement **AMBIGUOUS**: P1 does not explicitly require a reusable shared key and does not explicitly say that authenticated bootstrap messages alone suffice. Candidate B is **PROMISING** if P1 allows the latter result shape. Its Theorem 3 authenticates each peer's exact message under a distinct shared `sid` and `ε=2^-t` per online attempt/SID, but does not require the two messages or contexts to agree, does not return a reusable key, and does not prove long-term public-key possession. Candidate C remains the studied direct-key option if P1 requires that output; its external-context-to-key gap is **NEW PROOF REQUIRED** only if C is pursued. Candidate A's P1 mapping and all Candidate C findings remain preserved. No construction is selected. Shortcake remains implementation research only, not the production security core.

P2 outcome: **RESEARCH CONTINUES**. The [construction mapping](construction-selection.md) records **P1 CLARIFICATION REQUIRED** for the result shape and shared-key requirement; it also preserves the separate context-agreement/key-context-association ambiguity without editing P1. Candidate B's basic message-authentication theorem has no identified new proof gap if the result is limited to authenticated peer-supplied bytes and its profile enforces SID, role, encoding, mismatch, and attempt rules. A result claiming long-term key control still needs a separately justified PoP bound to the relevant peer/session. If Candidate C is chosen for a shared-key result, its context-to-key composition remains **NEW PROOF REQUIRED**; its existing FGSW key-confirmation result does not authenticate application context omitted from its SID. Candidate D's one-session assumption could be enforced only by rejecting all concurrent instances at each party, including attacker-created ones, and clarifying P1's current coexistence requirement. Its practical ideal-commitment instantiation remains **NOT ESTABLISHED**. P3 is gated.

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
