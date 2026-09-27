# Protocol status

## NO PRODUCTION PROTOCOL SELECTED

The protocol is not implemented. This repository is pre-alpha and not suitable for production use.

Four constructions have been evaluated in P2. Pasini–Vaudenay (PKC 2006) is a generic SAS-AKE composition; Beskorovajnov–Müller-Quade (ACNS 2026 / IACR ePrint 2025/1598) prove SAS authentication composed into one-shot secure message transfer; Jarecki–Saxena (SCN 2010; full proof in the 2012 version) directly prove a three-round SAS-AKA with a fresh shared key and a concurrent-session bound, assuming a non-malleable commitment and SS-CCA public-key encryption; and Čagalj–Čapkun–Hubaux (Proceedings of the IEEE 2006) give DH-SC, which authenticates DH public parameters and identifiers under an ideal commitment and a one-active-session-per-party assumption. Candidate C's Enc-MCA authenticates arbitrary strings, but Enc-AKA Theorem 2 fixes `m_i = null`, `m_j = K`; no joint result binds separately authenticated context to that key. The focused P2 review classifies the desired property as **injective agreement on data** (including key, roles, peers, ceremony and semantic context), distinguishes this from key-context association, and finds no direct theorem for Candidate C. FGSW Theorem 5.1 provides generic post-AKE key confirmation under Match-security/key-secrecy and KDF/MAC assumptions, but confirms Candidate C's existing transcript SID, which excludes application context. The P1 context requirement is **AMBIGUOUS**; proposed wording is recorded in the construction mapping, without editing P1. Candidate C's static long-term encryption-key reuse is not forward-secret. No construction is selected. Shortcake upstream remains implementation research, not the production security core.

P2 outcome: **RESEARCH CONTINUES**. The [construction mapping](construction-selection.md) records the P1 context audit as **P1 CONTEXT REQUIREMENT IS AMBIGUOUS**, and context-to-key binding as **NEW PROOF REQUIRED**. The single remaining P2 proof blocker is a proof/composition that binds both participants' generic context inputs to Candidate C's same fresh key while preserving key secrecy, authentication, and concurrency. P1's separate terminal-outcome wording ambiguity is handled by its proposed clarification; it is not another construction-proof gap. The prior post-AKE key-confirmation result remains separately available under its assumptions; it does not authenticate an external context omitted from Candidate C's SID. Candidate D does not provide an alternate path because its proof assumes ideal commitments and excludes concurrent sessions per party. P2 remains current; P3 is gated.

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
