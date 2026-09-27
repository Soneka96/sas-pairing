# Protocol status

## NO PRODUCTION PROTOCOL SELECTED

The protocol is not implemented. This repository is pre-alpha and not suitable for production use.

Candidates A–D remain preserved in P2. Pasini–Vaudenay (PKC 2006) is a generic SAS-AKE composition; Beskorovajnov–Müller-Quade (ACNS 2026 / IACR ePrint 2025/1598) prove UC mutual SAS authentication of peer messages and compose it into one-shot sender-to-receiver secure message transfer; Jarecki–Saxena (SCN 2010; full proof in the 2012 version) directly prove a three-round SAS-AKA with a fresh shared key and a concurrent-session bound, assuming a non-malleable commitment and SS-CCA public-key encryption; and Čagalj–Čapkun–Hubaux (Proceedings of the IEEE 2006) prove authentication of DH public parameters and identifiers under an ideal commitment and one active session per party. DH-SC's session limit could fit a serial profile only if P1's coexistence clause is clarified and the protocol rejects attacker-created overlapping instances; the ideal-commitment assumption remains a serious blocker.

Candidate E, Vodozemac / Matrix SAS, is **INSUFFICIENT TO SELECT** as a generic upstream construction. Current Vodozemac includes maintained X25519/HKDF-SHA-256 SAS and HMAC-SHA-256 primitives. Matrix v1.18 and `matrix-sdk-crypto` supply a Matrix-specific commit-before-reveal verification ceremony and state machine, but depend on Matrix user/device identifiers and trusted device-key/cross-signing semantics. Least Authority's 2022 report examined some Vodozemac SAS source code, but did not audit the full Matrix verification protocol/SDK or any generic extraction; the report also predates Vodozemac 0.10.0. Replacing Matrix identity/context fields creates a new security-sensitive profile requiring analysis and review. The Rust crate is Apache-2.0; the maintained Famedly Dart binding is AGPL-3.0; no maintained official .NET binding was found.

The current P1 audit finds the shared-key requirement **AMBIGUOUS**: P1 does not explicitly require a reusable shared key and does not explicitly say that authenticated bootstrap messages alone suffice. Candidate B is **PROMISING** if P1 allows the latter result shape. Its Theorem 3 authenticates each peer's exact message under a distinct shared `sid` and `ε=2^-t` per online attempt/SID, but does not require the two messages or contexts to agree, does not return a reusable key, and does not prove long-term public-key possession. Candidate C remains the studied direct-key option if P1 requires that output; its external-context-to-key gap is **NEW PROOF REQUIRED** only if C is pursued. Candidate A's P1 mapping and all Candidate C findings remain preserved. No construction is selected. Shortcake remains implementation research only, not the production security core.

P2 outcome: **RESEARCH CONTINUES**. The [construction mapping](construction-selection.md) records **P1 CLARIFICATION REQUIRED** for result shape/shared key, agreed-context versus same-key/context association, same-machine local authentication, and normal human-comparison UX; P1 is unchanged. Candidate B's basic message-authentication theorem has no identified new proof gap if the result is limited to authenticated peer-supplied bytes and its profile enforces SID, role, encoding, mismatch, and attempt rules. A result claiming long-term key control still needs a separately justified PoP bound to the relevant peer/session. If Candidate C is chosen for a shared-key result, its context-to-key composition remains **NEW PROOF REQUIRED**; its existing FGSW key-confirmation result does not authenticate application context omitted from its SID. Candidate D's practical ideal-commitment instantiation remains **NOT ESTABLISHED**. Candidate E's primitives may be reused, but generic extraction of the Matrix ceremony is not justified by the current audit or specification: its Matrix identity/transcript assumptions must not be silently removed. No candidate is selected and P3 is gated.

The motivating DovahLink path is Windows-to-Windows and may be same-machine. The normal remote flow need not ask users to type/transcribe a SAS; UI comparison can present the SAS. A same-machine no-SAS path is only a **PROFILE POSSIBILITY** using authenticated/restricted OS IPC with explicit same-user malware assumptions; loopback, machine names and same IP are not authentication. TLS 1.3 with persistent identities/fingerprint comparison remains an architecture alternative. RFC 9266's TLS exporter is a channel binding, not a proven shortened SAS. Neither P2 nor this status selects a local shortcut or TLS.

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

A future human-comparison format remains open. The earlier illustrative approximately 40-bit Crockford Base32 string is retained as a UX candidate only; no alphabet, length, grouping, or entropy value is selected, and no security claim depends on it. The profile must account for partial comparison, confusing glyphs, accidental approval, accessibility, localization, display conditions, and repeated-mismatch fatigue. Retry constraints needed for a security bound belong to the protocol/security contract; consumers may enforce stricter product policy but may not bypass required constraints while claiming the same bound.
