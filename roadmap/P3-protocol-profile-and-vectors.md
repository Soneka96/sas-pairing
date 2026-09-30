# P3 — Protocol Profile and Deterministic Vectors

## Status

**P3 REMOTE EXPERIMENTAL SPECIFICATION FINALIZED.** The authoritative profile and document precedence are in [protocol status](../docs/protocol-status.md). The owner policy is one owning process and one live exposed ceremony per authority, with a shared 10-opportunity process/session budget and separate mandatory pre-exposure resource controls. Pair counting is `n_A + n_B - 1`; 19 applies only to a joint 10/10 window within both process sessions, not arbitrary restarts. **F-02 = FALSE POSITIVE UNDER THE STATED IDEALIZED ASSUMPTIONS:** the attacker may know its own DH shared secret after the honest public contribution is revealed; the needed property is target-SAS unpredictability before the attacker fixes its contribution. The full argument remains conditional and is not formally verified. AI-assisted review is not a qualified professional audit; the owner waived the human-review gate for experimental P4 and no professional audit is currently planned. Historical multi-ceremony/eight-slot/`5,497`-epoch material is non-normative. The separate same-device profile and adapter remain candidate-only and unapproved.

P3.5 AI-assisted review findings and the conditional argument are documented; the qualified human-review gate was waived by the owner for experimental development, not completed. P3.6 records the explicit selection of the corrected vodozemac remote profile and current owner policy as the experimental baseline. The full argument remains conditional; no formal verification or professional audit is claimed. P2 historically selected Candidate B; the later ownership-based reopening did not disprove it, and it remains a formal reference and possible fallback. The existing dependency pin is vodozemac 0.11.0. P3's separate same-device profile remains candidate-only, and the Windows principal-bound named-pipe adapter remains unapproved. The conformance matrix's current experimental requirements are documentation artifacts, not security proof; its case set may evolve.

## Goal

Developed the reviewable, language-neutral remote experimental profile and vectors, and specify the separate same-device local profile. The remote experimental baseline is selected; production-profile approval remains distinct. Do not implement production cryptography in P3.

## Why this phase exists

Implementation needs a precise profile that removes ambiguity and stays within its stated evidence and assumptions. The human-review prerequisite was waived for experimental P4, but the assurance limitation remains.

## Inputs / prerequisites

- The review-ready candidate package and its evidence, assumptions, and limitations. Candidate B's historical P2 selection alone is not a current selection.
- P1 requirements and the authoritative architecture and protocol-status documents.

## Scope

**Remote profile:** the owner selected the corrected vodozemac profile for experimental implementation, subject to its documented assumptions and P4 prerequisites. Candidate B remains a historical formal reference and possible fallback. Any consumer-specific Host/Client mapping is a non-normative integration example, not a generic protocol role. Carry the exact authenticated public-key bytes unchanged into later pinning/proof-of-possession checks; do not silently replace an identity key, and require explicit re-pairing under a new trust epoch for identity changes.

**Same-device local profile:** the abstract candidate contract is in [the local profile draft](../docs/p3-same-device-local-profile-draft.md), with rationale in its [separate decision log](../docs/p3-same-device-security-decisions.md). It defines an approved-adapter architecture, mutual endpoint authentication and consumer authorization, local selection, lifecycle, Host approval, bootstrap/context semantics, result limitations, transcript-derived identity, canonical framing, message types/schemas, state/duplicate/completion semantics, and a 65,536-byte complete-record maximum. Its resource policy sets four active ceremonies globally across both roles, one ceremony per authenticated connection, one `AwaitHostDecision` with no queue, locally controlled admission, 60-second machine inactivity, a 2-minute Host decision, a 5-minute absolute deadline, and two mandatory finite global limiters with deployment-selected values. No Windows/Linux/macOS/Android/iOS adapter is approved. Exact deployment limiter values, adapter decisions/reviews, and independent external security review remain open. Deterministic local fixture and conformance-case artifacts are recorded in P3; they do not approve this profile. Do not treat same machine, loopback, IP, hostname, discovery name, process name, or LAN proximity as proof. Do not claim resistance to an attacker controlling the trusted OS/user boundary enough to impersonate or control the authorized participant.

## Out of scope

Reopening P2 decisions without recording the evidence that requires it; implementation; language-specific APIs or ABI; consumer-specific policy; and unsupported security claims.

## Deliverables

A selected experimental remote profile, decision records for durable choices, and deterministic vectors that independent implementations can consume. The [vodozemac security decisions log](../docs/p3-vodozemac-security-decisions.md) records rationale and evidence boundaries. Vector correctness is conformance evidence, not proof of cryptographic security.

## Security invariants

Keep the profile application-neutral, fail closed on invalid or ambiguous state, avoid silent downgrade/fallback, and preserve all justified ceremony, role, transcript, context, approval, and attempt constraints.

## Exit criteria

The remote experimental selection and baseline acceptance are recorded. This does not complete the separate local-profile/adapter work, formally verify the argument, or meet production-readiness gates. The owner waived the qualified-human-review prerequisite for experimental P4 only; this was not a completed review. Conformance artifacts do not prove cryptographic security.

## STOP conditions

Return to P2 or stop if the selected construction cannot support a required profile decision or if the profile would exceed its evidence.

## What this unlocks

P4 is the next planned phase and is authorized but not complete. Begin with the narrowly scoped Rust authority-ownership and shared guard/accounting foundation in the [P4 roadmap](P4-native-security-core.md). P5 remains an implementation-focused review after P4; production use and release remain unapproved.
