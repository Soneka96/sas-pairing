# sas-pairing current manager context

**Current status (2026-09-30):** Owner decision [0002](../../docs/decisions/0002-experimental-vodozemac-selection.md) selects the corrected vodozemac remote profile and owner policy for experimental implementation, pinned to vodozemac 0.11.0. P4 is authorized but not complete. The qualified-human-review gate was waived for experimental development, not completed; no professional audit or formal verification is claimed. F-02 is a false positive under the stated idealized assumptions: an attacker need not remain ignorant of its own DH shared secret after an honest public contribution is revealed; target SAS must be unpredictable before the attacker fixes its contribution. The complete per-pair argument remains conditional. Pair counting remains `n_A + n_B - 1`; 19 applies only to a joint 10/10 window within both process sessions, not arbitrary restarts. CR-01 retains residual assumptions and implementation verification limits. Older multi-ceremony/eight-slot/`5,497`-epoch material is historical and non-normative.

## Project purpose

Language-neutral human-authenticated pairing for exchanging bootstrap data. The core should remain reusable and application-neutral; DovahLink is the original consumer, not the architectural owner. Consumer trust and authorization stay with consuming applications.

## Current repository phase

**PRE-ALPHA. P3 REMOTE EXPERIMENTAL SPECIFICATION FINALIZED; P4 SECURITY FOUNDATION IN PROGRESS.** The first Windows Rust core increment implements OS-backed process ownership, ceremony authorization, shared exposure admission/accounting, and terminal cleanup, with same-session process tests. The owner accepted account-scoped Windows authorities in decision 0003; owner-run manual same-account cross-session ownership verification was completed on 2026-09-30 (not automated CI). The remote cryptographic ceremony and conformance suite are not implemented. Production use and release are not approved. The separate same-device profile and platform adapters remain candidate-only and do not block remote P4.

## P1 result contract

P1 accepts mutual authentication of exact role-positioned bootstrap bytes and selected security-relevant context for one ceremony; a reusable pairing key is not required. Authenticated public-key bytes mean only that the peer supplied them. They do not establish external identity truth or proof of possession. If both participants return success, results must be compatible; local success may be asymmetric after final acknowledgement loss.

## P2 remote-construction state

P2 originally selected Candidate B as the abstract remote construction. P3 research exposed substantial custom design and maintenance responsibilities for its concrete instantiation. The owner reopened selection for that ownership reason, not because Candidate B was shown insecure; it remains a formal reference and possible fallback. The owner has selected the existing vodozemac-based remote candidate for experimental implementation. It does not inherit Matrix's protocol security argument or establish production security.

## Candidate B

Candidate B is Beskorovajnov–Müller-Quade mutual `π_SAS^×`: historically selected at P2 and the strongest formal reference. Its abstract result fits the authenticated-bootstrap contract, without requiring a reusable pairing key. Concrete instantiation remains unsupported on current evidence: the paper leaves the commitment formula/opening representation and byte encoding unspecified and uses a random-oracle SAS. The P3 `STOP concrete cryptographic selection` records the project's evidence and ownership boundary; it does not mean Candidate B was cryptographically disproven. Do not map Candidate B to SHA-256 or infer theorem preservation from a salted hash.

## Vodozemac candidate

The selected experimental baseline pins vodozemac 0.11.0 and specifies X25519, a SHA-256 responder commitment, canonical framing, transcript identity, Matrix decimal SAS, bootstrap/completion MACs, context, and lifecycle. Its argument assumes SHA-256 collision resistance for commitment binding; random-oracle-style SHA-256 commitment hiding and relevant HKDF-SHA256 behavior; fresh unpredictable non-reused ephemeral keys; accepted contributory X25519 inputs; correct exposure ordering; and atomic ownership/guard enforcement. Ordinary HKDF PRF security alone is not claimed sufficient where an attacker knows its leg's derived secret. F-02 is rejected under the stated idealized assumptions; the complete construction remains conditional and unverified. Neither SHA-256 nor HKDF-SHA256 is proven to behave as a random oracle. The proposed result remains `P_per_pair ≤ 2^-39 + δ` and, only for a joint 10/10 window within both process sessions, `P_joint ≤ 19 × 2^-39 + ε`, with unsupported terms symbolic. This is not an arbitrary-restart, lifetime, or human-error bound. Earlier AI review's **PREVIOUS PROOF NOT ESTABLISHED** verdict applies to the earlier argument; no professional audit or formal verification is claimed.

## Current construction status

- Candidate B: historically selected at P2; remains a formal reference and possible fallback, not the current implementation direction. Its concrete instantiation remains unsupported, and the owner judged the custom cryptographic ownership too high for this project.
- Vodozemac: selected for experimental implementation; no production-security or release approval.
- Candidate B: historical P2 formal selection and reference/fallback; not shown insecure.

## P3 work completed

- Remote vodozemac candidate profile and D-series decision record, including transcript identity, context/expected-peer semantics, attempt model, resource model, and timeout/admission rules.
- Separate authenticated-local candidate profile, decisions, deterministic vector, and conformance cases.
- Windows principal-bound named-pipe adapter candidate research.
- Remote and local deterministic fixture sets and a conformance matrix with 166 documented cases, including 18 current owner-policy cases at this branch state.

These artifacts remain useful candidate work; vectors demonstrate byte/derivation reproducibility, not security proof.

## Authenticated-local profile

**CANDIDATE — NOT PRODUCTION APPROVED.** It is separate from either remote construction. It defines mutual endpoint authentication, consumer authorization, remote exclusion, exact connection binding, fresh Initiator/Responder nonces, transcript identity, one-ceremony-per-connection, one ceremony-specific Host decision at a time with no queue, and local admission that network input cannot enable. It sets four global active slots, 60-second machine inactivity, a 2-minute Host decision deadline, a 5-minute absolute deadline, and mandatory finite global operational rate controls. Local attempts do not consume remote SAS accounting. Zero platform adapters are approved.

## Windows adapter

**Windows principal-bound named-pipe adapter — CANDIDATE — NOT APPROVED.** It authenticates a configured Windows principal/logon-session boundary only. It does not authenticate an executable, signer, binary hash, or human. Its draft specifies `LOCAL\\` scope, `PIPE_REJECT_REMOTE_CLIENTS`, explicit owner/DACL, mutual endpoint authentication, same-user plus logon-session authorization, `SECURITY_IDENTIFICATION`, `FILE_FLAG_FIRST_PIPE_INSTANCE`, and non-inheritable handles. Zero production-approved local adapters remain.

## Deterministic vectors

Two fixture sets exist: remote vodozemac and authenticated-local. They demonstrate deterministic bytes and derivations only. The remote fixture covers commitment, transcript identity, SAS, bootstrap MACs, and completion MACs; the local fixture covers START, ACCEPT, transcript identity, APPROVE, REJECT, ACK, and outer record framing. The conformance matrix has 166 documented cases at the current branch head, including 18 documentation-only owner-policy cases; they are not executable tests.

## Current phase boundary

The remote experimental selection and baseline acceptance are recorded. This does not complete separate local-profile/adapter work, formally verify the argument, or meet production-readiness gates.

## Next P4 action

Begin the Rust authority owner and atomic exposure reservation enforcing one process, one live ceremony, and the shared ten-opportunity budget before any contribution is released. Resolve any platform-specific ownership detail as an explicit P4 prerequisite before implementing it. Follow the [P4 roadmap](../../roadmap/P4-native-security-core.md); this is a recommendation, not a claim that implementation exists.

## Decisions that must not be silently changed

- Do not change the selected vodozemac target, extend its features, or relabel it as Candidate B.
- Do not invent a concrete Candidate B hash/commitment mapping.
- P4 experimental implementation is authorized but not yet done; do not present it as production-approved.
- Do not change protocol bytes or vector values, approve Windows, or mark any local adapter approved.
- Do not claim vectors prove security or claim `2^-39` for the complete protocol as established.
- Preserve Candidate B history and vodozemac candidate work; do not reopen frozen local mechanics without evidence.

## Reusable work for future integrations

Likely reusable: generic bootstrap/result semantics, exact authenticated-key-byte preservation, context/expected-peer concepts, distinction between authentication and proof of possession, consumer-owned durable trust, the local candidate, Windows adapter research, resource-limit lessons, fail-closed state/duplicate principles, and portions of conformance organization/tooling. Construction-specific vodozemac work includes its remote X25519 ceremony, SHA-256 commitment formula, Matrix decimal SAS, bootstrap/completion MAC structures, and remote fixture.

## Production status

**PRE-ALPHA. NOT PRODUCTION READY. NO PRODUCTION CRYPTOGRAPHY IMPLEMENTED. VODOZEMAC SELECTED FOR EXPERIMENTAL IMPLEMENTATION. ZERO APPROVED SAME-DEVICE ADAPTERS. NO PROFESSIONAL AUDIT OR FORMAL VERIFICATION CLAIMED.**

## Standing project rules

- Specify and review protocols before implementing production behavior. Research and vectors are not security proof or architecture selection.
- Consumer-supplied identity/context values are inputs, not trusted facts; only values authenticated and checked by the selected protocol may be called authenticated.
- Protocol/security requirements own attempt constraints required by a security bound. Consumers may tighten, but not bypass them while claiming the same guarantees.
- Human comparison is part of the security system; account for partial checking, confusing glyphs, accidental approval, fatigue, accessibility, localization, and display conditions.
- Dart and .NET are intended wrappers around one core, not parallel production crypto implementations.
- Independent external review is required before production-readiness claims.
- Fail closed on ambiguous security state. Compatibility is not required before the first stable release unless explicitly approved.
