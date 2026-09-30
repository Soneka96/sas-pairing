# sas-pairing current manager context

**Current CR-01 gate (2026-09-30):** The owner selected the [remote session safety policy](../../docs/p3-one-shot-remote-pairing-decision.md): one live exposed ceremony across roles/connections, explicit retries only, and 10 exposed SAS opportunities per process/session per core. The previously reviewed pair-count model is `n_A + n_B - 1`, at most 19 tested pairs for a 10/10 joint window. Pair-counting remediation is documented; the per-tested-pair `2^-39` premise remains unverified, so parent CR-01 remains open. The older multi-ceremony/`5,497` candidate material below is historical. Vodozemac is favored, not selected, and P4 is blocked. The transcript prefix remains consistent with its deterministic vector.

## Project purpose

Language-neutral human-authenticated pairing for exchanging bootstrap data. The core should remain reusable and application-neutral; DovahLink is the original consumer, not the architectural owner. Consumer trust and authorization stay with consuming applications.

## Current repository phase

**PRE-ALPHA. P3 IS BLOCKED — REVIEW READY.** The independent-review package for the favored vodozemac remote candidate is prepared; no external review has occurred and no remote construction is selected. No production cryptography is implemented. Documentation consolidation does not clear the security gate.

## P1 result contract

P1 accepts mutual authentication of exact role-positioned bootstrap bytes and selected security-relevant context for one ceremony; a reusable pairing key is not required. Authenticated public-key bytes mean only that the peer supplied them. They do not establish external identity truth or proof of possession. If both participants return success, results must be compatible; local success may be asymmetric after final acknowledgement loss.

## P2 remote-construction state

P2 originally selected Candidate B as the abstract remote construction. P3 concrete-instantiation work exposed substantial project-owned cryptographic design and proof-mapping/maintenance for Candidate B. The owner decided that this was too much custom cryptographic ownership for the project and deliberately reopened the implementation-direction choice. This is an engineering/security ownership decision, not a finding that Candidate B or its paper is insecure. Candidate B remains an important formal reference and possible fallback. The project now **FAVORS INVESTIGATING** a ceremony built from maintained vodozemac primitives because it may reduce custom-crypto ownership. That candidate has not replaced Candidate B and is **NOT SELECTED**; project-specific security analysis and independent review are still required. Current verdict: **NO REMOTE CONSTRUCTION READY FOR SELECTION.**

## Candidate B

Candidate B is Beskorovajnov–Müller-Quade mutual `π_SAS^×`: historically selected at P2 and the strongest formal reference. Its abstract result fits the authenticated-bootstrap contract, without requiring a reusable pairing key. Concrete instantiation remains unsupported on current evidence: the paper leaves the commitment formula/opening representation and byte encoding unspecified and uses a random-oracle SAS. The P3 `STOP concrete cryptographic selection` records the project's evidence and ownership boundary; it does not mean Candidate B was cryptographically disproven. Do not map Candidate B to SHA-256 or infer theorem preservation from a salted hash.

## Vodozemac candidate

`sas-pairing-vodozemac-ceremony-profile-draft-01` is the **FAVORED CANDIDATE — NOT SELECTED**, concrete, vectorized, and reviewable. It pins vodozemac 0.11.0 as a candidate and specifies X25519, a SHA-256 responder commitment, canonical framing, transcript identity, Matrix decimal SAS, bootstrap/completion MACs, context and expected-peer semantics, candidate accounting, resource controls, timeouts, and state handling. The older aggregate `N = 5,497`, `ε = 10^-8` policy is historical candidate text, superseded for current owner policy by the 10-opportunity process/session ceiling. The complete active-MITM composition, commitment hiding/binding, and per-tested-pair `≤ 2^-39` premise remain unverified. The 19-pair union-bound arithmetic is conditional on that premise. Matrix/vodozemac precedent and deterministic vectors are not a proof of this composition.

## Current construction status

- Candidate B: historically selected at P2; remains a formal reference and possible fallback, not the current implementation direction. Its concrete instantiation remains unsupported, and the owner judged the custom cryptographic ownership too high for this project.
- Vodozemac: favored candidate because maintained primitives may reduce custom-crypto ownership; complete project-specific security argument is not independently established; not selected.
- Therefore neither remote construction meets the evidence threshold for final selection. A separate explicit owner selection remains required after review.

## P3 work completed

- Remote vodozemac candidate profile and D-series decision record, including transcript identity, context/expected-peer semantics, attempt model, resource model, and timeout/admission rules.
- Separate authenticated-local candidate profile, decisions, deterministic vector, and conformance cases.
- Windows principal-bound named-pipe adapter candidate research.
- Remote and local deterministic fixture sets and a conformance matrix with 148 stable cases at this branch state.

These artifacts remain useful candidate work; vectors demonstrate byte/derivation reproducibility, not security proof.

## Authenticated-local profile

**CANDIDATE — NOT PRODUCTION APPROVED.** It is separate from either remote construction. It defines mutual endpoint authentication, consumer authorization, remote exclusion, exact connection binding, fresh Initiator/Responder nonces, transcript identity, one-ceremony-per-connection, one ceremony-specific Host decision at a time with no queue, and local admission that network input cannot enable. It sets four global active slots, 60-second machine inactivity, a 2-minute Host decision deadline, a 5-minute absolute deadline, and mandatory finite global operational rate controls. Local attempts do not consume remote SAS accounting. Zero platform adapters are approved.

## Windows adapter

**Windows principal-bound named-pipe adapter — CANDIDATE — NOT APPROVED.** It authenticates a configured Windows principal/logon-session boundary only. It does not authenticate an executable, signer, binary hash, or human. Its draft specifies `LOCAL\\` scope, `PIPE_REJECT_REMOTE_CLIENTS`, explicit owner/DACL, mutual endpoint authentication, same-user plus logon-session authorization, `SECURITY_IDENTIFICATION`, `FILE_FLAG_FIRST_PIPE_INSTANCE`, and non-inheritable handles. Zero production-approved local adapters remain.

## Deterministic vectors

Two fixture sets exist: remote vodozemac and authenticated-local. They demonstrate deterministic bytes and derivations only. The remote fixture covers commitment, transcript identity, SAS, bootstrap MACs, and completion MACs; the local fixture covers START, ACCEPT, transcript identity, APPROVE, REJECT, ACK, and outer record framing. The conformance matrix has 148 cases at the current branch head.

## Current blocker

P3 cannot complete its remote-profile exit criteria while no remote construction is selected and required independent review remains outstanding. The review package is ready, but only an independent human review and subsequent explicit owner decision can advance selection. Local-profile/adapter gates also remain open. P3 must not be marked complete or treated as ready for P4.

## Single next security action

Use [the independent review package](../../docs/p3-vodozemac-independent-review-package.md) to obtain a focused external cryptographic review before any remote-construction selection change. Review the SHA-256 commitment assumptions; complete active-MITM composition; per-opportunity `2^-39` premise; adaptive abort, retry, concurrency, and grinding; role/context/transcript/MAC composition; and same-device predicate/adapter boundary if included in v1. The review does not preselect vodozemac; the owner must make a separate explicit selection decision afterward.

## Decisions that must not be silently changed

- Do not extend vodozemac features, select it, or relabel it as Candidate B.
- Do not invent a concrete Candidate B hash/commitment mapping.
- Do not implement production cryptography or begin P4 security-core implementation.
- Do not change protocol bytes or vector values, approve Windows, or mark any local adapter approved.
- Do not claim vectors prove security or claim `2^-39` for the complete protocol as established.
- Preserve Candidate B history and vodozemac candidate work; do not reopen frozen local mechanics without evidence.

## Reusable work regardless of remote winner

Likely reusable: generic bootstrap/result semantics, exact authenticated-key-byte preservation, context/expected-peer concepts, distinction between authentication and proof of possession, consumer-owned durable trust, the local candidate, Windows adapter research, resource-limit lessons, fail-closed state/duplicate principles, and portions of conformance organization/tooling. Construction-specific vodozemac work includes its remote X25519 ceremony, SHA-256 commitment formula, Matrix decimal SAS, bootstrap/completion MAC structures, and remote fixture.

## Production status

**PRE-ALPHA. NOT PRODUCTION READY. NO PRODUCTION CRYPTOGRAPHY IMPLEMENTED. NO REMOTE CONSTRUCTION READY FOR FINAL SELECTION. ZERO APPROVED SAME-DEVICE ADAPTERS. INDEPENDENT SECURITY REVIEW REQUIRED.**

## Standing project rules

- Specify and review protocols before implementing production behavior. Research and vectors are not security proof or architecture selection.
- Consumer-supplied identity/context values are inputs, not trusted facts; only values authenticated and checked by the selected protocol may be called authenticated.
- Protocol/security requirements own attempt constraints required by a security bound. Consumers may tighten, but not bypass them while claiming the same guarantees.
- Human comparison is part of the security system; account for partial checking, confusing glyphs, accidental approval, fatigue, accessibility, localization, and display conditions.
- Dart and .NET are intended wrappers around one core, not parallel production crypto implementations.
- Independent external review is required before production-readiness claims.
- Fail closed on ambiguous security state. Compatibility is not required before the first stable release unless explicitly approved.
