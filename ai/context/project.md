# sas-pairing current manager context

## Project purpose

Language-neutral human-authenticated pairing for exchanging bootstrap data. The core should remain reusable and application-neutral; DovahLink is the original consumer, not the architectural owner. Consumer trust and authorization stay with consuming applications.

## Current repository phase

**PRE-ALPHA. P3 IS BLOCKED for remote-profile completion. NO REMOTE CONSTRUCTION IS READY FOR FINAL SELECTION.** No production cryptography is implemented. Documentation consolidation does not clear the security gate.

## P1 result contract

P1 accepts mutual authentication of exact role-positioned bootstrap bytes and selected security-relevant context for one ceremony; a reusable pairing key is not required. Authenticated public-key bytes mean only that the peer supplied them. They do not establish external identity truth or proof of possession. If both participants return success, results must be compatible; local success may be asymmetric after final acknowledgement loss.

## P2 remote-construction state

P2 historically selected Candidate B as the abstract remote construction. Later evidence reopened the project-level selection question because its concrete instantiation is unresolved. The separate vodozemac candidate has not replaced Candidate B. Current verdict: **NO REMOTE CONSTRUCTION READY FOR SELECTION — additional cryptographic review required.**

## Candidate B

Candidate B is Beskorovajnov–Müller-Quade mutual `π_SAS^×`: the prior P2 selection and strongest formal direction. Its abstract result fits the authenticated-bootstrap contract, without requiring a reusable pairing key. Concrete instantiation is blocked: the paper leaves the commitment formula/opening representation and byte encoding unspecified, uses a random-oracle SAS, and current evidence does not justify a real-hash security claim or complete faithful implementation. Preserve `STOP concrete cryptographic selection` in [the instantiation research](../../docs/p3-candidate-b-instantiation-research.md). Do not map Candidate B to SHA-256 or infer theorem preservation from a salted hash.

## Vodozemac candidate

`sas-pairing-vodozemac-ceremony-profile-draft-01` is a **separate concrete, vectorized, reviewable candidate — NOT SELECTED**. It pins vodozemac 0.11.0 as a candidate and specifies X25519, a SHA-256 responder commitment, canonical framing, transcript identity, Matrix decimal SAS, bootstrap/completion MACs, context and expected-peer semantics, accounting, resource controls, timeouts, and state handling. Its complete active-MITM composition, commitment hiding/binding, per-opportunity `≤ 2^-39` premise, aggregate `N = 5,497`, `ε = 10^-8` policy, and adaptive abort/retry/concurrency/grinding argument have not been independently established. The arithmetic is conditional on the per-opportunity premise. Matrix/vodozemac precedent and deterministic vectors are not a proof of this composition.

## Why neither is selected today

- Candidate B: strongest formal evidence and prior P2 selection; concrete instantiation unresolved.
- Vodozemac: concrete and reviewable, with deterministic profile and vectors; complete project-specific security argument not independently established; not selected.
- Therefore neither remote construction meets the evidence threshold for final selection.

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

## Known secondary cleanup

- Correct stale project-wide wording about bilateral completion to the local verified-result contract.
- Confirm endpoint-specific SAS accounting in R-WIRE-013 after the role/state clarification in this handoff.
- Finish checking remaining historical references to deferred vectors after the current profile/log status notes.

These are secondary consistency items, not the current remote-selection blocker.

## Current blocker

P3 cannot complete its remote-profile exit criteria while Candidate B is not concretely instantiable on current evidence and vodozemac remains unselected. P3 must not be marked complete or treated as ready for P4.

## Single next security action

Obtain one focused independent cryptographic review of the complete vodozemac remote candidate before any remote-construction selection change. The review must give a go/no-go view on SHA-256 commitment assumptions; the complete active-MITM composition; the per-opportunity `2^-39` premise; adaptive abort, retry, concurrency, and grinding; role/context/transcript/MAC composition; and whether the profile warrants reopening P2 and selecting it. This review does not preselect vodozemac.

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
