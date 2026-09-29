# P3 — Protocol Profile and Deterministic Vectors

## Status

**BLOCKED ON REMOTE CONSTRUCTION SELECTION / REVIEW.** P3 has produced substantial candidate work, including deterministic remote-vodozemac and authenticated-local fixtures and a 148-case conformance matrix (see `docs/p3-deterministic-vectors.md`, `docs/p3-conformance-cases.md`, and `vectors/`). Candidate B remains the prior P2 abstract selection, but its concrete instantiation is unresolved. The vodozemac candidate is concrete and reviewable but is not selected; its complete project-specific security argument has not been independently established. The local profile remains candidate-only, and the Windows principal-bound named-pipe adapter remains **not approved**; zero production-approved local adapters exist. P3 remote-profile completion cannot satisfy its exit criteria until a remote construction is deliberately selected and appropriately profiled/reviewed. Independent review, exact local limiter values, Windows per-release validation, adapter conformance, and remaining candidate gates remain open. Candidate work is preserved; P3 is not complete and the current branch is not ready for P4.

## Goal

Develop reviewable, language-neutral candidate profiles and deterministic conformance vectors, and specify the separate same-device local profile. Remote-profile completion requires a deliberate construction selection first. Do not implement production cryptography in P3.

## Why this phase exists

Implementation and independent review need one precise profile that removes ambiguity while staying within the construction and assumptions justified in P2.

## Inputs / prerequisites

- A deliberately selected remote construction with evidence, assumptions, limitations, and a reviewed security argument. Candidate B's prior P2 selection alone is not enough to satisfy this prerequisite.
- P1 requirements and the authoritative architecture and protocol-status documents.

## Scope

**Remote Candidate B profile:** define a deterministic mapping between generic Initiator/Responder roles and Candidate B's S/R positions; exact bootstrap message schemas; canonical encoding; authenticated/fixed protocol, profile, and version negotiation with downgrade prevention; SID generation and lifecycle; commitment instantiation; random-oracle/hash profile; SAS bit length and rendering; full-comparison UX contract; bilateral confirmation semantics; aggregate attempt/retry budget; persistence across restart; stale approval handling; cancellation; timeout; concurrent ceremonies; terminal-state handling; and deterministic vectors. Any consumer-specific Host/Client mapping is a non-normative integration example, not a generic protocol role. Preserve the ideal-OOB assumptions and human-error limits; do not present the theorem as a guarantee against human mistakes or atomic durable storage. Carry the exact authenticated public-key bytes unchanged into later pinning/proof-of-possession checks; do not silently replace an identity key, and require explicit re-pairing under a new trust epoch for identity changes.

**Same-device local profile:** the abstract candidate contract is in [the local profile draft](../docs/p3-same-device-local-profile-draft.md), with rationale in its [separate decision log](../docs/p3-same-device-security-decisions.md). It defines an approved-adapter architecture, mutual endpoint authentication and consumer authorization, local selection, lifecycle, Host approval, bootstrap/context semantics, result limitations, transcript-derived identity, canonical framing, message types/schemas, state/duplicate/completion semantics, and a 65,536-byte complete-record maximum. Its resource policy sets four active ceremonies globally across both roles, one ceremony per authenticated connection, one `AwaitHostDecision` with no queue, locally controlled admission, 60-second machine inactivity, a 2-minute Host decision, a 5-minute absolute deadline, and two mandatory finite global limiters with deployment-selected values. No Windows/Linux/macOS/Android/iOS adapter is approved. Exact deployment limiter values, adapter decisions/reviews, and independent external security review remain open. Deterministic local fixture and conformance-case artifacts are recorded in P3; they do not approve this profile. Do not treat same machine, loopback, IP, hostname, discovery name, process name, or LAN proximity as proof. Do not claim resistance to an attacker controlling the trusted OS/user boundary enough to impersonate or control the authorized participant.

## Out of scope

Reopening P2 decisions without recording the evidence that requires it; implementation; language-specific APIs or ABI; consumer-specific policy; and unsupported security claims.

## Deliverables

A reviewed candidate profile, explicit decision records for durable choices as appropriate, and deterministic vectors that independent implementations can consume. The [vodozemac security decisions log](../docs/p3-vodozemac-security-decisions.md) records rationale and review boundaries for that separate unselected candidate. Vector correctness is conformance evidence, not proof of cryptographic security.

## Security invariants

Keep the profile application-neutral, fail closed on invalid or ambiguous state, avoid silent downgrade/fallback, and preserve all justified ceremony, role, transcript, context, approval, and attempt constraints.

## Exit criteria

The exit criteria cannot be satisfied from the current branch. A remote construction must first be deliberately selected on adequate evidence; the selected profile must then be sufficiently precise for independent implementation and review, security-sensitive choices must trace to accepted evidence, and vectors must cover positive behavior and meaningful negative or mutation cases. Candidate vectors do not satisfy the construction-selection or independent-review gate.

## STOP conditions

Return to P2 or stop if the selected construction cannot support a required profile decision or if the profile would exceed its evidence.

## What this unlocks

P4 remains unavailable from the current branch. It may be planned only after a remote construction is selected and its profile and security gates are satisfied.
