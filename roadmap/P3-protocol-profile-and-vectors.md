# P3 — Protocol Profile and Deterministic Vectors

## Status

**CR-01 PAIR COUNTING DOCUMENTED; PER-PAIR ARGUMENT CONDITIONAL — PREVIOUS PROOF NOT ESTABLISHED; CR-01 REMAINS OPEN.** The owner-selected remote policy is one live exposed ceremony per pairing authority and 10 opportunities per process/session across both roles. The pair-count model is `n_A + n_B - 1`, at most 19 in a 10/10 joint window. The second adversarial AI review found no concrete attack above the ideal term but concluded **PREVIOUS PROOF NOT ESTABLISHED**. The reconstructed `2^-39 + δ` argument awaits qualified independent human verification. Historical multi-ceremony/eight-slot/`5,497`-epoch material is non-normative. Vodozemac remains favored, not selected, and P4 remains blocked.

**P3 CANDIDATE PACKAGE: SECURITY SELECTION BLOCKED.** The vodozemac remote candidate's review package is prepared at [`docs/p3-vodozemac-independent-review-package.md`](../docs/p3-vodozemac-independent-review-package.md); two AI reviews have examined the per-pair argument, but qualified independent human verification has not occurred. P2 historically selected Candidate B, then the owner reopened the implementation direction during P3 for cryptographic ownership reasons. This does not disprove Candidate B, which remains a formal reference and possible fallback. Vodozemac remains the **FAVORED CANDIDATE — NOT SELECTED**. The complete project-specific security argument remains conditional and unverified. P3 has produced deterministic remote-vodozemac and authenticated-local fixtures and a 162-case documentation matrix, including 14 current owner-policy cases (see `docs/p3-deterministic-vectors.md`, `docs/p3-conformance-cases.md`, and `vectors/`). Those cases are not executable tests. The local profile remains candidate-only, and the Windows principal-bound named-pipe adapter remains **not approved**; zero production-approved local adapters exist. The next remote gate is focused independent verification (P3.5), followed by any candidate remediation and an explicit owner selection/profile-freeze decision (P3.6). P3 is not complete and P4 cannot begin until those gates pass.

## Goal

Develop reviewable, language-neutral candidate profiles and deterministic conformance vectors, and specify the separate same-device local profile. Remote-profile completion requires a deliberate construction selection first. Do not implement production cryptography in P3.

## Why this phase exists

Independent pre-implementation review and a later implementation need a precise candidate profile that removes ambiguity and stays within its stated evidence and assumptions.

## Inputs / prerequisites

- The review-ready candidate package and its evidence, assumptions, and limitations. Candidate B's historical P2 selection alone is not a current selection.
- P1 requirements and the authoritative architecture and protocol-status documents.

## Scope

**Remote profile after selection:** fully specify the selected construction's exact roles, message schemas, canonical encoding, version/downgrade behavior, ceremony identity and lifecycle, cryptographic inputs, transcript, SAS and human comparison, confirmation, attempt budget, persistence, replay/concurrency, terminal state, and deterministic vectors. The vodozemac candidate is currently favored for investigation but is not selected; Candidate B remains a formal reference and possible fallback. Any consumer-specific Host/Client mapping is a non-normative integration example, not a generic protocol role. Carry the exact authenticated public-key bytes unchanged into later pinning/proof-of-possession checks; do not silently replace an identity key, and require explicit re-pairing under a new trust epoch for identity changes.

**Same-device local profile:** the abstract candidate contract is in [the local profile draft](../docs/p3-same-device-local-profile-draft.md), with rationale in its [separate decision log](../docs/p3-same-device-security-decisions.md). It defines an approved-adapter architecture, mutual endpoint authentication and consumer authorization, local selection, lifecycle, Host approval, bootstrap/context semantics, result limitations, transcript-derived identity, canonical framing, message types/schemas, state/duplicate/completion semantics, and a 65,536-byte complete-record maximum. Its resource policy sets four active ceremonies globally across both roles, one ceremony per authenticated connection, one `AwaitHostDecision` with no queue, locally controlled admission, 60-second machine inactivity, a 2-minute Host decision, a 5-minute absolute deadline, and two mandatory finite global limiters with deployment-selected values. No Windows/Linux/macOS/Android/iOS adapter is approved. Exact deployment limiter values, adapter decisions/reviews, and independent external security review remain open. Deterministic local fixture and conformance-case artifacts are recorded in P3; they do not approve this profile. Do not treat same machine, loopback, IP, hostname, discovery name, process name, or LAN proximity as proof. Do not claim resistance to an attacker controlling the trusted OS/user boundary enough to impersonate or control the authorized participant.

## Out of scope

Reopening P2 decisions without recording the evidence that requires it; implementation; language-specific APIs or ABI; consumer-specific policy; and unsupported security claims.

## Deliverables

A reviewed candidate profile, explicit decision records for durable choices as appropriate, and deterministic vectors that independent implementations can consume. The [vodozemac security decisions log](../docs/p3-vodozemac-security-decisions.md) records rationale and review boundaries for that separate unselected candidate. Vector correctness is conformance evidence, not proof of cryptographic security.

## Security invariants

Keep the profile application-neutral, fail closed on invalid or ambiguous state, avoid silent downgrade/fallback, and preserve all justified ceremony, role, transcript, context, approval, and attempt constraints.

## Exit criteria

Candidate specification work is substantially review-ready, but P3 exit criteria cannot be satisfied from the current branch. First, an independent pre-implementation review must determine whether the proposed composition/profile is defensible enough to select and implement. After any necessary candidate remediation, the owner must explicitly select a construction and freeze its profile, with security-sensitive choices traced to accepted evidence and vectors covering positive behavior and meaningful negative or mutation cases. Candidate vectors do not satisfy the independent-review or owner-selection gate.

## STOP conditions

Return to P2 or stop if the selected construction cannot support a required profile decision or if the profile would exceed its evidence.

## What this unlocks

P3.5 pre-implementation construction security review is next; P3.6 is the subsequent owner selection/remediation and profile-freeze gate. P4 remains unavailable until those gates pass. P5 is a distinct post-implementation review of whether the Rust core correctly and safely implements the reviewed construction/profile.
