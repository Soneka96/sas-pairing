# P3 independent security review package — vodozemac remote candidate

## Status and review request

**REVIEW PACKAGE READY — EXTERNAL REVIEW NOT YET OBTAINED.** This package describes a favored but unselected remote candidate. It is a request for independent analysis, not a claim of security or an owner selection decision. Candidate B was selected at P2 and later deliberately reopened by the owner because a concrete instantiation would require substantial project-owned cryptographic design and proof-mapping/maintenance. That engineering/security ownership decision does not disprove Candidate B. Vodozemac is favored for investigation because maintained primitives may reduce custom-crypto ownership; its use in this new composition does not inherit Matrix's protocol security argument.

**CR-01 update:** The owner-selected policy is one live exposed ceremony per pairing authority and 10 exposed opportunities per process/session across both roles. With I1 terminal irreversibility and I2 SAS lifetime, the structural pair-count model is `n_A + n_B - 1`, at most 19 in a 10/10 joint window. The older persistent `N = 5,497`/`ε = 10^-8` and multi-ceremony rules are historical and non-normative. The first AI review supported an ideal `2^-39` bound. The second adversarial AI review found no concrete attack exceeding that ideal term but gave the verdict **PREVIOUS PROOF NOT ESTABLISHED** because assumptions and reasoning were incomplete. The profile now records a conditional reconstruction; CR-01 remains open pending focused independent verification. These AI reviews are not a qualified human audit or formal verification. This package does not select vodozemac or authorize P4.

**Review question:** Verify the corrected proposed argument in profile §7, including its candidate-pair game, conditioning point, per-role key/message ordering, adaptive scheduling and selective abort treatment, and assumptions for SHA-256 commitment binding/hiding, HKDF-SHA256, X25519 inputs, and ephemeral-key freshness. Determine whether `P_per_pair ≤ 2^-39 + δ` is justified under those assumptions. This narrow review is not a selection decision or P4 authorization.

The reviewer should give a finding for each question in §6, including a reasoned **go / no-go / conditional** conclusion, assumptions, attack preconditions, and any required profile change. This review does not itself select the candidate; owner selection remains a separate decision.

## Scope and threat model

The adversary controls an untrusted network and may observe, inject, modify, replay, reorder, delay, drop, and duplicate messages; adaptively schedule, selectively abort, and initiate repeated locally authorized attempts. The owner policy permits only one live exposed ceremony per pairing authority. The adversary does not control an honest endpoint or its cryptographic RNG under the stated assumptions. Human comparison may fail or be partial; the security claim must state its assumptions and must not count vectors as proof. A cross-instance authority guard is required; a process-local mutex is insufficient.

The proposed result authenticates that the peer supplied exact bootstrap bytes, roles, ceremony identity, version/profile, and agreed security-relevant context in the compared ceremony. It does not prove ownership of a public key, establish external identity truth, grant application authorization, or create a reusable pairing secret. The consuming application owns durable trust and later proof-of-possession checks. The generic profile is application-neutral.

## Candidate construction and source traceability

The normative proposal is [the generic vodozemac ceremony profile draft](p3-vodozemac-ceremony-profile-draft.md); rationale and candidate decisions are in the [security decision log](p3-vodozemac-security-decisions.md). In brief, the draft combines vodozemac X25519 SAS key agreement, a responder commit-before-reveal SHA-256 value, transcript-derived ceremony identity, Matrix-style three-group decimal SAS, transcript/context-bound bootstrap and completion MACs, bilateral local comparison/approval, and finite attempt/resource/state policies. All project framing, commitment, MAC context, transcript, and policy composition is new project work.

The candidate pins `vodozemac = 0.11.0` at upstream commit `db1b34820f3102307284e762f335b3f72c735bf0` (tag object `9cdcc49ec1b213570a3a59cdeb40e8310999ea9e`; crate archive SHA-256 `ba935af014ca0ae5fb468daa51da81a8a0df7daad23c052c878b7c690cdf2574`). Its upstream manifest identifies Apache-2.0, Rust 1.89, and `unsafe_code = "deny"`; its changelog dates 0.11.0 to 2026-09-11. The pinned `sas.rs` exposes SAS key agreement, HKDF-derived SAS bytes, non-contributory shared-secret rejection, and MAC operations used by the draft. These are traceability and API-semantics observations, not an audit of all transitive dependencies, proof of RNG/entropy suitability on each target, or proof of the composed protocol.

Least Authority's 2022 audit examined older vodozemac revisions, and the report states that several issues were unresolved at verification, including memory exposure against swap/side-channel attacks and a 64-bit tag in the then-reviewed `src/cipher/mod.rs` Olm cipher path. The current candidate instead calls `sas::EstablishedSas` MAC methods; the pinned source emits the full HMAC output, so the old cipher-path finding must not be mislabeled as the current SAS MAC. The audit does not establish current secret-memory safety or review this generic ceremony. Matrix's 2026 security response separately confirms an all-zero-output behavior in an Olm 3DH path while stating its SAS path rejects non-contributory outputs; that Matrix-specific Olm finding is not evidence of a SAS flaw or proof that this composition is secure. The exact profile's ephemeral-secret lifecycle and platform assumptions remain review questions.

Primary sources checked for this package:

- [Pinned upstream SAS implementation](https://github.com/matrix-org/vodozemac/blob/db1b34820f3102307284e762f335b3f72c735bf0/src/sas.rs)
- [Pinned upstream manifest](https://github.com/matrix-org/vodozemac/blob/db1b34820f3102307284e762f335b3f72c735bf0/Cargo.toml)
- [Pinned upstream changelog](https://github.com/matrix-org/vodozemac/blob/db1b34820f3102307284e762f335b3f72c735bf0/CHANGELOG.md)
- [Least Authority 2022 audit report](https://matrix.org/media/Least%20Authority%20-%20Matrix%20vodozemac%20Final%20Audit%20Report.pdf)
- [Matrix 2026 response on reported vodozemac issues](https://matrix.org/blog/2026/02/analysis-of-reported-issues-in-vodozemac/)
- [Matrix SAS verification specification, v1.18](https://spec.matrix.org/v1.18/client-server-api/#short-authentication-string-sas-verification) — precedent for Matrix's ceremony, not a proof of this generic composition
- Candidate B's [ePrint 2025/1598](https://eprint.iacr.org/2025/1598) — the previously selected formal reference, not the current implementation direction

## Security-property mapping

| Requirement / claim | Candidate mechanism | Evidence and unresolved boundary |
|---|---|---|
| Active MITM resistance | Fresh X25519 SAS, responder commit-before-reveal, complete 39-bit decimal comparison, transcript-bound MACs and completion | vodozemac API and Matrix precedent establish primitive/API behavior only. The composition's per-opportunity `≤ 2^-39` bound is not independently established. |
| Ceremony, role, version, and context binding | Canonical framed messages; fixed roles/profile/version; transcript-derived identity; checked shared context/expected-peer semantics; MAC inputs | Specified in the candidate profile and vectors. Reviewer must assess field completeness, ordering, domain separation, unknown-key-share and role-confusion risks. |
| Replay, stale approval, and concurrency | Request ID is routing only; identity derives from transcript; ceremony state and approvals are bound to that identity; active limits and fail-closed terminal states | Specified candidate behavior and conformance cases. No independent review or implementation evidence. |
| Authenticated bootstrap result | Role-specific MACs and completion checks cover exact bootstrap bytes and selected context; result returns those exact bytes | Composition is project-specific and unreviewed. Does not assert public-key possession or durable application trust. |
| Repeated online attempts | One live exposed ceremony per pairing authority; at most 10 exposed opportunities per process/session across both roles; at most 19 pairs in a 10/10 joint window | Proposed `P_per_pair ≤ 2^-39 + δ` and `P_joint ≤ 19 × 2^-39 + ε` remain conditional; `δ`/`ε` are symbolic. No lifetime bound. |
| RNG and ephemeral lifecycle | Fresh, unpredictable, non-reused key material per ceremony | Exact upstream API is pinned. Entropy adequacy and fork/snapshot/restored-state/rollback/RNG-failure behavior on supported targets need review; no snapshot resistance is claimed. |
| Same-device SAS bypass | Separate abstract profile requires an approved OS-authenticated adapter, mutual endpoint authentication, authorization, and remote exclusion | Not part of this remote-candidate selection. Generic predicate and Windows adapter remain candidate-only; zero adapters are approved. |

## Concrete attack and composition questions

Pair counting is documented; the corrected security argument is conditional and not independently verified. The review must not condition on an attacker view containing both completed SAS values or assume the attacker commits one leg before learning the other leg's SAS. Check per-ceremony message ordering and the remaining unpredictable honest contribution at the stated conditioning point. Evaluate the explicit random-oracle-style assumptions; ordinary HKDF PRF security alone is not asserted sufficient when the attacker knows the derived secret on its own leg. Concrete SHA-256 and HKDF-SHA256 are not proven random oracles. CR-01 remains open.

1. Does the full commit, key agreement, SAS, MAC, and completion composition support the proposed conditional active-MITM argument? Distinguish SHA-256 collision resistance for binding from random-oracle-style hiding for the commitment.
2. Is the relevant HKDF-SHA256 construction covered by the stated random-oracle-style assumption for the unknown honest contribution and bound context? Explain why PRF security alone does or does not suffice when the attacker knows the derived secret on its own leg.
3. Is the `2^-39` ideal term justified at the specified conditioning point for each candidate pair? Assess the exact event, two honest ceremonies, adaptive scheduling, selective aborts, and per-role message ordering without conditioning on both completed SAS values.
4. Are fresh unpredictable ephemeral keys and accepted X25519 inputs sufficient under the specified assumptions? What evidence is required for fork, VM snapshot, restored-state, RNG-failure, or duplicated-state conditions on each supported target?
5. Does atomic cross-instance single-ceremony enforcement and the explicit 10-per-process/session exposure budget support the `n_A + n_B - 1` pair count? Do not interpret 19 as a lifetime bound.
6. Do the exact transcript and MAC inputs bind every security-relevant field in a unique order, including roles, profile/version, ceremony identity, both bootstrap messages, shared context, and expected-peer constraints?
7. Are bootstrap and completion MACs composed correctly, and does I1/I2 prevent terminal revival and stale approval/SAS use?
8. Is the authority-wide guard, session budget, and explicit retry/authorization behavior implementable without a protocol message or wire-format change? Identify any precise unresolved coordination requirement.
9. For any v1 same-device SAS-free path, does the separate generic predicate establish mutual endpoint authenticity, authorization for this exact ceremony, and remote-peer exclusion? Does the Windows draft meet that predicate under its explicit principal/logon-session boundary? If not, recommend excluding that path from v1 rather than treating locality labels as evidence.

## Review artifacts

- [Threat model and requirements](threat-model.md)
- [Owner one-shot decision and focused CR-01 analysis](p3-one-shot-remote-pairing-decision.md)
- [Remote candidate protocol/profile](p3-vodozemac-ceremony-profile-draft.md)
- [Candidate decision and evidence log](p3-vodozemac-security-decisions.md)
- [Reuse assessment and alternatives](p3-vodozemac-reuse-assessment.md)
- [Deterministic vectors](p3-deterministic-vectors.md) and [remote vector data](../vectors/p3-remote-vodozemac-draft-01.json)
- [Conformance cases](p3-conformance-cases.md)
- [Same-device profile](p3-same-device-local-profile-draft.md) and [Windows adapter candidate](p3-local-adapter-windows-draft.md)

Vectors demonstrate reproducibility and conformance only. Conformance cases should be read as proposed checks mapped to invariants, not executed production evidence. Neither artifact demonstrates cryptographic security.

## Alternatives and current decision boundary

- **Candidate B:** historically selected at P2; retained as a formal reference and possible fallback. The owner reopened the implementation direction because concrete instantiation would create too much custom cryptographic design and proof-maintenance ownership. This did not disprove Candidate B.
- **Vodozemac-based ceremony:** favored candidate because maintained primitives may reduce that ownership. Not selected; independent project-specific security review and an explicit owner decision are prerequisites.
- **Complete Matrix verification:** not a generic drop-in because its identity and trust semantics are Matrix-specific.
- **New production core, language wrappers, or consumer integration:** out of scope for this review and P3.

## Review status

Two AI reviews have examined the per-pair argument, but no qualified independent human review has occurred. AI analysis, repository conformance cases/vectors, upstream reputation, and upstream audit statements are not substitutes. If a qualified independent reviewer is unavailable, leave P3 at **BLOCKED — REVIEW READY**; do not select this construction or claim security approval.
