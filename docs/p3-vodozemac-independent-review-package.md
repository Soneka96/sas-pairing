# P3 independent security review package — vodozemac remote candidate

## Status and review request

**REVIEW PACKAGE READY — EXTERNAL REVIEW NOT YET OBTAINED.** This package describes a favored but unselected remote candidate. It is a request for independent analysis, not a claim of security or an owner selection decision. Candidate B was selected at P2 and later deliberately reopened by the owner because a concrete instantiation would require substantial project-owned cryptographic design and proof-mapping/maintenance. That engineering/security ownership decision does not disprove Candidate B. Vodozemac is favored for investigation because maintained primitives may reduce custom-crypto ownership; its use in this new composition does not inherit Matrix's protocol security argument.

**CR-01 update:** The owner selected a [10-exposure process/session ceiling](p3-one-shot-remote-pairing-decision.md) per core. Under the one-live-ceremony, terminal-irrevocability, SAS-lifetime, and explicit-retry rules, the previously reviewed pair-count model gives `n_A + n_B - 1`, at most 19 for a 10/10 joint window. The older `N = 5,497`/`ε = 10^-8` and concurrent-ceremony rules below are historical candidate text. Pair-counting remediation is documented, but the parent CR-01 remains open pending independent verification of the per-tested-pair `2^-39` premise. This package does not select vodozemac or authorize P4.

**Review question:** Verify whether each security-relevant tested candidate pair in the corrected vodozemac composition has conditional ideal full-SAS match probability at most `2^-39` under active MITM scheduling and the stated cryptographic assumptions. Assess the exact candidate-pair event and any assumptions needed for this premise. This narrow question is not a selection decision or P4 authorization.

The reviewer should give a finding for each question in §6, including a reasoned **go / no-go / conditional** conclusion, assumptions, attack preconditions, and any required profile change. This review does not itself select the candidate; owner selection remains a separate decision.

## Scope and threat model

The adversary controls an untrusted network and may observe, inject, modify, replay, reorder, delay, drop, and duplicate messages; run concurrent ceremonies; and initiate repeated attempts. The adversary does not control an honest endpoint, its cryptographic RNG, or the intended human comparison surface. Human comparison may fail or be partial; the security claim must state its assumptions and must not count vectors as proof.

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
| Repeated online attempts | Current owner policy: at most 10 exposed opportunities per process/session per core; at most 19 tested pairs in a 10/10 joint window under the reviewed pair-count model | `19 × 2^-39 ≈ 3.456 × 10^-11` is conditional on the still-open per-pair premise. The older durable `N = 5,497`, `ε = 10^-8` candidate policy is historical, not current owner policy. |
| RNG and ephemeral lifecycle | vodozemac `Sas::new()` and the candidate's one-run lifecycle | Exact upstream code is pinned. Entropy adequacy, platform behavior, fork/runtime interactions, and temporary-secret handling still need review. |
| Same-device SAS bypass | Separate abstract profile requires an approved OS-authenticated adapter, mutual endpoint authentication, authorization, and remote exclusion | Not part of this remote-candidate selection. Generic predicate and Windows adapter remain candidate-only; zero adapters are approved. |

## Concrete attack and composition questions

Pair-counting remediation is documented by the owner-selected ceiling and the previously reviewed `n_A + n_B - 1` model; it does not establish the cryptographic premise. The remaining immediate question is the conditional ideal full-SAS match probability for each security-relevant tested candidate pair under active MITM scheduling and the stated assumptions. The candidate's composition-specific use of this premise remains unverified. Older questions about a 20-attempt ceiling, durable `N = 5,497` accounting, and concurrent candidate ceremonies are historical context only. CR-01 remains open until the narrow per-pair premise is independently verified.

1. Does the full commit, key agreement, SAS, MAC, and completion composition provide the claimed active-MITM property under the stated ideal human-comparison model? Is the deterministic SHA-256 commitment adequately hiding and binding for this use, and what concrete assumption justifies that claim?
2. For each security-relevant tested candidate pair in the corrected vodozemac composition, is its conditional ideal full-SAS match probability at most `2^-39` under active MITM scheduling and the stated cryptographic assumptions?
3. Which exact assumptions and candidate-pair event are necessary for that per-pair premise, including adversarial abort and scheduling? Do not treat the process/session safety ceiling as a lifetime bound.
4. Do the exact transcript and MAC inputs bind every security-relevant field in a unique order, including roles, profile/version, ceremony identity, both bootstrap messages, shared context, and expected-peer constraints? Are unknown-key-share, cross-ceremony, role-confusion, and downgrade attacks excluded?
5. Are bootstrap and completion MACs composed correctly? Can either party report local success without the exact peer evidence and same-ceremony human approval required by the contract? What happens under loss or replay of the final acknowledgement?
6. Does the replay/duplicate/stale-message state machine preserve attempt accounting and prevent approval or result transfer across runs, after restart, or across active connections?
7. Does the specified vodozemac API and its pinned RNG/key lifecycle actually provide the semantics the profile assumes on all supported platforms? What source or target-specific evidence is missing?
8. For any v1 same-device SAS-free path, does the separate generic predicate establish mutual endpoint authenticity, authorization for this exact ceremony, and remote-peer exclusion? Does the Windows draft meet that predicate under its explicit principal/logon-session boundary? If not, recommend excluding that path from v1 rather than treating locality labels as evidence.

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

No independent external review has occurred. AI analysis, repository tests/vectors, upstream reputation, and upstream audit statements are not substitutes. If a qualified independent reviewer is unavailable, leave P3 at **BLOCKED — REVIEW READY**; do not select this construction or claim security approval.
