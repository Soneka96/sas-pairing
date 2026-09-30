# P3 independent security review package — vodozemac remote candidate

## Status and review request

**REVIEW PACKAGE AND AI-ASSISTED FINDINGS RECORDED — NO QUALIFIED HUMAN AUDIT OBTAINED.** This package preserves the review request, evidence, findings, and limitations for the vodozemac remote candidate, now selected by the owner for experimental implementation. It does not claim formal verification, production security, or professional certification. Candidate B's historical P2 selection and formal evidence remain preserved; the owner's later decision to reopen selection was about custom-cryptography ownership, not a finding that Candidate B is insecure. Vodozemac's use in this new composition does not inherit Matrix's protocol security argument.

**CR-01 and F-02 disposition:** The owner policy allows one owning process, one live exposed ceremony, and a shared 10-opportunity budget across both roles, threads, and connections. With I1 terminal irreversibility and I2 SAS lifetime, the structural model is `n_A + n_B - 1`; maximum 19 and `P_joint ≤ 19 × 2^-39 + ε` apply only to a joint 10/10 window where both endpoints remain within their process sessions. This does not cover arbitrary restarts or lifetime use. Older persistent `N = 5,497`/`ε = 10^-8` and multi-ceremony rules are historical and non-normative. Earlier AI reviews recorded **PREVIOUS PROOF NOT ESTABLISHED** for the earlier argument. The latest focused AI-assisted review records **F-02 = FALSE POSITIVE UNDER THE STATED IDEALIZED ASSUMPTIONS**: an attacker can calculate its own DH secret after an honest public contribution is revealed, and the SAS claim does not require it to remain hidden then; the target SAS must remain unpredictable before the attacker fixes its contribution. This conditional disposition does not prove the complete protocol. Pair-count remediation is documented, while residual assumptions and verification obligations remain accepted only for experimental development. No qualified human audit or formal verification is claimed.

**Recorded review disposition:** F-02 is rejected for the specific disputed property under the stated idealized assumptions. The conditional argument continues to depend on fresh unpredictable honest ephemeral contributions, correct commitment timing and binding/hiding assumptions, correct role-specific order, the full injectively encoded SAS context, random-oracle-style assumptions for relevant SAS derivation, and correct exposure accounting. Source facts about protocol order and APIs are recorded separately from this conditional reasoning. The prior **PREVIOUS PROOF NOT ESTABLISHED** verdict remains part of the history of the earlier argument; no complete formal proof or professional audit is claimed. The owner's authorization to proceed experimentally does not depend on declaring all assurance work complete.

**Evidence distinction:** The protocol profile specifies the public-message order; the pinned upstream source supports the relevant X25519 API behavior. From those inputs, it follows that after an honest public contribution is revealed, a participating attacker can compute the shared secret on its own DH leg; the disposition does not claim this value remains hidden. The conclusion that this does not require an additional X25519 hardness assumption for the disputed SAS property is conditional cryptographic reasoning, relying on the assumptions above and on target-SAS unpredictability before the attacker fixes its contribution. This is not a source-verified theorem about the full composition.

The questions below remain useful as implementation and assurance limitations. The owner has separately selected the profile for experimental development and waived a qualified-human-review prerequisite for P4 only. Selection does not resolve every review question or grant production approval.

## Scope and threat model

The adversary controls an untrusted network and may observe, inject, modify, replay, reorder, delay, drop, and duplicate messages; adaptively schedule, selectively abort, and initiate repeated locally authorized attempts. The owner policy permits exactly one owning process per pairing authority and one live exposed ceremony; exclusive ownership must be acquired atomically before exposure, with uncertain acquisition failing closed. A second process cannot initiate or accept an exposed ceremony with an already-owned authority. The owner process shares the 10-opportunity budget across roles, threads, and connections. The adversary does not control an honest endpoint or its cryptographic RNG under the stated assumptions. Human comparison may fail or be partial; the security claim must state its assumptions and must not count vectors as proof. A process-local mutex alone is insufficient to prevent another process from using the authority.

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
| Repeated online attempts | One owning process and one live exposed ceremony per authority; one shared 10-opportunity process/session budget across both roles, threads, and connections | Proposed `P_per_pair ≤ 2^-39 + δ` and `P_joint ≤ 19 × 2^-39 + ε` remain conditional; 19 applies only in a joint 10/10 window within both process sessions. No arbitrary-restart or lifetime bound; `δ`/`ε` are symbolic. |
| RNG and ephemeral lifecycle | Fresh, unpredictable, non-reused key material per ceremony | Exact upstream API is pinned. Entropy adequacy and fork/snapshot/restored-state/rollback/RNG-failure behavior on supported targets need review; no snapshot resistance is claimed. |
| Same-device SAS bypass | Separate abstract profile requires an approved OS-authenticated adapter, mutual endpoint authentication, authorization, and remote exclusion | Not part of this remote-candidate selection. Generic predicate and Windows adapter remain candidate-only; zero adapters are approved. |

## Concrete attack and composition questions

Pair counting is documented; the corrected security argument is conditional and not formally verified. The analysis must not condition on an attacker view containing both completed SAS values or assume the attacker commits one leg before learning the other leg's SAS. It records per-ceremony message ordering and the remaining unpredictable honest contribution at the stated conditioning point. Evaluate the explicit random-oracle-style assumptions; ordinary HKDF PRF security alone is not asserted sufficient when the attacker knows the derived secret on its own leg. Concrete SHA-256 and HKDF-SHA256 are not proven random oracles. CR-01's structural remediation is documented, with residual assumptions and verification limitations accepted for experimental development.

1. Does the full commit, key agreement, SAS, MAC, and completion composition support the proposed conditional active-MITM argument? Distinguish SHA-256 collision resistance for binding from random-oracle-style hiding for the commitment.
2. Is the relevant HKDF-SHA256 construction covered by the stated random-oracle-style assumption for the unknown honest contribution and bound context? Explain why PRF security alone does or does not suffice when the attacker knows the derived secret on its own leg.
3. Is the `2^-39` ideal term justified at the specified conditioning point for each candidate pair? Assess the exact event, two honest ceremonies, adaptive scheduling, selective aborts, and per-role message ordering without conditioning on both completed SAS values.
4. Are fresh unpredictable ephemeral keys and accepted X25519 inputs sufficient under the specified assumptions? What evidence is required for fork, VM snapshot, restored-state, RNG-failure, or duplicated-state conditions on each supported target?
5. Does atomic single-owner-process enforcement, the shared 10-per-process/session exposure budget, and one live ceremony support the `n_A + n_B - 1` pair count? Confirm that 19 applies only to a joint 10/10 window where both endpoints remain in their respective process sessions, and does not extend across arbitrary restarts.
6. Do the exact transcript and MAC inputs bind every security-relevant field in a unique order, including roles, profile/version, ceremony identity, both bootstrap messages, shared context, and expected-peer constraints?
7. Are bootstrap and completion MACs composed correctly, and does I1/I2 prevent terminal revival and stale approval/SAS use?
8. Is atomic exclusive ownership, the process-owned guard and shared session budget, and explicit retry/authorization behavior implementable without a protocol message or wire-format change? Identify the P4 obligations for ownership enforcement, crash handling, and safe release. Do not propose a platform mechanism as part of this review.
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
- **Vodozemac-based ceremony:** selected for experimental implementation by [owner decision](decisions/0002-experimental-vodozemac-selection.md); no production-security approval is implied.
- **Complete Matrix verification:** not a generic drop-in because its identity and trust semantics are Matrix-specific.
- **New production core, language wrappers, or consumer integration:** out of scope for this review and P3.

## Review status

Security research and adversarial review were AI-assisted. No qualified independent human audit, formal verification, or professional security certification has occurred. Independent AI review is useful development evidence but is not equivalent to a professional audit. The owner explicitly waived the human-review gate for experimental P4 development; the review was not completed. No production use or release is thereby authorized, and any public release must disclose these limitations.
