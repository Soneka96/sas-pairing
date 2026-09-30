# 0002 — Experimental vodozemac selection and implementation authorization

**Status:** Accepted by the project owner on 2026-09-30. Experimental development only.

## Context

Candidate B was selected historically during P2 based on available formal security evidence. P3 research later identified substantial custom cryptographic design and maintenance responsibilities for its concrete instantiation. The owner reopened construction selection for that ownership reason; this did not demonstrate Candidate B insecure. The vodozemac-based remote pairing candidate has since been reviewed with AI-assisted adversarial analysis, while qualified independent human review and formal verification have not occurred.

## Decision

**OWNER DECISION: APPROVED.** The owner authorizes:

1. `VODOZEMAC = SELECTED FOR EXPERIMENTAL IMPLEMENTATION`, for the existing corrected vodozemac-based remote pairing candidate and its owner-approved policy.
2. The current corrected specification and owner policy as the experimental development baseline, pinned to vodozemac `0.11.0` at source revision `db1b34820f3102307284e762f335b3f72c735bf0`, crate archive SHA-256 `ba935af014ca0ae5fb468daa51da81a8a0df7daad23c052c878b7c690cdf2574`.
3. Progress toward P4 native Rust security-core development without obtaining a qualified independent human security audit.
4. Use of existing AI-assisted adversarial reviews as development evidence, not formal verification, a professional audit, or security certification.
5. Explicit documentation of residual assumptions, unresolved assurance questions, and implementation obligations.

The previous qualified-human-review prerequisite is **waived by the owner for experimental P4 development**; the review was not completed. This informed risk acceptance does not resolve all security questions, establish production security, or authorize production use or release. Any public release must disclose the assurance limitations accurately. Other development and release gates remain in force unless explicitly changed here.

Candidate B's historical P2 selection and formal evidence remain part of the record. It is not declared insecure, and this decision does not reopen the construction comparison. The separate same-device profile and OS-specific adapters remain independently gated. This generic library decision adds no DovahLink-specific requirements. Permanent device trust, reconnect behavior, forgetting, and revocation remain consumer-level integration responsibilities.

## Review dispositions and security boundary

**F-02 = FALSE POSITIVE UNDER THE STATED IDEALIZED ASSUMPTIONS.** The challenged property required an additional unpredictability claim for an X25519 shared secret after an honest public contribution is revealed. A participating attacker can ordinarily calculate its own Diffie–Hellman shared secret at that point; the SAS argument does not require that secret to remain hidden after exposure. It instead requires the target SAS to remain unpredictable before the attacker fixes the relevant contribution. This conditional reasoning depends on fresh unpredictable honest ephemeral contributions, correct commitment timing, commitment binding and hiding under the stated assumptions, correct role-specific message order, full injectively encoded SAS context, random-oracle-style assumptions for the relevant derivation, and correct exposure accounting. The focused AI-assisted review found no additional X25519 hardness assumption necessary for that disputed property under this model. Source-verified facts and this conditional reasoning are distinguished in the review package. This disposition does not prove the complete protocol secure.

**CR-01: STRUCTURAL REMEDIATION DOCUMENTED; RESIDUAL ASSUMPTIONS AND VERIFICATION REQUIREMENTS ACCEPTED FOR EXPERIMENTAL DEVELOPMENT.** The one-process/one-live-ceremony/ten-opportunity policy addresses the original unbounded comparison-accounting issue within its stated scope. The per-pair argument remains conditional and has not been formally verified. Concrete cryptographic assumptions, implementation correctness, target-specific ephemeral freshness, and real-world human behavior remain limitations accepted for experimental development. Keep the reviewed model `n_A + n_B - 1`, `MAX_TESTED_PAIRS = 19` in a joint 10/10 process-session window, and `P_joint ≤ 19 × 2^-39 + ε` (approximately `3.456 × 10^-11 + ε`); do not assign a numeric `ε`, extend this to arbitrary restarts or relationships, or describe it as a lifetime, human-error, end-to-end, or concrete-implementation guarantee.

The remote baseline retains the existing trust boundary (network locality is not trust), single owning process per authority, one live exposed ceremony, shared ten-opportunity process/session budget, explicit local authorization per exposure, no automatic retry/resume/reconnect continuation, I1 terminal irreversibility, I2 SAS invalidation, and atomic guard/accounting before contribution release. No wire message or cryptographic formula is added or changed.

## Consequences and P4 prerequisites

P4 may begin as experimental implementation, is not complete, and must fail closed when a security-critical invariant cannot be enforced. At minimum it must implement and verify exact message ordering; the pinned dependency; fresh, unpredictable, non-reused ephemeral material; one-process authority ownership and safe acquisition/release; shared ceremony guard and ten-opportunity budget; atomic exposure accounting; no automatic retries; terminal irreversibility; SAS invalidation and stale-callback rejection; malformed-input handling; deterministic vectors; normative conformance cases; and fail-closed behavior. It must assess target-specific RNG, fork, snapshot, restored-state, and process-ownership limitations. No platform ownership mechanism is selected here. Any genuinely undecided normative detail is a P4 prerequisite, not an implementation choice.

The implementation and integration add risks. AI-assisted security research and independent AI review are not equivalent to a qualified professional audit. No formal verification, independent professional security certification, production-security approval, or final release-readiness decision is claimed. The P5 implementation review and other existing release gates remain in force.
