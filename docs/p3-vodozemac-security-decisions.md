# P3 vodozemac candidate — security decisions and review log

This document records the rationale, evidence boundaries, alternatives, assumptions, and review gates behind the vodozemac ceremony candidate. It is an audit trail, not a protocol specification. The normative candidate source is [the vodozemac ceremony profile draft](p3-vodozemac-ceremony-profile-draft.md); this log does not replace it.

## Status and architecture boundary

Candidate B remains the **SELECTED P2 remote construction**, while its concrete production instantiation remains gated. The vodozemac ceremony is a separate **CANDIDATE — NOT SELECTED**. If later accepted, the proposed reuse direction is one shared Rust security ceremony using vodozemac with thin Dart/.NET wrappers; no independent Dart or .NET cryptography. That architecture is not a final production selection. No production cryptography or remote protocol is approved. Independent external review remains mandatory.

The assessment recommends the shared Rust-core direction only as promising reuse, subject to a complete profile and independent review ([reuse assessment](p3-vodozemac-reuse-assessment.md), §18). Vodozemac primitives and Matrix ceremony behavior are precedent, not evidence that this generic composition is secure.

## Decision records

### D1 — Candidate status and proposed reuse boundary

**Status:** Candidate decision; architecture not selected for production.

**Decision:** Keep Candidate B as the selected P2 remote construction. Keep vodozemac as a separate P3 candidate. If it is eventually accepted, use one shared Rust ceremony around vodozemac and thin Dart/.NET wrappers.

**Problem and rationale:** vodozemac supplies maintained SAS primitives, while Matrix supplies a Matrix-specific ceremony. A generic adaptation changes identity, context, framing, and result semantics; it cannot inherit Matrix's security argument by reuse alone. One shared core would keep protocol behavior in one implementation if this candidate passes review.

**Alternatives considered:** Select Candidate B's eventual concrete instantiation; reuse the complete Matrix state machine; implement independent Dart/.NET cryptography. Candidate B's instantiation remains gated, Matrix semantics are application-specific, and duplicate cryptographic implementations are not the proposed reuse path.

**Assumptions / evidence:** P2 construction selection, the [vodozemac reuse assessment](p3-vodozemac-reuse-assessment.md), and the candidate profile's source traceability (§13). These support research direction, not acceptance of the generic ceremony.

**Does not establish:** Production architecture, production protocol approval, or security of the generic mapping.

**Repository history:** `3ba5a7e` introduced the separate generic vodozemac candidate and stated Candidate B's selection boundary.

**Independent-review status:** Full independent external protocol/security review remains required.

### D2 — Routing handle versus established ceremony identity

**Status:** Candidate decision.

**Decision:** Use `request_id` only for pre-establishment routing and correlation. After `START`, `ACCEPT`, `INITIATOR_KEY`, and `RESPONDER_KEY` are fixed, identify the established ceremony by the SHA-256 digest of their canonical transcript, with the profile's domain separator and length framing.

**Problem:** An Initiator-generated request identifier can be replayed after restart or reused across cryptographically distinct runs.

**Rationale:** A replayed `START` may create fresh Responder ephemeral state. The fresh key changes the transcript and therefore the candidate ceremony identity, subject to the digest assumption. Old SAS-derived MACs, approval, and completion state do not authenticate the new run. A new run reaching the SAS exposure boundary consumes a new attempt. This renders replay ineffective as replay of the old authenticated ceremony without requiring an unbounded durable request-ID history solely for authentication freshness.

**Alternative considered:** Keep a durable database of all previously seen request IDs and reject reuse. It adds persistent historical state but does not replace attempt accounting; the candidate instead relies on fresh cryptographic state and transcript binding for ceremony authentication.

**Assumptions / evidence:** Fresh unpredictable Responder ephemeral material, canonical transcript equality, and SHA-256 collision resistance for the identity binding. Profile §§4, 9, and 11.2 describe the boundary; P1 separately requires freshness.

**Does not establish:** Request-ID entropy, generation, or collision requirements; those remain unresolved. Nor is replayed `START` necessarily rejected or free of resource/attempt cost.

**Repository history:** `7d10cc8` bound authoritative ceremony identity to the transcript and distinguished it from the request handle.

**Independent-review status:** Transcript/role/domain binding and replay reasoning remain for independent review.

### D3 — Local verified completion, not atomic bilateral success

**Status:** Candidate decision; completion semantics were clarified against stale P1 wording.

**Decision:** Define success by each endpoint's local authenticated evidence for the exact ceremony. If the final acknowledgement is lost, the Initiator may satisfy its local result condition while the Responder has no result. If both return results, they must be compatible; conflicting successful results are forbidden.

**Rationale:** A finite message exchange cannot make two distributed processes atomically persist success or guarantee common knowledge under message loss. The three-message completion exchange gives each side a local verified condition and constrains compatible outcomes without claiming simultaneous success.

**Alternatives considered:** Require atomic bilateral success or durable bilateral trust persistence. The exchange cannot guarantee either across arbitrary message loss and independent local storage.

**Assumptions / evidence:** Profile §9 gives the exact evidence known to each role and the asymmetric final-ACK-loss case. P1's result contract permits asymmetric observation while requiring compatible results when both succeed.

**Does not establish:** Atomic durable trust persistence, common knowledge, or that both applications stored trust.

**Repository history:** `68d41e8` tightened completion framing; `80d1005` replaced stale bilateral-success phrasing with local verified completion and clarified the P1 semantics.

**Independent-review status:** The three-message contract and compatible-result argument remain for independent review.

### D4 — Cancellation, duplicate delivery, and terminal state

**Status:** Candidate decisions.

**Decision:** Use wire `CANCEL / 0x09`; authenticate it after shared SAS establishment using the separate non-wire `CancelAuthFrame / 0x34`. Before shared state exists, cancellation is local only. Ignore an exact duplicate of an accepted active message idempotently; changed duplicates and illegal/reordered messages fail. Terminal state and any emitted result are immutable.

**Rationale:** An unauthenticated early cancellation cannot be treated as peer intent. Later cancellation must be bound to role, reason, and the exact ceremony. Exact-duplicate handling tolerates network retransmission without repeating cryptographic work or state transitions; changed, misplaced, or stale input cannot revive or alter a run.

**Alternatives considered:** Accept unauthenticated remote cancellation before key establishment; treat changed duplicates as retries; allow late terminal messages to revise results. These weaken the authentication or state boundary and are not in the candidate.

**Assumptions / evidence:** Profile §§6 and 11.2–11.4 define the wire/authentication distinction, duplicate classification, and terminal behavior. These are project adaptations, not inherited generic guarantees from Matrix.

**Does not establish:** A fixed timeout value, which remains unresolved, or implementation/runtime secret-erasure guarantees.

**Repository history:** `80d1005` reconciled cancellation authentication and duplicate/terminal semantics; `68d41e8` tightened completion and terminal handling.

**Independent-review status:** Authentication contexts, state-machine behavior, and cleanup guarantees remain for independent review.

### D5 — SHA-256 commit-before-reveal without a separate nonce

**Status:** Candidate decision; assumptions remain open to review.

**Decision:** Retain the profile's SHA-256 commitment over the exact canonical `START` and `R_pub`, without adding a separate random nonce.

**Rationale:** The single-attempt binding argument is that R fixes `R_pub` before seeing `I_pub`; changing it while opening the same commitment would require a SHA-256 collision for distinct encoded inputs. The hiding rationale relies on an honestly generated, high-entropy hidden `R_pub` and a random-oracle-style (or equivalent pseudorandom-output) assumption for SHA-256 on that input. A separate nonce showed no demonstrated material benefit for this candidate's stated purpose.

**Alternatives considered:** Add an independent commitment nonce; choose a separate standardized commitment primitive; reject the construction. No reviewed evidence in this branch established a material gain from an extra nonce or selected a separate primitive. Rejection remains possible if independent review does not accept the assumptions.

**Security assumptions:** Adequate unpredictability/min-entropy from the selected vodozemac RNG/key-generation path; collision resistance for binding; random-oracle-style/equivalent hiding for high-entropy hidden input. Collision resistance and ordinary preimage resistance alone do **not** prove generic hiding.

**Evidence / precedent:** Matrix v1.18 is precedent for responder commit-before-reveal order and SHA-256 in its own ceremony. The exact binary formula and its generic hiding argument are project adaptations, not inherited Matrix proofs. Profile §5 states the formula and boundaries.

**Does not establish:** A general hiding commitment, information-theoretic hiding, resistance to multi-session grinding without accounting, or a theorem for concrete SHA-256.

**Repository history:** `ede6473` made the commitment binding and hiding assumptions explicit.

**Independent-review status:** Independent review must accept the exact encoding, binding argument, RNG/entropy path, and hiding assumption.

### D6 — Matrix/vodozemac decimal SAS, compare-only

**Status:** Candidate representation decision.

**Decision:** Retain vodozemac/Matrix decimal SAS: three 13-bit groups, exactly `2^39` complete values, displayed for whole-value comparison without typing or transcription.

**Rationale:** This uses maintained upstream representation support and a compact, familiar display. Emoji adds only three bits. A longer decimal or custom Base32 adds custom mapping and UX complexity; the candidate instead constrains repeated opportunities through aggregate accounting.

**Alternatives considered:** Emoji; longer decimal; custom Base32.

**Evidence / precedent:** [Matrix v1.18 SAS verification](https://spec.matrix.org/v1.18/client-server-api/#short-authentication-string-sas-verification) and the [vodozemac `SasBytes` API](https://docs.rs/vodozemac/latest/vodozemac/sas/struct.SasBytes.html) support the representation. The generic ceremony's security claim does not transfer from that precedent. Profile §7 states the mapping and human-comparison boundary.

**Does not establish:** That the whole system is “39-bit secure.” One charged opportunity contributes at most `2^-39` only if the complete construction assumptions are accepted and the entire SAS is compared correctly. Human mistakes are outside that statistical term.

**Repository history:** `3ba5a7e` introduced the decimal SAS mapping; `8c404eb` and `875436e` established the attempt-accounting and aggregate-policy context for retaining it.

**Independent-review status:** The per-opportunity bound, human-comparison assumptions, and aggregate policy remain for independent review.

### D7 — Reserve SAS attempts before key exposure; never refund

**Status:** Candidate security-policy decision.

**Decision:** The Initiator durably reserves an attempt before releasing `INITIATOR_KEY / I_pub`. The Responder reserves after validating `I_pub` and before revealing `RESPONDER_KEY / R_pub`. Once charged, an attempt is never refunded after abort, mismatch, timeout, cancellation, later failure, or success.

**Rationale:** Charge before the peer receives enough information to derive a candidate SAS. Fail-closed durable reservation prevents a crash or retry from erasing an opportunity that may have been exposed.

**Alternatives considered:** Charge on start, after key release, or only on mismatch; refund unused or failed attempts. Start may precede a SAS opportunity; charging later can miss an exposed guess, while refunds can replenish the budget after attacker-controlled failures.

**Assumptions / evidence:** The candidate's shared local counter is atomic and durable for its epoch. Resource/DoS admission, SAS-security accounting, and UX/fatigue policy are separate controls. Profile §§11.1–11.1.1 and P1 set these boundaries.

**Does not establish:** A deployment's persistence or rollback resistance, or that a network-rate policy is supplied by the SAS counter.

**Repository history:** `8c404eb` defined attempt accounting; `875436e` set its aggregate policy; `2c02f7c` explicitly separated resource admission from SAS charging.

**Independent-review status:** Exposure boundary, atomicity, persistence, recovery, and no-refund behavior remain for review.

### D8 — Aggregate SAS candidate policy

**Status:** Project-owner candidate policy decision; not an external standard's target.

**Decision:** Candidate per-opportunity term `≤ 2^-39`, subject to review; target `ε = 10^-8` per local epoch; maximum `N = 5,497` charged opportunities per epoch.

**Rationale:** The union bound gives `N × 2^-39 ≈ 9.9989848 × 10^-9 < 10^-8`. The 128-attempt `2^-32` option was judged unnecessarily restrictive and more sensitive to denial-of-service pressure. The `10^-6` option permits 549,756 opportunities and was judged too permissive. The selected volume is far above plausible ordinary pairing volume while retaining a small statistical term. These are project judgments, not values dictated by Bluetooth or another external standard.

**Alternatives considered:** `2^-32 / 128`; `10^-6 / 549,756`; and timed/window replenishment. A window could replenish opportunities without a lifetime cap; the candidate instead scopes the stated target to an explicit epoch.

**Evidence / precedent:** Arithmetic in profile §7 and the policy in §11.1. The calculation bounds only the SAS random-match component, conditional on the independent acceptance of the per-opportunity term.

**Does not establish:** A complete protocol-failure bound, lifetime bound, or protection from human error, endpoint compromise, RNG failure, or other protocol vulnerabilities.

**Repository history:** `875436e` records the target and maximum; `8c404eb` establishes the attempt-accounting model.

**Independent-review status:** The `2^-39` premise and the policy's fit remain for independent review.

### D9 — Durable accounting epoch and explicit reset

**Status:** Candidate policy decision.

**Decision:** Maintain a durable local SAS security-accounting epoch. Do not replenish by timer; successful pairing does not reset the count. Exhaustion blocks further remote SAS opportunities. Only an explicit locally authorized reset creates a new epoch; a network-only attacker cannot trigger it. Reset does not erase earlier statistical exposure.

**Rationale:** A numeric maximum needs a defined accounting scope and cannot silently replenish through ordinary time, success, restart, or attacker-controlled events. The `10^-8` claim is **per epoch**, not lifetime. Reinstall or rollback without an external durable anchor may begin or restore a different epoch and narrows the claim.

**Alternatives considered:** Automatically timed/window reset or implicit reset after successful pairing. These grant fresh opportunities without preserving a continuous claim about the old epoch.

**Assumptions / evidence:** Epoch state and count survive ordinary restart, reboot, and application update; deployment-specific rollback guarantees are required only for claims across rollback. Profile §11.1 and P1 define scope and limits.

**Does not establish:** A lifetime aggregate bound across resets/reinstall or a generic rollback-resistant store.

**Repository history:** `8c404eb` defined attempt accounting; `875436e` adopted the aggregate maximum and epoch policy.

**Independent-review status:** Reset authorization, durable storage, epoch scope, and rollback claims remain for review.

### D10 — Deterministic resource maxima and responder admission

**Status:** Candidate resource-policy decision.

**Decision:** Retain maxima of 65,536 bytes per complete wire frame; 16,384 per bootstrap; request ID 1–64; application identity 1–1,024; key algorithm 1–64 ASCII; public key 1–4,096; shared context 0–8,192; 65,536 bytes per generated Base64url cryptographic input; and at most eight active Responder ceremonies globally per applicable local security core.

**Rationale:** Byte caps give deterministic parser, allocation, and cryptographic-input bounds. Eight active ceremonies is an engineering/resource-safety limit, not a cryptographic-strength parameter. Stricter deployment limits are allowed; raising these maxima while claiming conformance is not.

**Alternatives considered:** Leave semantic `u32` lengths effectively unbounded; choose larger frame/bootstrap maxima; allow much higher concurrency. The branch adopted fixed maxima to bound work, while exact global rate thresholds remain separate and unresolved.

**Evidence / precedent:** Current profile §§3–4 and 11.1.1; the limits are project adaptations, not inherited Matrix or vodozemac limits.

**Does not establish:** That the chosen maxima fit every deployment, that serial request rates are bounded, or that multi-process integrations coordinate a global slot count.

**Repository history:** `2c02f7c` introduced the current field/frame/Base64url maxima and eight-slot responder limit.

**Independent-review status:** Adequacy, implementation enforcement, and deployment-wide coordination remain for review.

### D11 — Approval and result bind to the exact ceremony

**Status:** Candidate decision.

**Decision:** Associate human approval with the transcript-derived ceremony identity. The approval MAC binds the full SAS, sender/receiver roles, bootstrap, and ceremony. Return the exact authenticated peer bootstrap and ceremony identity in `PairingResult`.

**Rationale:** A reused request ID must not reuse approval. Transcript identity and role-specific MAC context keep approval and result attached to one established run and the exact peer-supplied bytes.

**Alternatives considered:** Treat request ID as authoritative after establishment; return a digest instead of exact bootstrap bytes; treat authenticated public-key bytes as proof of possession. Those choices would lose exact-ceremony or result semantics, or overstate what the protocol establishes.

**Assumptions / evidence:** Profile §§7–9. The consumer still validates expected peer properties and decides external truth and authorization.

**Does not establish:** Ownership, control, or possession of the private key corresponding to an authenticated public key; external identity truth; or application authorization.

**Repository history:** `7d10cc8` established transcript-derived identity and approval binding; `80d1005` clarified local result conditions; `3ba5a7e` introduced the exact bootstrap result boundary.

**Independent-review status:** Transcript binding, MAC contexts, expected-peer boundary, and result compatibility remain for review.

## Current unresolved P3 gates

These gates are based on the current candidate profile, P3 roadmap, and supporting assessments. They are not resolved by recording the decisions above.

- Request-ID entropy, generation, and collision requirements remain **REVIEW REQUIRED** (profile §4).
- Exact acceptable vodozemac release, complete RNG/key-generation path, unpredictability, and zeroization/lifecycle guarantees remain under-specified or review-dependent (profile §§5, 14; reuse assessment §18).
- Application-context semantics and expected-peer validation are specified as byte equality and consumer responsibility, but whether these are the right generic semantics remains an independent-review question (profile §§4, 8, 14).
- Exact monotonic timeout duration remains open (profile §11.3).
- Global resource/rate thresholds and multi-process coordination of the eight-slot bound remain open (profile §§11.1.1, 14).
- The separate same-device profile remains P3 work (P3 roadmap); it is not defined by this vodozemac candidate.
- Deterministic vector values and conformance vectors remain deferred (profile §12).
- P3 remains in progress; cross-document consistency and roadmap exit criteria are not complete (P3 roadmap). The repository does not record a completed full internal whole-profile re-review; informal/internal review cannot substitute for the independent external review required by P5.
- Independent external security review of the complete candidate and its cryptographic assumptions remains mandatory before selection or any production-readiness claim.

## Evidence and review boundaries

- **Primary/external precedent:** [Matrix Client-Server v1.18 SAS ceremony](https://spec.matrix.org/v1.18/client-server-api/#short-authentication-string-sas-verification), [vodozemac SAS/MAC APIs](https://docs.rs/vodozemac/latest/vodozemac/sas/index.html), and [RFC 4648 Base64url](https://www.rfc-editor.org/rfc/rfc4648.html#section-5). These support only the behavior and APIs within their own scopes.
- **Project adaptation:** Generic binary framing, bootstrap and context schema, transcript-derived ceremony identity, completion/cancellation details, decimal SAS adoption, `ε = 10^-8`, `N = 5,497`, accounting epochs, and resource maxima.
- **Internal analysis:** Branch decisions and their alternatives were refined through repository research and internal adversarial analysis. This work is useful engineering rationale, not independent security review.
- **Independent external review:** Still required. No internal AI, fresh-agent, or repository review is described here as an external audit or approval.

## Repository history trace

The references below are the verified commits on `security/p3-vodozemac-ceremony-profile`, in order after `origin/main` `cb1e1d01e734ecc664fb5052ef817ca8c4b061d9`:

- `3ba5a7e375cac0521dbfbf60fe57feeca014d6c6` — introduced the generic vodozemac candidate profile.
- `80d1005bcc967b39c3408fad1ff8d431484334f9` — reconciled cancellation, duplicate, terminal, replay, and local completion semantics.
- `68d41e8e3af3c869f67f35747b3e63449acce77d` — tightened completion framing semantics.
- `7d10cc8bd0ebe0a96f360db73cb46f5dca6dd7f0` — bound authoritative ceremony identity to the transcript.
- `ede64739dde8168a6ccbaecfb8d4a1332d0d3b2a` — stated commitment security assumptions.
- `8c404eb050cc38db92015cd30a077e0c9d973ac7` — defined SAS attempt accounting.
- `875436e494c2cd407e80dd9018cd896232811ddd` — set aggregate SAS policy.
- `2c02f7c346a077db6d7d90f7254eb724981e68c1` — set candidate resource bounds.

Each record cites the commit that introduced or materially clarified its decision. Where a decision spans related changes, the record lists both rather than assigning a single commit artificially. The full branch diff is confined to the candidate profile and threat model; the decision log preserves traceability without copying prior review reports or treating commit subjects as the evidence.
