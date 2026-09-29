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

**Does not establish:** Request-ID uniqueness or freshness from the ID alone, authentication, or freedom from resource/attempt cost when a replayed `START` begins a new run. The candidate generation/routing policy is recorded in D12 and remains subject to review as part of the complete profile.

**Repository history:** `7d10cc8` bound authoritative ceremony identity to the transcript and distinguished it from the request handle.

**Independent-review status:** Transcript/role/domain binding and replay reasoning remain for independent review.

### D12 — Public request-ID generation and active routing uniqueness

**Status:** Candidate policy decision; independent review of the complete profile remains required.

**Decision:** For an honest Initiator, the shared security core generates exactly 16 raw request-ID bytes using its reviewed OS-backed CSPRNG. Before emitting `START`, it atomically checks and reserves the value in the applicable active local routing namespace; a collision with another active local request is regenerated before `START`. Incoming wire syntax remains any canonical opaque nonempty value of 1–64 bytes. Incoming values receive no entropy validation and are treated as attacker-controlled. The transport/session layer supplies connection/session identity for safe local dispatch; state is associated with that context plus request ID (or equivalent state-object binding). The core owns generation, reservation, state association, and the semantics that keep request ID from becoming ceremony authority. Applications receive the generated value for routing/correlation, diagnostics, or logs, but SHOULD NOT choose it.

**Role and rationale:** The request ID is public, non-secret, network-observable diagnostic/routing context. It provides pre-establishment correlation and an active local collision-resistant handle. Sixteen uniformly random bytes provide an extremely strong accidental-collision margin, simple fixed generation without persistent counters, reduced trivial cross-session linkability, and fewer predictable pairing-volume/restart patterns. A counter could theoretically provide routing uniqueness if perfectly coordinated, but would complicate process/restart coordination, may need persistent state, expose activity patterns, and increase linkability without improving authentication. The CSPRNG requirement is the honest-generation mechanism; protocol authentication does not depend on request-ID unpredictability. It is separate from entropy requirements for ephemeral DH/SAS state.

For `n` cumulative generations of 128 uniformly random bits, the birthday approximation is `P_collision ≈ n(n - 1) / (2 × 2^128)`. Illustrative values are:

| Cumulative generations `n` | Approximate collision probability |
|---:|---:|
| 1,000 | `1.47 × 10^-33` |
| 1,000,000 | `1.47 × 10^-27` |
| 1,000,000,000 | `1.47 × 10^-21` |

These examples are not a formal protocol security bound. The security-relevant scope for honest-local collision checking is smaller because it concerns only simultaneously active state in the applicable namespace.

**Alternatives considered:** 64-bit random IDs (less collision margin); 96-bit random IDs (adequate in many scopes but no benefit over a fixed 16-byte handle); 256-bit random IDs (larger field/use without material need); UUIDv4 (unneeded UUID conventions and variant/version bits); a monotonically increasing counter (coordination, restart, persistence, activity-pattern, and linkability costs); and caller-provided opaque IDs (allows predictable/colliding inputs to drive local protocol starts and weakens core ownership of safe reservation). None improves the selected simple fixed-width routing handle. Incoming malicious IDs remain accepted within the parser's 1–64-byte bound, regardless of generation policy.

**Security assumptions and state rules:** The OS-backed CSPRNG is required for honest generation, but request-ID unpredictability is **not** an authentication assumption. A predictable request ID alone MUST NOT break protocol authentication. The ID does not establish freshness, peer identity, authorization, ceremony identity, replay protection, secrecy, SAS security, or historical/global uniqueness. It MUST NOT alone authorize messages, state transitions, approval, result retrieval, reset, or SAS accounting. The honest local uniqueness requirement is only that two simultaneously active requests do not alias the same routing/state key within the applicable local namespace. No persistent historical-ID database is required. After a request becomes terminal and active state is gone, later ID reuse is not automatically a security failure: each run uses new cryptographic state and the transcript-derived `ceremony_identity` distinguishes established runs.

Before establishment, state is bound to connection/session context plus request ID, or equivalent internal state-object binding; peer-controlled ID alone is not authoritative across multiple sessions. The same ID on different connections represents separate runs, consumes separate responder slots, and independently consumes an SAS attempt if it reaches exposure. Such runs MUST NOT share a state object. Within one active routing key, an exact duplicate `START` is ignored idempotently without new state or repeated output/key generation; a conflicting `START` fails closed under existing duplicate/illegal-state rules without overwrite, merge, restart, approval inheritance, or accounting reset. Cross-connection messages cannot dispatch into another state merely by matching its ID. After the transcript through `RESPONDER_KEY` is fixed, `ceremony_identity` remains authoritative for SAS display, approval, MACs, completion, and results; request ID remains optional routing/diagnostic context.

On restart, active state and pending approval are discarded; historical request IDs are not persisted to prevent reuse. A replayed `START` may create a new policy-eligible run with fresh cryptographic state. If it reaches SAS exposure, it consumes a new attempt. Reuse cannot inherit approval/results or bypass resource or SAS accounting. Random generation reduces trivial linkability but does not establish anonymity or unlinkability; other metadata may correlate sessions.

**Does not establish:** Authentication, freshness, peer identity, authorization, ceremony identity, replay security by itself, possession, secrecy, SAS security, anonymity/unlinkability, or global/historical uniqueness. Request-ID unpredictability is not relied upon for any protocol-authentication claim.

**Repository history:** `9a95910a4e01f8c291ee57af3f2d365dca8b5285` records this candidate request-ID policy.

**Independent-review status:** Candidate policy defined; generation, collision reservation, routing isolation, and the distinction from authentication/freshness remain subject to independent review as part of the complete profile. This internal decision is not an independent external security review.

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

**Does not establish:** That the timeout policy recorded in D15 is suitable for every deployment, or implementation/runtime secret-erasure guarantees.

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

### D13 — Exact vodozemac dependency and secret lifecycle

**Status:** Candidate dependency/lifecycle decision recorded; independent review remains open.

**Decision:** Analyze this P3 candidate against exactly `vodozemac = 0.11.0 exact`. This is a documentation/specification pin, not a Cargo dependency. If advanced to P4, use `vodozemac = { version = "=0.11.0", default-features = false }`, implement and revalidate that choice, and capture/review the actual P4 workspace's resolved `Cargo.lock` graph. The 0.11.0 manifest uses semver-compatible ranges and does not freeze `rand`, `rand_core`, `getrandom`, `hmac`, `sha2`, `x25519-dalek`, or their transitives.

**Rationale:** 0.11.0 is the current stable release; it exposes the required SAS API; comparison of the 0.10.0-to-0.11.0 `src/sas.rs` change found no material SAS semantic regression; the exact source uses contributory X25519 validation; and the tagged/released source can be reviewed precisely. The 0.11.0 release changes the SAS RNG call from `thread_rng()` to `rng()` while preserving the `ThreadRng` path.

**Feature decision:** Disable defaults. `libolm-compat` is unnecessary and this candidate MUST use standard SAS MAC behavior, not its legacy invalid-Base64 compatibility path. `precomputed-tables` is unnecessary for correctness; disabling it is a binary-size/performance choice, not a security-strength gain, and does not change candidate SAS results or contributory validation. Do not enable `low-level-api`, `insecure-pk-encryption`, `experimental-session-config`, or `wasm_js` without a future target-specific analysis. The tagged `x25519-dalek` dependency disables its own defaults but explicitly enables `zeroize`; vodozemac's `default-features = false` does not remove that feature.

**RNG and failure behavior:** Tagged source follows `Sas::new()` → `rand::rng()` → `ThreadRng` → `SysRng` → `rand_core`/`getrandom` → OS entropy → `EphemeralSecret::random_from_rng`. The candidate assumes the exact P4-locked Rand/getrandom path obtains cryptographically secure randomness from each supported OS; vodozemac does not implement an entropy source. `Sas::new()` returns `Sas`, not a `Result`; ThreadRng may panic on system seeding/reseeding failure. No success may follow failed entropy generation; depending on runtime panic policy the failure may unwind or terminate, so integration cannot promise a graceful protocol error. ThreadRng does not reseed after `fork()`: supported Unix/Linux deployments that fork after initialization must reseed the child before SAS key generation or avoid inherited state. Request IDs remain a separate core-generated 16-byte OS-CSPRNG operation.

**X25519 and secret lifecycle:** The parser rejects peer-key lengths other than 32 bytes; vodozemac rejects non-contributory DH results. `Sas::diffie_hellman` consumes `Sas` and drops its `EphemeralSecret`; `EstablishedSas` owns the shared secret through SAS/MAC use. P4 MUST drop native SAS session state on every terminal path. The tagged manifest explicitly enables x25519-dalek's `zeroize` feature; the inspected published x25519-dalek 3.0.0 source zeroizes `EphemeralSecret` and `SharedSecret` in `Drop`. P4 must revalidate this against the actual resolved version in its lockfile.

**Guarantee boundary and limitation:** This establishes the upstream zeroization-on-drop behavior for those X25519 secret types only. Derived SAS bytes, HKDF/HMAC key and state temporaries, MAC/input buffers, and other copies are not comprehensively guaranteed to zeroize. This is not complete memory sanitization or a guarantee about swap, dumps, compiler/runtime copies, or process termination. Independent review must determine whether this boundary and the temporary-material limitation are adequate; do not add unsafe freed-memory zeroization tests.

**Supply-chain identity:** Crate `vodozemac`, version `0.11.0`, release date `2026-09-11`, Rust MSRV `1.89` (an integration/build requirement, not a cryptographic claim); upstream tag `0.11.0`; annotated tag object `9cdcc49ec1b213570a3a59cdeb40e8310999ea9e`; tagged source commit `db1b34820f3102307284e762f335b3f72c735bf0`; crates.io checksum `ba935af014ca0ae5fb468daa51da81a8a0df7daad23c052c878b7c690cdf2574`. GitHub reports the annotated tag signature valid. The project has not independently obtained or validated the maintainer signing key. The signed Git tag does not prove the crates.io archive is byte-identical to the tag; the checksum identifies the published archive and was verified against both crates.io index metadata and the downloaded package archive.

**Alternatives considered:** Remain on 0.10.0; track latest/main; use a git dependency; or enable a broader/default feature set. The exact release is required for reproducibility; floating or git-source choices weaken release identity; the omitted features are not needed for this candidate.

**Does not establish:** Production approval, selection of this protocol, complete memory sanitization, security of the generic sas-pairing ceremony, current independent audit of vodozemac 0.11.0, or review of future dependency upgrades.

**Evidence:** [GitHub tag-signature verification record](https://api.github.com/repos/matrix-org/vodozemac/git/tags/9cdcc49ec1b213570a3a59cdeb40e8310999ea9e); [vodozemac 0.11.0 tagged SAS source](https://github.com/matrix-org/vodozemac/blob/db1b34820f3102307284e762f335b3f72c735bf0/src/sas.rs), [tagged manifest](https://github.com/matrix-org/vodozemac/blob/db1b34820f3102307284e762f335b3f72c735bf0/Cargo.toml), [tagged release notes](https://github.com/matrix-org/vodozemac/blob/db1b34820f3102307284e762f335b3f72c735bf0/CHANGELOG.md), [crates.io version metadata](https://crates.io/crates/vodozemac/0.11.0), [published archive](https://static.crates.io/crates/vodozemac/vodozemac-0.11.0.crate), [x25519-dalek 3.0.0 source](https://docs.rs/crate/x25519-dalek/3.0.0/source/src/x25519.rs), and [Rand 0.10.2 ThreadRng source](https://github.com/rust-random/rand/blob/0.10.2/src/rngs/thread.rs). The version/MSRV and manifest feature values were checked against the exact tag; the archive checksum was independently matched to the index metadata.

**Repository history:** `060e41eba81756df4b6f1da0903eb14df3a8622e` records this decision on `security/p3-vodozemac-ceremony-profile`.

**Independent-review status:** Open. Independent reviewers must accept the exact dependency, feature configuration, ThreadRng/getrandom path and target assumptions, fork integration where applicable, zeroization boundary, complete profile, and temporary-material limitations. The P4 consumer lockfile must resolve and capture the exact dependency graph; the upstream source repository's lockfile is not that graph.

### D14 — Application context and expected-peer semantics

**Status:** Candidate decision; independent external review remains mandatory.

**Decision:** The consumer deliberately selects local open/first-contact mode (`expected_peer = none`) or expected-peer mode. Expected constraints are independently sourced local exact-byte inputs over an intentional subset of `application_identity`, `key_algorithm`, and/or the asserted key. A key expectation always compares `(key_algorithm, public_key)` together; an algorithm-only expectation may constrain `key_algorithm` without asserting a key. No wire-mode bit is added. Missing, malformed, unavailable, inconsistent, or uncheckable expected data fails closed and MUST NOT downgrade to open mode. Success authenticates exact peer-supplied bootstrap bytes under the participant's independently supplied, byte-equal local `shared_context`; it does not by itself authorize or persist trust.

**Timing:** On `START`, bounded parsing and canonical bootstrap validation precede local-context equality, supplied expected-peer checks, and required algorithm/key-encoding validation; those semantic checks precede atomic responder-slot reservation, active state, ephemeral generation, and `ACCEPT`. On `ACCEPT`, frame/bootstrap/commitment-field validation and the same locally knowable checks precede SAS-attempt reservation and `INITIATOR_KEY`. A known pre-exposure mismatch yields no result, SAS display, SAS charge, trust write, or weaker fallback. Existing no-refund behavior after SAS exposure remains.

**Context and key meaning:** `shared_context` is opaque exact application-level security-domain binding, independent at each participant and separate from protocol domain separators. Empty is allowed and means no additional context separation is requested by this field. If a security decision depends on an application, environment, tenant, account, purpose, or other domain not otherwise independently bound, that distinction MUST be represented in independently supplied context. Context and bootstrap fields are not secret. `application_identity` is an opaque authenticated claim whose external meaning and mapping belong to the consumer. The algorithm identifier is authenticated exactly; supported-algorithm policy and semantic interpretation belong to consumer/core policy. The key bytes are authenticated with that exact algorithm identifier, without proof of possession.

**Narrow claim and limitations:** A successful result means that the human-approved ceremony peer supplied the exact authenticated bootstrap bytes returned in this exact ceremony under a context matching the participant's independent local input, and local authenticated completion conditions were satisfied. “Human-approved ceremony peer” means the protocol peer whose complete SAS was compared and approved, not an independently established person, account, device, or principal. Open mode learns exact supplied bytes only. Partial expected constraints establish only their exact local matches. No external identity truth, public-key possession, authorization, durable trust write, atomic bilateral persistence, or generic identity verdict is established. Preserve the exact authenticated `(key_algorithm, public_key)`; a later directory lookup MUST NOT silently substitute another key. Consumers own identity mapping, authorization, trust persistence, display-name mapping, context meaning/canonicalization, supported algorithms, and later proof-of-possession/reconnect semantics. The shared core owns exact comparisons, algorithm/key pair binding, pre-exposure timing, fail-closed outcomes, and preserving the authenticated bytes. No arbitrary callbacks, database/network lookups, or language API design are specified here.

**Attack cases and rationale:** Independent local context comparison rejects context substitution before SAS exposure. A known expected identity/key mismatch rejects before SAS exposure; without expected constraints, the result authenticates supplied bytes only. A copied third-party public key is not proof of possession. Authenticated K1 cannot become directory-returned K2 through result handling. Missing expected state cannot silently downgrade expected-peer pairing to open mode.

**Alternatives considered:** Post-success-only validation was rejected because a known mismatch must fail before SAS exposure. An expected-peer wire bit was rejected because mode is a local consumer decision. Always requiring an expected peer was rejected because deliberate first-contact bootstrap is supported. A universal/default context and mandatory nonempty context were rejected because empty can intentionally mean no additional separation and only the application knows relevant domains. Automatically deriving context from application identity was rejected because it neither independently binds other security domains nor supplies consumer-defined canonicalization.

**Repository history:** `2cc6ef3df867ae36a5d92f1bdea76b9e3c0dc7d6` records this decision on `security/p3-vodozemac-ceremony-profile`.

**Vector/test implications:** Future conformance/state-machine coverage includes open success; expected identity and algorithm/key matches; each mismatch; partial expectations; responder mismatch before slot allocation; initiator mismatch before SAS-attempt reservation; no display/charge/result on pre-boundary mismatch; no expected-to-open downgrade; intentional empty context and independent-context mismatch; rejection of peer-copied context as local input; and preservation of authenticated K1 against lookup K2. No vectors or production tests are generated here.

**Independent-review status:** Candidate semantics are now defined; they are not externally reviewed or approved. Independent review must assess their fit with the complete candidate and confirm the pre-exposure ordering. Candidate B remains the SELECTED P2 construction; this vodozemac profile remains CANDIDATE — NOT SELECTED.

### D15 — Remote admission, timeout, and exhaustion-resistance policy

**Status:** Candidate decision; independent review remains required.

**Decision:** A Responder integration MUST provide an independently locally controlled remote-pairing admission policy. Reference/general interactive integrations SHOULD default to disabled and enable only after deliberate local action. Consumers MAY deliberately choose continuous enablement; it is permitted, remains subject to all counters, and accepts greater remote-exhaustion availability risk without violating the candidate's SAS bound by itself. A disabled gate rejects new `START`s before semantic/cryptographic work and is rechecked atomically at the responder SAS-exposure boundary. Closing or expiring the local admission window aborts active Responder runs and never resumes them. Neither admission changes nor the window reset/refund the durable SAS epoch.

Use a non-extendable five-minute absolute ceremony deadline and a 60-second machine/protocol inactivity deadline. The absolute timer starts at Initiator local-state creation or, for Responder, when a valid bounded `START` passes local admission and enters active state. The inactivity timer covers machine/protocol waits, pauses while the complete SAS awaits deliberate human action, refreshes only on valid expected state progress, and is never refreshed by duplicates, junk, keepalives, or UI activity. Both use monotonic elapsed time; resume after suspension rechecks deadlines conservatively, and process restart aborts active ceremonies while durable SAS accounting survives.

Every Responder deployment MUST have two distinct finite global controls across the applicable local security-core/endpoint scope: a START/resource-admission limiter and an SAS-opportunity release limiter at or immediately before the charged key release. Numeric rates are deployment-selected, not universal. Per-IP, identity, request-ID, connection, or other rotatable labels cannot be the sole global control. Worker/process instances serving the same endpoint coordinate whichever global state they claim. START-limiter persistence is not required for the aggregate SAS bound; a time-to-exhaustion claim requires enough coordinated/persistent limiter state to prevent restart or worker bypass. The eight-slot cap controls concurrency, the START limiter controls serial admission work, the SAS limiter slows irreversible budget consumption, and the durable `N = 5,497` counter caps total charged opportunities.

An unauthenticated remote attacker may repeat `START → ACCEPT → valid attacker I_pub → charge opportunity → RESPONDER_KEY / R_pub → abort`. It need not display, compare, approve, or complete. Consuming all 5,497 opportunities is a persistent availability attack: the endpoint fails closed and remote SAS pairing remains unavailable until separately locally authorized epoch reset. This availability attack is not by itself an authentication-probability violation and does not enlarge the aggregate `10^-8` random-match bound. Pairing enablement, successful ceremonies, restart, time windows, timeout, and rate control never reset or refund attempts.

**Rationale:** Local admission preserves deliberate local intent and prevents a network-only attacker from creating a Responder SAS opportunity while disabled. Its exposure-boundary recheck closes the race between local disablement and key release. Separate timeouts bound stale and stalled state while leaving deliberate human comparison enough time under a finite absolute deadline. Global START control addresses serial unauthenticated work; the separate SAS-release control slows irreversible use of a persistent finite budget. Neither rate control substitutes for the eight concurrent slots or durable SAS accounting. Keeping budget exhaustion distinct from authentication failure preserves the stated statistical claim while documenting the persistent availability consequence.

**Alternatives considered:** Permanently open admission; a local gate without an atomic exposure-boundary recheck; a per-request network-triggered approval prompt; a cryptographic pre-admission token/cookie; a fixed universal numeric rate; timeout-only protection; and rate-limiting-only protection. Permanently open increases remote-exhaustion risk; a local-only first check leaves a stale-state race; per-request prompts permit unauthenticated prompt fatigue; tokens/cookies introduce a separate cryptographic protocol and do not replace local intent or resource limits; universal rates do not fit varied deployments; and timeouts or rate limits alone do not provide the other control's property.

**Evidence / precedent:** Profile §§11.1.1–11.3 and 12. The current [Matrix Rust SDK SAS state source](https://matrix-org.github.io/matrix-rust-sdk/src/matrix_sdk_crypto/verification/sas/sas_state.rs.html) defines `MAX_AGE = 60 * 5 seconds` and `MAX_EVENT_TIMEOUT = 60 seconds`. This is supporting engineering precedent only; it does not prove the numbers universally optimal or prove this generic candidate's policy. Illustrative rate arithmetic (not limits or defaults): 5,497 charged opportunities at one per second take about 1 hour 32 minutes; at 10 per minute, about 9 hours 10 minutes; at 60 per hour, about 3 days 19 hours 37 minutes. These examples show why a finite total budget does not make rate control unnecessary.

**Security boundary:** Exhaustion affects availability; the total durable counter continues to enforce the candidate's aggregate SAS bound. Admission enablement does not reset the epoch, and charged attempts are not refunded. No new wire bit, error, or message is added. `expected_peer = none` remains D14 open peer identity mode, not open network admission; matching expected-peer bytes do not authenticate admission or prove long-term-key possession.

**Future vector/test implications:** Cover disabled/default admission, explicit enablement, continuous-enabled operation, no network enablement, disabled `START` before slot/key/`ACCEPT`, closure and window expiry aborting active Responder runs, closure/exposure races and charged/no-charge outcomes, no epoch reset/refund on admission changes, timeout boundaries and terminal cleanup, human approval timer exclusion, valid-progress-only inactivity refresh, both global limiter scopes and bypass rotation, worker coordination, restart abort with durable-budget preservation, and fail-closed exhaustion. No vectors or implementation tests are produced by this decision.

**Open gates:** Exact numeric START/SAS rates; cross-process/storage implementation; platform clock and suspend behavior; rate-state persistence needed for claimed time-to-exhaustion; independent review of admission/timeout policy; same-device profile; deterministic vectors; and final P3 consistency/adversarial review. P3 remains in progress.

**Repository history:** `c6a367af99f5c9029151d6549401d60186c0f699` records this decision on `security/p3-vodozemac-ceremony-profile`.

**Independent-review status:** These are candidate decisions, not external review or approval. Candidate B remains the SELECTED P2 construction with its concrete production instantiation gated. The vodozemac ceremony remains CANDIDATE — NOT SELECTED; no production protocol is approved and independent external review remains mandatory.

## Current unresolved P3 gates

These gates are based on the current candidate profile, P3 roadmap, and supporting assessments. They are not resolved by recording the decisions above.

- Request-ID generation, active-local collision handling, and routing policy are defined as candidate decisions (profile §4, D12); they are not an undecided candidate-design gate, but remain subject to independent review as part of the complete profile. Incoming peer-selected IDs remain attacker-controlled within the 1–64-byte syntax.
- Exact vodozemac release, candidate feature selection, known RNG path, X25519 contributory behavior, and basic long-lived secret lifecycle are now specified as candidate decisions (profile §5, D13); they remain subject to independent review. Still open are independent acceptance of ThreadRng/getrandom and entropy adequacy, the actual P4 resolved dependency versions, supported target-platform RNG assumptions, Linux fork integration where applicable, and adequacy of temporary-material zeroization.
- Application-context and expected-peer semantics are now defined as candidate local inputs, exact comparisons, and pre-exposure checks (profile §§4, 8, 10); their fit and enforcement still require independent review.
- Local remote-admission semantics, the five-minute absolute timeout, 60-second inactivity timeout, global START limiter requirement, and global SAS-exposure limiter requirement are defined as candidate decisions (profile §11.1.1–§11.3, D15) and remain subject to independent review.
- Exact numeric rates, cross-process/storage implementation, clock/suspend behavior, rate-state persistence needed for time-to-exhaustion claims, and multi-process coordination of admission, eight slots, both limiters, and the durable counter remain open (profile §§11.1.1–11.3, D15).
- The separate same-device profile remains P3 work (P3 roadmap); it is not defined by this vodozemac candidate.
- Deterministic vector values and conformance vectors remain deferred (profile §12).
- Independent audit of the complete candidate remains open; internal research is not independent external security review.
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

Each record cites the commit that introduced or materially clarified its decision. Where a decision spans related changes, the record lists both rather than assigning a single commit artificially. The branch also updates the vodozemac candidate decision log and P3 roadmap status; it preserves review boundaries without copying prior review reports or treating commit subjects as evidence.
