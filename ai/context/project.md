# sas-pairing current manager context

**Current status (2026-10-04):** **P4 experimental native Rust security core COMPLETE. P5 implementation + protocol security review COMPLETE (P5.1 broad pass, P5.1.1 classification correction, P5.2 generated sequences, P5.3 dependency/unsafe deep review, P5.4 final synthesis; [final synthesis](../../docs/p5-security-review/final-synthesis.md)). P6 review remediation + protocol freeze COMPLETE — PROTOCOL CANDIDATE FROZEN (P6.1–P6.3 remediated P5-F-002, P5-F-001, P5-F-003; P6.4 + P6.4.1 and P6.5 dispositioned P5-F-005 and P5-F-007; P6.6 froze the experimental remote candidate `sas-pairing-vodozemac-profile-draft-01`, version 1, for P7; [final closure](../../docs/p6-remediation/final-closure.md)). P7 — Native ABI COMPLETE — NATIVE ABI V1 FROZEN (P7.1–P7.6 under owner decisions P7-D-001 to P7-D-012; P7.7 final hardening + ABI v1 freeze under P7-D-013, with a two-sided public-ABI ceremony proven and the P6-D-004 ABI panic containment evidence complete; [P7 final closure](../../docs/p7-native-abi/final-closure.md)). P8 — Dart Package IN PROGRESS — P8.1 COMPLETE (Dart package foundation + frozen native ABI v1 bindings on the one branch `feature/p8-dart-package`; owner decision P8-D-001; [P8 package](../../docs/p8-dart-package/README.md)); P8.2 COMPLETE (Runtime / Authority / Host lifecycle wrapper; owner decision P8-D-002, corrected by P8.2.1: public `SasPairingInitializationException` for native-library initialization failures, `READY` valid only with 1–10 remaining). P8.3 COMPLETE (Windows listener ownership + cooperative network driver; owner decision P8-D-003: Bootstrap value, listening-socket transfer token through the native in/out slot, attach / detach, one bounded drive or resume recheck per call with every event delivered also when `out_failure` is set, connection wrappers, `RUN_UNTRACKED` close guidance, private run and result references). P8.4 COMPLETE (run + ceremony control + SAS presentation; owner decision P8-D-004: a public `SasPairingRun` per exact native run handle, never a request ID; the local Initiator start with its request ID learned from a later event; the explicit trusted-local steps, one native call each with no chaining; `WRITE_PENDING` status (did not run) versus action flag (ran, output retained); SAS presentation as display data with decisions bound to the presented 32-byte ceremony identity; no final-ACK API; a real two-endpoint Windows ceremony through the public Dart API). P8.5 COMPLETE (PairingResult API + result ownership; owner decision P8-D-005: a public `SasPairingResult` per native result handle, owned by the runtime and surviving connection close, detach, owner-loop failure, host and authority close, and native FATAL; delivered by drive events without reading; an explicit synchronous `read()` into an immutable `SasPairingResultData` (the PEER role, exact bytes, the reused `SasPairingCeremonyIdentity`) with exact-length copies and info/copy contradictions as contract violations; reads allowed after native FATAL but refused after a contract violation; explicit idempotent destroy and the runtime cascade; never-reused handles; local verified completion only, no trust automation). P8.6 (native artifact distribution + P8 closure) is next. No production-security approval, formal verification, or professional audit.** Owner decision [0002](../../docs/decisions/0002-experimental-vodozemac-selection.md) selects the corrected vodozemac remote profile and owner policy for experimental implementation, pinned to vodozemac 0.11.0; the P4 core implements it and its current normative conformance cases are closed. The qualified-human-review gate was waived for experimental development, not completed; no professional audit or formal verification is claimed. F-02 is a false positive under the stated idealized assumptions: an attacker need not remain ignorant of its own DH shared secret after an honest public contribution is revealed; target SAS must be unpredictable before the attacker fixes its contribution. The complete per-pair argument remains conditional. Pair counting remains `n_A + n_B - 1`; 19 applies only to a joint 10/10 window within both process sessions, not arbitrary restarts. CR-01 retains residual assumptions and implementation verification limits. Older multi-ceremony/eight-slot/`5,497`-epoch material is historical and non-normative.

## Project purpose

Language-neutral human-authenticated pairing for exchanging bootstrap data. The core should remain reusable and application-neutral; DovahLink is the original consumer, not the architectural owner. Consumer trust and authorization stay with consuming applications.

## Current repository phase

**PRE-ALPHA. P3 REMOTE EXPERIMENTAL SPECIFICATION FINALIZED; P4 COMPLETE — EXPERIMENTAL NATIVE SECURITY CORE; P5 SECURITY REVIEW COMPLETE; P6 COMPLETE — EXPERIMENTAL PROTOCOL CANDIDATE FROZEN; P7 COMPLETE — NATIVE ABI V1 FROZEN; P8 IN PROGRESS — P8.5 COMPLETE, P8.6 NEXT.** The crate-private Rust core in `core/` implements, for the selected remote profile:

- OS-backed Windows authority ownership (account-scoped, decision 0003), failing closed on uncertainty; other platforms fail closed;
- one exposed-ceremony guard, the volatile 10-opportunity budget, and ceremony-specific local authorization;
- the complete selected remote ceremony through SAS presentation and local MATCH/REJECT/CANCEL;
- `BOOTSTRAP_MAC` approval authentication, the three-message authenticated completion handshake, and authenticated post-SAS `CANCEL`;
- ceremony absolute/inactivity deadlines and the P3 resource controls, including the authority-wide START limiter;
- session-bound routing, the transport model, and Host local actions;
- an experimental Windows connected-TCP adapter and a bounded `WSAPoll` owner loop over an already-bound listener.

Details are in the [P4 roadmap](../../roadmap/P4-native-security-core.md). [P4 conformance closure](../../docs/p4-conformance-closure.md) maps the 92 current normative P4 rows (39 `R-OWNER`, 26 `R-WIRE`, 23 `R-MAC`, 4 applicable `R-RESOURCE-006`–`009` timeout rows) with no remaining P4-core gap; `R-MAC-001` and `R-MAC-015` are PARTIAL (fixed-secret fixture values cannot be recomputed through the pinned vodozemac API), the cross-session part of `R-OWNER-012` is PASS — MANUAL (owner-run, 2026-09-30, not CI), and fork, VM snapshot, restored, and duplicated-state environments are documented limitations. There is no public native API/ABI, SDK, or consumer integration, and no deployment networking policy. Production use and release are not approved. The separate same-device profile and platform adapters remain candidate-only.

## P1 result contract

P1 accepts mutual authentication of exact role-positioned bootstrap bytes and selected security-relevant context for one ceremony; a reusable pairing key is not required. Authenticated public-key bytes mean only that the peer supplied them. They do not establish external identity truth or proof of possession. If both participants return success, results must be compatible; local success may be asymmetric after final acknowledgement loss.

## P2 remote-construction state

P2 originally selected Candidate B as the abstract remote construction. P3 research exposed substantial custom design and maintenance responsibilities for its concrete instantiation. The owner reopened selection for that ownership reason, not because Candidate B was shown insecure; it remains a formal reference and possible fallback. The owner has selected the existing vodozemac-based remote candidate for experimental implementation. It does not inherit Matrix's protocol security argument or establish production security.

## Candidate B

Candidate B is Beskorovajnov–Müller-Quade mutual `π_SAS^×`: historically selected at P2 and the strongest formal reference. Its abstract result fits the authenticated-bootstrap contract, without requiring a reusable pairing key. Concrete instantiation remains unsupported on current evidence: the paper leaves the commitment formula/opening representation and byte encoding unspecified and uses a random-oracle SAS. The P3 `STOP concrete cryptographic selection` records the project's evidence and ownership boundary; it does not mean Candidate B was cryptographically disproven. Do not map Candidate B to SHA-256 or infer theorem preservation from a salted hash.

## Vodozemac candidate

The selected experimental baseline pins vodozemac 0.11.0 and specifies X25519, a SHA-256 responder commitment, canonical framing, transcript identity, Matrix decimal SAS, bootstrap/completion MACs, context, and lifecycle. Its argument assumes SHA-256 collision resistance for commitment binding; random-oracle-style SHA-256 commitment hiding and relevant HKDF-SHA256 behavior; fresh unpredictable non-reused ephemeral keys; accepted contributory X25519 inputs; correct exposure ordering; and atomic ownership/guard enforcement. Ordinary HKDF PRF security alone is not claimed sufficient where an attacker knows its leg's derived secret. F-02 is rejected under the stated idealized assumptions; the complete construction remains conditional and unverified. Neither SHA-256 nor HKDF-SHA256 is proven to behave as a random oracle. The proposed result remains `P_per_pair ≤ 2^-39 + δ` and, only for a joint 10/10 window within both process sessions, `P_joint ≤ 19 × 2^-39 + ε`, with unsupported terms symbolic. This is not an arbitrary-restart, lifetime, or human-error bound. Earlier AI review's **PREVIOUS PROOF NOT ESTABLISHED** verdict applies to the earlier argument; no professional audit or formal verification is claimed.

## Current construction status

- Candidate B: historically selected at P2; remains a formal reference and possible fallback, not the current implementation direction. Its concrete instantiation remains unsupported, and the owner judged the custom cryptographic ownership too high for this project.
- Vodozemac: selected for experimental implementation and implemented in the P4 experimental native core; no production-security or release approval.
- Candidate B: historical P2 formal selection and reference/fallback; not shown insecure.

## P3 work completed

- Remote vodozemac candidate profile and D-series decision record, including transcript identity, context/expected-peer semantics, attempt model, resource model, and timeout/admission rules.
- Separate authenticated-local candidate profile, decisions, deterministic vector, and conformance cases.
- Windows principal-bound named-pipe adapter candidate research.
- Remote and local deterministic fixture sets and a conformance matrix; its current normative P4 scope is the 92 rows above, and its other rows are historical or candidate-only.

These artifacts remain useful candidate work; vectors demonstrate byte/derivation reproducibility, not security proof.

## Authenticated-local profile

**CANDIDATE — NOT PRODUCTION APPROVED.** It is separate from either remote construction. It defines mutual endpoint authentication, consumer authorization, remote exclusion, exact connection binding, fresh Initiator/Responder nonces, transcript identity, one-ceremony-per-connection, one ceremony-specific Host decision at a time with no queue, and local admission that network input cannot enable. It sets four global active slots, 60-second machine inactivity, a 2-minute Host decision deadline, a 5-minute absolute deadline, and mandatory finite global operational rate controls. Local attempts do not consume remote SAS accounting. Zero platform adapters are approved.

## Windows adapter

**Windows principal-bound named-pipe adapter — CANDIDATE — NOT APPROVED.** It authenticates a configured Windows principal/logon-session boundary only. It does not authenticate an executable, signer, binary hash, or human. Its draft specifies `LOCAL\\` scope, `PIPE_REJECT_REMOTE_CLIENTS`, explicit owner/DACL, mutual endpoint authentication, same-user plus logon-session authorization, `SECURITY_IDENTIFICATION`, `FILE_FLAG_FIRST_PIPE_INSTANCE`, and non-inheritable handles. Zero production-approved local adapters remain.

## Deterministic vectors

Two fixture sets exist: remote vodozemac and authenticated-local. They demonstrate deterministic bytes and derivations only. The remote fixture covers commitment, transcript identity, SAS, bootstrap MACs, and completion MACs; the local fixture covers START, ACCEPT, transcript identity, APPROVE, REJECT, ACK, and outer record framing. The conformance matrix rows are documentation; the executable evidence for the 92 current normative rows is indexed in [P4 conformance closure](../../docs/p4-conformance-closure.md).

## Current phase boundary

The remote experimental selection, baseline acceptance, the P4 experimental native core, the internal P5 review, and P6 remediation with the experimental protocol-candidate freeze are complete. This does not complete the separate local-profile/adapter work, formally verify the argument, remove the accepted limitations, or meet production-readiness gates.

## P5 final result (frozen)

Internal, AI-assisted review of the frozen P4 core; not a professional audit, formal verification, or production approval. 34 / 34 planned review surfaces COMPLETE; no PARTIAL or NOT-STARTED coverage remains. No confirmed CRITICAL or HIGH finding. No finding was remediated in P5.

- **REMEDIATED-IN-P6:** P5-F-002 MEDIUM (no finite connection-level/pre-frame lifetime; 16 idle connections held the live cap), fixed in P6.1 by the P6-D-001 connection lifetime (10 s first frame, 10 s quiescent, 10 s / 2 s owner-less output; live ceremonies keep their own deadlines).
- **REMEDIATED-IN-P6:** P5-F-001 LOW (owner loop discarded readable/pending data on `POLLHUP`), fixed in P6.2 by P6-D-003: on a connection `POLLERR`/`POLLNVAL` stay hard failures, `POLLHUP` is drained toward EOF one operation per drive and does not suppress a retained frame's write; the P6-D-001 deadlines bound a half-closed peer.
- **REMEDIATED-IN-P6:** P5-F-003 LOW (same-process re-registration reset the budget and START limiter, contrary to current P3), fixed in P6.3 under P6-D-002: the registry keeps one process session per canonical authority until process exit (budget, START limiter, limiter clock); release or the final drop ends only the registration, re-registration reacquires the OS lease and continues the same accounting, and uncertain, poisoned, or held state fails closed with `OwnershipUncertain`; only a new process starts fresh.
- **DISPOSITIONED-IN-P6:** P5-F-005 INFO (entropy panic in `Sas::new()`), P6.4 under P6-D-004: the core does no panic recovery and stays fail-closed; the P7 ABI must catch every panic inside Rust at every export, poison the affected context permanently (stable fatal error, no core re-entry, destroy still allowed), never run the caught panic payload's destructor (P6.4.1: mark fatal, then suppress destruction, e.g. `mem::forget`), never reset accounting in the same process (recovery = process restart), and ship an unwind-compatible artifact; `panic = "abort"` and `extern "C-unwind"` are not the ABI policy. Mandatory P7 requirement, not a remediation.
- **DISPOSITIONED-IN-P6:** P5-F-007 INFO (reverse asymmetric completion at the Initiator's deadline boundary), P6.5 under P6-D-005: the Initiator's success stays judged at its live final-ACK send confirmation (never backdated to the last-byte instant; `>=` expiry, no grace period); either endpoint may be the only `PairingResult` holder (I-only after a lost final ACK, R-only when I's deadline is reached between its complete write and its confirmation); two results never conflict; I's following timeout CANCEL may end R's session under §11.2 after R's result and never revokes it. P3 §9/§10/§11.3 clarified; no production change.
- **OPEN:** none. All five findings P5 handed to P6 are remediated or dispositioned.
- **ACCEPTED-LIMITATION:** P5-F-004, P5-F-008 to P5-F-012.
- **FALSE-POSITIVE:** P5-F-006, P5-F-013 to P5-F-022.

Finding IDs are stable; the next free ID is P5-F-023. The P6 disposition table and order are in [final synthesis §10](../../docs/p5-security-review/final-synthesis.md#10-p6-handoff).

## P6 final result (frozen)

P6 is complete ([final closure](../../docs/p6-remediation/final-closure.md)); internal and AI-assisted, not a professional audit, formal verification, or production approval.

- **Frozen candidate:** `sas-pairing-vodozemac-profile-draft-01`, version 1 (identifier and version unchanged). Semantics = the authoritative [P3 profile](../../docs/p3-vodozemac-ceremony-profile-draft.md) as amended in place in P6 + the final owner decisions P6-D-001 to P6-D-005 ([decisions](../../docs/p6-remediation/decisions.md)). P6 changed no wire bytes, vectors, or cryptography.
- **Normative conformance:** still 92 rows (39 `R-OWNER`, 26 `R-WIRE`, 23 `R-MAC`, 4 `R-RESOURCE-006`–`009`); P6 amended rows in place and added none.
- **Production changes (all traced):** P6-D-001 connection lifetime (`1ce0753`), P6-D-003 graceful hang-up (`c4212f2`), P6-D-002 process-session accounting (`5aa1b15`). F-005 and F-007 are documentation/policy dispositions with no production change.
- **Accepted limitations remain:** P5-F-004 (SID range checks, optional hardening not done), P5-F-008 (lock-path TOCTOU), P5-F-009 (fork/snapshot/duplicated state), P5-F-010 (secret remanence), P5-F-011 (suspend behavior unverified), P5-F-012 (START/pending saturation within bounds). The per-pair argument stays conditional.

## Next action

P4 is frozen as the completed experimental native security core, P5 is complete, and P6 is complete with the protocol candidate frozen; do not re-run P5 or P6. P6 work happened on the one branch `feature/p6-review-remediation-protocol-freeze`, closed by one pull request. Owner decisions are in [docs/p6-remediation/decisions.md](../../docs/p6-remediation/decisions.md): P6-D-001 (P5-F-002 timer model and values), P6-D-002 (P5-F-003: keep current P3 semantics; implemented in P6.3), P6-D-003 (P5-F-001 graceful hang-up handling), P6-D-004 (P5-F-005 native panic containment, owned by P7), and P6-D-005 (P5-F-007 local completion and final-ACK deadline boundary). **[P7 — Native ABI](../../roadmap/P7-native-abi.md) is COMPLETE — NATIVE ABI V1 FROZEN** (P7.1–P7.7 on the one branch `feature/p7-native-abi` from `main` `5becd09`; one pull request at closure, left for the owner's independent review and never merged by an agent). The authoritative summary is the [P7 final closure](../../docs/p7-native-abi/final-closure.md); the frozen values are the [ABI v1 manifest](../../docs/p7-native-abi/abi-v1-manifest.md); the decisions are P7-D-001 to P7-D-013 ([decisions](../../docs/p7-native-abi/decisions.md)). ABI version `1`, exactly 25 `extern "C"` exports, 48 frozen statuses, six opaque never-reused `uint64_t` handle kinds, six padding-free records; one central panic boundary with a permanent process fatal state (recovery = OS process restart) and payload destructors never run; one native image resident per process (P7-D-002); runtime-owned results meaning local completion only (P6-D-005); nine explicit ceremony actions with adapter-owned frames and final-ACK confirmation; Windows TCP is the only supported networking, other platforms fail closed. P7.7 proved two independent public-ABI endpoint processes can pair through a byte-transparent relay. **P8 — Dart Package is in progress (P8.1, P8.2, P8.3, and P8.4 complete, P8.5 next, on `feature/p8-dart-package`, from `main` `80ecbb1`; P8-D-001 to P8-D-004 in [docs/p8-dart-package/decisions.md](../../docs/p8-dart-package/decisions.md))**; P8 consumes ABI v1 and must not change any P7 file; P8 and P9 must follow the wrapper handoff of P7-D-013 item 13 ([ABI contract §21](../../docs/p7-native-abi/abi-contract.md#21-wrapper-handoff-p8-p9)), including SHOULD-close after `RUN_UNTRACKED`. Do not change any frozen ABI v1 value, layout, export, or ownership rule without an owner decision on ABI version and compatibility. The P5 package ([docs/p5-security-review](../../docs/p5-security-review/README.md)) and the P6 package ([docs/p6-remediation](../../docs/p6-remediation/README.md)) stay historical evidence.

## Decisions that must not be silently changed

- Do not change the selected vodozemac target, extend its features, or relabel it as Candidate B.
- Do not invent a concrete Candidate B hash/commitment mapping.
- The P4 experimental native security core is implemented and conformance-closed; do not relabel it production-approved.
- Do not change protocol bytes or vector values, approve Windows, or mark any local adapter approved.
- The P6 freeze is an experimental protocol-candidate freeze for P7 only; do not rename the profile, bump its version, or relabel it final, production, or audited. A change to its wire, cryptography, ceremony authentication, result semantics, or accounting needs an owner decision and re-review.
- Do not claim vectors prove security or claim `2^-39` for the complete protocol as established.
- Preserve Candidate B history and vodozemac candidate work; do not reopen frozen local mechanics without evidence.

## Reusable work for future integrations

Likely reusable: generic bootstrap/result semantics, exact authenticated-key-byte preservation, context/expected-peer concepts, distinction between authentication and proof of possession, consumer-owned durable trust, the local candidate, Windows adapter research, resource-limit lessons, fail-closed state/duplicate principles, and portions of conformance organization/tooling. Construction-specific vodozemac work includes its remote X25519 ceremony, SHA-256 commitment formula, Matrix decimal SAS, bootstrap/completion MAC structures, and remote fixture.

## Production status

**PRE-ALPHA. EXPERIMENTAL NATIVE SECURITY CORE IMPLEMENTED. NO PRODUCTION-SECURITY APPROVAL. NOT PRODUCTION READY. VODOZEMAC SELECTED FOR EXPERIMENTAL IMPLEMENTATION. ZERO APPROVED SAME-DEVICE ADAPTERS. NO PROFESSIONAL AUDIT OR FORMAL VERIFICATION.**

## Standing project rules

- Specify and review protocols before implementing production behavior. Research and vectors are not security proof or architecture selection.
- Consumer-supplied identity/context values are inputs, not trusted facts; only values authenticated and checked by the selected protocol may be called authenticated.
- Protocol/security requirements own attempt constraints required by a security bound. Consumers may tighten, but not bypass them while claiming the same guarantees.
- Human comparison is part of the security system; account for partial checking, confusing glyphs, accidental approval, fatigue, accessibility, localization, and display conditions.
- Dart and .NET are intended wrappers around one core, not parallel production crypto implementations.
- Independent external review is required before production-readiness claims.
- Fail closed on ambiguous security state. Compatibility is not required before the first stable release unless explicitly approved.
