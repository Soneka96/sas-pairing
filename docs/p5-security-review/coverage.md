# P5 Review Coverage

Status of the P5.1 first broad pass over the frozen P4 core (`e21ff0b`), as deepened by P5.2 ([adversarial sequences](adversarial-sequences.md)) and P5.3 ([dependency, unsafe, and secret-lifetime deep review](dependency-unsafe-deep-review.md)).

- **COMPLETE:** the surface was reviewed end to end against production source with the stated method, and no first-pass work on it is outstanding. Deeper techniques may still be worthwhile; see "Open questions".
- **PARTIAL:** reviewed, but part of the surface was covered by reasoning over representative cases, or relies on unexamined upstream code.
- **NOT-STARTED:** not reviewed.

Methods: **S** = specification-to-code tracing, **A** = adversarial reasoning against the [attacker models](review-method.md#4-attacker-and-fault-models), **T** = derived table, **R** = executed reproducer, **D** = dependency source inspection, **X** = tooling (Clippy review lints, advisory query), **G** = generated deterministic sequences or forced interleavings (P5.2), **P** = locked-source provenance and reachability analysis of upstream crates (P5.3).

Test references are P4 test names (`module::name` = `core/src/module.rs` tests; `it::` = `core/tests/security_core.rs`), consulted as evidence only.

| # | Surface | Status | Method | P3 sections | Source | Tests consulted | Findings | Open questions |
|---|---|---|---|---|---|---|---|---|
| 1 | Authority ownership (Windows lock) | COMPLETE | S A T | §11.1.2; decision 0003 | `lib.rs` `os_lock`, `register` | `it::process_ownership_and_full_reservation_lifecycle`, `it::simultaneous_independent_processes_have_one_owner_and_safe_replacement`, `windows_tests::*` | F-003, F-004, F-008 | Cross-session automation needs a self-hosted runner ([ownership §8](ownership-and-ffi.md#8-r-owner-012-manual-cross-session-evidence)) |
| 2 | Exposure and accounting (guard + 10) | COMPLETE | S A T | §11.1, §11.1.3 | `lib.rs` `reserve`; `ceremony.rs` `expose_key` | `it::shared_guard_race_has_one_winner`, `host::the_eleventh_exposure_is_refused_as_exhaustion_without_a_contribution`, `ceremony::an_ephemeral_generation_panic_exposes_nothing_and_refunds_nothing` | F-003, F-013 (FP) | — |
| 3 | Local authorization | COMPLETE | S A | §11.1.3 | `lib.rs` `authorize`/`reserve`; `host.rs` | compile-fail doctest, `host::exposure_authorization_is_ceremony_specific_and_exposes_nothing` | — | How consent is obtained is P7/P10 ([boundaries](assumptions-and-boundaries.md)) |
| 4 | Request IDs | COMPLETE | S A | §4 | `request_id.rs`, `lib.rs` `reserve_request_id`, `router.rs` | `request_id::*`, `router::the_same_request_id_on_another_session_is_an_independent_run` | F-017 (FP) | — |
| 5 | START limiter | COMPLETE | S A T | §11.1.1 limiter | `start_limiter.rs`, `lib.rs` `admit_start` | `start_limiter::*`, `ceremony::simultaneous_candidates_admit_exactly_four` | F-012 (AL), F-021 (FP) | — |
| 6 | Pre-exposure resource controls | COMPLETE | S A T | §11.1.1 | `lib.rs`, `transport.rs`, `ceremony.rs` | `ceremony::four_pending_responders_hold_slots_but_no_guard_or_opportunity`, `transport::*` | F-002, F-012 (AL), F-020 (FP) | — |
| 7 | Canonical parsing and framing | COMPLETE | S A | §3.1, §4 | `protocol.rs` | `protocol::every_structural_mutation_class_is_rejected_for_every_wire_type`, `transport::every_split_point_of_every_wire_type_reconstructs_the_original` | F-015 (FP) | Property or fuzz testing not performed (recommended) |
| 8 | Commitment | COMPLETE | S A | §5 | `crypto.rs`, `ceremony.rs` | `ceremony::a_start_changed_in_transit_fails_the_commitment_with_no_sas_and_no_refund` | — | — |
| 9 | Ephemeral key generation | COMPLETE | S D R P | §5 | `crypto.rs`; vodozemac `Sas::new`; rand `ThreadRng` (ChaCha12, 64 KiB reseed); getrandom `ProcessPrng` | `ceremony::an_ephemeral_generation_panic_exposes_nothing_and_refunds_nothing`; P5.3 F005-001..005 | F-005, F-009 (AL) | The RNG path was reviewed in locked source (P5.3). The OS entropy quality of `ProcessPrng` is trusted |
| 10 | Contributory checks | COMPLETE | S D | §5 | `crypto.rs` `establish`; vodozemac `diffie_hellman`; x25519 `was_contributory` | `crypto::rejects_bad_and_noncontributory_peer_keys` | F-014 (FP) | — |
| 11 | Transcript / `ceremony_identity` | COMPLETE | S T | §9 | `crypto.rs` | `crypto::deterministic_encoding_matches_authoritative_vector` | — | — |
| 12 | SAS derivation and presentation | COMPLETE | S D T | §7, §10 I2 | `crypto.rs`, `ceremony.rs`; vodozemac `bytes`/`decimals` | `crypto::every_sas_context_field_is_bound_into_the_live_sas`, `ceremony::complete_sas_is_presented_only_after_transcript_identity_is_fixed` | — | UI rendering is external |
| 13 | Approval MAC | COMPLETE | S A T | §8 | `crypto.rs`, `ceremony.rs` | `ceremony::peer_mac_binds_identity_sas_sender_bootstrap_roles_and_purpose` | F-022 (FP) | — |
| 14 | Completion MACs | COMPLETE | S A T | §9 | same | `ceremony::finish_macs_bind_type_purpose_direction_and_identity` | F-007 | — |
| 15 | Authenticated CANCEL | COMPLETE | S A T | §11.3 | same | `ceremony::cancel_mac_binds_frozen_types_purpose_roles_identity_and_reason`, `ceremony::cancel_before_sas_establishment_is_invalid_input_without_mac_work` | F-022 (FP) | — |
| 16 | State machine | COMPLETE (P5.2) | S A T G | §6, §10, §11.3 | `ceremony.rs` | `ceremony::*`; P5.2 SM-I/SM-R (835 CI + 35,684 deep sequences), DUP-001, DEADLINE-001..004 | F-007 | Bounded: honest prefixes × suffix ≤ 3 over a 25-action alphabet, both roles, every invariant held. No exhaustive model of unbounded sequences |
| 17 | Duplicate semantics | COMPLETE | S T G | §6, §11.2 | `ceremony.rs` `duplicate`; `router.rs` `classify_start` | `ceremony::exact_duplicate_is_idempotent_and_changed_duplicate_is_terminal`, `router::exact_duplicate_starts_are_ignored_without_charge_output_or_new_state`; P5.2 DUP-001 (55 cells), ROUTER-RACE-004 | — | — |
| 18 | Timeout and deadline semantics | COMPLETE | S A T G | §11.3, §11.1.1 | `deadline.rs`, `ceremony.rs`, `transport.rs` | `deadline::*`, `ceremony::large_monotonic_jumps_never_extend_a_ceremony`; P5.2 DEADLINE-001..004, TCP-DEADLINE-001, F007, LOOP-DEADLINE-001 | F-002, F-007, F-011 (AL) | — |
| 19 | Router and session isolation | COMPLETE (P5.2) | S A G | §4, §11.2 | `router.rs` | `router::closing_during_*`, `host::a_local_action_and_a_session_close_linearize_at_the_session_lease`; P5.2 ROUTER-RACE-001..009 | F-005, F-017 (FP) | Every linearization point forced in both orders, repeated (25–100 iterations), plus barrier races. No loom-style exhaustive interleaving |
| 20 | Transport framing and resource controls | COMPLETE | S A R G | §11.1.1 | `transport.rs` | `transport::*`; P5.2 TCP-STREAM-001..003, TCP-RD-001/002 | F-002 | — |
| 21 | Host facade | COMPLETE | S | §11.2 | `host.rs` | `host::*` | — | — |
| 22 | Local callback targeting | COMPLETE | S A | §7, §10 | `router.rs` `with_exact_run`; `ceremony.rs` `live_session` | `host::a_stale_run_ref_or_identity_never_reaches_a_replacement_under_a_reused_request_id` | F-017 (FP) | — |
| 23 | Send-confirmation boundary | COMPLETE | S A | §9 | `host.rs` `FinalAck`; `windows_tcp.rs` `confirm` | `host::an_unconfirmed_final_ack_never_becomes_success`, `windows_tcp::a_scripted_ceremony_confirms_the_final_ack_only_after_its_last_byte_is_written` | F-007, F-019 (FP) | — |
| 24 | Windows TCP adapter | COMPLETE | S A T R G | §3.1, §9, §11.1.1 | `windows_tcp.rs` | `windows_tcp::*`; P5.2 TCP-W-001/002, F007, F002-001, TCP-OUT-001 | F-001, F-002, F-007 | — |
| 25 | Owner-loop readiness and fairness | COMPLETE | S A R G | §11.1.1 | `windows_owner_loop.rs` | `windows_owner_loop::*`; P5.2 LOOP-READY-001, LOOP-DEADLINE-001, LOOP-HUP-001..003, F001-001 | F-001, F-002 | Real-socket facts from one Windows build and CI |
| 26 | Shutdown and teardown | COMPLETE | S A | §11.1.2(5), §11.2 | `router.rs` `teardown`; `transport.rs`; `windows_tcp.rs`; `windows_owner_loop.rs` `shut_all` | `router::uncertain_session_teardown_fails_closed_and_never_reopens` | F-005 | — |
| 27 | Uncertain ownership cleanup | COMPLETE | S A T | §11.1.2(4–5) | `lib.rs`, `router.rs`, `transport.rs` | `windows_tests::poisoned_shared_state_fails_closed`, `ceremony::sas_is_invalidated_even_when_guard_release_is_uncertain` | — | — |
| 28 | Unsafe Rust / Win32 FFI | COMPLETE | S A T X D P R | §11.1.2 | `lib.rs` `os_lock`; `windows_owner_loop.rs` `wsa_poll`; reachable upstream `unsafe` | `windows_tests::token_user_parsing_does_not_assume_buffer_alignment`; P5.3 `p5_f_004_token_user_sid_lies_inside_the_returned_buffer_on_this_windows` | F-004 (AL, P5.3) | 16 production sites re-enumerated; reachable upstream `unsafe` audited in P5.3 ([deep review §4–§5](dependency-unsafe-deep-review.md#4-reachable-upstream-unsafe)) |
| 29 | Allocation and integer safety | COMPLETE | S X | §3.1 | all | `protocol::exact_resource_boundaries_and_untrusted_lengths` | F-020 (FP) | — |
| 30 | Panic and abort surfaces | COMPLETE | S X | §5 | all | as above | F-005 | — |
| 31 | Secret lifetime and zeroization | COMPLETE | S D T P | §5 | `crypto.rs`, `ceremony.rs`; x25519-dalek `Drop`; rand `BlockRng`; hkdf/hmac/sha2 features | `ceremony::generic_termination_failure_and_drop_invalidate_sas`; P5.3 SECRET-TYPE-001 | F-010 (AL, strengthened in P5.3) | — |
| 32 | Side channels | COMPLETE (P5.3) | S D T P | — | `crypto.rs`, `ceremony.rs`; digest `verify_slice` → `ctutils` → `cmov` asm; curve25519 ladder and `subtle` | — | F-016 (FP) | Complete for the remote threat scope: every comparison classified, every secret path traced to its constant-time primitive ([deep review §9](dependency-unsafe-deep-review.md#9-side-channels-32)). Not measured and not formally proven; local hardware side channels out of scope |
| 33 | Dependency assumptions | COMPLETE (P5.3) | D X P R | §5 (pins) | `Cargo.toml`, `Cargo.lock`; 96 locked crates | P5.3 B64-REF-001/002, B64-ENGINE-001/002 | F-006 (FP, P5.3) | Graph rebuilt with `--locked`; 96/96 checksums verified; reachability, features, duplicates, pin, bypass, and advisories reviewed ([deep review §1–§3, §12–§13](dependency-unsafe-deep-review.md#12-dependencies-33)). Upstream correctness beyond inspected paths is trusted |
| 34 | External integration assumptions | COMPLETE | S | §8, §11.1.2 | — | — | — | Recorded in [assumptions and boundaries](assumptions-and-boundaries.md) |

## Additional review items

| Item | Status | Result |
|---|---|---|
| Attacker models (12, see method §4) | COMPLETE | Each applied to the surfaces above. Unsupported environments were only checked against claims |
| P4 partials `R-MAC-001`, `R-MAC-015` | COMPLETE | Evidence limitation only ([protocol composition §9](protocol-composition.md#9-r-mac-001-and-r-mac-015-partials)) |
| P4 manual evidence `R-OWNER-012` (cross-session) | COMPLETE | Retained as manual; automation on hosted CI is not meaningful ([ownership §8](ownership-and-ffi.md#8-r-owner-012-manual-cross-session-evidence)) |
| Security-claim language in docs | COMPLETE | No claim materially exceeds the evidence ([findings](findings.md#other-disproved-hypotheses-not-filed)) |
| Static analysis | COMPLETE | fmt and Clippy pass on both targets; review lints triaged ([secrets §7](secrets-panics-dependencies.md#7-static-analysis)) |
| Advisory scan | COMPLETE | OSV, 96 crates, no advisories (2026-10-02T09:01Z, P5.1; repeated 2026-10-02T15:23Z, P5.3) |

## Recommended review harnesses (from P5.1; status after P5.2)

| Harness | Reason | Target | Expected value | P5.2 status |
|---|---|---|---|---|
| Generated message/action sequences against `RemoteCeremony` (both roles, every state, exact or changed duplicates, reorders, local actions, deadline advances) | Surface 16 was PARTIAL in P5.1. The hand-derived table may miss cross-state interactions | `ceremony.rs` | High: checks I1/I2, no second output, and no result before its conditions, for every sequence up to a bounded length | Done: SM-I/SM-R, DUP-001 |
| Parser property tests (arbitrary bytes, mutated canonical frames, decode/encode round trip, `wire_frame_extent` agreement with `decode`) | Surface 7 was reviewed manually only | `protocol.rs`, `transport.rs` | Medium: the codec is small and well tested, so this mostly guards regressions | Not done (codec only; stays a recommendation) |
| Transport fragmentation model (random chunking, concatenation, EOF and hang-up placement) | F-001 shows adapter-level stream semantics were under-tested | `transport.rs`, `windows_tcp.rs`, owner loop | High for the adapter | Done (deterministic, not random): TCP-STREAM, TCP-RD, LOOP-HUP |
| Router concurrency stress (threads racing START, deliver, local actions, close, deadline polls) | Surface 19 was PARTIAL in P5.1 | `router.rs` | Medium | Done: ROUTER-RACE-001..009 |
| Deadline boundary generation (± 1 ns around every deadline, for every state and clock fault) | Exact-boundary behavior is safety-relevant (F-007) | `deadline.rs`, `ceremony.rs`, `windows_tcp.rs` | Medium | Done: DEADLINE-001..004, TCP-DEADLINE-001, F007 |
| Reference Base64url comparison across all lengths up to the cap | F-006 | `crypto.rs` | Low to medium | Done in P5.3: B64-REF-001 (CI) and B64-REF-002 (every length 0..=65,536, manual) |

No fuzzing framework or new dependency was introduced in P5.1, P5.2, or P5.3. After P5.2, side channels (#32) and dependency assumptions (#33) were `PARTIAL`. P5.3 completed both for the current threat scope. **No surface is `PARTIAL` after P5.3.** Recommendations that remain open (parser property or fuzz testing; loom-style exhaustive interleaving; a self-hosted cross-session runner) are optional deeper techniques, not gaps in planned coverage.
