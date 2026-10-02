# P5 Reproducers

Review infrastructure only. Nothing here changes production behavior, and nothing here runs in CI unless stated.

**Frozen at P5 closure (P5.4).** The inventory below is final for P5. The four EXPECTED-FAIL reproducers (three for P5-F-001, one for P5-F-002) and the P5.1 throwaway patch stay failing and unapplied until P6 remediates; their expectations must not be changed to make them pass. The per-finding P6 action for each test is in the [final synthesis](../final-synthesis.md#reproducer-inventory-frozen).

> **P6 update (P6.1):** P5-F-002 was remediated ([record](../../p6-remediation/p5-f-002.md)). `p5_f_002_idle_connections_eventually_release_their_live_slot` now passes and runs as a normal regression test (its `#[ignore]` was removed). The patch test `p5_f_002_frameless_connections_do_not_hold_the_live_cap_forever` is superseded by permanent regressions and is not applied; its transport hunk no longer applies to P6 heads, while the patch's P5-F-001 hunk still applies to `core/src/windows_owner_loop.rs`. The three P5-F-001 reproducers still fail as recorded below until P6.2. The table and outputs below are the P5 closure record.

> **P6 update (P6.2):** P5-F-001 was remediated ([record](../../p6-remediation/p5-f-001.md)). The three P5-F-001 EXPECTED-FAIL KNOWN-BUG REPRODUCERS are now **PASSING REGRESSIONS SINCE P6.2**: their `#[ignore]` was removed and they run in CI; each doc comment records that it failed on the frozen P4/P5 code. `p5_f_001_owner_loop_dispatches_complete_frames_before_graceful_close` carries one documented qualification under decision P6-D-003: after two frames and a *full* close, the loop's first ACCEPT draws the closed peer's reset, and that hard failure (`POLLERR`) may end the connection before the second frame; the same frames before a half-close are all dispatched (`graceful_hang_up::real_two_frames_before_shutdown_send_are_each_dispatched_once`). The patch test `p5_f_001_a_complete_frame_before_a_graceful_close_is_dispatched` passes when its owner-loop hunk is applied to the P6.2 fix in a disposable worktree; it stays unapplied (it relies on a 200 ms sleep) and is superseded by `graceful_hang_up::real_complete_start_then_close_is_dispatched`. The OS-fact test `p5_f_001_wsapoll_reports_hang_up_while_written_bytes_remain_readable` stays PASSING EVIDENCE, because hang-up and readable bytes still coexist on Windows; LOOP-HUP-001..003 and F001-001 stay PASSING EVIDENCE and now record the dispatched frames, the Responder's result, and the written frame.

Every entry is exactly one of three kinds:

- **PASSING EVIDENCE TEST:** runs in CI and passes. It pins an OS fact, characterizes current behavior, or asserts only properties that must stay true after P6 too. It never asserts a known bug as desired behavior.
- **EXPECTED-FAIL KNOWN-BUG REPRODUCER:** an in-repository `#[ignore]` test that states the *desired* future invariant and fails today. It does not run in CI. P6 removes the `#[ignore]` when it remediates.
- **THROWAWAY PATCH:** a patch applied only to a disposable worktree; never applied in P5.

| Finding | Reproducer | Kind | Where it runs | Expected today |
|---|---|---|---|---|
| [P5-F-001](../findings.md#p5-f-001) | `core/tests/p5_review_evidence.rs::p5_f_001_wsapoll_reports_hang_up_while_written_bytes_remain_readable` | PASSING EVIDENCE TEST | CI (`windows-latest`) | **Passes.** OS precondition: `POLLHUP \| POLLRDNORM` after a graceful close, bytes still readable |
| P5-F-001 | `windows_owner_loop::tests::p5_owner_loop_review::p5_loop_hup_001_real_graceful_close_matrix`, `…p5_loop_hup_002_real_final_ack_then_close_is_safe`, `…p5_loop_hup_003_real_half_close_while_output_pending`, `…p5_f001_001_scripted_final_ack_with_hang_up_fails_closed_safely` | PASSING EVIDENCE TEST | CI | **Pass.** They assert the OS facts and fail-closed safety, and record how many frames were dispatched or written (today none) |
| P5-F-001 | `…p5_owner_loop_review::p5_f_001_owner_loop_dispatches_complete_frames_before_graceful_close` | EXPECTED-FAIL KNOWN-BUG REPRODUCER | manual `--ignored` | **Fails:** 0 of 1, 0 of 1, 0 of 2 complete frames dispatched (close, half-close, two frames) |
| P5-F-001 | `…p5_owner_loop_review::p5_f_001_owner_loop_responder_loses_final_ack_before_graceful_close` | EXPECTED-FAIL KNOWN-BUG REPRODUCER | manual `--ignored` | **Fails:** the loop as Responder loses the delivered final ACK (`revents 0x0102`), no Responder result |
| P5-F-001 | `…p5_owner_loop_review::p5_f_001_owner_loop_writes_pending_output_after_peer_half_close` | EXPECTED-FAIL KNOWN-BUG REPRODUCER | manual `--ignored` | **Fails:** after a peer half-close (`revents 0x0012`) the loop's retained START is never written |
| P5-F-001 | `p5-f-001-f-002-reproducers.patch` → `windows_owner_loop::tests::p5_f_001_a_complete_frame_before_a_graceful_close_is_dispatched` | THROWAWAY PATCH | disposable worktree | **Fails** (P5.1; superseded by the in-repository reproducers above, kept for continuity) |
| [P5-F-002](../findings.md#p5-f-002) | `windows_tcp::tests::p5_transport_review::p5_f002_001_connection_lifetime_cases`, `…p5_tcp_out_001_retained_output_lifetime_versus_ceremony_lifetime` | PASSING EVIDENCE TEST | CI | **Pass.** They assert only the finitely released cases and record subcases A, B, C as unreleased |
| P5-F-002 | `…p5_transport_review::p5_f_002_idle_connections_eventually_release_their_live_slot` | EXPECTED-FAIL KNOWN-BUG REPRODUCER | manual `--ignored` | **Fails:** subcases A (zero bytes), B (idle after its run), C (owner-less CANCEL retained) still hold a live slot after 24 h of sweeps |
| P5-F-002 | `p5-f-001-f-002-reproducers.patch` → `transport::tests::p5_f_002_frameless_connections_do_not_hold_the_live_cap_forever` | THROWAWAY PATCH | disposable worktree | **Fails** (P5.1) |
| [P5-F-007](../findings.md#p5-f-007) | `windows_tcp::tests::p5_transport_review::p5_f007_final_ack_deadline_boundary_end_to_end` | PASSING EVIDENCE TEST | CI | **Passes.** Characterizes the boundary: only "owner check at D−1 ns, confirmation at D" gives the reverse asymmetric outcome. F-007 is classified as intended behavior needing documentation, so this is a normal test, not a reproducer |
| — (P5.2 coverage) | `p5_sm_*`, `p5_dup_001_*`, `p5_deadline_*`, `p5_router_race_*`, `p5_tcp_*`, `p5_loop_*` | PASSING EVIDENCE TEST | CI | **Pass.** No invariant violation ([adversarial sequences](../adversarial-sequences.md)) |
| — (P5.2 coverage) | `ceremony::tests::p5_sequence_review::p5_sm_deep_generated_sequences_depth_three_unreduced`, `windows_tcp::tests::p5_transport_review::p5_tcp_rd_deep_read_sequences_length_four` | PASSING EVIDENCE TEST (deep, manual) | manual `--ignored` | **Pass.** 35,684 and 4,680 sequences (2026-10-02) |
| [P5-F-004](../findings.md#p5-f-004) (P5.3) | `core/tests/p5_review_evidence.rs::p5_f_004_token_user_sid_lies_inside_the_returned_buffer_on_this_windows` | PASSING EVIDENCE TEST (OS observation, not the API contract) | CI (`windows-latest`) | **Passes.** SID at offset 16, length 28, ends at the 44 returned bytes, stable; range proven before any dereference; unaligned starts refused (error 998) |
| [P5-F-005](../findings.md#p5-f-005) (P5.3) | `windows_tcp::tests::p5_entropy_panic_review::p5_f005_001..003`, `windows_owner_loop::tests::p5_entropy_panic_loop::p5_f005_004..005` | PASSING EVIDENCE TEST (characterization) | CI | **Pass.** Panic injected at the existing P4 pause points and caught around the real Router, adapter, and owner-loop calls. They assert no result, no refund, and no reuse, and record the residue (orphan claim; poisoned Initiator run → uncertain; live slot held) |
| [P5-F-006](../findings.md#p5-f-006) (P5.3) | `crypto::tests::p5_dependency_review::p5_b64_ref_000..001`, `…p5_b64_engine_001..002` | PASSING EVIDENCE TEST | CI | **Pass.** Independent reference, 306 lengths × 4 patterns, cap edges; scalar engine proven at compile time; unused `Simd` engine agrees on x86_64 |
| P5-F-006 (P5.3) | `crypto::tests::p5_dependency_review::p5_b64_ref_002_every_length_up_to_the_frame_maximum` | PASSING EVIDENCE TEST (deep, manual) | manual `--ignored` | **Passes.** Every length 0..=65,536, 2 patterns, 131,074 encodings, 48.9 s (2026-10-02) |
| — (P5.3, F-010 context) | `crypto::tests::p5_dependency_review::p5_secret_type_001_secret_holders_are_not_clone_and_debug_shows_only_public_keys` | PASSING EVIDENCE TEST (compile-time type properties) | CI | **Passes** |

### Running the P5.2 in-repository reproducers and deep runs

```text
cargo test --manifest-path core/Cargo.toml --lib p5_f_00 -- --ignored --nocapture
cargo test --manifest-path core/Cargo.toml --lib p5_sm_deep p5_tcp_rd_deep -- --ignored --nocapture
```

The first command runs the four EXPECTED-FAIL reproducers. All four fail today (2026-10-02, Windows 11 Pro 10.0.26200, rustc 1.99.0), with the observations shown in the table. The second command passes.

The P5.3 deep run:

```text
cargo test --manifest-path core/Cargo.toml --lib p5_b64_ref_002 -- --ignored --nocapture
```

P5.3 added no EXPECTED-FAIL reproducer: none of its findings is a confirmed defect that a reproducer must keep failing.

## P5.1 throwaway patch

The patch adds two `#[ignore]`d unit tests inside existing `#[cfg(test)]` modules. It is kept as a patch and **not applied** in P5. (P5.2 added its in-repository tests through one test-module declaration per file instead; see the table above.) Each test asserts the *correct* behavior, so it fails until P6 remediates, and P6 can then apply the patch, remove the `#[ignore]`, and keep the test as a regression test.

## Running the patch reproducers

From the repository root on Windows:

```powershell
git worktree add --detach ..\sas-pairing-p5-repro HEAD
git -C ..\sas-pairing-p5-repro apply docs/p5-security-review/reproducers/p5-f-001-f-002-reproducers.patch
cargo test --manifest-path ..\sas-pairing-p5-repro\core\Cargo.toml --lib p5_f_00 -- --ignored --nocapture
git worktree remove --force ..\sas-pairing-p5-repro
```

The patch was regenerated in P5.2 so that it applies cleanly to the P5.2 branch head, whose test modules gained one declaration each (checked with `git apply --check`). It changes only `#[cfg(test)]` code. It uses only existing test helpers; the P5-F-001 test adds one 200 ms pause so that the FIN arrives before the loop's next readiness wait. The P5.2 in-repository reproducers replace that pause with a bounded `WSAPoll` wait for hang-up readiness, so they need no sleep. On the P5.2 head the `p5_f_00` filter also selects the four in-repository reproducers. Re-run on 2026-10-02 at `5ca9476` with the patch applied, all six failed as expected. P5.3 regenerated it again for its own module declarations: only the context lines changed, and the added lines are identical. It applies to the P5.3 head (`git apply --check`), and with it applied all six still failed as expected (2026-10-02).

## Recorded output (2026-10-02, Windows 11 Pro 10.0.26200, rustc 1.99.0, base `e21ff0b`)

```text
running 2 tests
P5-F-002 counts after 24 h idle: (0, 16, 0)
P5-F-002 seventeenth activation after 24 h: Some(ResourceLimited)
test transport::tests::p5_f_002_frameless_connections_do_not_hold_the_live_cap_forever ... FAILED
P5-F-001 observed events: [Closed(ConnectionRef(SessionHandle { router: 2, session: 1 }), Readiness(258))]
P5-F-001 limiter after: StartLimiterSnapshot { tokens: 4, remainder: 0ns, last: 0ns, rolling: 0 }
test windows_owner_loop::tests::p5_f_001_a_complete_frame_before_a_graceful_close_is_dispatched ... FAILED
```

`Readiness(258)` is `0x0102`, which is `POLLHUP | POLLRDNORM`. The START limiter is untouched, so the START frame never reached the Router. The P5-F-001 test was repeated 5 times with the same result.

## Standalone OS experiment (before the in-repository test)

A scratch program outside the repository (`windows-sys` 0.59, the core's own version) connected over loopback, wrote 11 bytes, and then closed or half-closed the connection:

```text
write+drop(graceful close): revents=0x0102 HUP=true ERR=false NVAL=false RDNORM=true read=Ok(11)
write+shutdown(Write): revents=0x0102 HUP=true ERR=false NVAL=false RDNORM=true read=Ok(11)
write only (control): revents=0x0100 HUP=false ERR=false NVAL=false RDNORM=true read=Ok(11)
```
