# P5 Reproducers

Review infrastructure only. Nothing here changes production behavior, and nothing here runs in CI unless stated.

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

### Running the P5.2 in-repository reproducers and deep runs

```text
cargo test --manifest-path core/Cargo.toml --lib p5_f_00 -- --ignored --nocapture
cargo test --manifest-path core/Cargo.toml --lib p5_sm_deep p5_tcp_rd_deep -- --ignored --nocapture
```

The first command runs the four EXPECTED-FAIL reproducers. All four fail today (2026-10-02, Windows 11 Pro 10.0.26200, rustc 1.99.0), with the observations shown in the table. The second command passes.

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

The patch was regenerated in P5.2 so that it applies cleanly to the P5.2 branch head, whose test modules gained one declaration each (checked with `git apply --check`). It changes only `#[cfg(test)]` code. It uses only existing test helpers; the P5-F-001 test adds one 200 ms pause so that the FIN arrives before the loop's next readiness wait. The P5.2 in-repository reproducers replace that pause with a bounded `WSAPoll` wait for hang-up readiness, so they need no sleep. On the P5.2 head the `p5_f_00` filter also selects the four in-repository reproducers. Re-run on 2026-10-02 at `5ca9476` with the patch applied, all six failed as expected.

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
