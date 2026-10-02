# P5 Reproducers

Review infrastructure only. Nothing here changes production behavior, and nothing here runs in CI unless stated.

| Finding | Reproducer | Where it runs | Expected today |
|---|---|---|---|
| [P5-F-001](../findings.md#p5-f-001) | `core/tests/p5_review_evidence.rs::p5_f_001_wsapoll_reports_hang_up_while_written_bytes_remain_readable` | In the repository; runs in CI on `windows-latest` | **Passes.** It pins the OS precondition: after a graceful close, `WSAPoll` reports `POLLHUP \| POLLRDNORM` and the written bytes are still readable. |
| [P5-F-001](../findings.md#p5-f-001) | `p5-f-001-f-002-reproducers.patch` → `windows_owner_loop::tests::p5_f_001_a_complete_frame_before_a_graceful_close_is_dispatched` | Disposable worktree only | **Fails** (demonstrates the defect) |
| [P5-F-002](../findings.md#p5-f-002) | `p5-f-001-f-002-reproducers.patch` → `transport::tests::p5_f_002_frameless_connections_do_not_hold_the_live_cap_forever` | Disposable worktree only | **Fails** (demonstrates the defect) |

The patch adds two `#[ignore]`d unit tests inside existing `#[cfg(test)]` modules. It is kept as a patch and **not applied** in P5, so no production source file changes in this phase. Each test asserts the *correct* behavior, so it fails until P6 remediates, and P6 can then apply the patch, remove the `#[ignore]`, and keep the test as a regression test.

## Running the patch reproducers

From the repository root on Windows:

```powershell
git worktree add --detach ..\sas-pairing-p5-repro HEAD
git -C ..\sas-pairing-p5-repro apply docs/p5-security-review/reproducers/p5-f-001-f-002-reproducers.patch
cargo test --manifest-path ..\sas-pairing-p5-repro\core\Cargo.toml --lib p5_f_00 -- --ignored --nocapture
git worktree remove --force ..\sas-pairing-p5-repro
```

The patch applies cleanly to `e21ff0b` (checked with `git apply --check`). It uses only existing test helpers; the P5-F-001 test adds one 200 ms pause so that the FIN arrives before the loop's next readiness wait.

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
