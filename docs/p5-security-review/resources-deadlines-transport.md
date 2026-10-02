# P5 Analysis — Resources, START Limiter, Deadlines, TCP Adapter, Owner Loop

Reviewed source: `core/src/lib.rs`, `start_limiter.rs`, `deadline.rs`, `transport.rs`, `windows_tcp.rs`, `windows_owner_loop.rs` (production parts) at `e21ff0b`.

## 1. Resource table

| Resource | Max | Owner | Acquired | Released | Uncertainty | Queue | Peer-controlled amplification |
|---|---|---|---|---|---|---|---|
| SAS opportunities | 10 per registration | `Shared::remaining` | `reserve` (atomic with guard) | Never | Poisoned → fail closed | None | None: needs local authorization |
| Exposed-ceremony guard | 1 | `Shared::active` | `reserve` | `terminate` / `Ceremony::drop` after state drop | Poisoned → held | None | None |
| START limiter | Burst 4, 1 per 5 s; 12 per rolling 60 s | `Shared::start_limiter` | `admit_start` under `shared` | Time only | Unsafe clock → refuse, no mutation | None | A peer can consume all admission ([P5-F-012](findings.md#p5-f-012), by design) |
| Pending Responders | 4 | `Shared::pending_responders` | `admit_pending_responder` | Exposure, terminal, or drop (`Option` taken once) | Poisoned → held | None | A peer can hold each for ≤ 60 s |
| Preliminary operations | 2 | `Shared::preliminary_operations` | `preliminary_permit` (R admission, R DH, I ephemeral) | `PreliminaryPermit::drop` | Poisoned → held | None | Bounded by limiter × 1 DH per run |
| Pending accepts | 4 (loop holds ≤ 1) | `Shared::pending_accepts` | `AcceptPermit::begin` | `activate` or drop (`held` flag) | Poisoned → held | None | 1 accept per drive |
| Live connections | 16 | `Shared::live_connections` | `activate` | Transport teardown, **only after the Router session is CLOSED** | Uncertain → held forever | None | **Held indefinitely by idle peers** ([P5-F-002](findings.md#p5-f-002)) |
| Incomplete frames | 4 per authority, 1 per connection | `Shared::incomplete_frames` / `Option<Partial>` | First retained byte | Frame complete or teardown | Poisoned → held | None | 10 s whole / 2 s idle per frame |
| Partial-frame buffer | ≤ 65,536 B per connection, ≤ 4 at once | `Partial::bytes` | `reserve_exact(target − len)` after the declaration is validated | With the partial | — | — | Bounded |
| Retained outbound frame | 1 per connection (≤ 65,536 B) | `PendingWrite` | `retain` | Last byte written, discard, or teardown | — | No queue: reads and actions pause | A peer that stops reading stalls only its own connection |
| Retained TCP read suffix | 8 KiB fixed box per connection | `ReadSuffix` | One `read` | Consumed by the host | — | — | Bounded |
| Router routes per session | Responders ≤ 4 pending + 1 exposed per authority; Admitting claims ≤ concurrent callers; Initiators **unbounded (local only)** | `Router::table` | Admission or local start | Terminal (removed by the remover), session teardown | Poisoned → uncertain | — | A peer cannot create Initiator routes |
| Initiator request-ID reservations | Unbounded (local only) | `Shared::initiator_request_ids` | `reserve_request_id` | Terminal or drop | Poisoned → held | — | None |
| `seen` per run | ≤ 7 frames | `RemoteCeremony::seen` | Accepted inbound frame | Run drop or success | — | — | Bounded by frame size |
| Deadline scan work | ≤ 8 route polls per session per sweep; 2 sweeps per drive | Router / owner loop | — | — | — | — | Bounded |
| Owner-loop descriptors and events | ≤ 17 `WSAPOLLFD`, ≤ 17 events per drive | `drive_into` | — | — | — | — | Bounded |

**Composition.** A peer's worst case per authority: 16 connections × (8 KiB suffix + one outbound frame ≤ 64 KiB), plus 4 partial frames × 64 KiB, plus ≤ 5 peer-driven runs × (`seen` + transcript copies of ≤ ~50 KiB). That is a few MiB, and per-call CPU is bounded by the limiter and permits. **No peer-driven composition reaches unbounded memory or work.** The only unbounded collections (Initiator runs and request-ID reservations, Router sessions created with `open_session`) grow only through trusted local calls.

## 2. START limiter, rebuilt mathematically

State: whole `tokens ∈ 0..=4`, `remainder ∈ [0, 5 s)` (0 when full), `last`, and admission instants (≤ 12, non-decreasing). For `now ≥ last`: `total = remainder + (now − last)`; `tokens′ = min(4, tokens + ⌊total / 5 s⌋)`; `remainder′ = 0` if `tokens′ = 4`, else `total mod 5 s`; records with `now − t ≥ 60 s` are dropped from the front. Admit iff `tokens′ ≥ 1 ∧ records < 12`, then `tokens′ −= 1` and push `now`. Arithmetic is `u128` nanoseconds and checked `Duration` operations. `now < last` → `UnsafeClock` with no mutation.

| Case | Result |
|---|---|
| `t = 0`, fresh | 4 admitted, 5th refused. `last = 0` is the clock origin, and a full bucket accrues nothing |
| `t ∈ (0, 5 s)` after 4 at 0 | Refused. The refill remainder keeps accruing; a refusal resets nothing |
| `t = 5 s` | Exactly 1 token (`⌊5/5⌋`) |
| `t = 10 s` with no admission since 0 | 2 tokens |
| 4 at 0, then 1 each at 5…40 s (12 records) | 45 s and 59.999 s refused by the rolling component, with no token consumed |
| `t = 55 s` | Records at 0 are 55 s old and still count |
| `t = 60 s` | Records at 0 are exactly 60 s old and evicted (`≥`). 8 remain, so admission is possible |
| `t > 60 s`, long idle | `tokens = 4` (cap), `remainder = 0`. No hidden credit |
| Clock backwards or missing | Refused; state unchanged |
| Overflow | `checked_add`/`checked_sub`, `u128` nanoseconds, `try_from` → `UnsafeClock` instead of wrap |

**Extra-credit search.** (a) The remainder is zeroed at the cap, so idle time beyond refill buys nothing. (b) A refusal commits only elapsed-time bookkeeping, identical to P3 steps 2–3. (c) A token is consumed only together with a record push, and vice versa. (d) The clock is read inside the `shared` critical section, so readings are ordered with the state they change. (e) The limiter is created only in `register` ([P5-F-003](findings.md#p5-f-003) covers in-process re-registration). **No extra-credit path found** ([P5-F-021](findings.md#p5-f-021)).

## 3. Deadlines

| Concept | Value | Start | Refreshed by | Check | Notes |
|---|---|---|---|---|---|
| Ceremony absolute | 5 min | I: local creation; R: pending admission | Never | `total ≥ 5 min` | Reported over inactivity when both expired |
| Ceremony inactivity | 60 s | Same | `step()` when `progress_point` changes (new state, recorded authorization, verified peer MAC) | `idle ≥ 60 s` and state `Running` | Suspended only in `AwaitLocalApproval`. Restarts at approval |
| Pending pre-exposure | 60 s fixed | R pending admission (clock read before slot) | Never | `held ≥ 60 s` | Ends when R crosses exposure |
| Transport frame | 10 s whole / 2 s no progress | First retained byte | Retained-byte progress (idle only) | `≥` | Only while a frame is incomplete. **No deadline for a connection with no frame in progress** ([P5-F-002](findings.md#p5-f-002)) |
| Owner-loop wait | ≤ 250 ms | — | — | — | Scheduling only. A wake is not progress |
| START limiter clock | Authority-scoped | Registration | — | Inside the `shared` lock | Independent of ceremony clocks |

- **Duplicates, junk, polls, presentation, and UI activity** refresh nothing (`progress_point` unchanged; `presentation` uses read-only `evaluate`).
- **Clock failure:** missing or backwards readings → `ClockUnavailable` (ceremony), `UnsafeClock` (limiter), or `ClockUnavailable` (transport), each fail-closed with no timeout claim and no mutation.
- **Pending-output preflight:** before each write of a frame owned by a live run, the adapter polls that exact run's deadlines. An unsent frame of an ended run is discarded (its timeout CANCEL may take the slot). A partly sent one closes the connection with nothing appended (`AbandonedPartialFrame`), so a truncated frame is never followed by another frame.
- **Stale output after expiry:** no frame of an expired run is written after the expiry is observed. The remaining window is that the final ACK's last byte is written after a live preflight and the run expires before `confirm`. The bytes are then on the wire, I has no result, and R may succeed ([P5-F-007](findings.md#p5-f-007)). No other stale output was found.
- **Suspend and resume:** `recheck_after_resume` sweeps before any I/O. Whether `Instant` counts suspended time is unverified ([P5-F-011](findings.md#p5-f-011)).

## 4. Windows TCP adapter

| Event | Behavior | Result |
|---|---|---|
| Partial read | Bytes go to the suffix; one frame per call; the remainder is fed before the next read | No loss or duplication |
| Several frames in one read | One per `on_readable`; the owner loop sets `buffered` (zero wait) | Exact |
| WouldBlock / Interrupted | No host call, refresh, or confirmation | Exact |
| `read` = 0 (EOF) | Teardown: every run on the session terminal, opportunity kept, no result | Exact |
| EOF mid-frame or after exposure | Same teardown; the partial frame and its slot are released | Exact |
| Partial write | `offset` advances; reads and local actions stay paused | No second output |
| `write` = 0 or error | Teardown; a `FinalAck` is never confirmed | No success after a failed write |
| Final ACK partial write then deadline | `AbandonedPartialFrame` → close | R sees a truncated frame and EOF and fails. I has no result |
| Final ACK complete | `confirm_sent` → result (or a timeout if expired, [P5-F-007](findings.md#p5-f-007)) | Exact |
| Timeout while a frame is pending | The owner's frame is discarded (unsent) or the connection closed (partial). The CANCEL goes into a free slot only | Exact |
| Hidden retries | None in this module | — |
| Peer stops reading | Our write stalls; ceremony deadlines still run and end the run (frame discarded or connection closed). A retained **CANCEL of an already terminal run has no owner and no deadline**, so a never-reading peer keeps that connection open indefinitely | Folded into [P5-F-002](findings.md#p5-f-002) |

## 5. Owner loop

- **Fairness:** per drive, each connection gets at most one socket operation, served in a fixed order, and the one accept comes after all connections. A readable or writable flood on one connection cannot starve others. A listener flood costs one accept-and-refuse per drive. Sweeps are bounded (§1). This is preserved by implementation, not only intended.
- **Readiness handling:** `FAILED = POLLERR | POLLHUP | POLLNVAL` closes the connection **before any read**. On Windows, a graceful peer close is reported as `POLLHUP | POLLRDNORM` while the bytes sent before the FIN are still readable, so those bytes are discarded ([P5-F-001](findings.md#p5-f-001)). Error plus writable is closed without writing, which is correct.
- **Poll failure:** fail closed (listener dropped, every connection close attempted). `WSAEINTR` makes no progress.
- **Listener failure:** the listener is dropped and live connections continue. Nothing rebinds.
- **Owner uncertainty:** any `OwnershipUncertain` fails the loop closed, and uncertain capacity stays held.
- **16 connections + accept:** activation refuses at the authority-wide cap and the socket is dropped. A loop-local count above 16 would be an accounting break → fail closed.
- **Descriptor rebuild and stale handles:** `fds` is rebuilt every drive from live adapters. Indices stay valid until the post-loop `retain`, and sockets closed by the second sweep are marked `served` and get no I/O.
- **Removal during iteration:** `retain` after the loop. `fail` drains and returns immediately.
- **Local action during pending write:** `Refused::WritePending` before the host is called.
- **Resume recheck:** a sweep only, with no I/O or accept.
