# P5.2 — State-Machine and Transport Adversarial Sequence Review

Increment P5.2 of the [P5 review](README.md). P5.1 asked whether each transition looked correct. P5.2 asks whether the system stays correct under bounded sequences of valid, invalid, duplicated, reordered, delayed, fragmented, closed, and timed-out events. It deepens the two P5.1 `PARTIAL` surfaces, the state machine (#16) and Router concurrency (#19), plus the transport stream semantics behind [P5-F-001](findings.md#p5-f-001), [P5-F-002](findings.md#p5-f-002), and [P5-F-007](findings.md#p5-f-007).

> Internal, AI-assisted review evidence. Generated tests cover bounded sequence spaces only and are not proof. Not a professional audit or formal verification.

## 1. Phase discipline and where the evidence lives

P5.2 changes no production behavior and adds no dependency. Almost every surface it drives is crate-private (`RemoteCeremony`, `Router`, the host, the transport, the TCP adapter, the owner loop's scripted readiness). Integration tests in `core/tests/` cannot reach these, and P5 must not widen visibility. So the review tests sit inside the existing `#[cfg(test)] mod tests` modules, as the P5.2 task permits. Each of four source files gains one `mod p5_…;` declaration inside its test module, and the code is in separate files:

| File | Families |
|---|---|
| `core/src/ceremony/tests/p5_sequence_review.rs` | SM-I, SM-R, DUP, DEADLINE |
| `core/src/router/tests/p5_concurrency_review.rs` | ROUTER-RACE |
| `core/src/windows_tcp/tests/p5_transport_review.rs` | F007, TCP-STREAM, TCP-RD, TCP-W, TCP-DEADLINE, F002, TCP-OUT |
| `core/src/windows_owner_loop/tests/p5_owner_loop_review.rs` | LOOP-READY, LOOP-DEADLINE, F001, LOOP-HUP |

A non-test build never reads these files. The only diff to existing production source files is those four test-module declarations (`git diff origin/main -- core/src`), and `Cargo.toml` and `Cargo.lock` are unchanged.

**Determinism.** No randomness or seeds anywhere. Ordering is fixed, request IDs are fixed (or scripted), and ceremony, transport, and START-limiter clocks are `ManualClock`s. Thread interleavings are forced with the existing per-thread pause points, channels, and exact-state waits. No test sleeps. Real-socket tests wait on `WSAPoll` readiness in bounded loops that fail after 10 s.

## 2. State-machine harness (SM, DUP, DEADLINE)

**World.** A target `RemoteCeremony` plus an honest peer, which is a real `RemoteCeremony` of the other role on its own authority. Every frame the target produces is delivered to the peer. The peer then takes each legal local step eagerly (authorize and expose, MATCH and its own MAC, INITIATOR_FINISH, and the final-ACK send confirmation), and its frames queue for the target. Both roles are explored independently. Many transitions are intentionally asymmetric.

**Action alphabet (25).**

| Group | Actions |
|---|---|
| Network | `Next` (honest next frame) · `DupLast` (exact copy of the last accepted frame) · `DupFirst` (exact copy of the first, older accepted frame) · `ChangedLast` (changed duplicate) · `CorruptNext` (honest next frame, last byte changed: tag, key, or context) · `WrongIdNext` (another request ID) · `TruncNext` (malformed: last byte missing) · `Foreign` (same step from an independent ceremony with the same request ID and START) · `Future` (a later step of that ceremony) · `Reflect` (the target's own last output) · `WrongRole` (BOOTSTRAP_MAC/CANCEL with the sender flipped) · `PeerCancel` (the honest peer's authenticated CANCEL) |
| Local | `Authorize` · `Expose` · `Approve` (live identity) · `ApproveStale` (another identity) · `Reject` · `Cancel` · `EmitMac` · `EmitFinish` · `Confirm` (exact final-ACK bytes) · `ConfirmWrong` |
| Lifecycle | `Poll` (no time passes) · `Expire` (absolute deadline passes, then poll) · `Close` (local termination, as a session or connection teardown does) |

The duplicate matrix adds `WrongIdLast` and `WrongRoleLast`, which perturb the last accepted frame M itself.

**Bounds and pruning.**

- **Honest prefixes.** The suffix starts from every honest state on one complete ceremony: 11 for the Initiator (`AwaitAccept` … `Succeeded`) and 9 for the Responder.
- **Suffix.** Every sequence of at most `depth` applicable actions. Applicability is state-aware: no `Next` without a pending honest frame, no `ConfirmWrong` without a pending final ACK, and so on. Local actions are always applicable, because refusing them in every state is part of the test.
- **Terminal stop.** A node that reached a terminal state is not expanded. It instead receives the 12-action terminal postfix (`Next`, `DupLast`, `Approve`, `Cancel`, `Reject`, `Authorize`, `Expose`, `EmitMac`, `EmitFinish`, `Confirm`, `Poll`, `Close`). Every live sequence is closed and then receives the same postfix. So all of these act on every terminal state reached, and none may produce a result, an outbound frame, an exposure, or any change.
- **Verified no-op reduction (CI tier only).** In the suffix, one second passes before every action. After each action the harness compares a fingerprint of the target: state, the `seen` duplicate record, both deadline origins (probed by evaluating the deadlines at fixed instants), admission accounting (terminal flag, authorization, request-ID reservation, pending slot), SAS bytes, the result, and the peer's state and queues. Duplicates, idempotent repeats, quiet polls, and local refusals must leave it unchanged. This is asserted at every such step, and it is also the "no refresh" check. A node whose last action left the fingerprint unchanged is not expanded, because its subtree equals its parent's, which is explored. The manual deep run does no reduction.
- **Cost.** One X25519 operation takes about 11 ms in the unoptimized test profile, and a sequence needs one to four. This sets the split between the CI tier and the deep tier.

**Oracle.** The oracle is not a second protocol implementation. It tracks terminality, result count, exposure count, authorizations, the target's outputs by wire type, honest versus injected input, the authority's budget, guard, pending slot, request-ID reservation, and START-limiter snapshot. It asserts these after every step:

| Invariant (P5.2 §10) | Check |
|---|---|
| Terminal irreversibility | A finished run never changes state, produces output or a result, or exposes again |
| Result uniqueness | At most one `PairingResult`; once produced it never changes |
| Exposure accounting | A contribution appears only after an accepted authorization; at most one per run; the budget drops by exactly that one and is never refunded |
| Guard | Held exactly while this exposed run is live |
| Pending slot / reservation | R holds a pending slot exactly while live and unexposed; I holds its request-ID reservation exactly while live |
| Request isolation | An injected frame (other request ID, other ceremony, future step, reflection, flipped role, corruption, truncation) accepted without error must be an unauthenticated pre-SAS contribution (ACCEPT or INITIATOR_KEY); any such run never reaches a result |
| Stale local callback | A refusal (stale identity, not yet allowed, already done) changes nothing at all (fingerprint) |
| Authentication ordering | A result requires local MATCH, own MAC emitted, the honest peer MAC verified, no injected input accepted, and the role's completion boundary: R after verifying both honest INITIATOR_FINISH and INITIATOR_FINISH_ACK; I only on `Confirm` of its exact final-ACK bytes after RESPONDER_FINISH_ACK. The result names the presented `ceremony_identity` and the peer's exact bootstrap |
| Duplicate semantics | An exact duplicate changes nothing (no output, no state, no record, no deadline origin); a changed duplicate is terminal |
| Wrong-state input | Any rejected network input is terminal with no result, never "ignored and still live" |
| Liveness | Honest progress is never refused on a live run that accepted no injected input. Adversarial no-ops do not break the honest path |
| Outputs | Only the role's own frame types with its own sender role; each type at most once |
| Limiter | No START admission, charge, or refund after the run exists |
| Cleanup | Between sequences no guard, pending slot, preliminary permit, or reservation is left over |

### Results

| Family | Tier | Role | Prefixes | Suffix | Sequences | Steps | Terminal leaves | Results reached | Injected frames accepted |
|---|---|---|---|---|---|---|---|---|---|
| SM-I-001a/b | CI | I | 11 | ≤ 2, reduced | 455 | 2,580 | 245 | 3 | ACCEPT ×20 |
| SM-R-001a/b | CI | R | 9 | ≤ 2, reduced | 380 | 1,709 | 201 | 3 | INITIATOR_KEY ×44 |
| SM-I-002 | deep, manual | I | 11 | ≤ 3, unreduced | 19,124 | 135,338 | 10,340 | 92 | ACCEPT ×434 |
| SM-R-002 | deep, manual | R | 9 | ≤ 3, unreduced | 16,560 | 97,262 | 8,543 | 92 | INITIATOR_KEY ×1,064 |

The CI tier skipped 146 verified no-op subtrees. **Every invariant held in all 36,519 sequences.** The only injected frames ever accepted were the two unauthenticated pre-SAS slots, and every such run later failed closed with no result: a foreign ACCEPT fails the commitment, and a foreign INITIATOR_KEY gives different SAS and MAC keys. No BOOTSTRAP_MAC, completion frame, or CANCEL that was not byte-identical honest input was ever accepted.

What the families cover in particular:

- **Terminal irreversibility:** the postfix reached every terminal state of every sequence: failure, timeout, peer CANCEL, local reject or cancel, close, and success.
- **Local action sequencing:** approve before SAS, approve twice, reject or cancel then approve, approve after timeout (`Expire` → `Approve`), authorize twice (terminal: a stale local `authorize` ends the run, as P5.1 recorded), expose twice or without authorization (terminal, nothing spent), MAC or finish twice (`AlreadyEmitted`, no effect), confirm with wrong bytes (no effect), and `EmitFinish` at the Responder (`NotInitiator`, no effect).
- **Stale callbacks:** `ApproveStale`, and `Approve`/`Reject`/`Cancel` before a SAS exists, change nothing. Stale `RunRef`s after route replacement or close are covered at the Router level (§7). An action while an outbound write is pending is `Refused::WritePending` at the adapter (P4 test, re-exercised by TCP-W).

### Duplicate and reorder matrix (DUP-001)

For each honest prefix whose last step accepted a peer frame M, the harness applies each perturbation of M once, then the postfix: 55 cells.

| M (receiver) | exact M | changed M | older frame again | future frame early | M, other request ID | M, sender flipped | own frame reflected |
|---|---|---|---|---|---|---|---|
| START (R) | ignored | terminal | — | terminal | terminal | — | terminal |
| ACCEPT (I) | ignored | terminal | — | terminal | terminal | — | terminal |
| INITIATOR_KEY (R) | ignored | terminal | ignored | terminal | terminal | — | terminal |
| RESPONDER_KEY (I) | ignored | terminal | ignored | terminal | terminal | — | terminal |
| BOOTSTRAP_MAC (I and R) | ignored | terminal | ignored | terminal (R) | terminal | terminal | terminal |
| RESPONDER_FINISH_ACK (I) | ignored | terminal | ignored | — | terminal | — | terminal |
| INITIATOR_FINISH (R) | ignored | terminal | ignored | — | terminal | — | terminal |
| after success (I and R) | no effect (`Completed`) | no effect | no effect | — | no effect | — | no effect |

"—" means not applicable: no older frame yet, no later step exists, or the frame type has no sender field. "Ignored" means the fingerprint is unchanged: no output, state, record, or deadline change. This matches P3 §6 and §11.2 everywhere. An exact duplicate that reaches a *removed* route is a Router-level unknown route and is session-fatal. That is the P5.1 note, and P3 §11.2 behavior.

### Deadlines (DEADLINE-001..004)

Every probe is applied at the boundary −1 ns, exactly, and +1 ns.

| Family | Deadline | States | Probes | Cases | Result |
|---|---|---|---|---|---|
| DEADLINE-001 | 60 s inactivity | every live honest state, both roles | poll, honest next frame, exact duplicate | 135 | Live at −1 ns; at exactly 60 s and +1 ns `TimedOut(Inactivity)`, input not applied, no result, CANCEL iff a shared SAS existed. `AwaitLocalApproval` (SAS displayed) is live at every offset (suspended). For a pending Responder the 60 s pending lifetime coincides and the ceremony deadline is reported first |
| DEADLINE-002 | 60 s pending pre-exposure | R after I_KEY and after authorization, with progress at 30 s; R after exposure | same | 21 | `PendingExpired` at exactly 60 s from admission despite progress; after exposure it no longer applies |
| DEADLINE-003 | 5 min absolute | every post-SAS state, both roles, parked at the suspended SAS until 250 s so inactivity cannot fire first | same | 87 | Live at −1 ns; exactly 300 s from creation (I) or admission (R) is `TimedOut(Absolute)` with the authenticated CANCEL, however recent the last progress |
| DEADLINE-004 | inactivity refresh rules | I states awaiting machine progress, one action at 30 s | — | 49 | No refresh by an exact duplicate, an older exact duplicate, a refused stale MATCH, an idempotent own MAC, a poll, or a read-only SAS presentation (fingerprint unchanged). Refresh (expiry moves to 90 s) by a new state, a verified peer MAC after local MATCH, or a recorded exposure authorization. The absolute deadline never refreshes (DEADLINE-003) |
| TCP-DEADLINE-001 | 2 s no-progress, 10 s whole-frame | an incomplete frame at the adapter | completing bytes, poll | 24 | Expiry at `elapsed >= deadline`. Retained-byte progress refreshes only the idle deadline. A WouldBlock read or a poll refreshes nothing. With no incomplete frame there is no transport deadline at all (P5-F-002) |

Malformed and changed input are terminal at once, so "does not refresh" holds trivially for them. ROUTER-RACE-009 shows that a sibling run's progress on the same session does not refresh another run.

## 3. Transport stream model (TCP-STREAM, TCP-RD, TCP-W)

The model drives the scripted-socket TCP adapter with a real Router and host. Where key generation would dominate, the probe frame is a START refused by an exhausted START limiter: dispatched as a run-local refusal, uncharged, with no output.

| Family | What | Count | Result |
|---|---|---|---|
| TCP-STREAM-001/002 | `A`, `A‖B`, `A‖B‖C`, `BIG‖B` (BIG > one 8 KiB read), `A‖A`, each under whole, 1+rest, rest+1, byte-by-byte, magic, header, length-prefix, request-ID, and bootstrap splits, splits at, before, and inside the next header and length at every frame boundary, and 7, 64, 1000, 8192-byte chunks | 95 | Each frame dispatched exactly once, in order, the right request ID, each ACCEPT written once. No dispatch from an incomplete frame. Suffix fully consumed, no incomplete frame left, no busy loop, at most one socket operation per call. A complete frame left in the suffix is served with no new readiness (owner loop: zero wait, LOOP-READY `Buffered`), so it causes no artificial timeout |
| TCP-STREAM-003 | magic prefix, length prefix, payload prefix, complete + partial next, complete only, each then EOF, in one read and byte by byte | 10 | Complete frames dispatched, incomplete bytes never; `PeerClosed`; one shutdown; every run ended; counts `(0, 0, 0, 0)` |
| TCP-RD-001 / -002 | every sequence of at most 3 (CI) or 4 (manual) read results over `{WouldBlock, Interrupted, 1 byte, 7 bytes, rest of frame, all, EOF, error}` on a two-frame stream | 584 / 4,680 | Exactly the frames whose last byte arrived before the end are dispatched, in order, once. WouldBlock and Interrupted change nothing. EOF or an error tears down exactly once and releases everything. A partial second frame stays only in the transport's one incomplete slot |
| TCP-W-001 | every sequence of at most 3 write results over `{WouldBlock, Interrupted, 1 byte, 7 bytes, zero, error, owner expires}` for a live Initiator's retained START, then an unblocked write | 399 | Offsets only grow; the wire is always a prefix of the frame, never a repeated byte; `Written` exactly at the last byte; zero write → `Io(WriteZero)`; error after partial → closed; owner expired before any byte → frame discarded (no CANCEL before SAS) with no write call; after a partial write → `AbandonedPartialFrame` with nothing appended |
| TCP-W-002 | every sequence of at most 2 such results for the Initiator's final ACK, through the Responder | 56 | The Initiator's result appears only on the call that writes the last byte, and never after a zero write, an error, or an abandoned partial write. The Responder succeeds only from the complete frame. Both results agree |

## 4. Owner loop

### Readiness classification (LOOP-READY-001)

Eleven `revents` values were tested against three adapter shapes (idle with readable input, write pending, input retained in the suffix), forced through scripted readiness: 33 cases.

| revents | Idle (readable frame) | Write pending | Suffix holds a frame |
|---|---|---|---|
| 0 | nothing | nothing | read from suffix, zero wait |
| POLLIN / POLLRDNORM | one read, dispatch | nothing (reads pause) | read from suffix, no socket read |
| POLLOUT | nothing | one write | read from suffix |
| POLLERR, POLLERR\|POLLIN, POLLNVAL | close, no I/O | close, no I/O | close, no I/O |
| POLLHUP, POLLHUP\|POLLIN, POLLHUP\|POLLRDNORM | **close, no read** | **close, no write** | **close, the complete retained frame discarded** |
| POLLOUT\|POLLHUP | close | **close, no write** | close |

No combination failed the whole loop. POLLOUT without write interest, and POLLHUP on a socket that never connected, are not combinations Windows produces naturally. They are listed for classification precedence only.

### Precedence

| Order | Current rule | Assessment |
|---|---|---|
| 1 | Deadline sweep before the wait and again after it, before any socket I/O; a connection with a sweep event does no I/O in that drive | Correct, and intentional (LOOP-DEADLINE-001) |
| 2 | `FAILED = POLLERR \| POLLHUP \| POLLNVAL` → close before read or write | Correct for ERR and NVAL. **Wrong for HUP:** it discards readable bytes, the complete retained suffix, and the loop's own pending output after a peer half-close (P5-F-001) |
| 3 | Write pending and POLLOUT → one write; no read while a frame is retained | Correct: one-slot backpressure. Combined with an owner-less retained frame it can last forever (P5-F-002 C) |
| 4 | Otherwise POLLIN or retained input → one read (zero wait while input is retained) | Correct |
| 5 | At most one accept, after all connections | Correct (P5.1) |

### Deadline versus socket readiness (LOOP-DEADLINE-001)

The deadline passes during the readiness wait while the socket is ready. The post-wait sweep wins, so no expired run performs further socket I/O:

- **Read:** the expired Initiator's next frame stays unread in the expiry drive. The next drive reads it, finds the route gone, and ends the session (P3 §11.2 unknown or stale route).
- **Write:** an expired run's unsent START is discarded with zero write calls.
- **Final ACK:** see P4 `a_final_ack_whose_run_expires_before_the_loop_writes_it_is_never_written_further`, and §6 for the confirmation boundary.
- **CANCEL:** an owner-less timeout CANCEL of an already terminal run has no deadline and is written after the wait. This is correct: it is the best-effort notification and belongs to no live run.

## 5. P5-F-001 evidence (real Windows and scripted)

LOOP-HUP-001 to -003 run the production owner loop with a real listener and real `WSAPoll`. The test waits, without reading, until `WSAPoll` on the loop's socket reports hang-up. This makes the timing deterministic with no sleep, and replaces P5.1's 200 ms pause.

| Case | Peer action | `revents` | Loop event | Frames dispatched | Cleanup |
|---|---|---|---|---|---|
| A | full START, close | `0x0102` HUP\|RDNORM | `Closed(Readiness(258))` | 0 of 1 | exact, nothing left |
| B | full START, `shutdown(Send)`, socket kept | `0x0102` | `Closed(Readiness(258))` | 0 of 1 | exact |
| C | partial START, close | `0x0102` | `Closed(Readiness(258))` | 0 of 0 (correct) | exact |
| D | two STARTs, close | `0x0102` | `Closed(Readiness(258))` | 0 of 2 | exact |
| E | final INITIATOR_FINISH_ACK, close (the loop as Responder, a real ceremony) | `0x0102` | `Closed(Readiness(258))` | the ACK is not read: Initiator has a result, **Responder none** | exact; Responder's opportunity kept, guard released |
| F (new) | the loop holds an unwritten START; peer `shutdown(Send)` | `0x0012` HUP\|WRNORM | `Closed(Readiness(18))` | the peer receives 0 bytes | exact |

Scripted F001-001 repeats E with forced `POLLHUP | POLLRDNORM`, with the same outcome. **Safety held in every case:** no result from an incomplete or unread frame, no second result, no result for the wrong run, and exact cleanup. Fail-closed is the current security behavior, and no more serious consequence was found.

## 6. P5-F-007 evidence (F007-001/002)

The Initiator's final-ACK boundary was driven end to end through two scripted adapters, for both deadlines, with exact hand-clock instants. The owner check is the deadline preflight inside `on_writable`. The confirmation is `confirm_sent`, which runs the run's own deadline check. `ManualClock::advance_after(1, …)` moves time between those two readings.

| Deadline D | Case | Owner check / confirmation | Wire | Initiator | Responder |
|---|---|---|---|---|---|
| inactivity 60 s, absolute 300 s | both live | D−2 ns / D−1 ns | full final ACK | result | result (agree) |
| both | **crosses before confirmation** | D−1 ns / exactly D | full final ACK, then CANCEL | **timeout, no result** | **result**, then I's CANCEL is an unknown route: `SessionProtocolFailure` ends R's connection after its result |
| both | expired at check | D / D | CANCEL only | timeout, no result | verified peer CANCEL, no result |
| both | expired after check | D+1 ns | CANCEL only | timeout, no result | verified peer CANCEL, no result |
| both | partial then crosses | 4 bytes at D−1 ns; next write at D | 4-byte prefix | `AbandonedPartialFrame`, no result | truncated frame + EOF, no result |

The reverse asymmetric completion is reproducible exactly as hypothesized, and only in the crossing case. The Initiator writes the complete final ACK, gets no result because the deadline (`>=`) is reached between the owner check and the confirmation, and the Responder verifies that ACK and holds the only result. That result is fully authenticated: the Initiator's final MAC proves it verified R's finish after both approvals.

One correction to the P5.1 text: R does not ignore I's following CANCEL as `Completed`. At Router level R's route was removed on success, so the CANCEL is an unknown route. That is session-fatal under P3 §11.2 and ends R's connection, and any sibling runs on it, after R already returned its result.

## 7. Router concurrency (ROUTER-RACE-001..009)

Each scenario runs forced interleavings and, where meaningful, barrier-released races. Forced interleavings use the existing per-thread pause points (`ResponderAdmitted`, `InitiatorStarted`, `CloseWaiting`, `DeadlineRunLocked`, `LocalRunLocked`), channel hand-offs, and an exact-state wait on the run's `Arc` holder count. In a barrier race the interleaving varies, and the invariants are checked for every outcome. Every hand-off times out after 10 s and fails the test instead of hanging. The default is 100 iterations, and 25 for scenarios that generate keys. `P5_RACE_ITERATIONS=<n>` scales a manual run.

| ID | Race | Iterations (forced + race) | Observed |
|---|---|---|---|
| 001 | close vs inbound delivery to a run | 25 + 25 | the entered operation keeps its outcome, then close terminates the run; or `UnknownSession` |
| 002 | close vs START admission | 25 + 25 | the paused admission sees CLOSING: no route, no ACCEPT, permit and slot released before close returns, limiter charge kept; races: refused at entry with no charge, or admitted then closed |
| 003 | close vs local Initiator creation | 100 + 100 | START suppressed, reservation released before close returns |
| 004 | duplicate / conflicting STARTs | 25×2 forced + 25 four-way races | identical copy during admission: `Duplicate`, uncharged; changed copy: both fail, nothing installed; four-way race: exactly one run, one charge |
| 005 | local callback vs deadline driver (expired run) | 100×2 orders | callback first: driver sees `Busy`, the callback's own deadline check ends the run; driver first: the callback then finds a terminal run (`NoLiveSas`); exactly one deadline outcome |
| 006 | the same after a real key exchange | 25×2 | exactly one authenticated timeout CANCEL, verified by the peer; guard released once; opportunity kept; no result |
| 007 | local callback vs close | 100 + 100 | an entered callback completes, then close; otherwise `UnknownSession` |
| 008 | deadline driver vs close (run live or expired) | 100×2 | driver finishes its one current run, then close completes |
| 009 | sibling progress vs another run's inactivity | 1 | no refresh: A expires at exactly 60 s |

The suite was also run five times at the defaults and once with `P5_RACE_ITERATIONS=500` (500 forced and 500 race iterations per scenario, 36 s); all passed. Across all iterations there was no deadlock, panic, double result, duplicate route, resource leak, output after close where forbidden, double guard release, or budget refund. Stale `RunRef`s were rejected (`UnknownRoute` / `UnknownSession`). In barrier races the close side usually wins. The forced orders exercise the other side deterministically every iteration.

**Session close sequences (`R-OWNER-040`).** ROUTER-RACE-001, -002, -003, -007, and -008 cover close interleaved with existing-run delivery, START admission, Initiator creation, local actions, and deadline expiry. Once close begins nothing new enters; an in-flight step settles; nothing installs after close; abandoned creation emits no ACCEPT or START; resources are released once. Close with pending output is the adapter's one teardown: the retained frame is discarded and nothing is written (P4 TCP and owner-loop teardown tests, re-exercised by TCP-W and TCP-OUT).

## 8. P5-F-002 evidence (F002-001, TCP-OUT-001)

Every clock is advanced by 24 h in hourly steps, with the owner loop's per-connection sweep after each step (frame-deadline poll, then ceremony-deadline poll):

| Case | State | Finite release today |
|---|---|---|
| A | admitted, zero bytes | **no** (live 1 after 24 h) |
| B | complete START admitted, its run ended by its own deadline, then idle | **no** (the run ends; the connection stays) |
| C | incomplete frame | yes (`WholeFrameTimeout` / `IdleTimeout`) |
| D | complete unroutable frame | yes (immediate close) |
| E | the Responder's owner-less timeout CANCEL retained for a peer that never reads | **no** (CANCEL retained after 24 h) |
| F | 16 idle connections, then a 17th | refused (`ResourceLimited`), as P5.1 showed |

TCP-OUT-001 separates output lifetime from ceremony lifetime:

- A frame a live run owns never outlives that run. At its deadline an unsent frame is discarded, and a partly sent one closes the connection.
- What replaces an unsent owned frame is the run's timeout CANCEL. That CANCEL, like a local REJECT's or CANCEL's frame, has no owner and no deadline. To a peer that never reads it stays forever, and while it is retained the socket is not read either.

**One root cause or several?**

| Question | A (first header) | B (idle, no live run) | C (owner-less output) |
|---|---|---|---|
| Code condition | no incomplete frame → no transport deadline | the same condition | the same condition; also no read while the frame is retained |
| Affected resource | one authority-wide live-connection slot (and session) | the same | the same, plus one retained frame ≤ 64 KiB |
| P3 requirement | §11.1.1 header/idle-read deadlines; lifetime and cleanup | §11.1.1 lifetime and cleanup | the same |
| Remediation | a finite connection lifetime or idle policy in the transport/adapter, decided once | the same policy | the same policy; it must explicitly also bound a retained owner-less frame |

They share one root cause: no connection-level lifetime exists outside an incomplete frame. They also share one resource, one P3 control, and one remediation decision, so they stay under **P5-F-002** as subcases A, B, and C rather than separate findings. Subcase C adds an explicit P6 requirement: whatever timer is chosen must also bound output that has no owner.

## 9. Findings produced

**No new findings** (no P5-F-023 or later). Candidates examined and not filed:

- The session-fatal stale route after a run ended (P3 §11.2; P5.1 note).
- The discarded complete suffix on hang-up, and the dropped pending output after a peer half-close. Both are the same root cause as P5-F-001 and are recorded as its subcases.
- The owner-less retained CANCEL (P5-F-002 C).
- The close side usually winning barrier races (scheduling, not a defect).

Existing findings changed: P5-F-001 strengthened, P5-F-002 strengthened with subcases, P5-F-007 reproduced and corrected ([findings](findings.md)). No severity or status changed, and the finding counts are unchanged.

## 10. How to run

```text
cargo test --manifest-path core/Cargo.toml                                   # CI tier (included)
cargo test --manifest-path core/Cargo.toml --lib p5_ -- --nocapture          # CI tier with family reports
cargo test --manifest-path core/Cargo.toml --lib p5_sm_deep p5_tcp_rd_deep -- --ignored --nocapture
P5_RACE_ITERATIONS=1000 cargo test --manifest-path core/Cargo.toml --lib p5_router_race
cargo test --manifest-path core/Cargo.toml --lib p5_f_00 -- --ignored --nocapture   # EXPECTED-FAIL reproducers
```

The CI tier adds about 23 s to `cargo test --lib` at four test threads (31 s against 8 s; 2026-10-02, Windows 11, rustc 1.99.0). The deep state-machine and read-sequence runs take about 2.5 min wall together on 16 threads. Reproducer classification: [reproducers](reproducers/README.md).

## 11. Limits

- Bounded spaces only: suffix depth 3 from honest prefixes, a reduced alphabet, representative chunk boundaries and `revents`.
- Not covered: arbitrary byte strings (codec mutation coverage is P4's), multi-router or multi-listener races beyond the transport cap tests, poisoned-lock interleavings beyond P4's tests, and exhaustive thread interleavings (no loom-style model checking).
- Real-socket facts are from one Windows build (Windows 11 Pro 26200) and CI's `windows-latest`.
- The honest peer is the same implementation as the target, so a symmetric defect in both could go unseen. The oracle checks relationships, not peer agreement.
