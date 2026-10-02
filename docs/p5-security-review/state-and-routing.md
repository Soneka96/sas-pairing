# P5 Analysis — State Machine, Duplicates, Router, Host

Reviewed source: `core/src/ceremony.rs`, `core/src/router.rs`, `core/src/host.rs` (production parts) at `e21ff0b`.

## 1. State transition table (rebuilt from `RemoteCeremony`)

Every inbound or local entry point runs through `step()`. The ceremony deadlines (and, for a pending Responder, the fixed 60 s lifetime) are enforced **first**. An expired run becomes terminal and the input is not applied. Inactivity restarts only when `progress_point()` changes, meaning a new state discriminant, a recorded exposure authorization, or a verified peer approval MAC.

Legend: **A** = applied and state advances (output in brackets); **D** = exact duplicate of the accepted frame for that run and type, ignored with no output and no MAC or crypto work; **F** = terminal failure (changed duplicate, wrong state, wrong role, failed validation, MAC failure; no result); **N** = refused with no effect (stale identity, not yet allowed, already done); **C** = `Completed`, no effect; **—** = not reachable through the Router. "R:" and "I:" mark role-specific rows.

| State (role) | START | ACCEPT | I_KEY | R_KEY | B_MAC | I_FIN | R_FACK | I_FACK | CANCEL | Local actions |
|---|---|---|---|---|---|---|---|---|---|---|
| `InitiatorCreated` (I) | — | — | — | — | — | — | — | — | — | `start()` → A [START]. The Router calls it before installing the route. |
| `InitiatorAwaitAccept` (I) | F | A (validate request ID, context, expected peer) or F | F | F | F | F | F | F | F | `authorize`/`expose_key` → F |
| `InitiatorAwaitAuthorization` (I) | F | D / F | F | F | F | F | F | F | F | `authorize` → A (records). Repeat → F. `expose_key` with authorization → permit, reserve → A [I_KEY] or F (Busy, Exhausted, no permit); without → F |
| `InitiatorAwaitResponderKey` (I) | F | D / F | F | A (commitment, then DH, transcript, SAS) or F | F | F | F | F | F | — |
| `ResponderAcceptSentAwaitInitiatorKey` (R) | D / F | F | A (permit, DH; non-contributory → F) | F | F | F | F | F | F | `authorize`/`expose_key` → F |
| `ResponderAwaitAuthorization` (R) | D / F | F | D / F | F | F | F | F | F | F | `authorize` → A. `expose_key` with authorization → reserve, transcript, SAS, release pending slot → A [R_KEY] or F |
| `AwaitLocalApproval` (both) | R: D / F | I: D / F | R: D / F | I: D / F | A (peer Verified) / D / F | F | F | F | verified → terminal (peer cancel) / F | `presentation` → Some (read-only). `approve_sas(cid)` → A; other cid → N. `reject`/`cancel(cid)` → terminal [CANCEL]. `emit_bootstrap_mac` → N. `emit_initiator_finish` → N |
| `LocallyApprovedAwaitingAuthentication` | as above | as above | as above | as above | A / D / F | F | F | F | as above | `approve` → N (AlreadyRecorded). `emit_bootstrap_mac` → A [B_MAC]. `reject`/`cancel` → terminal |
| `LocalMacSentAwaitingPeerMac` | as above | as above | as above | as above | A → `ApprovalsAuthenticated` / F | F | F | F | as above | `emit_bootstrap_mac` → N (AlreadyEmitted). `reject`/`cancel` → terminal |
| `ApprovalsAuthenticatedAwaitingCompletion` | as above | as above | as above | as above | D / F | R: A [R_FACK] or F; I: F | F | F | as above | I: `emit_initiator_finish` → A [I_FIN]. R: → N (NotInitiator) |
| `AwaitResponderFinish` (I) | — | D / F | — | D / F | D / F | F | A [I_FACK, pending send] or F | F | as above | `emit_initiator_finish` → N (AlreadyEmitted) |
| `AwaitInitiatorFinishAck` (R) | D / F | — | D / F | — | D / F | D (AlreadyAccepted) / F | F | A → **Succeeded** or F | as above | — |
| `AwaitInitiatorFinishAckSend` (I) | — | D / F | — | D / F | D / F | F | D / F | F | as above | `confirm(sent)`: exact bytes → **Succeeded**; other bytes → N; deadline expired → terminal [timeout CANCEL] |
| `Succeeded` | C | C | C | C | C | C | C | C | C | Every action → N or C. Removed from the Router by the operation that succeeded. |
| `Terminal` | F (no change) | … | … | … | … | … | … | … | … | Every action → N or error. Removed from the Router. |

**Asymmetry review (I vs R).** Intended P3 asymmetries: R keeps START in `seen`, I does not, so a START at an Initiator's key is a conflict. R performs DH before authorization and I after. R carries the pending-slot lifetime. I emits `INITIATOR_FINISH` only as a local action, while R's `RESPONDER_FINISH_ACK` and I's final ACK are produced automatically on verification. I succeeds only on send confirmation, R on verification. No unintended asymmetry found.

**Specific checks:**

- *State changed before verification:* receive paths take the old state with `mem::replace(…, Terminal)`. Failure leaves `Terminal`; success installs the next state. A panic mid-step therefore leaves `Terminal`, the conservative direction.
- *Guard released before secret invalidation:* every terminal path (`terminate`, `fail`, `succeed`, `Drop`) assigns the state (dropping `SasSession`/`EstablishedSas`/`EphemeralSas`) **before** `CeremonyExecutor::terminate` or `Ceremony::drop` releases the guard.
- *Result before cleanup certainty:* `succeed` installs `Succeeded` only after the guard release returns `Ok`.
- *Second output:* emissions are one-shot (`AlreadyEmitted`/`AlreadyRecorded`), duplicates produce nothing, and the Router removes finished runs.
- *Late callback after terminal:* `live_session` fails (`NoLiveSas`), and the Router's `RunRef` instance check fails (`UnknownRoute`).
- *Authorization misuse:* `authorize` outside an eligible state, or a second time, fails the run (F). That is fail-closed, but a stale local `authorize` on a live run kills it rather than being ignored. This is local-caller behavior and consistent with I1. No finding.

## 2. Duplicate semantics

P4's [duplicate table](../p4-conformance-closure.md#duplicate-semantics) was re-derived from `RemoteCeremony::duplicate`, `Router::classify_start`, and the receive entry points, and it matches. Points to note:

- `duplicate(kind, bytes)` runs **before** the state check, so an exact copy of an accepted frame is ignored in any later live state. A changed copy fails the run. `seen` keeps at most one copy per type (at most 7 entries, each at most 65,536 bytes) and is cleared at success.
- An exact duplicate of a terminal run's last frame, at Router level, reaches no run (the route was removed), so it is a stale route → session-fatal. That is P3 §11.2 behavior ("unknown or stale"). Under TCP this needs a misbehaving peer, because TCP does not duplicate segments into the byte stream.

## 3. Router and session isolation

| Attack | Result |
|---|---|
| The same request ID on two sessions | Two `RoutingKey`s, two independent runs. The START limiter is charged twice (two candidates) |
| Request ID replaced after a run ended | The key is reusable. Local actions carry a `RunRef` whose `instance` (the never-reissued `Ceremony` id) is rechecked under the run lock, so a stale reference never reaches the replacement |
| Stale `RunRef` from another session | `target.session != session` → `UnknownRoute` |
| Session close while a START is admitted | `begin_close` linearizes in the table critical section. The admission finishes outside the lock, sees `closing`, discards its run (slot and permit released), returns no ACCEPT, then drops its lease. Teardown waits for the lease |
| Close while a run operation is active | Teardown waits on the lifecycle condvar for `in_flight == 0`, then detaches routes and terminates runs |
| Unknown route (non-START) | The session becomes CLOSING in the same critical section that found no route. No run is guessed. Teardown follows. Other sessions are untouched |
| Concurrent duplicate START | The `Admitting` claim keeps the exact bytes: a copy is a duplicate (no charge), a changed one marks the claim conflicted (its admission is discarded) |
| Non-START for an `Admitting` key | Marks it conflicted. Out of order for that key only |
| Session reuse | Session numbers are never reissued, and exhaustion fails closed |
| Router drop | Every routed run drops, so its guard, slot, and request ID are released |
| Request-ID-only authority | **Not found.** Every lookup is by `(session, request_id)`. The final-ACK confirmation uses a non-exact key but must match the exact pending bytes, which carry a cid-bound MAC ([P5-F-019](findings.md#p5-f-019)) |

**Lock order.** run → table → lifecycle (leaf), and authority `shared` only under a run lock or with nothing held. Verified for `route_start` (admission with no router lock), `remove_finished` (table under run), `teardown` (run locks after the table is released), `poll_run` (`try_lock`), and `start_initiator_run` (`shared` before `table`). No inversion found. Teardown waits only on the condvar with no other lock held.

**Deadline driver.** At most 8 route inspections per call, one ordered-map seek each, a cursor that wraps at most once, skipping busy or admitting entries without waiting, and stopping at the first terminal outcome. Every continuously live run is reached. No starvation.

**Panic inside Router-managed work** ([P5-F-005](findings.md#p5-f-005)): an entropy panic during Responder admission unwinds out of `route_start` and leaves its `Route::Admitting` claim installed until session teardown, because no RAII guard removes it. A panic during an Initiator `expose_key` under `with_exact_run` poisons the run mutex. Later deadline polls and the session teardown then report `OwnershipUncertain`, so the session stays CLOSING and its live-connection count stays held. Both are fail-closed. Accounting and the no-success property hold.

## 4. Host facade and local callback targeting

- `dispatch` classifies with `protocol::routable` (common fields, and the START candidate structure only). Unroutable → the connection ends before any Router state. START goes to `receive_start_run` (admission); non-START goes to `deliver` (existing runs only).
- `ends_session` is `SessionProtocolFailure`, `UnknownSession`, or `OwnershipUncertain`. Every other Router error is run-local and the connection stays live.
- Local actions (`authorize_exposure`, `expose_key`, `approve_sas`, `emit_bootstrap_mac`, `reject_sas`, `cancel_sas`, `emit_initiator_finish`, `presentation`) each make exactly one call to one `RemoteCeremony` entry point through `with_exact_run`. The host chains nothing: authorization never exposes, MATCH never emits, and a MAC never emits a finish.
- **Send-confirmation boundary:** `Outbound::FinalAck` carries the session, request ID, and exact bytes. It is not `Clone`, and only this module creates one. `confirm_sent` rejects another session's token. The run compares the exact pending bytes.
- Diagnostic labeling: an exact duplicate of `RESPONDER_FINISH_ACK` at I is reported as `HostEvent::InitiatorFinishDuplicate`, a label only. No behavioral effect, no finding.

## 5. P5.2 generated-sequence and concurrency evidence

P5.2 checked the table above under bounded sequences instead of single transitions. Full method, counts, and tables: [adversarial sequences](adversarial-sequences.md).

- **Generated sequencing (§2 there).** Each role was explored from every honest state with every suffix of up to three actions over a 25-action alphabet: valid, duplicated, changed, injected, future, reflected, wrong-role, and wrong-request-ID frames; every local action; polls, expiry, and close. That is 835 sequences in CI (with verified no-op reduction) and 35,684 in the manual deep run (unreduced). No invariant failed. The only injected frames ever accepted were the unauthenticated pre-SAS ACCEPT and INITIATOR_KEY, and those runs never reached a result.
- **Terminal irreversibility.** A 12-action post-terminal battery ran after every terminal state reached: failure, timeout, peer CANCEL, local reject or cancel, close, and success. It produced no output, result, exposure, or state change.
- **Duplicates and reordering.** The DUP-001 matrix (55 cells) matches the duplicate table of §2: exact copies and older exact copies are ignored with no effect at all (no output, state, `seen`, or deadline change); every other variant is terminal; after success, everything is `Completed` with no effect.
- **Local actions and stale references.** Approve before SAS, approve twice, reject or cancel then approve, approve after expiry, MAC or finish twice, and stale identities are all refusals with no effect (fingerprint unchanged). Authorize twice and expose without authorization are terminal with nothing spent. This is the fail-closed behavior already noted in §1.
- **Router concurrency (§7 there).** ROUTER-RACE-001..009 force both orders of every linearization point (close vs delivery, START admission, Initiator creation, local callback, and deadline driver; duplicate and conflicting STARTs; callback vs timeout before and after SAS), repeated 25–100 times, plus barrier races. There was no deadlock, leak, double result, double guard release, or refund, and stale `RunRef`s were rejected. This supports the lock-order and linearization reading of §3. Surface #19 is now `COMPLETE` in [coverage](coverage.md).
