# P6 Owner Decisions

Stable owner decisions taken during P6. IDs `P6-D-NNN` are never reused. A decision records policy and values; the remediation record of each finding traces how it was implemented and verified.

## P6-D-001 — F-002 connection lifetime

- **Finding:** [P5-F-002](../p5-security-review/findings.md#p5-f-002) (MEDIUM): an admitted connection with no frame in progress had no finite lifetime.
- **Requirement:** P3 §11.1.1 ("Incoming connections", "Incomplete frame reception", "Lifetime and cleanup") already required finite header and idle bounds; it did not fix their model or values. This decision selects them.
- **Decision (owner-selected timer model):**

| Connection state | Governing deadline | Refreshed by |
|---|---|---|
| Admitted, before its first incoming frame begins | **10 s** from admission, monotonic and absolute for that wait | Nothing: not readiness, WouldBlock, empty polls, writes, or invalid or no-op activity |
| Inbound frame incomplete | The existing **10 s** whole-frame and **2 s** no-progress deadlines, unchanged | Retained-byte progress (the 2 s deadline only), as before |
| Live ceremony (a live run on the connection's session) | The existing ceremony deadlines (**5 min** absolute, **60 s** inactivity, **60 s** pending pre-exposure), which stay authoritative | As P3 §11.3 and §11.1.1 already define |
| No live run, no inbound frame in progress, no outbound frame pending (quiescent) | **10 s** quiescent deadline | Nothing but a new valid frame that leaves a live run; then the connection is no longer quiescent |
| Outbound frame retained with no live run owning the connection (owner-less output) | **10 s** absolute and **2 s** without write progress, from when the output becomes owner-less | Meaningful write progress refreshes the 2 s deadline only, never the 10 s one |

- A first byte accepted just before the first-frame deadline receives the normal whole-frame window; that stays finitely bounded.
- While a live ceremony exists, ceremony deadlines are authoritative. A valid ceremony waiting for local authorization, SAS comparison, approval, or another local action is never closed merely because no socket byte moved for 10 s.
- A quiescent connection is not kept for hypothetical reuse; 10 s allows immediate reuse while bounding the authority-wide live-connection resource.
- On owner-less output expiry the retained output is discarded and the connection closed. No result is manufactured from a partial write.
- Every expiry closes the connection through the existing teardown: the Router session is settled, then the live-connection permit is released exactly once. No START limiter, budget, guard, or other accounting change.
- Expiry is `now >= deadline` on the existing injected monotonic clocks.
- Not refreshed by: WouldBlock, Interrupted, empty owner-loop drives, repeated readiness, exact duplicates that create no new live work, malformed input, wrong request IDs, wrong-state input, failed admission, or local read-only actions.
- TCP keepalive is not part of the remediation (optional defense in depth only, not added in P6.1).
- **Wire, cryptography, and ceremony authentication:** unchanged.
- **Status:** decided by the owner for P6.1, 2026-10-02.

## P6-D-002 — F-003 owner-session policy

- **Finding:** [P5-F-003](../p5-security-review/findings.md#p5-f-003) (LOW): releasing and re-registering the same authority inside one live native process starts a fresh ten-opportunity budget and START limiter.
- **Decision:** **keep the current P3 process/session semantics.** The owner session is **not** redefined as the `TrustedAuthority` registration lifetime, and P3 is not changed to ratify the current implementation.
- **Consequence:** P6 will change the implementation so that release and re-registration inside the same native process does not silently create a fresh ten-opportunity budget or START limiter for the same authority. A fresh budget stays tied to the previous owning process having terminated and exclusive ownership having been safely established (P3 §11.1, §11.1.2(5); `R-OWNER-006`, `R-OWNER-022`, `R-OWNER-038(c)`).
- **Implementation:** a later P6 increment. P6.1 records the decision only and changes no F-003 behavior; the existing re-registration assertions in `core/tests/security_core.rs` stay as they are until then.
- **Status:** decided by the owner, 2026-10-02 (taken early, as P5 requested, because the alternative would have revised P3 policy before the protocol freeze).

## P6-D-003 — Graceful TCP hang-up handling

- **Finding:** [P5-F-001](../p5-security-review/findings.md#p5-f-001) (LOW): the experimental Windows owner loop treated `POLLHUP` like an error and closed the connection before any read or write, discarding complete frames the peer sent before its graceful close (including a delivered final `INITIATOR_FINISH_ACK`), input already retained in the adapter, and the loop's own pending output to a peer that had only half-closed.
- **Requirement:** existing P3 semantics, unchanged: received stream input is assembled into frames (§3.1, `R-WIRE-025`); the Responder's result follows verification of `INITIATOR_FINISH_ACK` (§9, `R-MAC-012`); a disconnect yields no result only when it comes *before* a participant's local condition is met. This decision records how the adapter's readiness handling meets them; it adds no protocol rule.
- **Decision (established connections):**
  - `POLLERR` and `POLLNVAL` stay **hard failures**: the connection closes immediately, before any further read or write, whatever else is reported with them (`POLLIN`, `POLLOUT`, `POLLHUP`, or input already retained in the adapter).
  - `POLLHUP` alone is **not** a failure. A graceful peer FIN or send-half-close ends only the peer's sending direction: the peer's earlier bytes may still be readable by us, and the peer may still receive our bytes. `POLLHUP` therefore never discards readable or retained input and never discards pending output.
  - With an outbound frame retained: writable readiness (also together with `POLLHUP`) makes one write; `POLLHUP` without writable readiness makes no socket I/O and closes nothing; readable readiness never reads past the retained frame (write backpressure is unchanged).
  - With no outbound frame retained: readable readiness, `POLLHUP` alone, or input already retained in the adapter makes one read step through the adapter (retained input first, then at most one OS read). A pure `POLLHUP` is enough for that read.
  - The connection closes only when a read returns EOF (`0`, the existing `PeerClosed` path, which is the graceful-close boundary), on an actual socket I/O error, on `POLLERR`/`POLLNVAL`, or by the existing deadline and teardown policy. EOF never completes a partial frame.
  - At most one adapter socket operation per connection per owner-loop drive, as before: no drain-to-EOF, read-until-WouldBlock, or write-all loop. A persistent hang-up is drained across later drives.
  - Deadlines keep their precedence: the deadline sweep runs before any socket I/O, so an expired connection, frame, or ceremony deadline wins over hang-up and readable data in the same drive. No hang-up-specific timer is added. A half-closed peer that never reaches EOF, or never accepts our output, stays bounded by the existing P6-D-001 first-frame, quiescent, incomplete-frame, and owner-less-output deadlines and by the ceremony deadlines.
  - A graceful close is transport information only. It never creates a `PairingResult`, confirms an unread final ACK, approves an SAS, refunds an opportunity, or implies peer rejection, compromise, or identity. A result still arises only from verifying an actually received frame.
- **Listener:** unchanged. `POLLERR`, `POLLHUP`, or `POLLNVAL` on the listener still drops it.
- **Wire, cryptography, ceremony authentication, and accounting:** unchanged.
- **Status:** decided by the owner for P6.2, 2026-10-02.

No decision is recorded yet for P5-F-005 or P5-F-007; both stay OPEN (INFO).
