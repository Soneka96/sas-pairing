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

No decision is recorded yet for P5-F-005 or P5-F-007; both stay OPEN (INFO).
