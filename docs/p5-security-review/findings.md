# P5 Findings

Findings of the P5 implementation and protocol security review of the frozen P4 core (`e21ff0b`). Method: [review-method.md](review-method.md). P5 records findings and does not remediate production behavior; [P6](../../roadmap/P6-review-remediation-and-protocol-freeze.md) does.

## Finding format

Every finding has these fields: **Title**, **Status**, **Severity**, **Confidence**, **Affected requirement(s)**, **Affected code**, **Threat scenario**, **Preconditions**, **Reproduction**, **Security impact**, **Why existing tests/conformance did not catch or prevent it**, **Recommended remediation**, **P6 disposition**, **Evidence**. IDs are stable and never reused.

### Severity (impact under realistic supported assumptions)

| Severity | Meaning |
|---|---|
| CRITICAL | Likely enables fundamental pairing-security failure: success without SAS agreement, remote exposure of secret material, or a material multiplication of security attempts by bypassing ownership or accounting. |
| HIGH | Serious security-property failure requiring important remediation. |
| MEDIUM | Security-relevant weakness with meaningful constraints or preconditions. |
| LOW | Defense-in-depth or narrow robustness weakness with limited security effect. |
| INFO | Observation, hardening opportunity, or assurance limitation with no demonstrated security violation. |

For `FALSE-POSITIVE` entries, severity is the severity the candidate **would have had if real**, so the summary shows what was ruled out.

### Confidence (certainty the finding is real)

| Confidence | Meaning |
|---|---|
| HIGH | Reproduced, or follows deterministically from source with no unverified premise. |
| MEDIUM | Follows from source but depends on an unverified external behavior. |
| LOW | Plausible, not confirmed. |

### Status

`OPEN` (confirmed defect, or confirmed mismatch with the current normative baseline; remediation recommended, even where the remedy's design or values still need an owner decision) · `NEEDS-DECISION` (confirmed behavior where whether the current normative baseline is violated depends on an unresolved owner interpretation; no finding currently has this status) · `FALSE-POSITIVE` (disproved) · `ACCEPTED-LIMITATION` (already accepted by an owner decision or the normative profile; re-confirmed here) · `OUT-OF-SCOPE` · `DUPLICATE` · `REMEDIATED-IN-P6` (not used in P5; set by P6 only after its closure bar is met, with the P5 entry otherwise preserved) · `DISPOSITIONED-IN-P6` (not used in P5; not a remediation claim; set by P6 when the reviewed behavior needs no P6 production fix and an owner decision either (A) accepts the current behavior and makes all required protocol and documentation semantics explicit, as for P5-F-007, or (B) accepts the current core behavior and assigns a mandatory implementation obligation to the later phase that owns the affected interface, as for P5-F-005).

## Summary

**P6 status update (P6.6, 2026-10-02):** [P5-F-002](#p5-f-002) is **REMEDIATED-IN-P6** under owner decision P6-D-001 ([remediation record](../p6-remediation/p5-f-002.md)), [P5-F-001](#p5-f-001) is **REMEDIATED-IN-P6** under owner decision P6-D-003 ([remediation record](../p6-remediation/p5-f-001.md)), and [P5-F-003](#p5-f-003) is **REMEDIATED-IN-P6** under owner decision P6-D-002 ([remediation record](../p6-remediation/p5-f-003.md)). [P5-F-005](#p5-f-005) is **DISPOSITIONED-IN-P6 (P6.4) — mandatory P7 ABI containment requirement** under owner decision P6-D-004 ([disposition record](../p6-remediation/p5-f-005.md)). [P5-F-007](#p5-f-007) is **DISPOSITIONED-IN-P6 (P6.5) — current conservative completion boundary retained and documented** under owner decision P6-D-005 ([disposition record](../p6-remediation/p5-f-007.md)). No finding that P5 handed to P6 as OPEN remains OPEN, and P6.6 closed P6 with the experimental protocol-candidate freeze ([P6 final closure](../p6-remediation/final-closure.md)); the accepted limitations and false positives below are unchanged. Current remediation status lives in the [P6 remediation package](../p6-remediation/README.md); the summary table and closure note below are the P5 closure snapshot and are left as P5 recorded them.

| Severity | Open | False Positive | Accepted Limitation | Out of Scope |
|---|---|---|---|---|
| CRITICAL | 0 | 1 (P5-F-013) | 0 | 0 |
| HIGH | 0 | 5 (P5-F-014, 017, 018, 019, 022) | 0 | 0 |
| MEDIUM | 1 (P5-F-002) | 3 (P5-F-015, 020, 021) | 0 | 0 |
| LOW | 2 (P5-F-001, 003) | 1 (P5-F-016) | 0 | 0 |
| INFO | 2 (P5-F-005, 007) | 1 (P5-F-006) | 6 (P5-F-004, 008–012) | 0 |

**No CRITICAL or HIGH finding is confirmed.** Nothing was found that yields pairing success without SAS agreement, exposes secret material remotely, or bypasses the one-owner / one-guard / ten-opportunity accounting under one registration. Across registrations inside one live process the budget does reset, contrary to the current P3 process/session policy; trusted local code, not a remote peer, must trigger it ([P5-F-003](#p5-f-003)).

Not every OPEN finding needs a production change. The INFO findings may close as hardening or documentation decisions in P6.

**P5 closure (P5.4):** P5 closed with **5 OPEN findings handed to P6** (P5-F-001, 002, 003, 005, 007), 6 accepted limitations, and 11 false positives, 22 in total. **No finding was remediated in P5**, and none is marked REMEDIATED-IN-P6, because P6 has not happened. P5.4 re-checked every entry and changed no ID, title, severity, confidence, or status. The P6 disposition table and recommended order are in the [final synthesis](final-synthesis.md#10-p6-handoff).

**P5.3 update** ([dependency, unsafe, and secret-lifetime deep review](dependency-unsafe-deep-review.md)): **no new finding.** Three findings were reclassified or strengthened from locked upstream source, primary Windows documentation, and new deterministic evidence. **P5-F-004** OPEN → ACCEPTED-LIMITATION: the unsafe reads rely on a Windows postcondition that the documented API implies but does not state in words; it holds empirically, and only a compromised OS (out of scope) could break it. **P5-F-006** OPEN → FALSE-POSITIVE: `URL_SAFE_NO_PAD` is the scalar, safe `GeneralPurpose` engine, the `simd-unsafe` engines are unreachable, and the encoder matched an independent reference for every length 0..=65,536. **P5-F-005** strengthened (reproduced through Router, adapter, and owner loop; new availability residue) and still OPEN for the panic-policy decision. **P5-F-010** strengthened (rand `ThreadRng` keeps upstream copies of the ephemeral key) and still accepted. **P5-F-009** unchanged. No severity rose.

**P5.2 update** ([adversarial sequences](adversarial-sequences.md)): bounded generated sequences (36,519 state-machine sequences, plus duplicate, deadline, stream, socket-script, readiness, and Router-race families) produced **no new finding** and no change of severity, status, or counts. P5-F-001 was strengthened: real-Windows matrix, the end-to-end final-ACK reproducer, and two subcases (a discarded buffered suffix; dropped pending output after a peer half-close). P5-F-002 was strengthened with subcases A (first header), B (idle after its run), and C (owner-less retained output), kept as one finding. P5-F-007 was reproduced end to end and its description corrected; it stays INFO.

## Finding index

| ID | Title | Severity | Confidence | Status |
|---|---|---|---|---|
| [P5-F-001](#p5-f-001) | Owner loop discards bytes received before a graceful peer close | LOW | HIGH | REMEDIATED-IN-P6 (P6.2; OPEN at P5 closure) |
| [P5-F-002](#p5-f-002) | Connections with no frame in progress never expire, so 16 idle peers hold the live-connection cap indefinitely | MEDIUM | HIGH | REMEDIATED-IN-P6 (P6.1; OPEN at P5 closure) |
| [P5-F-003](#p5-f-003) | In-process re-registration starts a fresh opportunity budget without process replacement | LOW | HIGH | REMEDIATED-IN-P6 (P6.3; OPEN at P5 closure) |
| [P5-F-004](#p5-f-004) | `token_user_sid` does not bound the OS-written SID to the returned buffer | INFO | HIGH | ACCEPTED-LIMITATION (P5.3) |
| [P5-F-005](#p5-f-005) | `Sas::new()` entropy panic leaves Router and adapter state conservatively stuck and escapes owner-loop calls | INFO | HIGH | DISPOSITIONED-IN-P6 (P6.4; mandatory P7 ABI containment requirement; OPEN at P5 closure) |
| [P5-F-006](#p5-f-006) | `base64`'s default `simd-unsafe` engine encodes every MAC and HKDF input | INFO (if real) | HIGH | FALSE-POSITIVE (P5.3) |
| [P5-F-007](#p5-f-007) | Reverse asymmetric completion at the Initiator's deadline boundary | INFO | HIGH | DISPOSITIONED-IN-P6 (P6.5; conservative completion boundary retained and documented; OPEN at P5 closure) |
| [P5-F-008](#p5-f-008) | Same-profile attacker can race the lock-path checks (TOCTOU) | INFO | HIGH | ACCEPTED-LIMITATION |
| [P5-F-009](#p5-f-009) | Fork, snapshot, restore, or duplicated state can repeat ephemeral material | INFO | HIGH | ACCEPTED-LIMITATION |
| [P5-F-010](#p5-f-010) | Secret remanence beyond the x25519-dalek drop boundary | INFO | HIGH | ACCEPTED-LIMITATION |
| [P5-F-011](#p5-f-011) | Monotonic time across system suspend is unverified | INFO | MEDIUM | ACCEPTED-LIMITATION |
| [P5-F-012](#p5-f-012) | An unauthenticated peer can saturate START admission and pending capacity | INFO | HIGH | ACCEPTED-LIMITATION |
| [P5-F-013](#p5-f-013) | More than ten contributions under one owner session | CRITICAL (if real) | HIGH | FALSE-POSITIVE |
| [P5-F-014](#p5-f-014) | Equivalent X25519 encodings allow an equal-SAS substitution | HIGH (if real) | HIGH | FALSE-POSITIVE |
| [P5-F-015](#p5-f-015) | Codec accepts two byte strings for one semantic message | MEDIUM (if real) | HIGH | FALSE-POSITIVE |
| [P5-F-016](#p5-f-016) | Non-constant-time comparisons leak secret material | LOW (if real) | HIGH | FALSE-POSITIVE |
| [P5-F-017](#p5-f-017) | Request-ID-only authority, or a stale `RunRef` reaching a replacement run | HIGH (if real) | HIGH | FALSE-POSITIVE |
| [P5-F-018](#p5-f-018) | Scope aliasing multiplies authorities inside the core | HIGH (if real) | HIGH | FALSE-POSITIVE |
| [P5-F-019](#p5-f-019) | Final ACK confirmed for another run under a reused key | HIGH (if real) | HIGH | FALSE-POSITIVE |
| [P5-F-020](#p5-f-020) | Shared counters underflow or wrap in release builds | MEDIUM (if real) | HIGH | FALSE-POSITIVE |
| [P5-F-021](#p5-f-021) | START limiter grants extra credit at boundaries or after idle | MEDIUM (if real) | HIGH | FALSE-POSITIVE |
| [P5-F-022](#p5-f-022) | A reflected BOOTSTRAP_MAC, CANCEL, or finish message is accepted | HIGH (if real) | HIGH | FALSE-POSITIVE |

## Confirmed findings

<a id="p5-f-001"></a>
### P5-F-001 — Owner loop discards bytes received before a graceful peer close

- **Status:** REMEDIATED-IN-P6 (P6.2). OPEN at P5 closure; the P5 record below is unchanged and the P6 note is appended at the end of this entry.
- **Severity:** LOW
- **Confidence:** HIGH
- **Affected requirement(s):** P3 §9 (the Responder's result follows verification of INITIATOR_FINISH_ACK); P3 §3.1 and `R-WIRE-025` (received input is assembled into frames); `R-MAC-012`.
- **Affected code:** `core/src/windows_owner_loop.rs:82` (`FAILED = POLLERR | POLLHUP | POLLNVAL`) and `:352–356` (FAILED readiness → `close()` before any read). The behavior is documented as intended in the module docs (lines 18–19).
- **Threat scenario:** An honest Initiator writes its final INITIATOR_FINISH_ACK, receives its result, and closes the TCP connection, which is a natural application pattern. On the Responder hosted by the owner loop, if the FIN has arrived by the next `WSAPoll`, Windows reports `POLLHUP | POLLRDNORM` while the final ACK is still readable. The loop closes without reading, so the Responder never verifies the final ACK and ends without a result. The same happens to any frame followed by a close or half-close, for example a START from a client that shuts down its write side.
- **Preconditions:** The experimental owner loop is the receiving side. The peer closes gracefully right after writing. The loop's next readiness wait happens after the FIN arrived; this is timing-dependent and likely on loopback or when the loop is busy.
- **Reproduction:**
  1. `core/tests/p5_review_evidence.rs::p5_f_001_wsapoll_reports_hang_up_while_written_bytes_remain_readable` (passing, in CI) pins the OS fact: after a graceful close, `revents` contains `POLLHUP` and `POLLRDNORM`, and the 11 written bytes are still readable before EOF.
  2. [Reproducer patch](reproducers/README.md), test `windows_owner_loop::tests::p5_f_001_a_complete_frame_before_a_graceful_close_is_dispatched`: a peer writes one complete START and closes. Observed `Closed(…, Readiness(258))` (258 = `0x0102` = `POLLHUP | POLLRDNORM`), and the START limiter is untouched (`tokens: 4, rolling: 0`), so the START never reached the Router. 5 of 5 runs, Windows 11 Pro 26200, rustc 1.99.0.
  3. The existing P4 test `windows_owner_loop::tests::error_or_hang_up_readiness_closes_a_connection_before_any_read_or_write` asserts the scripted `POLLHUP | POLLRDNORM` → close-before-read.
  4. **P5.2, real Windows, production owner loop and `WSAPoll`** ([adversarial sequences §5](adversarial-sequences.md#5-p5-f-001-evidence-real-windows-and-scripted)). Each case waits for hang-up readiness on the loop's socket without reading, so the timing is deterministic with no sleep. A full frame then close, a full frame then `shutdown(Send)`, and two frames then close each report `0x0102`, close as `Readiness(258)`, and dispatch 0 complete frames. A partial frame then close dispatches nothing, which is correct.
  5. **P5.2 end-to-end final-ACK consequence, now executed:** a real ceremony with the loop as Responder; the Initiator writes its final ACK, has its result, and closes at once. The loop reports `0x0102`, closes without reading, and the Responder gets no result. Test `p5_loop_hup_002_real_final_ack_then_close_is_safe` (passing, records the outcome) and the EXPECTED-FAIL reproducer `p5_f_001_owner_loop_responder_loses_final_ack_before_graceful_close` (`#[ignore]`).
  6. **P5.2 additional subcases, same root cause:** (a) a complete frame *already read* into the adapter's retained suffix is discarded when hang-up is then reported (scripted LOOP-READY-001, `Buffered | POLLHUP*` rows). (b) **write side:** when the peer half-closes (`shutdown(Send)`) while the loop holds an unwritten frame, Windows reports `POLLHUP | POLLWRNORM` (`0x0012`) and the loop closes without writing (`p5_loop_hup_003_real_half_close_while_output_pending`; EXPECTED-FAIL `p5_f_001_owner_loop_writes_pending_output_after_peer_half_close`). A Responder that half-closes after RESPONDER_FINISH_ACK, when it has nothing more to send, would make an owner-loop Initiator drop its own final ACK, and then neither side gets a result.
  7. Safety held in every P5.2 case: no result from an incomplete or unread frame, no second result, no result for another run, and exact cleanup (`p5_f001_001_scripted_final_ack_with_hang_up_fails_closed_safely`, LOOP-HUP-001..003).
- **Security impact:** No false success and no authentication or accounting effect: the Responder fails closed. It turns a *delivered* final ACK into the "Initiator succeeded, Responder has no result" outcome that P3 §9 attributes to message loss, and it can do so routinely when Initiators close promptly. Consumers may then hold one-sided trust, which P3 already requires them to tolerate. It also drops frames from half-closing peers, frames already buffered in the adapter, and (write side) the loop's own pending output to a half-closed peer, which can make both sides fail. This is a robustness and interoperability defect of the experimental adapter. P5.2 confirmed that the behavior is fail-closed in every case; the severity stays LOW.
- **Why existing tests/conformance did not catch or prevent it:** P4 intended "hang-up closes without I/O", and its scripted test asserts that. The real-loopback hang-up test accepts either `Readiness` or `PeerClosed` with no data in flight. The real-loopback full ceremony runs the loop as Initiator only. Windows' report of hang-up together with readable data was never pinned.
- **Recommended remediation:** Treat `POLLHUP` without `POLLERR`/`POLLNVAL` as "readable until EOF": keep serving `on_readable` (retained suffix, then socket) one bounded operation per drive, and close only on `read() == 0` or an error. While a frame is retained, keep serving `on_writable` on writable readiness, because a half-closed peer still receives. Keep `POLLERR`/`POLLNVAL` as immediate close. A peer that never sends EOF stays bounded by the transport and ceremony deadlines (and by the P5-F-002 lifetime once remediated). Regression tests: enable the three P5.2 `#[ignore]` reproducers (complete frames before close or half-close, the loop-as-Responder final ACK, and pending output after a half-close).
- **P6 disposition:** Remediate (adapter-only, no protocol change). Enable the P5.2 EXPECTED-FAIL reproducers as regression tests. The OS-fact test and LOOP-HUP-001..003 stay as durable evidence.
- **Evidence:** the tests above; [adversarial sequences §4–§5](adversarial-sequences.md#4-owner-loop); [resources, deadlines, and transport §5–§6](resources-deadlines-transport.md#5-owner-loop); [reproducers](reproducers/README.md).
- **P6 remediation (appended in P6.2; the P5 record above is unchanged):**
  - **Decision:** [P6-D-003](../p6-remediation/decisions.md#p6-d-003--graceful-tcp-hang-up-handling): on an established connection `POLLERR` and `POLLNVAL` stay hard failures that close before any I/O; `POLLHUP` alone is a graceful peer FIN, drained toward EOF one operation per drive, and never suppresses a retained frame's write. Listener readiness is unchanged.
  - **Remediation commit:** `c4212f201540e537e95a04233b19bf47e5df1b3f` (`fix: drain graceful hang-up before close`) on `feature/p6-review-remediation-protocol-freeze`. Owner-loop readiness classification only (`CONNECTION_FAILED`, `READABLE`, `LISTENER_FAILED`); the adapter, the P6-D-001 lifetime that bounds a half-closed peer, and every wire, crypto, and accounting rule are unchanged.
  - **Regressions:** the three P5.2 `#[ignore]` reproducers now pass as normal tests (`…dispatches_complete_frames_before_graceful_close`, with one documented qualification for a full close after two frames, where the closed peer's reset is a hard failure; `…responder_loses_final_ack_before_graceful_close`; `…writes_pending_output_after_peer_half_close`); new permanent tests in `windows_owner_loop::tests::graceful_hang_up`, including the readiness precedence matrix and real-loopback close and `shutdown(Send)` cases. The P4 readiness test is split into its hard-failure meaning. The OS-fact test and LOOP-HUP-001..003 stay as evidence.
  - **Normative sync:** no P3 change needed; `R-WIRE-025` and `R-MAC-012` amended in place.
  - **CI:** Repository consistency, `windows-core`, and `unsupported-platform-fails-closed` SUCCESS at `c4212f2`.
  - **P6 review evidence:** readiness model, follow-up adversarial review, and verification in the [remediation record](../p6-remediation/p5-f-001.md).

<a id="p5-f-002"></a>
### P5-F-002 — Connections with no frame in progress never expire, so 16 idle peers hold the live-connection cap indefinitely

- **Status:** REMEDIATED-IN-P6 (P6.1). OPEN at P5 closure; everything below the P6 remediation note is P5's original record.
- **Severity:** MEDIUM
- **Confidence:** HIGH
- **Classification:** Confirmed implementation gap against P3 §11.1.1. P3 already requires the transport to bound header waiting with finite deadlines; P4 implements no such bound before a frame's first byte.
- **Required property:** An admitted unauthenticated transport connection cannot hold authority-wide connection capacity indefinitely while it waits for initial header or frame progress.
- **Affected requirement(s):** P3 §11.1.1, whose controls every implementation "MUST enforce": "Incoming connections" (the cap of 16 "includes connections that have not sent a frame"), "Incomplete frame reception" ("finite header/whole-frame deadlines plus an idle-read deadline"), and "Lifetime and cleanup" (temporary resources are released on timeout). The paragraph after the table says adapters "MUST NOT … omit a required control, make a cap unbounded". Also `R-OWNER-023`, `R-OWNER-026`, and the threat model's resource-bounded input.
- **Affected code:** `core/src/transport.rs:299–307` (`poll_frame_deadlines` returns at once with no clock read when no frame is partial) and `:370–392` (deadlines exist only for a `Partial`). `core/src/windows_owner_loop.rs:549–569` (the sweep calls only those polls). Neither `windows_tcp.rs` nor `windows_owner_loop.rs` has any connection lifetime or post-ceremony close.
- **Threat scenario:** A peer that can reach the listener opens 16 TCP connections and sends nothing. Alternatives: it finishes or abandons a ceremony and then stays silent, or it advertises a zero receive window so a retained, owner-less CANCEL never drains. Each connection holds one authority-wide live slot indefinitely. Every later connection to any listener of that authority is accepted and immediately refused (`ResourceLimited`). Honest half-open connections (a peer that vanished without FIN or RST) accumulate the same way, because the adapter enables no TCP keepalive.
- **Preconditions:** The listener is reachable by the attacker, which depends on the deployment's bind policy. The attacker keeps 16 connections open with no traffic.
- **Reproduction:** [Reproducer patch](reproducers/README.md), test `transport::tests::p5_f_002_frameless_connections_do_not_hold_the_live_cap_forever`: 16 frameless connections, transport clock advanced 24 h. Every `poll_frame_deadlines()` returns `Ok(())` and the connection is still live. Counts are `(pending 0, live 16, incomplete 0)`. A 17th activation is `ResourceLimited`. Supporting: the existing `transport::tests::sixteen_frameless_connections_fill_the_cap_and_the_seventeenth_is_refused`.
- **P5.2 subcases** ([adversarial sequences §8](adversarial-sequences.md#8-p5-f-002-evidence-f002-001-tcp-out-001)). Through the TCP adapter, every clock was advanced 24 h in hourly steps with the owner loop's per-connection sweep after each step:
  - **A, first header:** admitted with zero bytes. Not released.
  - **B, idle after its run:** a complete START admitted, its run ended by its own deadline, then idle. The run ends; the connection is not released.
  - **C, owner-less retained output:** the Responder's timeout CANCEL, or a local REJECT/CANCEL frame, retained for a peer that never reads. Not released, and the frame stays retained. A frame a live run owns *is* bounded by that run's deadline (discarded unsent, or the connection closed if partly sent), but the run's timeout CANCEL that replaces it has no owner and no deadline.
  - **Finite cases:** an incomplete frame (2 s/10 s deadlines) and a complete unroutable frame (immediate close).

  Passing evidence `p5_f002_001_connection_lifetime_cases` and `p5_tcp_out_001_retained_output_lifetime_versus_ceremony_lifetime` assert only the finite cases. The EXPECTED-FAIL reproducer `p5_f_002_idle_connections_eventually_release_their_live_slot` (`#[ignore]`) states the desired invariant for A, B, and C and fails today.
- **One finding, three subcases (P5.2 decision):** A, B, and C have one root cause: no connection-level lifetime exists outside an incomplete frame. They also share the code condition, the affected resource (one authority-wide live slot and its session, plus at most one retained frame ≤ 64 KiB in C), the P3 control (§11.1.1 header/idle-read deadlines and lifetime and cleanup), and the remediation decision (one finite connection lifetime or idle policy). They are not split into separate findings. C adds a requirement for that remediation: the chosen bound must also cover a retained frame with no owner.
- **Security impact:** Availability only. Remote pairing for the authority can be locked out persistently, at no cost, until local intervention. No effect on authentication, the SAS budget, the START limiter, or secrets. P3 says the numeric defaults are not DoS guarantees, but without a lifetime the cap can be exhausted permanently with zero ongoing traffic, and non-adversarial half-open sockets exhaust it over time.
- **Why existing tests/conformance did not catch or prevent it:** P4 started every transport deadline at a frame's first retained byte, and tested frameless connections only as correctly counted against the cap. That reading leaves a connection waiting for its first header with no finite bound, which the §11.1.1 header and idle-read deadlines do not permit. `R-OWNER-023` names only the 10-second whole-frame and 2-second idle values, and no conformance row states a time-to-first-header value, so the P4 PASS for that row did not test this case. The owner loop leaves close policy to its owner.
- **What is mandatory and what is undecided:** That a finite bound exists is required by current P3 and is not an open question. Its exact shape and values are not frozen. The 10-second whole-frame and 2-second no-progress defaults apply to the incomplete-frame controls. P3 gives no separate value for time to first header or first byte, for a connection's idle lifetime once it has no live run, or for how long a retained owner-less outbound frame may wait. P5 selects none of these values and does not change P3.
- **Recommended remediation:** In P6, after the owner selects the timer model and values: add a finite, never-refreshed first-header (pre-frame) deadline from activation; decide whether a separate idle deadline is needed for a connection with no live run; and decide a finite bound on a retained owner-less outbound frame where one applies. Each should close through the existing generic teardown, with no limiter, budget, or guard change. Optionally enable TCP keepalive in the adapter. Every chosen value must stay finite and must never reset an authority control.
- **P6 disposition:** Remediate. The owner selects the narrow finite timer model and values, then P6 changes the transport and adapter and enables the reproducers (the P5.1 patch test and the P5.2 `#[ignore]` test covering subcases A–C) as regression tests.
- **Evidence:** as above; [resources, deadlines, and transport §1, §3, §4, §6](resources-deadlines-transport.md); [adversarial sequences §8](adversarial-sequences.md#8-p5-f-002-evidence-f002-001-tcp-out-001).
- **P6 remediation (appended in P6.1; the P5 record above is unchanged):**
  - **Decision:** [P6-D-001](../p6-remediation/decisions.md#p6-d-001--f-002-connection-lifetime): 10 s from admission to the first frame; 10 s quiescent with no live run, no frame, and no pending output; 10 s absolute and 2 s no-progress for owner-less retained output; the existing 10 s / 2 s incomplete-frame deadlines unchanged; live ceremonies governed only by their ceremony deadlines.
  - **Remediation commit:** `1ce07537e9552ea5963fb563d83883dc96db2ebe` (`fix: bound connection lifetime`) on `feature/p6-review-remediation-protocol-freeze`. One transport-owned connection-lifetime state, checked by the owner-loop sweep before socket I/O and by the adapter before each write; expiry uses the existing teardown and releases the live slot exactly once. No wire, crypto, budget, guard, or limiter change.
  - **Regressions:** `p5_f_002_idle_connections_eventually_release_their_live_slot` now passes as a normal test (its `#[ignore]` removed); new permanent tests in `transport::tests::connection_lifetime`, `windows_tcp::tests::connection_lifetime`, and `windows_owner_loop::tests::connection_lifetime`, including the 16-idle / 17th-admission regression at exact boundaries. The P5.1 patch test is superseded by them.
  - **Normative sync:** P3 §11.1.1 "Connection lifetime" row; `R-OWNER-023` amended in place.
  - **P6 review evidence:** follow-up adversarial review, rebuilt resource table, and CI in the [remediation record](../p6-remediation/p5-f-002.md).

<a id="p5-f-003"></a>
### P5-F-003 — In-process re-registration starts a fresh opportunity budget without process replacement

- **Status:** REMEDIATED-IN-P6 (P6.3). OPEN at P5 closure; the P5 record below is unchanged and the P6 note is appended at the end of this entry.
- **Severity:** LOW
- **Confidence:** HIGH
- **Classification:** Confirmed mismatch with the current P3 owner-session reset policy.
- **Affected requirement(s):** P3 §11.1 ("The process has at most 10 exposed remote SAS opportunities"; "a legitimate process restart starts a new local session budget only after the previous owner has terminated and exclusive ownership has been safely established"; "A verified replacement owner starts a new session budget after the previous process terminates"). P3 §11.1.2(3) ("The native security core owns one process-wide authority registry"; for each identity it owns the volatile ten-opportunity counter). P3 §11.1.2(5) ("A replacement starts a fresh volatile ten-opportunity process/session budget only after safe exclusive acquisition; restarting a frontend while the owning process remains alive does not reset that budget"). The START limiter's "Lifetime and reset" rule (fresh state only for a new or safely replaced owner session). `R-OWNER-006`, `R-OWNER-022`, `R-OWNER-038(c)`.
- **Affected code:** `core/src/lib.rs:245–281` (`register_with` creates `Shared { remaining: 10, start_limiter: StartLimiter::new(), … }`), `:200–206` (`State::drop` removes the registry entry), `:311–322` (`release`).
- **Threat scenario:** Inside one live OS process, trusted code exhausts the budget, then releases the authority (or drops every handle) and calls `TrustedAuthority::register` with the same scope. The registry entry is gone and the process re-acquires the OS lease, so a fresh budget of 10 and a fresh START limiter exist, without any process termination. A future binding that re-registers on a frontend restart, UI reconnect, or error recovery would silently reset the budget while the native process lives.
- **Preconditions:** Code holding `TrustedAuthority` (trusted local code) releases and re-registers. A remote peer cannot trigger this.
- **Reproduction:** Existing integration tests: `process_ownership_and_full_reservation_lifecycle` (after 10 reservations and `Exhausted`, `release()` then `register(b"integration-owner")` → `Ready { remaining: 10 }`; `core/tests/security_core.rs:170–175`) and `ownership_is_never_released_while_ceremony_state_remains` (all handles dropped, re-register → `remaining: 10`; lines 315–323).
- **Security impact:** Remote input cannot trigger the reset, so severity stays LOW. The numeric 19-pair window is defined per owning-process session. In-process re-registration creates more ten-opportunity windows within one live native process, which current P3 does not allow. A future binding that re-registers on a frontend restart, UI reconnect, or error recovery would multiply those windows by accident, on events P3 says must not reset the budget. P3 claims no lifetime bound, and a genuine process replacement would also start a fresh budget.
- **Why existing tests/conformance did not catch or prevent it:** P4 used "owner session = `TrustedAuthority` registration lifetime" as its implementation model (closure note on `R-OWNER-006`: "Only a new `TrustedAuthority`, after the OS lease is acquired, has fresh state") and tested in-process re-registration as a correct replacement. That model is weaker than the current P3 process/session wording, which ties a fresh budget to termination of the previous owning process. The P4 PASS verdicts for `R-OWNER-006` and `R-OWNER-022` rest on it; `R-OWNER-022` evidence covers only the owner loop. P4 having chosen this model does not make it conformant.
- **Recommended remediation:** In P6, one of two paths:
  - **Default: keep the current P3 semantics and change the implementation.** A same-process release and re-registration must not silently start a fresh budget or START limiter for the same authority. P6 chooses the design.
  - **Alternative: change the policy.** The owner explicitly decides to revise P3 so that the owner session is the `TrustedAuthority` registration lifetime. This is a policy change, not a documentation clarification of the current baseline. It requires re-analyzing exposure accounting, updating P3, the conformance cases, and the security argument, and then aligning the implementation and the P7 binding rules.
- **P6 disposition:** Remediate under the default path unless the owner explicitly chooses the policy revision.
- **Evidence:** as above; [ownership and FFI §2, §5](ownership-and-ffi.md#2-lease-lifecycle).
- **P6 remediation (appended in P6.3; the P5 record above is unchanged):**
  - **Decision:** [P6-D-002](../p6-remediation/decisions.md#p6-d-002--f-003-owner-session-policy) (P6.1): keep the current P3 process/session semantics, the default path above. The owner session is not the registration lifetime; P3 is not revised.
  - **Remediation commit:** `5aa1b1580672304afe74d65f3270f8b1da333901` (`fix: preserve process-session accounting`) on `feature/p6-review-remediation-protocol-freeze`.
  - **Architecture:** the process-wide registry maps each canonical identity this process has successfully owned to one process session that holds the shared accounting (budget, START limiter, runtime counts, in the one mutex that keeps guard and opportunity reservation atomic) and the limiter clock, strongly, until the process exits; registrations are `Inactive`, `Active`, or `Uncertain` on top of it. Release and the final drop release the OS lease and leave the accounting; every reactivation acquires the lease anew and continues the same accounting; a failed first acquisition creates nothing; an uncertain release, poisoned accounting, or runtime resources left held fail closed with `OwnershipUncertain` until process replacement. No eviction, no persistence, no reset API.
  - **Budget regressions:** partial spend kept across explicit release (7) and the final drop (9); `Exhausted` survives re-registration; registration cycles grant exactly 10 in total; a day of monotonic time refills nothing. The two P4 assertions cited above are inverted (`Exhausted`, and `remaining: 9`) with comments recording the correction.
  - **Limiter regressions:** an emptied burst stays empty across immediate re-registration and gains exactly one token at 5 s; the R-OWNER-035 rolling schedule run with a re-registration before every decision still refuses at 45 s and 59.999 s and recovers at exactly 60 s by age; long idle restores capacity only at the next evaluation; a later registration cannot replace the session clock; P4's same-process fresh-limiter test is rewritten to the process-session meaning.
  - **Cross-process evidence:** a real foreign owner process between two registrations makes reactivation fail with `OwnershipUnavailable` and leaves 8, which continues after it exits; eight threads racing re-registration produce one winner per round over one budget; each new `ownership_probe --session` process starts at 10 while its own release and re-registration keeps 9; existing cross-process exclusion tests unchanged.
  - **Normative sync:** no P3 change needed; `R-OWNER-006`, `R-OWNER-017`, `R-OWNER-022`, `R-OWNER-031`, and `R-OWNER-038` amended in place (still 92 normative rows).
  - **CI:** Repository consistency, `windows-core`, and `unsupported-platform-fails-closed` SUCCESS at `5aa1b15`.
  - **P6 review evidence:** process-session model, state table, follow-up adversarial review, mutation checks, and verification in the [remediation record](../p6-remediation/p5-f-003.md).

<a id="p5-f-004"></a>
### P5-F-004 — `token_user_sid` does not bound the OS-written SID to the returned buffer

- **Status:** ACCEPTED-LIMITATION (reclassified from OPEN in P5.3)
- **Severity:** INFO
- **Confidence:** HIGH
- **Affected requirement(s):** Decision 0003 (failure to obtain token identity fails closed); P3 §11.1.2(4).
- **Affected code:** `core/src/lib.rs:711–735`.
- **Threat scenario:** `GetTokenInformation(TokenUser)` returns a header whose `Sid` pointer or `SubAuthorityCount` places the SID partly or wholly outside the returned bytes. `IsValidSid`, `GetLengthSid`, and `slice::from_raw_parts` then read outside `info`. The `SAFETY:` comment asserts "points into the still-borrowed `info`", but the code does not check it.
- **Preconditions:** A malformed Win32 result for the process's own token, which needs a compromised OS or in-process API hooking (outside the threat model).
- **Reproduction:** Source inspection. It cannot be induced without corrupting the OS API. The 20.1 alignment test builds only well-formed buffers.
- **Security impact:** None demonstrated under supported assumptions. This is defense-in-depth at an `unsafe` boundary.
- **Why existing tests/conformance did not catch or prevent it:** Increment 20.1 targeted alignment, and the range was assumed from the Windows contract.
- **Recommended remediation:** Before `IsValidSid`, require `info.as_ptr() + size_of::<TOKEN_USER>() ≤ sid < info.as_ptr() + info.len()`. After `GetLengthSid`, require `sid + len ≤ info.as_ptr() + info.len()`. Otherwise return `OwnershipUnavailable`. Add synthetic tests for an out-of-range pointer and an oversized sub-authority count. Optionally add `// SAFETY:` comments to the other `os_lock` blocks ([ownership and FFI §6](ownership-and-ffi.md#6-production-unsafe-inventory)).
- **P6 disposition:** Optional hardening, low effort.
- **P5.3 reclassification** ([deep review §6](dependency-unsafe-deep-review.md#6-p5-f-004-token_user-range)):
  - **Windows contract (Microsoft Learn, fetched 2026-10-02).** `GetTokenInformation`, `TOKEN_INFORMATION_CLASS`, `TOKEN_USER`, `SID_AND_ATTRIBUTES`, `IsValidSid`, `GetLengthSid`, and the WDK `ZwQueryInformationToken` say the buffer "receives a TOKEN_USER structure", that `ReturnLength` is the size "needed to store the requested information", and that `Sid` is "a pointer to a SID structure". None states in words that the pointer refers into the caller's buffer. That is strongly implied: the buffer is the only output storage, the required size covers the SID (44 bytes, not 16), nothing else is freed, and Microsoft's own sample uses the pointer and then frees only the buffer.
  - **Empirical, not contract.** `core/tests/p5_review_evidence.rs::p5_f_004_token_user_sid_lies_inside_the_returned_buffer_on_this_windows` (PASSING EVIDENCE TEST, CI) proves by address arithmetic before any dereference that the SID is at offset 16, is 28 bytes, ends exactly at the returned length, and is stable over 100 rounds, exact and oversized buffers, and 4- and 8-aligned starts. Unaligned starts are refused with error 998 (`ERROR_NOACCESS`), which fails closed.
  - **Rust reasoning.** The reads are sound given the OS postcondition. Only a compromised or hooked API, which the threat model excludes, could break it, and that same API could lie about the identity, which a range check would not detect. The `SAFETY:` wording states the postcondition as fact; it is not unsupported.
  - **Final:** ACCEPTED-LIMITATION, INFO, HIGH, under the normative baseline (threat model: compromised endpoint/OS out of scope; [assumptions §5](assumptions-and-boundaries.md#environmental-assumptions-the-core-relies-on)). **P6 recommendation:** unchanged and optional. Add the range checks and reword the `SAFETY:` comments to name the OS postcondition.
- **Evidence:** [ownership and FFI §4, §6](ownership-and-ffi.md#4-increment-201-token_user-re-audit); [deep review §5–§6](dependency-unsafe-deep-review.md#5-project-unsafe-and-ffi-re-audit).

<a id="p5-f-005"></a>
### P5-F-005 — `Sas::new()` entropy panic leaves Router and adapter state conservatively stuck and escapes owner-loop calls

- **Status:** DISPOSITIONED-IN-P6 (P6.4) — mandatory P7 ABI containment requirement. OPEN at P5 closure; the P5 record below is unchanged and the P6 note is appended at the end of this entry.
- **Severity:** INFO
- **Confidence:** HIGH
- **Affected requirement(s):** P3 §5 (no success from failed entropy; no graceful-error promise); P3 §11.2 (teardown); decision 0001 (future native boundary).
- **Affected code:** `core/src/crypto.rs:58–60`. Responder path: `core/src/router.rs:921–951` (the claim is inserted, admission runs outside the lock, and no RAII guard removes `Route::Admitting`). Initiator path: `core/src/ceremony.rs:1600`, running under `core/src/router.rs:1095–1103` (`on_run` holds the run mutex while `op` runs).
- **Threat scenario:** The OS entropy source fails while either:
  - (a) a peer's START is being admitted. The panic unwinds out of `Router::route_start`, and the `Admitting` claim for that `(session, request_id)` stays until session teardown. Copies of that START become "duplicates", and non-START frames for that key fail as out of order.
  - (b) a local `expose_key` runs. The run mutex is poisoned. Deadline polls and session teardown then report `OwnershipUncertain`, the session stays CLOSING with its live-connection count held, and the owner loop fails closed.

  In both cases the panic propagates out of `drive_once` or the local action to the caller.
- **Preconditions:** OS entropy failure, which an attacker cannot control. The effects persist only if the caller catches the panic and keeps using the objects; otherwise unwinding drops everything.
- **Reproduction:** Source inspection in P5.1; reproduced deterministically through the Router, adapter, and owner loop in P5.3 (see the P5.3 entry below). P4's injected-panic test `ceremony::tests::an_ephemeral_generation_panic_exposes_nothing_and_refunds_nothing` covers ceremony-level accounting only, not the unwind through the Router or adapter.
- **Security impact:** None for pairing security: no exposure, refund, or success (P4 evidence). The availability effect follows an event that is already catastrophic. A panic must also never cross a future FFI boundary.
- **Why existing tests/conformance did not catch or prevent it:** The P4 hook injects the panic below the Router and adapter, and no test unwinds through them.
- **Recommended remediation:** Decide the native library's panic policy: `panic = "abort"`, or a `catch_unwind` boundary at the P7 ABI. If unwinding stays, remove an `Admitting` claim with an RAII guard and treat a poisoned run as terminal for teardown, so recovery is bounded.
- **P6 disposition:** Owner decision on panic policy (together with P7); optional Router hardening.
- **P5.3 (strengthened; INFO, HIGH, OPEN)** ([deep review §7](dependency-unsafe-deep-review.md#7-p5-f-005-entropy-panic)):
  - **Exact origin.** rand 0.10.3 `ThreadRng` panics on a failed initial seed (`thread.rs:163`) or on a failed reseed after 64 KiB of output per thread (`thread.rs:70`). A caught reseed panic never reuses or extends output. getrandom 0.4.3 `ProcessPrng` is documented upstream as always returning TRUE on Windows 10 and later. A peer can drive reseeds but cannot cause the failure: not remotely triggerable.
  - **Reproduced deterministically** at the existing P4 pause points, catching the unwind around real calls (PASSING EVIDENCE TESTS `windows_tcp::tests::p5_entropy_panic_review::p5_f005_001..003`, `windows_owner_loop::tests::p5_entropy_panic_loop::p5_f005_004..005`).
  - **Responder:** an orphan `Admitting` claim; a duplicate START (including the adapter's retained replay) is ignored; a frame for that key marks it conflicted; teardown releases everything.
  - **Initiator:** the run is poisoned; Busy with the opportunity consumed. The next presentation, deadline poll, inbound frame, close, or owner-loop drive reports `OwnershipUncertain` and the adapter or loop fails closed. Dropping the detached run releases the guard and the request-ID reservation with no refund. **New residue:** one authority-wide live-connection slot and one CLOSING Router session stay held for the life of the registration.
  - **Security properties hold:** no result, no exposure without consumption, no refund, no premature guard reuse, no stale route accepting input. A future `extern "C"` ABI would abort on an escaping panic (Rust ≥ 1.81), not unwind, unless a binding opts into `C-unwind`.
  - **P6/P7:** choose `panic = "abort"`, or `catch_unwind` at every export that then discards the authority. Optionally add RAII cleanup of the claim and release transport accounting for a poisoned run.
- **Evidence:** [state and routing §3](state-and-routing.md#3-router-and-session-isolation); [secrets, panics, dependencies §3](secrets-panics-dependencies.md#3-panic-and-abort-surfaces); [deep review §7](dependency-unsafe-deep-review.md#7-p5-f-005-entropy-panic).
- **P6 disposition (appended in P6.4; the P5 record above is unchanged):**
  - **Decision:** [P6-D-004 — Native Panic Containment Policy](../p6-remediation/decisions.md#p6-d-004--native-panic-containment-policy). The core does no broad panic recovery. The P7 ABI catches every panic inside Rust before it can cross `extern "C"`, at every export and every Rust-owned thread root. The affected native context becomes permanently fatal, and later calls return a stable fatal-state error without entering the core. There is no same-process retry, re-registration, or accounting reset; recovery is a process restart. No panic payload is ABI contract. The supported artifact uses an unwind-compatible panic strategy, and P7 CI tests containment. `extern "C-unwind"` is not a supported contract. `panic = "abort"` is not the selected ABI policy, so the P5 suggestion above was considered and not chosen.
  - **Why no core remediation:** the panic is not remotely triggerable and fails closed. A core that resumed after a panic (internal `catch_unwind`, mutex-poison recovery) would trade that for a large, hard-to-review semantic commitment. The optional Router RAII and poisoned-run transport release stay optional hardening and are not needed under P6-D-004, because a panicked context is fatal.
  - **Current evidence (re-run in P6.4, assertions unchanged):** `p5_f005_001..005` and the P4 ceremony panic test pass. New test-only assertions (`9628fa3`) show that after a caught Initiator panic, dropping every handle and registering the same authority in the same process fails with `OwnershipUncertain` and never yields `Ready { remaining: 10 }` (P6.3 interaction). After the Responder panic, re-registration continues the same START limiter. A throwaway foreign-host experiment confirmed the Rust semantics: an escaping panic aborts the host, `catch_unwind` inside the export contains it under `unwind`, and nothing is caught under `abort`.
  - **Mandatory P7 requirement:** recorded in [P7](../../roadmap/P7-native-abi.md) as scope, security invariants, and exit criteria, including a deterministic panic-containment test. P7 cannot be completed without it.
  - **Not:** REMEDIATED-IN-P6 (no ABI exists yet), FALSE-POSITIVE (the panic is real), or ACCEPTED-LIMITATION (P7 has a mandatory obligation). It does not block the protocol freeze: no wire, crypto, or protocol-semantic change is needed.
  - **Normative sync:** no P3 change; `R-OWNER-013` amended in place (still 92 normative rows).
  - **P6 record:** [p5-f-005.md](../p6-remediation/p5-f-005.md).

<a id="p5-f-006"></a>
### P5-F-006 — `base64`'s default `simd-unsafe` engine encodes every MAC and HKDF input

- **Status:** FALSE-POSITIVE (reclassified from OPEN in P5.3)
- **Severity:** INFO (if real)
- **Confidence:** HIGH (that it is false)
- **Affected requirement(s):** P3 §3.2 (strict unpadded Base64url for every SAS, MAC, and CANCEL input); decision 0002 (the reviewed, pinned dependency path); `R-MAC-014`.
- **Affected code:** `core/Cargo.toml` (`base64 = "0.23"`, default features; vodozemac also enables the defaults); `core/src/crypto.rs:261–285` (`capped_base64url` → `URL_SAFE_NO_PAD.encode`). In `base64` 0.23.1, `default = ["std", "simd-unsafe"]`, which selects AVX2 or NEON `unsafe` encoders at run time.
- **Threat scenario:** A defect in a SIMD encoder for some length or CPU (AVX2 vs scalar vs NEON on a future mobile peer) would produce a different string for the same frame. Peers on the same CPU class would still agree. Peers on different classes would derive different MAC or HKDF inputs and fail closed. A memory-safety defect in that `unsafe` encoder would sit on attacker-influenced lengths (the bootstrap fields).
- **Preconditions:** An upstream encoder defect, and peers on different CPU classes.
- **Reproduction:** `cargo tree -e features` shows `base64 feature "simd-unsafe"`; source `base64-0.23.1/src/engine/simd.rs`. No defect was demonstrated.
- **Security impact:** *(P5.1 hypothesis, disproved in P5.3 below.)* None demonstrated. There is a fail-closed interoperability risk and an extra upstream `unsafe` surface in the authentication path. Fixture tests exercise only the CI machine's backend and the fixture's lengths.
- **Why existing tests/conformance did not catch or prevent it:** Feature unification is implicit. P4 recorded the version but not the feature.
- **Recommended remediation:** *(P5.1; superseded by P5.3.)* An owner decision to accept and record it, or to reduce it (ask vodozemac to allow disabling the feature, or adjust the core's `base64` features where unification allows). Add a test-only reference Base64url encoder compared across every length up to the 65,536-byte cap.
- **P6 disposition:** Decide; optional test. *Superseded by P5.3: nothing to remediate.*
- **P5.3 reclassification** ([deep review §8](dependency-unsafe-deep-review.md#8-p5-f-006-base64-simd)):
  - **The premise is false at the locked version.** `simd-unsafe` is enabled (from `default`, requested by both the core and vodozemac). In base64 0.23.1 it only compiles the separate `Simd`, `Avx2`, and `Neon` engines (`engine/simd.rs`, the crate's only `unsafe`). `URL_SAFE_NO_PAD` is the scalar `GeneralPurpose` engine: its `internal_encode` passes the no-op SIMD prefix `|_, _| (0, 0)` (`general_purpose/mod.rs:85-87`), and `base64::engine::Scalar` is its alias. vodozemac also uses `GeneralPurpose`. No crate in the graph constructs a SIMD engine, and the core never decodes.
  - **Evidence (`core/src/crypto/tests/p5_dependency_review.rs`):** a dependency-free bit-indexed reference encoder, checked against RFC 4648 vectors. B64-REF-001 (CI): 306 lengths (0..=256 and every boundary ±2 up to 65,538) × 4 patterns, with and without the longest production prefix, and exact cap edges; 0 mismatches, every over-cap input `Oversized`. B64-REF-002 (deep, `#[ignore]`): **every** length 0..=65,536, two patterns, 131,074 independent encodings, 0 mismatches, 48.9 s. B64-ENGINE-001: compile-time proof that the engine is `Scalar`. B64-ENGINE-002: the unused `Simd` engine also matches on this AVX2 host. NEON was source-reviewed only, never executed, and is unreachable.
  - **Impact had a backend differed:** fail-closed MAC or HKDF mismatch, never false authentication.
  - **Final:** FALSE-POSITIVE. The unused compiled `unsafe` module is supply-chain footprint only. Keep B64-ENGINE-001 and B64-REF-001 as regression guards for any future `base64` upgrade.
- **Evidence:** [secrets, panics, dependencies §6](secrets-panics-dependencies.md#6-dependencies); [deep review §8](dependency-unsafe-deep-review.md#8-p5-f-006-base64-simd).

<a id="p5-f-007"></a>
### P5-F-007 — Reverse asymmetric completion at the Initiator's deadline boundary

- **Status:** DISPOSITIONED-IN-P6 (P6.5) — current conservative completion boundary retained and documented; no production change required. OPEN at P5 closure; the P5 record below is unchanged and the P6 note is appended at the end of this entry.
- **Severity:** INFO
- **Confidence:** HIGH
- **Affected requirement(s):** P3 §9 (result conditions; asymmetric observation); P3 §11.3 (expiry produces no success).
- **Affected code:** `core/src/windows_tcp.rs:410–451, 649–663` (deadline preflight before the write; `confirm` checks deadlines again); `core/src/ceremony.rs:1173–1198` (`confirm_initiator_finish_ack_sent` runs `step()` first).
- **Threat scenario:** I's final ACK is fully written after a live preflight. Before `confirm` runs, the absolute or inactivity deadline expires. I times out with no result and offers its timeout CANCEL after the complete ACK. R receives the complete final ACK, verifies it, and succeeds. Outcome: R succeeded and I did not. *P5.2 correction:* R does not ignore I's following CANCEL as `Completed`. R's route was removed on success, so the CANCEL is an unknown route, which is session-fatal under P3 §11.2. It ends R's connection, and any sibling runs on it, after R already returned its result. A delivery-controlling attacker can aim for this window by slowing the drain of the final ACK until near the deadline. The window is only the time between the two clock readings inside one `on_writable` call, so in practice it is hit by chance or by scheduling delay rather than precisely.
- **Preconditions:** The final-ACK write completes just before a deadline: inactivity, 60 s after RESPONDER_FINISH_ACK, or the absolute 5 minutes from creation.
- **Reproduction (P5.2, deterministic, end to end):** `windows_tcp::tests::p5_transport_review::p5_f007_final_ack_deadline_boundary_end_to_end` ([adversarial sequences §6](adversarial-sequences.md#6-p5-f-007-evidence-f007-001002)) drives both deadlines through two scripted adapters with hand clocks (`ManualClock::advance_after`). Owner check at D−1 ns and confirmation at exactly D: the full 144-byte final ACK is written, I reports a timeout with no result and its CANCEL follows, and R verifies the ACK and returns the only result, then ends its connection on the CANCEL (`SessionProtocolFailure`). Control rows: D−2 ns / D−1 ns gives both results (they agree); an owner check at D or D+1 ns writes no ACK byte (CANCEL only; R verifies the peer CANCEL, no result); a partial write then D gives `AbandonedPartialFrame` and neither side has a result. Expiry is exactly at `>=`.
- **Security impact:** No conflicting success, since only one side succeeded, and R's success is fully authenticated: I's final MAC proves I verified R's finish after both approvals. P3 §9 describes only the I-success / R-failure direction, so consumers must equally tolerate R-success / I-failure. Consumers already have to tolerate the mirrored outcome, which a lost final ACK produces, and an attacker who controls delivery can produce one-sided outcomes in either direction anyway. P5.2 found no additional robustness or availability impact. This remains documentation clarity.
- **Classification after P5.2:** **unchanged: INFO, OPEN, confidence HIGH** (now reproduced, not only derived from source). The behavior is the intended conservative choice ("confirmation after expiry creates no result"), and its only gap is undocumented asymmetric semantics. It is neither a LOW robustness defect nor a false positive.
- **Why existing tests/conformance did not catch or prevent it:** P4 rightly treats "confirmation after expiry creates no result" as the safe choice but did not document the mirrored outcome. P4's test `windows_tcp::tests::deadlines_found_by_input_actions_or_confirmation_keep_their_cancel` (c) shows the Initiator side only.
- **Recommended remediation:** State in P3 §9 and the consumer guidance that either side may hold the only result, and that R's connection may end on I's following timeout CANCEL. Optionally (owner decision), judge the confirmation against the instant the last byte was written rather than the confirmation instant. If chosen, the P5.2 test's crossing row would change to "both results".
- **P6 disposition:** Documentation; optional decision. The P5.2 boundary test is a passing characterization; P6 updates its expected rows only if the owner changes the boundary rule.
- **Evidence:** [protocol composition §7](protocol-composition.md#7-completion-and-pairingresult); [resources, deadlines, and transport §3](resources-deadlines-transport.md#3-deadlines); [adversarial sequences §6](adversarial-sequences.md#6-p5-f-007-evidence-f007-001002).
- **P6 disposition (appended in P6.5; the P5 record above is unchanged):**
  - **Decision:** [P6-D-005 — Local Completion and Final-ACK Deadline Boundary](../p6-remediation/decisions.md#p6-d-005--local-completion-and-final-ack-deadline-boundary), option A. The Initiator's success stays judged when its final-ACK send is confirmed while the ceremony is live, never backdated to the last-byte instant. Either side may be the only result holder; I-only (lost final ACK) and R-only (this finding) are both valid profile outcomes, and two successful results can never conflict. The timeout `CANCEL` that ends R's session after its result stays under the current P3 §11.2 routing; a returned result is never revoked. The optional last-byte rule suggested above was considered and not selected.
  - **Implementation re-check:** the source at `3b8bf43` matches this record (preflight in `on_writable`, write, then `confirm_sent` → `confirm_initiator_finish_ack_sent` inside `step`, which checks deadlines first). No production change.
  - **Documentation:** P3 §9 (both asymmetric directions; local result is not bilateral commit), §10 (`AwaitResponderFinish` success only after a live send confirmation; `AwaitInitiatorFinishAck` independent of I's result), and §11.3 (a complete write earns no deadline exemption) were clarified. Conformance rows `R-OWNER-007`, `R-MAC-012`, `R-RESOURCE-006`, and `R-RESOURCE-007` were amended in place (still 92 normative rows). The core README states the reverse direction.
  - **Evidence:** `p5_f007_final_ack_deadline_boundary_end_to_end` passes unchanged; its crossing row stays R-only.
  - **Not:** REMEDIATED-IN-P6 (no defect fixed), FALSE-POSITIVE (the asymmetry is real), or ACCEPTED-LIMITATION (it is now an explicitly selected protocol semantic). It does not block the protocol freeze.
  - **P6 record:** [p5-f-007.md](../p6-remediation/p5-f-007.md).

<a id="p5-f-008"></a>
### P5-F-008 — Same-profile attacker can race the lock-path checks (TOCTOU)

- **Status:** ACCEPTED-LIMITATION · **Severity:** INFO · **Confidence:** HIGH
- **Affected requirement(s):** P3 §11.1.2(4); decision 0003.
- **Affected code:** `core/src/lib.rs:594–616, 737–782`.
- **Threat scenario:** Between `ensure_plain_directories` and `OpenOptions::open`, a process with write access to the profile replaces a parent directory with a junction and redirects the lock file. Two same-account processes could then lock different files.
- **Preconditions:** The attacker runs as the same Windows account, or as administrator.
- **Reproduction:** Not attempted; this is a documented limitation.
- **Security impact:** Such an attacker already controls the endpoint, which the threat model puts out of scope.
- **Why existing tests/conformance did not catch or prevent it:** It is documented as unsupported (core README "Ownership guarantees"; decision 0003 "does not establish … same-profile attacker resistance").
- **Recommended remediation:** None required. If it ever comes into scope, open components relative to held directory handles, or verify the opened handle with `GetFinalPathNameByHandleW`.
- **P6 disposition:** Keep as an accepted limitation.
- **Evidence:** [ownership and FFI §1](ownership-and-ffi.md#1-account-identity-and-lock-derivation).

<a id="p5-f-009"></a>
### P5-F-009 — Fork, snapshot, restore, or duplicated state can repeat ephemeral material

- **Status:** ACCEPTED-LIMITATION · **Severity:** INFO · **Confidence:** HIGH
- **Affected requirement(s):** P3 §5 (ephemeral freshness); `R-OWNER-013`, `R-OWNER-018`.
- **Affected code:** `core/src/crypto.rs:58–60` (`Sas::new()`). No detection exists.
- **Threat scenario:** A restored VM snapshot or duplicated process repeats `ThreadRng` state, and with it the ephemeral keys.
- **Preconditions:** An unsupported deployment.
- **Reproduction:** None; documented.
- **Security impact:** It would break the freshness assumption that the SAS argument needs. It is unsupported per P3 and P4.
- **Why existing tests/conformance did not catch or prevent it:** It is a documented limitation (P4 closure "Explicit Limitations").
- **Recommended remediation:** None for experimental scope. Any supported snapshot deployment needs a verified reseed mechanism first.
- **P6 disposition:** Keep.
- **Evidence:** `rand-0.10.3/src/rngs/thread.rs` documents no reseed on fork. **P5.3: unchanged** ([deep review §11](dependency-unsafe-deep-review.md#11-rng-fork-and-snapshot-p5-f-009)). Locked source confirms per-thread ChaCha12 state seeded from `ProcessPrng` and reseeded every 64 KiB of output. A restored or duplicated image replays that state until its next reseed, whatever Windows does for `ProcessPrng` on restore.

<a id="p5-f-010"></a>
### P5-F-010 — Secret remanence beyond the x25519-dalek drop boundary

- **Status:** ACCEPTED-LIMITATION · **Severity:** INFO · **Confidence:** HIGH
- **Affected requirement(s):** P3 §5 (zeroization boundary).
- **Affected code:** vodozemac `get_mac_key` (`Box<[u8; 32]>`), `SasBytes`, HKDF state; `SasSession::{sas_bytes, decimal}`.
- **Threat scenario:** Memory forensics after the fact recovers derived per-ceremony MAC keys or SAS bytes.
- **Preconditions:** Memory access to the endpoint (compromised endpoint, swap, crash dump).
- **Reproduction:** Source inspection.
- **Security impact:** Per-ceremony and ephemeral. The SAS is not a secret. Long-term keys are not involved. No memory-forensic resistance is claimed.
- **Why existing tests/conformance did not catch or prevent it:** Documented in P3 §5 and the P4 closure.
- **Recommended remediation:** None required.
- **P6 disposition:** Keep.
- **Evidence:** [secrets, panics, dependencies §1](secrets-panics-dependencies.md#1-secret-lifetime).
- **P5.3 (strengthened, still ACCEPTED-LIMITATION, INFO)** ([deep review §10](dependency-unsafe-deep-review.md#10-secret-lifetime-and-zeroization)): the zeroizing drop of `EphemeralSecret` and `SharedSecret` is confirmed at the locked versions. Beyond it, three upstream copies were not recorded in P5.1. (1) The raw ephemeral private-key bytes stay in rand's thread-local `BlockRng` output buffer (not zeroized). (2) Until the next reseed (up to 64 KiB of output per thread) they can be regenerated from the ChaCha12 state (rand documents "no further protections exist to in-memory state"). (3) `mul_clamped` makes a clamped `Scalar` copy that is not zeroized on drop. HKDF, HMAC, and SHA-256 state and the boxed MAC keys are not zeroized (`zeroize` features off). The project itself adds no secret copy. These copies need endpoint memory access, which is out of scope, and P3 §5 already excludes "other copies".

<a id="p5-f-011"></a>
### P5-F-011 — Monotonic time across system suspend is unverified

- **Status:** ACCEPTED-LIMITATION · **Severity:** INFO · **Confidence:** MEDIUM
- **Affected requirement(s):** P3 §11.3 (re-evaluate deadlines conservatively on resume).
- **Affected code:** `core/src/deadline.rs` (`SystemClock` over `std::time::Instant`, i.e. QueryPerformanceCounter on Windows).
- **Threat scenario:** If the clock does not count suspended time, a ceremony suspended mid-flight resumes with its deadlines extended by the suspension.
- **Preconditions:** A system suspend during a live ceremony.
- **Reproduction:** Not available. It needs a real suspend.
- **Security impact:** Bounded: an extension of a ceremony's lifetime, not an authentication failure.
- **Why existing tests/conformance did not catch or prevent it:** Documented in the P4 closure "Explicit Limitations". `recheck_after_resume` cannot add time the clock did not count.
- **Recommended remediation:** Verify the target's QueryPerformanceCounter behavior across suspend, or adopt a suspend-inclusive clock (owner decision).
- **P6 disposition:** Keep, or verify.
- **Evidence:** [resources, deadlines, and transport §3](resources-deadlines-transport.md#3-deadlines).

<a id="p5-f-012"></a>
### P5-F-012 — An unauthenticated peer can saturate START admission and pending capacity

- **Status:** ACCEPTED-LIMITATION · **Severity:** INFO · **Confidence:** HIGH
- **Affected requirement(s):** P3 §11.1.1 (authority-wide limits, "not … DoS guarantees").
- **Affected code:** `core/src/start_limiter.rs`; `core/src/lib.rs:373–398` (pending slots).
- **Threat scenario:** A peer sends valid STARTs at the limiter rate (4 at once, then 1 per 5 s, at most 12 per 60 s), keeping the authority-wide credit and the 4 pending slots occupied. Honest STARTs are then refused with `ResourceLimited` for as long as the attack lasts.
- **Preconditions:** A reachable listener.
- **Reproduction:** Follows from the specified limits. P4 tests cover the limits.
- **Security impact:** Availability only. It does not affect the SAS budget, authentication, or other authorities.
- **Why existing tests/conformance did not catch or prevent it:** Specified behavior. Authority-wide, peer-unkeyed limits are deliberate (P3 forbids per-peer keying).
- **Recommended remediation:** None within the profile. Use deployment controls: bind scope and firewall.
- **P6 disposition:** Keep.
- **Evidence:** [resources, deadlines, and transport §1–2](resources-deadlines-transport.md#1-resource-table).

## Disproved candidates (FALSE-POSITIVE)

Each was constructed as a concrete attack and then disproved against source. They are recorded so that later reviewers do not re-file them.

<a id="p5-f-013"></a>
### P5-F-013 — More than ten contributions under one owner session

- **Status:** FALSE-POSITIVE · **Severity (if real):** CRITICAL · **Confidence:** HIGH (that it is false)
- **Affected requirement(s):** P3 §11.1; `R-OWNER-003`, `005`, `006`, `015`.
- **Affected code:** `core/src/lib.rs:466–496`; `core/src/ceremony.rs:1574–1692`.
- **Threat scenario:** Release an 11th `I_pub` or `R_pub` through a Busy or Exhausted reservation, a duplicate `INITIATOR_KEY`, a repeated `expose_key`, a panic between reservation and decrement, a second router or session, or an owner-loop restart.
- **Preconditions / Reproduction:** Every path was traced ([ownership and FFI §5](ownership-and-ffi.md#5-attempt-bound-re-derived-from-code)).
- **Why false:** The decrement and guard are taken in one critical section after both checks. One `Ceremony` can reserve at most once. Both contributions are produced only after `reserve` returns. Duplicates never re-emit. A panic happens after the decrement. Only `register` creates budget state (in-process re-registration is the separate [P5-F-003](#p5-f-003)).
- **Security impact / remediation / P6:** None.
- **Evidence:** Source; `it::shared_guard_race_has_one_winner`; `host::the_eleventh_exposure_is_refused_as_exhaustion_without_a_contribution`.

<a id="p5-f-014"></a>
### P5-F-014 — Equivalent X25519 encodings allow an equal-SAS substitution

- **Status:** FALSE-POSITIVE · **Severity (if real):** HIGH · **Confidence:** HIGH
- **Affected requirement(s):** P3 §5, §7.
- **Affected code:** `core/src/crypto.rs:66–72, 291–342`.
- **Threat scenario:** A MITM re-encodes `I_pub` or `R_pub` (setting bit 255, using `u ≥ p`, or adding a torsion component) so that both endpoints derive the same DH secret.
- **Why false:** The exact key bytes are inside the SAS HKDF info, the transcript, and `ceremony_identity`, so any re-encoding changes the SAS and the identity at the endpoint that received it. That is an ordinary detectable MITM. Low-order points are rejected by `was_contributory`.
- **Remediation / P6:** None.
- **Evidence:** [protocol composition §3, §5](protocol-composition.md#3-ephemeral-keys-and-contributory-checks); `crypto::every_sas_context_field_is_bound_into_the_live_sas`.

<a id="p5-f-015"></a>
### P5-F-015 — Codec accepts two byte strings for one semantic message

- **Status:** FALSE-POSITIVE · **Severity (if real):** MEDIUM · **Confidence:** HIGH
- **Affected requirement(s):** P3 §3.1; `R-WIRE-002`–`011`.
- **Affected code:** `core/src/protocol.rs`.
- **Why false:** Per type, `u32be(len) ‖ value` framing with exact field counts is a bijection. Field decodings are injective (raw bytes, fixed width, exact enum sets). Cryptographic inputs use the received canonical bytes.
- **Evidence:** [protocol composition §1](protocol-composition.md#1-canonical-parser-and-framing).

<a id="p5-f-016"></a>
### P5-F-016 — Non-constant-time comparisons leak secret material

- **Status:** FALSE-POSITIVE · **Severity (if real):** LOW · **Confidence:** HIGH
- **Affected code:** `crypto::verify_commitment` (`==`), `receive_completion` (digest), `confirm_initiator_finish_ack_sent` (bytes), `validate_bootstraps`.
- **Why false:** Every compared value is public or local. MAC tags are compared in constant time by `digest`'s `verify_slice`.
- **Evidence:** [secrets, panics, dependencies §5](secrets-panics-dependencies.md#5-side-channels-within-realistic-scope). P5.3 traced the tag comparison through `ctutils` to `cmov`'s x86 `asm!` and classified every project comparison ([deep review §9](dependency-unsafe-deep-review.md#9-side-channels-32)).

<a id="p5-f-017"></a>
### P5-F-017 — Request-ID-only authority, or a stale `RunRef` reaching a replacement run

- **Status:** FALSE-POSITIVE · **Severity (if real):** HIGH · **Confidence:** HIGH
- **Affected requirement(s):** P3 §4, §11.2; `R-OWNER-008`, `R-WIRE-016`.
- **Affected code:** `core/src/router.rs`.
- **Why false:** Every lookup is by `(session, request_id)`. Local actions recheck `RunRef.instance` (a never-reissued `Ceremony` id) under the run lock. Session handles are never reissued. SAS decisions also require the exact `ceremony_identity`.
- **Evidence:** [state and routing §3](state-and-routing.md#3-router-and-session-isolation); `host::a_stale_run_ref_or_identity_never_reaches_a_replacement_under_a_reused_request_id`.

<a id="p5-f-018"></a>
### P5-F-018 — Scope aliasing multiplies authorities inside the core

- **Status:** FALSE-POSITIVE · **Severity (if real):** HIGH · **Confidence:** HIGH
- **Affected requirement(s):** P3 §11.1.2(1–2); decision 0003; `R-OWNER-020`.
- **Threat scenario:** Two textual scopes naming one capability get two guards and two budgets.
- **Why false (as a core finding):** True in effect, but the core's defined guarantee is per canonical identity. P3 and decision 0003 assign alias rejection to the trusted registry, and the core documentation says so. The P7 binding must not expose raw `register(&[u8])` to untrusted input ([assumptions](assumptions-and-boundaries.md)).
- **Evidence:** [ownership and FFI §3](ownership-and-ffi.md#3-authority-scope-attack-on-aliasing).

<a id="p5-f-019"></a>
### P5-F-019 — Final ACK confirmed for another run under a reused key

- **Status:** FALSE-POSITIVE · **Severity (if real):** HIGH · **Confidence:** HIGH
- **Affected code:** `core/src/host.rs:404–427`; `core/src/ceremony.rs:1180–1198`.
- **Why false:** `FinalAck` is created only by the host, is not `Clone`, and is session-checked. The run accepts only its exact pending bytes, which embed a MAC bound to its own `ceremony_identity`. A replacement run under the same key holds different pending bytes (`FinalAckMismatch`, no effect).
- **Evidence:** `host::an_unconfirmed_final_ack_never_becomes_success`.

<a id="p5-f-020"></a>
### P5-F-020 — Shared counters underflow or wrap in release builds

- **Status:** FALSE-POSITIVE · **Severity (if real):** MEDIUM · **Confidence:** HIGH
- **Affected code:** `lib.rs` (`pending_responders`, `preliminary_operations`, `remaining`); `transport.rs` (`pending_accepts`, `live_connections`, `incomplete_frames`); `router.rs` (`in_flight`).
- **Why false:** Every decrement is paired with exactly one increment through a value taken once (`Option::take`, the `held` and `ended` flags, RAII drop), or is guarded (`remaining > 0`). A poisoned lock skips the decrement, which over-counts conservatively.
- **Evidence:** [secrets, panics, dependencies §3](secrets-panics-dependencies.md#3-panic-and-abort-surfaces).

<a id="p5-f-021"></a>
### P5-F-021 — START limiter grants extra credit at boundaries or after idle

- **Status:** FALSE-POSITIVE · **Severity (if real):** MEDIUM · **Confidence:** HIGH
- **Affected requirement(s):** P3 §11.1.1; `R-OWNER-034`–`039`.
- **Affected code:** `core/src/start_limiter.rs`.
- **Why false:** At the cap the remainder is zeroed. A refusal commits only elapsed-time bookkeeping. A token and a record are always charged together. Eviction is at age `≥ 60 s`. Arithmetic is checked. A backwards clock leaves the state unchanged.
- **Evidence:** [resources, deadlines, and transport §2](resources-deadlines-transport.md#2-start-limiter-rebuilt-mathematically).

<a id="p5-f-022"></a>
### P5-F-022 — A reflected BOOTSTRAP_MAC, CANCEL, or finish message is accepted

- **Status:** FALSE-POSITIVE · **Severity (if real):** HIGH · **Confidence:** HIGH
- **Affected requirement(s):** P3 §6, §8, §9, §11.3; `R-WIRE-017`, `R-MAC-009`, `016`.
- **Why false:** Bidirectional messages must carry the expected peer role (a reflected one carries our own role), and every MAC context binds sender and receiver. Completion steps are accepted only in the matching state with the local role as receiver.
- **Evidence:** [protocol composition §6](protocol-composition.md#6-mac-domain-separation-rebuilt-from-cryptors).

## Other disproved hypotheses (not filed)

- *The ownership lease can be released while ceremony state is live:* `release` uses `Arc::try_unwrap` (`Busy`), and the drop path keeps the lease until the last `Arc<State>` drops (`it::ownership_is_never_released_while_ceremony_state_remains`).
- *A guard is released before secret invalidation:* every terminal path drops the state first ([state and routing §1](state-and-routing.md#1-state-transition-table-rebuilt-from-remoteceremony)).
- *A deadline poll or presentation refreshes inactivity:* `progress_point` is unchanged and `presentation` uses read-only `evaluate`.
- *A truncated frame is followed by another frame after a deadline:* `AbandonedPartialFrame` closes the connection with nothing appended.
- *Unbounded composition of bounded resources:* the peer-driven worst case is a few MiB ([resources §1](resources-deadlines-transport.md#1-resource-table)).
- *Lock-path aliasing through 8.3 names or case:* the same directory and the same file are reached.
- *`unsafe impl Send for Lease` is unsound:* the handle is synchronous, `OVERLAPPED` is not retained, and locks belong to the file object.
- *A stale CANCEL after success kills sibling runs:* this is P3 §11.2 behavior ("unknown or stale" → session-fatal), not a defect.
- *Documentation overclaims:* searched README, core README, architecture, protocol status, SECURITY, project context, and P4 closure for "secure", "prevents MITM", "authenticated", "production", "verified", "guarantee", and "proves". No claim materially exceeds the evidence.
