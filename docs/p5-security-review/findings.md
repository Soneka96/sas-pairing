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

`OPEN` (confirmed, remediation recommended) · `NEEDS-DECISION` (confirmed behavior whose remedy depends on an owner interpretation or value) · `FALSE-POSITIVE` (disproved) · `ACCEPTED-LIMITATION` (already accepted by an owner decision or the normative profile; re-confirmed here) · `OUT-OF-SCOPE` · `DUPLICATE` · `REMEDIATED-IN-P6` (not used in P5).

## Summary

| Severity | Open (incl. NEEDS-DECISION) | False Positive | Accepted Limitation | Out of Scope |
|---|---|---|---|---|
| CRITICAL | 0 | 1 (P5-F-013) | 0 | 0 |
| HIGH | 0 | 5 (P5-F-014, 017, 018, 019, 022) | 0 | 0 |
| MEDIUM | 1 (P5-F-002, NEEDS-DECISION) | 3 (P5-F-015, 020, 021) | 0 | 0 |
| LOW | 2 (P5-F-001; P5-F-003, NEEDS-DECISION) | 1 (P5-F-016) | 0 | 0 |
| INFO | 4 (P5-F-004, 005, 006, 007) | 0 | 5 (P5-F-008–012) | 0 |

**No CRITICAL or HIGH finding is confirmed.** Nothing was found that yields pairing success without SAS agreement, exposes secret material remotely, or bypasses the one-owner / one-guard / ten-opportunity accounting under one registration.

## Finding index

| ID | Title | Severity | Confidence | Status |
|---|---|---|---|---|
| [P5-F-001](#p5-f-001) | Owner loop discards bytes received before a graceful peer close | LOW | HIGH | OPEN |
| [P5-F-002](#p5-f-002) | Connections with no frame in progress never expire, so 16 idle peers hold the live-connection cap indefinitely | MEDIUM | HIGH | NEEDS-DECISION |
| [P5-F-003](#p5-f-003) | In-process re-registration starts a fresh opportunity budget without process replacement | LOW | HIGH | NEEDS-DECISION |
| [P5-F-004](#p5-f-004) | `token_user_sid` does not bound the OS-written SID to the returned buffer | INFO | HIGH | OPEN |
| [P5-F-005](#p5-f-005) | `Sas::new()` entropy panic leaves Router and adapter state conservatively stuck and escapes owner-loop calls | INFO | HIGH | OPEN |
| [P5-F-006](#p5-f-006) | `base64`'s default `simd-unsafe` engine encodes every MAC and HKDF input | INFO | HIGH | OPEN |
| [P5-F-007](#p5-f-007) | Reverse asymmetric completion at the Initiator's deadline boundary | INFO | HIGH | OPEN |
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

- **Status:** OPEN
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
  4. The final-ACK consequence follows from the same code path. An end-to-end ceremony with the loop as Responder was **not** run separately.
- **Security impact:** No false success and no authentication or accounting effect: the Responder fails closed. It turns a *delivered* final ACK into the "Initiator succeeded, Responder has no result" outcome that P3 §9 attributes to message loss, and it can do so routinely when Initiators close promptly. Consumers may then hold one-sided trust, which P3 already requires them to tolerate. It also drops frames from half-closing peers. This is a robustness and interoperability defect of the experimental adapter.
- **Why existing tests/conformance did not catch or prevent it:** P4 intended "hang-up closes without I/O", and its scripted test asserts that. The real-loopback hang-up test accepts either `Readiness` or `PeerClosed` with no data in flight. The real-loopback full ceremony runs the loop as Initiator only. Windows' report of hang-up together with readable data was never pinned.
- **Recommended remediation:** Treat `POLLHUP` without `POLLERR`/`POLLNVAL` as "readable until EOF": keep serving `on_readable` (retained suffix, then socket) one bounded operation per drive, and close only on `read() == 0` or an error. Keep `POLLERR`/`POLLNVAL` as immediate close. Add regression tests: the reproducer, and a real-loopback ceremony with the loop as Responder whose Initiator closes immediately after its final ACK.
- **P6 disposition:** Remediate (adapter-only, no protocol change). Turn the reproducer into a regression test.
- **Evidence:** the tests above; [resources, deadlines, and transport §5](resources-deadlines-transport.md#5-owner-loop); the experiment transcript in [reproducers](reproducers/README.md).

<a id="p5-f-002"></a>
### P5-F-002 — Connections with no frame in progress never expire, so 16 idle peers hold the live-connection cap indefinitely

- **Status:** NEEDS-DECISION
- **Severity:** MEDIUM
- **Confidence:** HIGH
- **Affected requirement(s):** P3 §11.1.1 "Incoming connections" (the cap of 16 "includes connections that have not sent a frame"), "Incomplete frame reception" ("finite header/whole-frame deadlines plus an idle-read deadline"), and "Lifetime and cleanup" (temporary resources are released on timeout); `R-OWNER-023`, `R-OWNER-026`; the threat model's resource-bounded input.
- **Affected code:** `core/src/transport.rs:299–307` (`poll_frame_deadlines` returns at once with no clock read when no frame is partial) and `:370–392` (deadlines exist only for a `Partial`). `core/src/windows_owner_loop.rs:549–569` (the sweep calls only those polls). Neither `windows_tcp.rs` nor `windows_owner_loop.rs` has any connection lifetime or post-ceremony close.
- **Threat scenario:** A peer that can reach the listener opens 16 TCP connections and sends nothing. Alternatives: it finishes or abandons a ceremony and then stays silent, or it advertises a zero receive window so a retained, owner-less CANCEL never drains. Each connection holds one authority-wide live slot indefinitely. Every later connection to any listener of that authority is accepted and immediately refused (`ResourceLimited`). Honest half-open connections (a peer that vanished without FIN or RST) accumulate the same way, because the adapter enables no TCP keepalive.
- **Preconditions:** The listener is reachable by the attacker, which depends on the deployment's bind policy. The attacker keeps 16 connections open with no traffic.
- **Reproduction:** [Reproducer patch](reproducers/README.md), test `transport::tests::p5_f_002_frameless_connections_do_not_hold_the_live_cap_forever`: 16 frameless connections, transport clock advanced 24 h. Every `poll_frame_deadlines()` returns `Ok(())` and the connection is still live. Counts are `(pending 0, live 16, incomplete 0)`. A 17th activation is `ResourceLimited`. Supporting: the existing `transport::tests::sixteen_frameless_connections_fill_the_cap_and_the_seventeenth_is_refused`.
- **Security impact:** Availability only. Remote pairing for the authority can be locked out persistently, at no cost, until local intervention. No effect on authentication, the SAS budget, the START limiter, or secrets. P3 says the numeric defaults are not DoS guarantees, but without a lifetime the cap can be exhausted permanently with zero ongoing traffic, and non-adversarial half-open sockets exhaust it over time.
- **Why existing tests/conformance did not catch or prevent it:** P4 read the frame deadlines as starting at a frame's first retained byte, and tested frameless connections only as correctly counted against the cap. No conformance row states a connection lifetime or time-to-first-byte. The owner loop leaves close policy to its owner.
- **Recommended remediation:** Values are an owner decision. Add a finite, never-refreshed time-to-first-header deadline from activation; a finite idle lifetime for a connection whose session has no live run; and a bound on how long a retained owner-less frame may wait. Each should close through the existing generic teardown, with no limiter, budget, or guard change. Optionally enable TCP keepalive in the adapter. P3 gives no values, so they must be chosen, kept finite, and never allowed to reset an authority control.
- **P6 disposition:** Owner decision on the P3 interpretation (does a frameless connection have a "header deadline"?) and the values, then remediation in the transport and adapter with the reproducer as a regression test.
- **Evidence:** as above; [resources, deadlines, and transport §1, §3, §4](resources-deadlines-transport.md).

<a id="p5-f-003"></a>
### P5-F-003 — In-process re-registration starts a fresh opportunity budget without process replacement

- **Status:** NEEDS-DECISION
- **Severity:** LOW
- **Confidence:** HIGH
- **Affected requirement(s):** P3 §11.1 ("10 exposed remote SAS opportunities" per owning process/session; "a legitimate process restart starts a new local session budget only after the previous owner has terminated"); P3 §11.1.2(5) ("restarting a frontend while the owning process remains alive does not reset that budget"); `R-OWNER-006`, `R-OWNER-022`, `R-OWNER-038(c)`.
- **Affected code:** `core/src/lib.rs:245–281` (`register_with` creates `Shared { remaining: 10, start_limiter: StartLimiter::new(), … }`), `:200–206` (`State::drop` removes the registry entry), `:311–322` (`release`).
- **Threat scenario:** Inside one live OS process, trusted code exhausts the budget, then releases the authority (or drops every handle) and calls `TrustedAuthority::register` with the same scope. The registry entry is gone and the process re-acquires the OS lease, so a fresh budget of 10 and a fresh START limiter exist, without any process termination. A future binding that re-registers on a frontend restart, UI reconnect, or error recovery would silently reset the budget while the native process lives.
- **Preconditions:** Code holding `TrustedAuthority` (trusted local code) releases and re-registers. A remote peer cannot trigger this.
- **Reproduction:** Existing integration tests: `process_ownership_and_full_reservation_lifecycle` (after 10 reservations and `Exhausted`, `release()` then `register(b"integration-owner")` → `Ready { remaining: 10 }`; `core/tests/security_core.rs:170–175`) and `ownership_is_never_released_while_ceremony_state_remains` (all handles dropped, re-register → `remaining: 10`; lines 315–323).
- **Security impact:** The numeric 19-pair window is defined per owning-process session. In-process re-registration creates more such windows within one process lifetime. It gives a remote attacker nothing and allows no more than a process restart would, and P3 claims no lifetime bound. The risk is at the integration level: a binding could reset the budget on events P3 says must not reset it.
- **Why existing tests/conformance did not catch or prevent it:** P4 deliberately defined the owner session as the registration lifetime (closure note on `R-OWNER-006`: "Only a new `TrustedAuthority`, after the OS lease is acquired, has fresh state") and tested it as correct replacement. `R-OWNER-022` evidence covers only the owner loop.
- **Recommended remediation:** An owner decision between (a) ratifying "owner session = registration lifetime" in P3 or decision text and requiring P7 bindings never to re-register except on genuine owner replacement, and (b) making the core refuse a second registration of an identity within one process lifetime (a process-lifetime tombstone), so that only a new process starts a fresh budget.
- **P6 disposition:** Owner decision, then either a documentation correction or a core change with tests.
- **Evidence:** as above; [ownership and FFI §2, §5](ownership-and-ffi.md#2-lease-lifecycle).

<a id="p5-f-004"></a>
### P5-F-004 — `token_user_sid` does not bound the OS-written SID to the returned buffer

- **Status:** OPEN
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
- **Evidence:** [ownership and FFI §4, §6](ownership-and-ffi.md#4-increment-201-token_user-re-audit).

<a id="p5-f-005"></a>
### P5-F-005 — `Sas::new()` entropy panic leaves Router and adapter state conservatively stuck and escapes owner-loop calls

- **Status:** OPEN
- **Severity:** INFO
- **Confidence:** HIGH
- **Affected requirement(s):** P3 §5 (no success from failed entropy; no graceful-error promise); P3 §11.2 (teardown); decision 0001 (future native boundary).
- **Affected code:** `core/src/crypto.rs:58–60`. Responder path: `core/src/router.rs:921–951` (the claim is inserted, admission runs outside the lock, and no RAII guard removes `Route::Admitting`). Initiator path: `core/src/ceremony.rs:1600`, running under `core/src/router.rs:1095–1103` (`on_run` holds the run mutex while `op` runs).
- **Threat scenario:** The OS entropy source fails while either:
  - (a) a peer's START is being admitted. The panic unwinds out of `Router::route_start`, and the `Admitting` claim for that `(session, request_id)` stays until session teardown. Copies of that START become "duplicates", and non-START frames for that key fail as out of order.
  - (b) a local `expose_key` runs. The run mutex is poisoned. Deadline polls and session teardown then report `OwnershipUncertain`, the session stays CLOSING with its live-connection count held, and the owner loop fails closed.

  In both cases the panic propagates out of `drive_once` or the local action to the caller.
- **Preconditions:** OS entropy failure, which an attacker cannot control. The effects persist only if the caller catches the panic and keeps using the objects; otherwise unwinding drops everything.
- **Reproduction:** Source inspection. P4's injected-panic test `ceremony::tests::an_ephemeral_generation_panic_exposes_nothing_and_refunds_nothing` covers ceremony-level accounting only, not the unwind through the Router or adapter.
- **Security impact:** None for pairing security: no exposure, refund, or success (P4 evidence). The availability effect follows an event that is already catastrophic. A panic must also never cross a future FFI boundary.
- **Why existing tests/conformance did not catch or prevent it:** The P4 hook injects the panic below the Router and adapter, and no test unwinds through them.
- **Recommended remediation:** Decide the native library's panic policy: `panic = "abort"`, or a `catch_unwind` boundary at the P7 ABI. If unwinding stays, remove an `Admitting` claim with an RAII guard and treat a poisoned run as terminal for teardown, so recovery is bounded.
- **P6 disposition:** Owner decision on panic policy (together with P7); optional Router hardening.
- **Evidence:** [state and routing §3](state-and-routing.md#3-router-and-session-isolation); [secrets, panics, dependencies §3](secrets-panics-dependencies.md#3-panic-and-abort-surfaces).

<a id="p5-f-006"></a>
### P5-F-006 — `base64`'s default `simd-unsafe` engine encodes every MAC and HKDF input

- **Status:** OPEN
- **Severity:** INFO
- **Confidence:** HIGH
- **Affected requirement(s):** P3 §3.2 (strict unpadded Base64url for every SAS, MAC, and CANCEL input); decision 0002 (the reviewed, pinned dependency path); `R-MAC-014`.
- **Affected code:** `core/Cargo.toml` (`base64 = "0.23"`, default features; vodozemac also enables the defaults); `core/src/crypto.rs:261–285` (`capped_base64url` → `URL_SAFE_NO_PAD.encode`). In `base64` 0.23.1, `default = ["std", "simd-unsafe"]`, which selects AVX2 or NEON `unsafe` encoders at run time.
- **Threat scenario:** A defect in a SIMD encoder for some length or CPU (AVX2 vs scalar vs NEON on a future mobile peer) would produce a different string for the same frame. Peers on the same CPU class would still agree. Peers on different classes would derive different MAC or HKDF inputs and fail closed. A memory-safety defect in that `unsafe` encoder would sit on attacker-influenced lengths (the bootstrap fields).
- **Preconditions:** An upstream encoder defect, and peers on different CPU classes.
- **Reproduction:** `cargo tree -e features` shows `base64 feature "simd-unsafe"`; source `base64-0.23.1/src/engine/simd.rs`. No defect was demonstrated.
- **Security impact:** None demonstrated. There is a fail-closed interoperability risk and an extra upstream `unsafe` surface in the authentication path. Fixture tests exercise only the CI machine's backend and the fixture's lengths.
- **Why existing tests/conformance did not catch or prevent it:** Feature unification is implicit. P4 recorded the version but not the feature.
- **Recommended remediation:** An owner decision to accept and record it, or to reduce it (ask vodozemac to allow disabling the feature, or adjust the core's `base64` features where unification allows). Add a test-only reference Base64url encoder compared across every length up to the 65,536-byte cap.
- **P6 disposition:** Decide; optional test.
- **Evidence:** [secrets, panics, dependencies §6](secrets-panics-dependencies.md#6-dependencies).

<a id="p5-f-007"></a>
### P5-F-007 — Reverse asymmetric completion at the Initiator's deadline boundary

- **Status:** OPEN
- **Severity:** INFO
- **Confidence:** HIGH
- **Affected requirement(s):** P3 §9 (result conditions; asymmetric observation); P3 §11.3 (expiry produces no success).
- **Affected code:** `core/src/windows_tcp.rs:410–451, 649–663` (deadline preflight before the write; `confirm` checks deadlines again); `core/src/ceremony.rs:1173–1198` (`confirm_initiator_finish_ack_sent` runs `step()` first).
- **Threat scenario:** I's final ACK is fully written after a live preflight. Before `confirm` runs, the absolute or inactivity deadline expires. I times out with no result and offers its timeout CANCEL after the complete ACK. R receives the complete final ACK, verifies it, succeeds, and then ignores I's CANCEL (`Completed`). Outcome: R succeeded and I did not. A delivery-controlling attacker can aim for this window by slowing the drain of the final ACK until near the deadline.
- **Preconditions:** The final-ACK write completes just before a deadline: inactivity, 60 s after RESPONDER_FINISH_ACK, or the absolute 5 minutes from creation.
- **Reproduction:** Source inspection. It is deterministic with hand clocks (`ManualClock::advance_after`), but no reproducer was added.
- **Security impact:** No conflicting success, since only one side succeeded, and R's success is fully authenticated: I's final MAC proves I verified R's finish after both approvals. P3 §9 describes only the I-success / R-failure direction, so consumers must equally tolerate R-success / I-failure. This is documentation clarity.
- **Why existing tests/conformance did not catch or prevent it:** P4 rightly treats "confirmation after expiry creates no result" as the safe choice but did not document the mirrored outcome.
- **Recommended remediation:** State in P3 §9 and the consumer guidance that either side may hold the only result. Optionally (owner decision), judge the confirmation against the instant the last byte was written rather than the confirmation instant.
- **P6 disposition:** Documentation; optional decision.
- **Evidence:** [protocol composition §7](protocol-composition.md#7-completion-and-pairingresult); [resources, deadlines, and transport §3](resources-deadlines-transport.md#3-deadlines).

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
- **Evidence:** `rand-0.10.3/src/rngs/thread.rs` documents no reseed on fork.

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
- **Evidence:** [secrets, panics, dependencies §5](secrets-panics-dependencies.md#5-side-channels-within-realistic-scope).

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
