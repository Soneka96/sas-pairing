# P6 Final Closure — Review Remediation and Protocol Candidate Freeze

> **Experimental protocol-candidate freeze only.** This closes P6 for an experimental, pre-alpha project. It is not production approval, a professional security audit, formal verification, certification, standards approval, or a proof of the complete cryptographic argument. The P5 review and every P6 follow-up review were internal and AI-assisted.

## 1. Scope

P6 took the five findings the internal P5 review handed over as OPEN, remediated or dispositioned each one under a recorded owner decision, synchronized the authoritative P3 profile and the normative conformance cases, and then decided whether the reviewed remote protocol candidate is stable enough for downstream native-ABI work. This document is that decision and the P6 closure summary. It adds no protocol behavior, owner decision, conformance row, or production change; P6.6 is documentation and status closure only.

Per-finding evidence lives in the remediation and disposition records ([p5-f-002.md](p5-f-002.md), [p5-f-001.md](p5-f-001.md), [p5-f-003.md](p5-f-003.md), [p5-f-005.md](p5-f-005.md), [p5-f-007.md](p5-f-007.md)); owner decisions live in [decisions.md](decisions.md). This document summarizes them and does not replace them.

## 2. Starting baseline

| Item | Value |
|---|---|
| `main` baseline | `57131ad4878063baf326fe0b2f7a0eded7a47982`, the merge of the P5 pull request #11 |
| P5 closure | `b892937a6740bee4a877d3beea815cca6d24c48c` ([P5 final synthesis](../p5-security-review/final-synthesis.md)) |
| P6 branch | `feature/p6-review-remediation-protocol-freeze`, one branch for every P6 increment, 0 commits behind `main` at closure |
| Implementation baseline | The experimental P4 native Rust core in `core/`, frozen and conformance-closed by P4 ([P4 conformance closure](../p4-conformance-closure.md)) and reviewed by P5 |
| Normative baseline | The [P3 remote profile](../p3-vodozemac-ceremony-profile-draft.md), owner decisions 0001–0003, the [threat model](../threat-model.md), and the [P3 conformance cases](../p3-conformance-cases.md) |

P4 was the frozen reviewed implementation baseline, and P5 reviewed it as it then was. P6 remediated and dispositioned the review findings on top of that baseline. The P4 conformance closure and the P5 package stay historical evidence of their own phases; neither is restated as if it already contained the P6 changes.

## 3. P6 increment history

| Increment | Scope | Commits | Outcome |
|---|---|---|---|
| P6.1 | P6 package and owner decisions; remediate P5-F-002; record the P5-F-003 decision | `ca2ee45` (decisions), `1ce0753` (fix), `79fc2dc` (record) | P5-F-002 REMEDIATED-IN-P6 (P6-D-001); P6-D-002 recorded |
| P6.2 | Remediate P5-F-001 graceful hang-up handling | `57779a7` (decision), `c4212f2` (fix), `e8f887a` (record) | P5-F-001 REMEDIATED-IN-P6 (P6-D-003) |
| P6.3 | Remediate P5-F-003 process-session accounting | `5aa1b15` (fix), `43eca55` (record) | P5-F-003 REMEDIATED-IN-P6 (P6-D-002) |
| P6.4 | Decide and disposition the P5-F-005 entropy-panic / ABI policy | `9628fa3` (test-only evidence), `77fb931` (decision and record) | P5-F-005 DISPOSITIONED-IN-P6 (P6-D-004), type B: mandatory P7 obligation |
| P6.4.1 | Correct P6-D-004's panic-payload disposal (item 14) and add the Drop-panicking-payload P7 exit test | `3b8bf43` | Policy correction; no new decision ID, finding, or production change |
| P6.5 | Disposition P5-F-007 reverse asymmetric completion | `6ab4175` | P5-F-007 DISPOSITIONED-IN-P6 (P6-D-005), type A: accepted semantics; P3 §9, §10, §11.3 clarified |
| P6.6 | Final cross-check, protocol-candidate freeze, and P6 closure | this closure commit | P6 COMPLETE; candidate frozen for P7 (§16) |

## 4. Final finding disposition

| Finding | P5 severity | P5 status at closure | Final P6 disposition | Decision | Evidence |
|---|---|---|---|---|---|
| [P5-F-001](../p5-security-review/findings.md#p5-f-001) | LOW | OPEN | **REMEDIATED-IN-P6** (P6.2) | [P6-D-003](decisions.md#p6-d-003--graceful-tcp-hang-up-handling) | [p5-f-001.md](p5-f-001.md); fix `c4212f2`; three P5 reproducers converted to passing regressions |
| [P5-F-002](../p5-security-review/findings.md#p5-f-002) | MEDIUM | OPEN | **REMEDIATED-IN-P6** (P6.1) | [P6-D-001](decisions.md#p6-d-001--f-002-connection-lifetime) | [p5-f-002.md](p5-f-002.md); fix `1ce0753`; P5 reproducer converted to a passing regression |
| [P5-F-003](../p5-security-review/findings.md#p5-f-003) | LOW | OPEN | **REMEDIATED-IN-P6** (P6.3) | [P6-D-002](decisions.md#p6-d-002--f-003-owner-session-policy) | [p5-f-003.md](p5-f-003.md); fix `5aa1b15`; `windows_tests::process_session` family and real-process probe |
| [P5-F-005](../p5-security-review/findings.md#p5-f-005) | INFO | OPEN | **DISPOSITIONED-IN-P6** (P6.4, corrected P6.4.1); the P7 implementation obligation remains | [P6-D-004](decisions.md#p6-d-004--native-panic-containment-policy) | [p5-f-005.md](p5-f-005.md); `p5_f005_001..005` fail-closed evidence; [P7 roadmap](../../roadmap/P7-native-abi.md) exit criteria |
| [P5-F-007](../p5-security-review/findings.md#p5-f-007) | INFO | OPEN | **DISPOSITIONED-IN-P6** (P6.5) | [P6-D-005](decisions.md#p6-d-005--local-completion-and-final-ack-deadline-boundary) | [p5-f-007.md](p5-f-007.md); `p5_f007_final_ack_deadline_boundary_end_to_end` unchanged |

**No P5 OPEN finding remains unresolved.** P5's historical closure counts are unchanged: 22 findings, of which 5 were OPEN at P5 closure, 6 ACCEPTED-LIMITATION, and 11 FALSE-POSITIVE ([P5 findings](../p5-security-review/findings.md)). No new finding was raised in P6, and the next free P5 ID stays `P5-F-023`.

The eleven false positives (P5-F-006, P5-F-013 to P5-F-022) stay classified and evidenced exactly as P5 recorded them; P6 did not revisit them.

## 5. Owner decisions

The final, frozen P6 decision set is [P6-D-001 to P6-D-005](decisions.md). Each is decided; none has an open alternative, and none contradicts or duplicates another. No further owner choice was needed for the freeze, so there is no P6-D-006.

| Decision | Subject | Final state | Finding |
|---|---|---|---|
| [P6-D-001](decisions.md#p6-d-001--f-002-connection-lifetime) | Connection lifetime | Decided (P6.1) and implemented: 10 s first frame, 10 s quiescent, 10 s / 2 s owner-less output; live ceremonies keep their own deadlines | P5-F-002 |
| [P6-D-002](decisions.md#p6-d-002--f-003-owner-session-policy) | Process-session accounting | Decided (P6.1): keep the P3 process/session semantics; implemented in P6.3 | P5-F-003 |
| [P6-D-003](decisions.md#p6-d-003--graceful-tcp-hang-up-handling) | Graceful TCP hang-up | Decided (P6.2) and implemented: `POLLERR`/`POLLNVAL` hard, `POLLHUP` drained toward EOF | P5-F-001 |
| [P6-D-004](decisions.md#p6-d-004--native-panic-containment-policy) | Native panic containment | Decided (P6.4), clarified in P6.4.1 (item 14); no core change; implementation owned by P7 | P5-F-005 |
| [P6-D-005](decisions.md#p6-d-005--local-completion-and-final-ack-deadline-boundary) | Local completion / final-ACK boundary | Decided (P6.5): confirmation-time rule retained (option A); option B rejected; no implementation change | P5-F-007 |

How they fit together: P6-D-001 bounds every connection state, and P6-D-003 relies on those bounds for half-closed peers instead of adding a hang-up timer. P6-D-002 fixes the accounting lifetime that P6-D-004 then refuses to reset after a panic. P6-D-005 adds no deadline or grace period, so P6-D-001's and P3 §11.3's deadlines stay the only timers.

## 6. Frozen protocol candidate

| Item | Value |
|---|---|
| Profile identifier | `sas-pairing-vodozemac-profile-draft-01` (unchanged) |
| Profile version | `1` (unchanged) |
| Authoritative semantics | [P3 vodozemac ceremony profile](../p3-vodozemac-ceremony-profile-draft.md), as amended in place during P6 |
| Owner policy | Decisions 0001–0003 and the [one-shot remote session policy](../p3-one-shot-remote-pairing-decision.md), unchanged |
| P6 freeze evidence | [P6 decisions](decisions.md) and the per-finding records |
| Reproducibility fixture | [vectors/p3-remote-vodozemac-draft-01.json](../../vectors/p3-remote-vodozemac-draft-01.json), unchanged |
| Pinned dependency | vodozemac 0.11.0, unchanged |

**P3 plus the P6 amendments and decisions are the frozen experimental candidate semantics.** P3 stays the one authoritative normative document. The P6 decisions are remediation and freeze evidence; they select values and boundaries inside what P3 already required (P3 §11.1.1 carries the P6-D-001 "Connection lifetime" row; §9, §10, and §11.3 carry the P6-D-005 clarification), and they do not form a competing specification. The wire profile is not renamed and its version is not incremented: freezing means this reviewed experimental candidate is stable enough for P7 to wrap, not that a new protocol identifier, draft, or "final" protocol exists.

### Wire freeze check

`git diff 57131ad..HEAD` shows no P6 change to `vectors/`, `docs/p3-deterministic-vectors.md`, `core/Cargo.toml`, or `core/Cargo.lock`, and none to the codec, cryptography, START limiter, or deadline modules (`core/src/protocol.rs`, `core/src/crypto.rs` and `core/src/crypto/`, `core/src/start_limiter.rs`, `core/src/deadline.rs`, `core/src/request_id.rs`). The P3 profile's P6 edits touch only §9 (result semantics), the §10 state table (completion rows), the §11.1.1 resource table (the new connection-lifetime row), and §11.3 (deadline wording). Consequently P6 changed none of: message type assignments, field order, field framing, profile identifier, profile version, completion MAC structure, `CANCEL` structure, transcript encoding, or commitment encoding.

### Crypto freeze check

P6 made no semantic change to X25519 handling, the vodozemac version or pin, SAS derivation, the commitment, the SHA-256 transcript, HKDF use, `BOOTSTRAP_MAC`, the completion MAC, the `CANCEL` MAC, or the canonical Base64url rules. P6 altered only connection lifecycle and resource policy (P6-D-001), transport readiness (P6-D-003), process accounting lifetime (P6-D-002), native-panic ABI policy (P6-D-004, documentation), and completion-result documentation (P6-D-005).

## 7. Frozen normative conformance

The normative set is unchanged at **92 rows** ([P3 conformance cases](../p3-conformance-cases.md)):

| Family | Rows | Note |
|---|---:|---|
| `R-OWNER-*` | 39 | `001`–`040`; the table has no `R-OWNER-028` (the numbering skips it, as P4 recorded) |
| `R-WIRE-*` | 26 | `001`–`026` |
| `R-MAC-*` | 23 | `001`–`023` |
| `R-RESOURCE-*` (applicable) | 4 | `006`–`009`, the timeout rows |
| **Total** | **92** | |

Checked at P6.6: every ID appears exactly once, the ID sets of all six families (including the non-normative ones) are identical to `main`, nothing was added, removed, or renumbered, and the conformance header's "P6 AMENDMENTS" note lists every P6 amendment (P6.1 `R-OWNER-023`; P6.2 `R-WIRE-025`, `R-MAC-012`; P6.3 `R-OWNER-006`, `017`, `022`, `031`, `038`; P6.4 `R-OWNER-013`; P6.5 `R-OWNER-007`, `R-MAC-012`, `R-RESOURCE-006`, `007`). `R-STATE-*`, `R-ACCOUNT-*`, and the other `R-RESOURCE-*` rows stay historical and non-normative; local-profile and adapter rows stay candidate-only.

## 8. Production changes made in P6

Every P6 production change traces to one finding, one decision, its regression tests, and its record. `git diff 57131ad..HEAD -- core/src` contains nothing else.

| Finding | Decision | Commit | Production files | Effect |
|---|---|---|---|---|
| P5-F-002 | P6-D-001 | `1ce0753` | `transport.rs` (`Lifetime`, connection deadlines), `router.rs` (`session_has_live_run`), `host.rs`, `windows_tcp.rs` (`poll_connection_deadlines`, write preflight, output progress), `windows_owner_loop.rs` (sweep) | Every admitted connection has exactly one finite governing deadline |
| P5-F-001 | P6-D-003 | `c4212f2` | `windows_owner_loop.rs` (readiness masks and dispatch) | `POLLHUP` drains toward EOF; `POLLERR`/`POLLNVAL` stay hard failures |
| P5-F-003 | P6-D-002 | `5aa1b15` | `lib.rs` (process-session registry, `State::end`), `bin/ownership_probe.rs` (`--session` test mode) | Budget, START limiter, and limiter clock live for the process session |

The remaining `core/src` and `core/tests` changes are test-only: permanent regression modules, converted P5 reproducers, test comment updates, and the P6.4 test-only fail-closed assertions (`9628fa3`). The `ceremony.rs` change is inside its test module.

**Dispositions, not remediations.** P5-F-005 and P5-F-007 changed no production code. P5-F-005 is a policy decision whose implementation obligation belongs to P7; P5-F-007 accepts the current behavior and documents it in P3 and the conformance rows.

## 9. Resource and deadline model

Frozen values (P3 §11.1.1, §11.3, and the START limiter rules; P6-D-001 added the connection-lifetime rows). Every bound is finite or governed by a finite process-session lifetime. Deployments may lower these values; any increase needs an explicit resource budget and must stay finite.

| Resource / state | Bound / deadline | Owner |
|---|---|---|
| Live unauthenticated connections | 16 per authority | Transport adapter (authority-wide transport admission) |
| Accept queue | 4 per authority | Transport adapter |
| Incomplete frames | 1 per connection, 4 per authority | Transport adapter |
| Frame size | 65,536 bytes, enforced before buffering | Codec / transport |
| Incomplete frame | 10 s whole frame, 2 s without progress | Transport adapter |
| First frame after admission | 10 s, never extended (P6-D-001) | Transport adapter |
| Quiescent connection (no live run, no frame, no output) | 10 s (P6-D-001) | Transport adapter |
| Owner-less output | 10 s absolute, 2 s without write progress (P6-D-001) | Transport adapter |
| Connection with a live ceremony | No connection timer; the ceremony's deadlines govern | Core (ceremony) |
| Pending pre-exposure Responder runs | 4 per authority | Core |
| Expensive preliminary operations | 2 per authority | Core |
| Pending-state deadline | 60 s from admission, never extended | Core |
| Ceremony absolute deadline | 5 min, never extended | Core |
| Ceremony inactivity deadline | 60 s; suspended while the complete SAS awaits deliberate human comparison (P3 §11.3), while the absolute deadline continues | Core |
| Exposure opportunity budget | 10 per authority per process session; never refunded or reset in the same process (P6-D-002) | Core (process-session registry) |
| Exposed-ceremony guard | 1 per authority | Core |
| START burst limiter | Capacity 4, refill 1 token per 5 s | Core (process session) |
| START rolling limiter | At most 12 admitted in `(now - 60 s, now]` | Core (process session) |
| Process-session registry entries | One per canonical authority this process has owned, from trusted local scopes only; never evicted; ends at process termination | Core |
| Active local Initiator request-ID reservations | One per live local Initiator ceremony, released at its terminal cleanup | Core |
| Owner loop | 1 + 16 polled sockets, at most one accept per drive, at most one socket operation per connection per drive, 250 ms maximum wait | Experimental Windows owner loop |

All deadlines use injected monotonic clocks and expire at `elapsed >= deadline`. Behavior across system suspend is not fully verified (P5-F-011, §12).

### Process-session semantics (P6-D-002)

For one canonical authority inside one native process, the ten-opportunity budget, the START limiter, and the limiter's monotonic clock persist across `release()`, the final handle drop, re-registration, listener or owner-loop restart, and frontend restart, until the process terminates. Every registration still reacquires the OS lease, so another process cannot own the same authority at the same time; while one registration is active a second gets `AlreadyRegistered`, and while another process holds the lease registration gets `OwnershipUnavailable`. Only a new process, after it safely acquires ownership, starts a fresh volatile process session. Uncertain release, poisoned accounting, or runtime resources left held fail that authority closed with `OwnershipUncertain` for the rest of the process. There is no reset API and no durable lifetime counter.

### Connection and hang-up semantics (P6-D-001, P6-D-003)

On an established connection, `POLLERR` and `POLLNVAL` are hard failures before any read or write, whatever else is reported. `POLLHUP` is a graceful stream condition: retained and readable input is drained toward EOF (one adapter read step per drive), pending output is not discarded because the peer half-closed, and EOF closes the connection without completing a partial frame. The owner loop makes at most one socket operation per connection per drive. A half-closed peer that never reaches EOF or never accepts output stays bounded by the P6-D-001 first-frame, quiescent, incomplete-frame, and owner-less-output deadlines and by the ceremony deadlines; the deadline sweep runs before any socket I/O. The listener is unchanged: `POLLERR`, `POLLHUP`, or `POLLNVAL` drops it.

## 10. Result semantics

Under P6-D-005 and P3 §9:

- **Initiator result:** the complete `INITIATOR_FINISH_ACK` was accepted by I's local send operation, and I confirmed that send while its ceremony was still live. Success is judged at the confirmation instant and never backdated to the last-byte write; no last-byte timestamp is recorded.
- **Responder result:** R received and verified the authenticated `INITIATOR_FINISH_ACK` while R's own ceremony was live.
- **Either endpoint may be the sole result holder.** I-only: the final ACK is lost after I's confirmed send. R-only: I's deadline is reached between its complete write and its confirmation, while R verifies the ACK.
- **No conflicting successful results:** if both return results, they agree on `ceremony_identity`, roles, authenticated bootstrap bytes, `shared_context`, and profile/version.
- **No bilateral-commit claim, no result rollback, no final-ACK grace period.** A later disconnect, timeout `CANCEL`, or session-fatal unknown route (P3 §11.2) never revokes a returned result. A `PairingResult` is local verified completion of one exact ceremony; consumers must tolerate either side being the only holder and must not treat it as a distributed commit.

## 11. Panic / native-boundary handoff

P6-D-004 (with the P6.4.1 item 14 correction) keeps the core fail-closed with no internal panic recovery, and assigns containment to P7. P6 does **not** implement it. The [P7 roadmap](../../roadmap/P7-native-abi.md) records the mandatory requirements and exit criteria:

```text
every native export runs its Rust work inside catch_unwind
  -> on Err(payload): mark the affected native context fatal
  -> suppress the payload's destruction (its destructor must not run; e.g. mem::forget)
  -> return a stable, language-neutral fatal ABI error
  -> every later call on that context returns the fatal-state error without re-entering the core
```

Also mandatory: coverage of every export and every Rust-owned thread root; destroy stays possible and never reactivates pairing; no panic payload, type name, path, string, secret, or address crosses the ABI; no custom panic hook that defeats containment; an unwind-compatible supported artifact pinned in CI (`panic = "abort"` and `extern "C-unwind"` are not the policy). Recovery is **process replacement**, never a same-process accounting reset (P6-D-002). The P7 exit tests run the containment path with an ordinary payload and with a Drop-panicking payload and show the payload destructor never runs. P7 containment is not runnable today; the current fail-closed core behavior is pinned by `p5_f005_001..005` and the P6.4 assertions.

## 12. Accepted limitations

These stay **accepted limitations**, re-confirmed by P5 and not remediated in P6. Nothing in P6 should be read as fixing them.

| Finding | Limitation | P6 position |
|---|---|---|
| [P5-F-004](../p5-security-review/findings.md#p5-f-004) | `token_user_sid` does not bound the OS-written SID pointer to the returned buffer; relies on a documented-by-implication Windows postcondition | ACCEPTED-LIMITATION. The `TOKEN_USER` range checks remain optional future hardening, not done in P6 |
| [P5-F-008](../p5-security-review/findings.md#p5-f-008) | A same-profile or administrator process can race the lock-path checks (TOCTOU) | ACCEPTED-LIMITATION; such an attacker already controls the endpoint (decision 0003) |
| [P5-F-009](../p5-security-review/findings.md#p5-f-009) | Fork, VM snapshot, restore, or duplicated state can repeat RNG state and ephemeral material | ACCEPTED-LIMITATION; unsupported deployments. No freshness or ownership claim across them |
| [P5-F-010](../p5-security-review/findings.md#p5-f-010) | Secret copies remain beyond the guaranteed upstream zeroization boundary (secret remanence) | ACCEPTED-LIMITATION; needs endpoint memory access |
| [P5-F-011](../p5-security-review/findings.md#p5-f-011) | Monotonic-clock behavior across system suspend is not fully verified | ACCEPTED-LIMITATION; bounded effect (a longer ceremony lifetime). Verification or a suspend-inclusive clock remains optional future work |
| [P5-F-012](../p5-security-review/findings.md#p5-f-012) | An unauthenticated peer can saturate START admission and pending capacity within the selected bounds | ACCEPTED-LIMITATION; specified, bounded, authority-wide behavior, not a DoS guarantee. P6-D-001 now bounds idle connections, but saturation within the limits stays possible |

Also unchanged: the conditional per-pair argument (`P_per_pair ≤ 2^-39 + δ`; `P_joint ≤ 19 × 2^-39 + ε` only for a joint 10/10 window within both process sessions) with its stated assumptions (SHA-256 commitment binding and random-oracle-style hiding, relevant HKDF-SHA256 behavior, fresh unpredictable ephemerals, contributory X25519, correct exposure ordering, atomic ownership and guard enforcement, and ideal human comparison); `R-MAC-001` and `R-MAC-015` PARTIAL (fixed-secret fixture values not recomputable through the pinned API); the cross-session part of `R-OWNER-012` resting on the owner-run manual verification of 2026-09-30; Windows-only executed evidence, with Linux evidence limited to the CI fail-closed job.

## 13. Security claims and non-claims

**Claimed (experimental scope only):**

- `sas-pairing-vodozemac-profile-draft-01` version 1 is a reviewed experimental protocol candidate (internal, AI-assisted P5 review).
- Every P5 finding handed to P6 is remediated or dispositioned under a recorded owner decision.
- The current implementation has regression evidence for each P6 remediation, including converted P5 reproducers.
- The normative conformance set (92 rows) is synchronized with the authoritative P3 profile.
- The downstream native-ABI requirements (P6-D-004 panic containment, P6-D-002 accounting preservation, P6-D-005 result semantics) are identified and recorded in the P7 roadmap.

**Not claimed:**

- production security, production readiness, or release approval;
- a professional audit or certification;
- formal verification, model checking, or a mathematical end-to-end proof;
- zero vulnerabilities;
- a complete side-channel or constant-time proof;
- safety under fork, VM snapshot, restore, or duplicated authority state;
- a durable or lifetime SAS probability bound, or any bound across arbitrary restarts;
- a DoS guarantee from the resource limits;
- any approved same-device profile or platform adapter.

The per-pair argument remains conditional on its stated assumptions.

## 14. Regression evidence

Representative permanent regression and evidence tests per finding (full tables are in each record):

| Finding | Tests |
|---|---|
| P5-F-002 | `transport::tests::connection_lifetime::*` (transition table, first-frame and quiescent boundaries at −1 ns / exact / +1 ns, 16 frameless connections and the 17th refusal released at exactly 10 s, nothing-refreshes cases, failing clocks); `windows_tcp::tests::connection_lifetime::*` (owner-less output 10 s / 2 s, quiescent after a real ceremony, an active ceremony silent for four minutes not killed); `windows_owner_loop::tests::connection_lifetime::*` (16 idle peers through real drives, sweep before I/O); converted `p5_f_002_idle_connections_eventually_release_their_live_slot`; `p5_tcp_out_001` |
| P5-F-001 | `windows_owner_loop::tests::graceful_hang_up::*` (readiness precedence matrix, retained input under hang-up, EOF, deadline bounds, hard failure over retained input, final ACK with hang-up, real full close and `shutdown(Send)` loopback cases); the three converted `p5_f_001_*` reproducers; the renamed P4 `error_or_invalid_handle_readiness_*` test |
| P5-F-003 | `windows_tests::process_session::*` (release and drop keep the budget, exhaustion survives re-registration, burst and rolling limiter history persist, clock continuity, ownership races, foreign holder, uncertainty and poisoning fail closed); `security_core` integration tests including the real-process `every_new_process_starts_fresh_but_its_re_registration_does_not`; `ceremony::tests::only_a_new_process_session_starts_a_fresh_limiter` |
| P5-F-005 | `ceremony::tests::an_ephemeral_generation_panic_exposes_nothing_and_refunds_nothing`; `p5_f005_001..005` through the Router, adapter, and owner loop, with the P6.4 post-panic re-registration assertions; `tests::poisoned_shared_state_fails_closed` |
| P5-F-007 | `p5_f007_final_ack_deadline_boundary_end_to_end` (crossing row R-only, unchanged); `ceremony::tests::final_ack_lost_after_send_leaves_only_the_initiator_with_a_local_result` (I-only); final-ACK confirmation, expiry, and unknown-route tests at the ceremony, host, adapter, and owner-loop layers |

No P5 EXPECTED-FAIL reproducer remains: the four were converted to passing regressions with their remediations, and the P5.1 throwaway patch stays historical and unapplied. The three tests still `#[ignore]`d are long P5 deep runs (passing evidence, not known-bug reproducers).

## 15. Final verification

Run on Windows at the P6.6 closure tree (its Rust sources, manifests, and lockfile are identical to `6ab4175`; `git diff 6ab4175 -- core/src core/Cargo.toml core/Cargo.lock vectors/` is empty):

| Check | Result |
|---|---|
| `rustc --version` | `rustc 1.99.0 (b940084d7 2026-09-28)` |
| `cargo fmt --manifest-path core/Cargo.toml -- --check` | Pass |
| `cargo clippy --manifest-path core/Cargo.toml --all-targets -- -D warnings` | Pass (Windows); also pass for `--target x86_64-unknown-linux-gnu` (compile-level only; Linux tests run in CI) |
| `cargo test --manifest-path core/Cargo.toml` | Pass: 415 unit (3 ignored deep runs), 2 `p5_review_evidence`, 9 `security_core`, 1 doc test; 0 failed |
| Targeted P6 regression set (§14), rerun by filter | Pass: 16 unit-test filters (`connection_lifetime` 15, `p5_f_002` 1, `p5_tcp_out_001` 1, `graceful_hang_up` 12, `p5_f_001` 3, `error_or_invalid_handle` 1, `real_loopback_peer_hang_up` 1, `process_session` 14, `only_a_new_process_session` 1, `poisoned_shared_state` 2, `p5_f005` 5, `an_ephemeral_generation_panic` 1, `p5_f007` 1, `final_ack` 21, `deadlines_found_by_input_actions_or_confirmation_keep_their_cancel` 1, `an_unknown_route` 3) and all 9 `security_core` integration tests; 0 failed. P7 ABI containment itself is not runnable yet |
| `p5_router_race_002_close_versus_start_admission` | Pass in the full suite, 100 of 100 isolated runs, and 20 of 20 runs of all nine `p5_router_race` tests. The one-off failure previously seen during P6.3 mutation testing did not recur on the clean P6 tree |
| Repository consistency checks (the `consistency.yml` script, run locally) | Pass |
| `git diff --check` | Pass |
| Relative Markdown links and anchors of the documents P6.6 touched (local script; the repository has no link checker) | Pass |
| GitHub Actions on the closure HEAD (Repository consistency; Rust security core `windows-core` and `unsupported-platform-fails-closed`) | Required green before the P6 pull request is opened; reported in the pull request |

## 16. Freeze decision

Every closure condition holds: the branch is not behind `main`; no P5 OPEN finding remains; P6-D-001 to P6-D-005 are final with no pending alternative; P3 is synchronized and remains authoritative; the normative conformance set is exactly 92; P6 changed no wire, vector, or cryptographic semantics; every production change has finding, decision, test, and record traceability; the accepted limitations are explicit; P6.6 changed no production code; local verification is green; and no new finding appeared.

**P6 REVIEW REMEDIATION COMPLETE.**

**The experimental remote protocol candidate `sas-pairing-vodozemac-profile-draft-01`, version 1, together with the P6 owner decisions and amended normative conformance requirements, is FROZEN FOR P7 NATIVE-ABI WORK.**

This is an experimental protocol-candidate freeze only. It is not production approval, professional security audit, or formal verification.

A later change to the frozen candidate's wire bytes, cryptography, ceremony authentication, result semantics, or security accounting needs an explicit owner decision, a corrected P3 profile and conformance set, and re-review; it reopens the relevant earlier gate rather than being made inside P7.

## 17. P7 handoff

[P7 — Native ABI](../../roadmap/P7-native-abi.md) is next and is unlocked only after the P6 pull request is reviewed and merged into `main`; it does not start from the unmerged P6 branch. P7 must:

- wrap the frozen candidate without changing its protocol behavior, and keep wrappers as callers of the one core;
- implement the P6-D-004 containment and pass its exit criteria (§11), including the Drop-panicking-payload test and the unwind-compatible artifact check;
- preserve process-session accounting across the boundary: no ABI path (handle close and reopen, re-registration, re-creation after a fatal panic) resets the budget or START limiter in the same process (P6-D-002);
- expose result semantics faithfully: a `PairingResult` is local verified completion, either side may be the only holder, and wrapper documentation must not present it as a bilateral commit (P6-D-005);
- keep the accepted limitations (§12) disclosed rather than implying they were solved.

## 18. Final status

| Item | State |
|---|---|
| P6 | **COMPLETE — PROTOCOL CANDIDATE FROZEN** (experimental) |
| P5 OPEN findings handed to P6 | 0 remaining: 3 REMEDIATED-IN-P6, 2 DISPOSITIONED-IN-P6 |
| Accepted limitations | P5-F-004, P5-F-008 to P5-F-012, unchanged |
| False positives | P5-F-006, P5-F-013 to P5-F-022, unchanged |
| Owner decisions | P6-D-001 to P6-D-005, final |
| Normative conformance | 92 rows (39 / 26 / 23 / 4) |
| Frozen candidate | `sas-pairing-vodozemac-profile-draft-01`, version 1 |
| Next | P7 — Native ABI, after the P6 pull request is reviewed and merged |
| Production status | Pre-alpha; not production-ready; no professional audit or formal verification |
