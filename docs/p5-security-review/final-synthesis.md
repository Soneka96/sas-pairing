# P5 Final Review Synthesis

> **Internal, AI-assisted implementation and protocol security review.** This is not a professional penetration test, a professional cryptographic audit, formal verification, model checking, exhaustive fuzzing, certification, a proof of constant-time behavior, or production-security approval.

This is the authoritative closure summary of P5. Detailed evidence stays in the documents it links to; this page does not repeat it.

## 1. Review target

| Item | Value |
|---|---|
| Target | The frozen experimental P4 native Rust security core (`core/`) |
| Baseline commit | `main` at `e21ff0bab97009cc771bfc90a6019496721baf78` (merge of the P4 PR). Its tree is byte-identical to the P4 final-freeze commit `5bf0a0b`; production code is that of the final P4 implementation commit `86e77ea` |
| Normative baseline | The selected P3 experimental remote profile and owner policy, decisions 0001–0003, the threat model, and the current P3 conformance rows ([README](README.md#normative-baseline)) |
| Review branch | `feature/p5-security-review` (one branch, one pull request) |
| Review commits | `2e49c68`, `3e4b383`, `e5da69c` (P5.1); `02f7086` (P5.1.1); `5ca9476`, `c4f26e2` (P5.2); `850b042`, `5ae05c7` (P5.3); and the P5.4 closure commit that adds this page |
| Toolchain and host | `rustc 1.99.0`, Windows 11 Pro 10.0.26200; CI `windows-latest` and `ubuntu-latest` |
| Review dates | 2026-10-02 (all increments) |

## 2. Review method

The [review method](review-method.md) was fixed before any conclusion and was never weakened. Each increment added techniques:

- **P5.1, broad adversarial review.** Specification-to-code tracing of every security-relevant P3 rule; adversarial reasoning over 34 review surfaces and 12 attacker and fault models; tables rebuilt from source (MAC domains, state transitions, resources, `unsafe`, Win32 errors, panics); review-only Clippy lints; an OSV/RustSec advisory query; and executed reproducers for every candidate rated MEDIUM or above. Every candidate passed a written false-positive discipline.
- **P5.1.1, classification correction.** P5-F-002 and P5-F-003 were reclassified from NEEDS-DECISION to OPEN against the current P3 text.
- **P5.2, generated adversarial sequences.** Bounded deterministic exploration with no randomness and no new dependency: 36,519 state-machine sequences for both roles, duplicate/reorder and deadline-boundary matrices, transport chunking and socket-result families, a `WSAPoll` readiness matrix, real-Windows graceful-close cases, and nine forced Router race scenarios ([adversarial sequences](adversarial-sequences.md)).
- **P5.3, dependency, unsafe, and secret-lifetime deep review.** The locked graph rebuilt with `--locked` and 96/96 archive checksums verified; runtime crypto paths traced into locked upstream source; reachable upstream and all project `unsafe` audited; Windows contracts taken from primary documentation and kept apart from OS observations; an independent Base64url reference; side channels classified to their primitives; secret lifetime traced past the zeroization boundary ([deep review](dependency-unsafe-deep-review.md)).
- **P5.4, synthesis and closure.** Reconciliation of every finding, the coverage matrix, the reproducer inventory, and every status document. No new technical review and no new test.

## 3. Coverage

**34 / 34 planned review surfaces COMPLETE. 0 PARTIAL. 0 NOT-STARTED.** See the [coverage matrix](coverage.md).

COMPLETE means that the planned P5 method was carried out end to end for that surface. It does not mean that the absence of defects was proven. The bounded techniques stay bounded:

- state-machine sequences go to suffix depth 3 from honest prefixes over a reduced alphabet, not unbounded sequences;
- Router concurrency forced every linearization point in both orders and repeated it, but no loom-style exhaustive interleaving was run;
- real-socket facts come from one Windows build and CI;
- side channels were classified and traced, not measured or proven constant-time;
- upstream crates are trusted beyond the inspected paths;
- no fuzzing, property testing, formal model, Miri, or sanitizer run was performed.

## 4. Final finding summary

Severity for a FALSE-POSITIVE entry is what the candidate would have been if real.

| Severity | Open | False positive | Accepted limitation | Out of scope | Total |
|---|---|---|---|---|---|
| CRITICAL | 0 | 1 | 0 | 0 | 1 |
| HIGH | 0 | 5 | 0 | 0 | 5 |
| MEDIUM | 1 | 3 | 0 | 0 | 4 |
| LOW | 2 | 1 | 0 | 0 | 3 |
| INFO | 2 | 1 | 6 | 0 | 9 |
| **Total** | **5** | **11** | **6** | **0** | **22** |

IDs `P5-F-001` to `P5-F-022` are stable; the next free ID is `P5-F-023`. No finding is NEEDS-DECISION, OUT-OF-SCOPE, DUPLICATE, or REMEDIATED-IN-P6. **No finding was remediated in P5.** Full entries: [findings](findings.md).

## 5. Confirmed OPEN findings

- **[P5-F-002](findings.md#p5-f-002) — MEDIUM, confidence HIGH.** An admitted connection with no frame in progress has no finite lifetime: zero bytes after admission (A), idle after its run ended (B), or holding an owner-less retained frame that the peer never drains (C). Sixteen silent peers therefore hold the authority-wide live-connection cap indefinitely and lock out remote pairing for that authority, at no ongoing cost. P3 §11.1.1 already requires finite header and idle-read deadlines; P4 started its transport deadlines only at a frame's first byte. Availability only.
- **[P5-F-001](findings.md#p5-f-001) — LOW, confidence HIGH.** The Windows owner loop treats `POLLHUP` as immediate failure. Windows reports `POLLHUP` together with readable data after a graceful close, so the loop discards complete frames still to be read, frames already buffered, and its own pending output to a half-closed peer. In practice an owner-loop Responder loses a delivered final ACK when the Initiator closes promptly. Every case fails closed.
- **[P5-F-003](findings.md#p5-f-003) — LOW, confidence HIGH.** Releasing and re-registering the same authority inside one live process starts a fresh ten-opportunity budget and START limiter. Current P3 allows a fresh budget only after the previous owning process has terminated. Only trusted local code can trigger it, not a remote peer.
- **[P5-F-005](findings.md#p5-f-005) — INFO, confidence HIGH.** A catastrophic OS entropy failure panics inside `Sas::new()` and unwinds through the Router, the TCP adapter, and the owner loop. Pairing security holds (no result, no exposure without consumption, no refund), but a caught unwind leaves conservative residue, and a future ABI needs an explicit panic policy.
- **[P5-F-007](findings.md#p5-f-007) — INFO, confidence HIGH.** At the Initiator's final-ACK deadline boundary the Responder can succeed while the Initiator does not; the Responder's connection then ends on the Initiator's timeout CANCEL. The outcome is fail-closed and authenticated, but P3 §9 documents only the opposite direction.

## 6. Accepted limitations

Each is bounded by the threat model or the normative profile. None is fixed, and none is an OPEN defect.

| ID | Limitation | Why it is accepted |
|---|---|---|
| [P5-F-004](findings.md#p5-f-004) | `token_user_sid` relies on the Windows `TokenUser` postcondition that the SID lies inside the returned buffer | The documented API implies it, and real Windows was observed to honor it. Only a compromised or hooked OS could break it, which is out of scope. Range checks remain optional P6 hardening |
| [P5-F-008](findings.md#p5-f-008) | A same-profile or administrator process can race the lock-path checks (TOCTOU) | Such an attacker already controls the endpoint (out of scope; decision 0003) |
| [P5-F-009](findings.md#p5-f-009) | Fork, VM snapshot, restore, or duplicated state can repeat RNG state and ephemeral material | Unsupported deployments under P3 and P4 |
| [P5-F-010](findings.md#p5-f-010) | Secret copies remain beyond the guaranteed upstream zeroization boundary | Needs endpoint memory access (out of scope); P3 §5 excludes other copies |
| [P5-F-011](findings.md#p5-f-011) | Monotonic-clock behavior across system suspend is unverified | Bounded effect: a longer ceremony lifetime, not an authentication failure. Confidence MEDIUM |
| [P5-F-012](findings.md#p5-f-012) | An unauthenticated peer can saturate START admission and pending capacity | Specified, bounded, authority-wide behavior; P3 says the limits are not DoS guarantees |

## 7. Disproved hypotheses

Eleven candidates were each constructed as a concrete attack and then disproved against source and evidence. They stay in [findings](findings.md#disproved-candidates-false-positive) so later reviewers do not re-file them. Their value is that the strongest attacks a reviewer would try first were attempted and ruled out:

- **[P5-F-013](findings.md#p5-f-013) (CRITICAL if real):** more than ten contributions under one registration. The decrement and guard are taken in one critical section; every path was traced.
- **[P5-F-014](findings.md#p5-f-014), [P5-F-022](findings.md#p5-f-022), [P5-F-019](findings.md#p5-f-019), [P5-F-017](findings.md#p5-f-017), [P5-F-018](findings.md#p5-f-018) (HIGH if real):** equivalent X25519 encodings, reflected authenticated messages, a final ACK confirmed for another run, request-ID-only or stale `RunRef` authority, and scope aliasing inside the core. The exact key bytes, roles, and identity are bound into every SAS and MAC input, and every lookup is session-scoped. Scope aliasing is the trusted registry's responsibility.
- **[P5-F-015](findings.md#p5-f-015), [P5-F-020](findings.md#p5-f-020), [P5-F-021](findings.md#p5-f-021) (MEDIUM if real):** codec ambiguity, counter underflow or wrap, and extra START-limiter credit. The codec is a bijection, every decrement is paired, and the limiter arithmetic was rebuilt and checked.
- **[P5-F-016](findings.md#p5-f-016) (LOW if real):** non-constant-time secret comparison. Every compared value is public or local, and MAC tags go through `verify_slice` to `cmov` assembly.
- **[P5-F-006](findings.md#p5-f-006) (INFO if real):** a SIMD Base64 engine in the authentication path. The production engine is the scalar `GeneralPurpose`, and it matched an independent reference for every length 0..=65,536.

## 8. Security conclusions

**P5 found no confirmed CRITICAL or HIGH issue.**

The review identified one MEDIUM availability and resource-lifetime implementation gap, two LOW robustness and policy mismatches, and two INFO hardening and documentation observations that remain OPEN for P6. P5 also retained six accepted limitations and disproved eleven candidate findings.

Within the review's method and limits, P5 found:

- no confirmed path to successful pairing without the required SAS agreement;
- no confirmed remote disclosure of secret material;
- no confirmed bypass of the one-owner, one-guard, ten-opportunity accounting under one registration;
- one MEDIUM availability gap (P5-F-002): remote pairing for an authority can be locked out persistently by idle connections;
- two LOW mismatches: an owner-loop robustness defect (P5-F-001) and an in-process budget reset against current P3 policy (P5-F-003);
- two INFO observations: a panic policy to decide (P5-F-005) and an undocumented asymmetric outcome (P5-F-007).

Every confirmed defect fails closed. None yields false success, secret exposure, or extra SAS attempts from a remote peer.

These conclusions do not make the project secure, proven secure, or production ready.

## 9. Assurance limitations

- **AI-assisted.** Reading can miss defects; the absence of a finding is not proof of absence.
- **Windows scope.** Executed evidence comes from one Windows build and CI's `windows-latest`. Linux evidence is only the CI fail-closed job. NEON code was never executed (it is also unreachable).
- **Bounded sequence depth.** P5.2's generated sequences and forced interleavings are bounded and deterministic.
- **No exhaustive model checking**, and no loom-style interleaving exploration.
- **No fuzzing framework** and no randomized property testing.
- **No formal verification.** The conditional protocol argument is not upgraded into a proof.
- **No professional audit**, penetration test, or certification.
- **Upstream trust** beyond the security-relevant paths P5.3 inspected in locked source. Compiled but unreachable code was not audited.
- **Side channels** classified and traced, not measured or proven constant-time. Local hardware side channels are out of scope.
- **No Miri or sanitizer run.**
- **Accepted environment assumptions** stand: no compromised OS or same-profile attacker, no fork, snapshot, or duplicated state, no endpoint memory access, and unverified suspend behavior ([assumptions and boundaries](assumptions-and-boundaries.md)).

## 10. P6 handoff

### Disposition of OPEN findings

| Finding | Severity | P6 disposition | Protocol change? | Production code? | Docs or policy? | Regression evidence |
|---|---|---|---|---|---|---|
| [P5-F-002](findings.md#p5-f-002) | MEDIUM | Owner selects a finite connection-lifetime model and values: a never-refreshed first-header (pre-frame) deadline, whether idle connections without a live run need a separate bound, and a bound on owner-less retained output. Then remediate through the existing generic teardown, with no limiter, budget, or guard change. Optionally enable TCP keepalive | No wire change. A normative clarification in P3 §11.1.1 only if the owner freezes the values | Yes: transport, TCP adapter, owner-loop sweep | Owner decision on timer model and values; P3 clarification if frozen | Enable `p5_f_002_idle_connections_eventually_release_their_live_slot` (subcases A–C) and apply the P5.1 patch test `p5_f_002_frameless_connections_do_not_hold_the_live_cap_forever`; keep `p5_f002_001…` and `p5_tcp_out_001…`; re-verify `R-OWNER-023` |
| [P5-F-001](findings.md#p5-f-001) | LOW | Remediate: treat `POLLHUP` without `POLLERR`/`POLLNVAL` as readable until EOF; keep writing retained output to a half-closed peer; keep `POLLERR`/`POLLNVAL` as immediate close | No | Yes: Windows owner loop (adapter only) | None beyond the core README's owner-loop text | Enable the three `p5_f_001_owner_loop_…` `#[ignore]` reproducers and apply the patch test `p5_f_001_a_complete_frame_before_a_graceful_close_is_dispatched`; keep the OS-fact test and `p5_loop_hup_001..003`, `p5_f001_001` |
| [P5-F-003](findings.md#p5-f-003) | LOW | **Default:** keep current P3 semantics and change the implementation so same-process release and re-registration cannot silently start a fresh budget or START limiter. **Alternative:** the owner explicitly revises P3 so that the owner session is the registration lifetime, with re-analysis of exposure accounting and the security argument. The owner chooses before the remediation design is frozen | Default: no. Alternative: yes (P3 policy revision) | Default: yes (authority registry). Alternative: alignment only | Owner decision required; the alternative updates P3, the conformance cases, and the P7 binding rules | The existing re-registration assertions in `core/tests/security_core.rs` change with the chosen path; re-verify `R-OWNER-006` and `R-OWNER-022` |
| [P5-F-005](findings.md#p5-f-005) | INFO | Owner decides the native panic policy together with P7: `panic = "abort"`, or `catch_unwind` at every export that then discards the authority. Optionally remove an orphan `Admitting` claim with an RAII guard and release transport accounting for a poisoned run | No wire change; a future ABI/runtime policy | Possibly: build profile, Router hardening, P7 exports | Owner decision; P7 ABI rules | Keep `p5_f005_001..005` as characterization; update their recorded residue if hardening lands |
| [P5-F-007](findings.md#p5-f-007) | INFO | Document in P3 §9 and the consumer guidance that either side may hold the only result, and that the Responder's connection may end on the Initiator's timeout CANCEL. Optionally (owner decision) judge confirmation against the last-byte write instant instead | Documentation clarification of P3 §9; no wire change. The optional boundary rule changes semantics only if chosen | Only if the optional rule is chosen | Yes: P3 §9 and consumer documentation | Keep `p5_f007_final_ack_deadline_boundary_end_to_end`; update its crossing row only if the boundary rule changes |

### Recommended P6 order

1. **P5-F-002 (MEDIUM)**, first because it is the only MEDIUM and it needs an owner decision on the timer model and values before any code.
2. **P5-F-001 (LOW)**, designed and landed together with P5-F-002 or after it, never before it. Its remedy keeps serving a hung-up connection until EOF and keeps writing to a half-closed peer; only the P5-F-002 connection lifetime bounds a peer that then stalls (the same resource as P5-F-002 subcase C). Both change the same transport, adapter, and owner-loop teardown paths, so one change set and one regression run is efficient.
3. **P5-F-003 (LOW)**, independent code (the authority registry), but its owner decision should be taken early, in parallel with 1 and 2, because the alternative path revises P3 policy, which the P6 protocol freeze depends on.
4. **P5-F-005 (INFO)**, decided with P7 ABI planning; the optional Router hardening is independent.
5. **P5-F-007 (INFO)**, documentation folded into the P6 protocol and consumer-documentation freeze.

### Optional P6 items that are not OPEN findings

- P5-F-004: add the `TOKEN_USER` range checks and reword the `SAFETY:` comments (optional hardening).
- P5-F-011: verify `QueryPerformanceCounter` across suspend, or adopt a suspend-inclusive clock (owner decision).
- Hygiene noted in P5.3: `// SAFETY:` comments on the ten undocumented production `unsafe` sites, and `--locked` in CI ([deep review §5, §14](dependency-unsafe-deep-review.md#14-reproducibility-and-ci-hygiene)).
- Deeper techniques P5 recommends but did not plan as coverage: parser property or fuzz testing, loom-style interleaving, and a self-hosted cross-session runner ([coverage](coverage.md#recommended-review-harnesses-from-p51-status-after-p52)).

### Reproducer inventory (frozen)

Every P5 test is review-only infrastructure, not product behavior, and stays in the repository for P6 as evidence, regression tests, or characterization. A non-test build never compiles the in-crate modules. No P5 test asserts that a bug must remain: known bugs are expressed only as `#[ignore]` expected-fail reproducers that state the desired invariant.

| Kind | Tests | Finding | P6 action |
|---|---|---|---|
| EXPECTED-FAIL KNOWN-BUG REPRODUCER (`#[ignore]`, fails today) | `p5_f_001_owner_loop_dispatches_complete_frames_before_graceful_close`, `p5_f_001_owner_loop_responder_loses_final_ack_before_graceful_close`, `p5_f_001_owner_loop_writes_pending_output_after_peer_half_close` | F-001 | Remove `#[ignore]` when remediated |
| EXPECTED-FAIL KNOWN-BUG REPRODUCER (`#[ignore]`, fails today) | `p5_f_002_idle_connections_eventually_release_their_live_slot` | F-002 | Remove `#[ignore]` when remediated |
| THROWAWAY PATCH (fails when applied) | `reproducers/p5-f-001-f-002-reproducers.patch`: `p5_f_001_a_complete_frame_before_a_graceful_close_is_dispatched`, `p5_f_002_frameless_connections_do_not_hold_the_live_cap_forever` | F-001, F-002 | Apply, remove `#[ignore]`, keep as regressions |
| PASSING EVIDENCE TEST (OS fact) | `p5_f_001_wsapoll_reports_hang_up_while_written_bytes_remain_readable`, `p5_f_004_token_user_sid_lies_inside_the_returned_buffer_on_this_windows` | F-001, F-004 | Keep |
| PASSING EVIDENCE TEST (characterization or safety properties) | `p5_loop_hup_001..003`, `p5_f001_001`, `p5_f002_001`, `p5_tcp_out_001`, `p5_f007_…`, `p5_f005_001..005` | F-001, F-002, F-007, F-005 | Keep; update recorded outcomes as fixes land |
| PASSING EVIDENCE TEST (regression guards) | `p5_b64_ref_000..001`, `p5_b64_engine_001..002`, `p5_secret_type_001` | F-006, F-010 | Keep as guards for dependency upgrades |
| PASSING EVIDENCE TEST (coverage families; some deep and manual) | `p5_sm_*`, `p5_dup_001_*`, `p5_deadline_*`, `p5_router_race_*`, `p5_tcp_*`, `p5_loop_*`, `p5_b64_ref_002` | — | Keep |

Commands and recorded outputs: [reproducers](reproducers/README.md).

## 11. P5 closure

**P5 IMPLEMENTATION + PROTOCOL SECURITY REVIEW COMPLETE.**

All 34 planned review surfaces are COMPLETE, every finding is reconciled with a stable severity, confidence, status, evidence, and P6 disposition, and every reproducer is classified. P5 closes with five OPEN findings by design: P5 is a review phase, and remediation belongs to P6.

**Production remediation has NOT been performed in P5.** P5 changed no production behavior, no protocol bytes, no vectors, no dependencies, and no normative P3 text. P4 stays the frozen implementation and conformance closure; P5 is the adversarial review of it.

**Next phase: P6 — Review Remediation + Protocol Freeze** ([roadmap](../../roadmap/P6-review-remediation-and-protocol-freeze.md)).
