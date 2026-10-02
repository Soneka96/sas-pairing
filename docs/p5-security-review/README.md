# P5 — Implementation + Protocol Security Review

> **This is an internal / AI-assisted implementation security review.** It is **not** a professional audit, formal verification, certification, or production-security approval. It does not upgrade the conditional protocol argument into a proof, and it grants no release approval.

## Status

**P5 REVIEW COMPLETE — FINAL SYNTHESIS RECORDED.** The authoritative closure summary is the **[P5 final review synthesis](final-synthesis.md)**.

All five increments are complete. P5.1 set up the review method and completed one broad adversarial pass over every major P4 surface. P5.1.1 reclassified P5-F-002 and P5-F-003 from NEEDS-DECISION to OPEN against the current P3 text. P5.2 completed the [state-machine and transport adversarial sequence review](adversarial-sequences.md). P5.3 completed the [dependency, unsafe/FFI, and secret-lifetime deep review](dependency-unsafe-deep-review.md). P5.4 reconciled the finding set, coverage, reproducers, and status documents and recorded the [final synthesis](final-synthesis.md) and P6 handoff.

- **Coverage:** 34 / 34 planned review surfaces COMPLETE, 0 PARTIAL, 0 NOT-STARTED ([coverage](coverage.md)). COMPLETE means the planned method was carried out, not that the absence of defects was proven.
- **Findings:** 22 in total: 5 OPEN, 11 FALSE-POSITIVE, 6 ACCEPTED-LIMITATION. No confirmed CRITICAL or HIGH finding.
- **Remediation:** none. P5 changed no production behavior; the five OPEN findings are handed to [P6](../../roadmap/P6-review-remediation-and-protocol-freeze.md).
- **Next phase:** P6 — Review Remediation + Protocol Freeze.

## Review target

| Item | Value |
|---|---|
| Target | Experimental P4 native Rust security core (`core/`), frozen |
| Reviewed commit | `main` at `e21ff0bab97009cc771bfc90a6019496721baf78` (merge of PR #10). Its tree is byte-identical to the P4 final-freeze commit `5bf0a0b8ab3de0c371568bc05b6bd8a16be8d474`. Production code is that of the final P4 implementation commit `86e77ea` |
| Review branch | `feature/p5-security-review` (single branch and single PR for all of P5) |
| Toolchain | `rustc 1.99.0 (b940084d7 2026-09-28)`, Windows 11 Pro 10.0.26200 |
| Date | 2026-10-02 (P5.1 through P5.4) |

## P5.4 summary

- **Synthesis and closure only:** no new technical review, no new test, and no new finding. Every finding ID P5-F-001 to P5-F-022 was re-checked for severity, confidence, status, evidence links, reproduction references, recommendation, and P6 disposition. Counts are unchanged.
- **Coverage frozen:** 34 / 34 COMPLETE.
- **Reproducer inventory frozen:** four EXPECTED-FAIL known-bug reproducers (three for P5-F-001, one for P5-F-002) and the P5.1 throwaway patch stay failing until P6 ([final synthesis §10](final-synthesis.md#reproducer-inventory-frozen)).
- **P6 handoff:** disposition table and recommended order in [final synthesis §10](final-synthesis.md#10-p6-handoff).
- **Production behavior, dependencies, vectors, and normative P3:** unchanged.

## P5.3 summary

- **Locked graph and provenance:** 97 resolved packages (96 from crates.io), rebuilt with `--locked`. Every cached archive matches its `Cargo.lock` checksum (96/96), and the extracted sources of the 20 security-relevant crates are byte-identical to them. Versions are as P5.1 recorded.
- **Runtime crypto paths** traced in the locked source: RNG (vodozemac `Sas::new` → rand `ThreadRng`/ChaCha12 → `ProcessPrng`), DH (x25519/curve25519 ladder), HKDF, HMAC with tag verification down to `cmov` assembly, and Base64url. Reachable upstream `unsafe` (curve25519 AVX2 dispatch, `subtle`, `cmov`, chacha20, rand, getrandom, sha2 SHA-NI, cpufeatures, zeroize) was inspected; no invariant takes attacker-controlled lengths.
- **Project `unsafe`:** 16 production sites (15 blocks + 1 `unsafe impl`), all sound. Ten lack `// SAFETY:` comments (hygiene). All `windows-sys` signatures match the documented prototypes.
- **Finding changes:** P5-F-004 → ACCEPTED-LIMITATION (the Windows contract implies the SID postcondition, and real Windows was observed to honor it). P5-F-006 → FALSE-POSITIVE (the authentication path uses the scalar, safe `GeneralPurpose` engine; the encoder matched an independent reference for every length 0..=65,536). P5-F-005 strengthened (reproduced through Router, adapter, and owner loop; an Initiator-side panic leaves one live-connection slot held), still INFO OPEN. P5-F-010 strengthened (rand keeps upstream copies of the ephemeral key), still accepted. P5-F-009 unchanged. **No new finding.**
- **Coverage:** side channels (#32) and dependency assumptions (#33) are now `COMPLETE` for the current threat scope. **No `PARTIAL` surface remains.**
- **Advisories:** OSV, 96 crates, none (2026-10-02T15:23Z).
- **Production behavior and dependency graph:** unchanged. One `#[cfg(test)]` module declaration each in `crypto.rs`, `windows_tcp.rs`, and `windows_owner_loop.rs`, and one integration test.

## P5.2 summary

- **Generated state-machine sequences:** 835 in CI (honest prefixes × suffix ≤ 2, with verified no-op reduction) and 35,684 in the manual deep run (suffix ≤ 3, unreduced), for both roles over a 25-action alphabet. No invariant failed: terminal irreversibility, one result, exposure only after authorization, guard, request and session isolation, stale callbacks, authentication ordering, duplicates, and wrong-state input. Also the 55-cell duplicate/reorder matrix and 292 ceremony deadline-boundary cases at −1 ns, exactly, and +1 ns.
- **Transport sequence families:** 95 chunking and concatenation patterns, 10 truncation-then-EOF cases, 584 (CI) and 4,680 (manual) read-result sequences, 399 + 56 write-result sequences, 24 frame-deadline boundary cases, a 33-case owner-loop readiness matrix, deadline-versus-readiness precedence, and real-Windows graceful-close cases.
- **Concurrency review:** nine Router race scenarios. Every linearization point is forced in both orders and repeated 25–100 times, plus barrier races. No deadlock, leak, double result, double guard release, or refund.
- **New findings:** none.
- **Changed findings:** P5-F-001 strengthened (real end-to-end final-ACK loss; buffered-suffix and pending-output subcases); P5-F-002 strengthened (subcases A first header, B idle after its run, C owner-less retained output, kept as one finding); P5-F-007 reproduced end to end and its description corrected. No severity, status, or count changed.
- **Coverage:** state machine (#16) and Router concurrency (#19) are now `COMPLETE`. Side channels (#32) and dependency assumptions (#33) remained `PARTIAL` after P5.2 (completed in P5.3).
- **Production behavior:** unchanged. The review tests sit inside existing `#[cfg(test)]` modules (one declaration each in `ceremony.rs`, `router.rs`, `windows_tcp.rs`, `windows_owner_loop.rs`); a non-test build never compiles them.

## Normative baseline

The [authoritative P3 profile](../p3-vodozemac-ceremony-profile-draft.md), the [remote session policy](../p3-one-shot-remote-pairing-decision.md), decisions [0001](../decisions/0001-single-native-security-core.md)–[0003](../decisions/0003-windows-account-scoped-ownership.md), the [threat model](../threat-model.md), and the current rows of the [P3 conformance cases](../p3-conformance-cases.md), with the precedence stated in [protocol status](../protocol-status.md).

## Relationship to P4 conformance closure

The [P4 conformance closure](../p4-conformance-closure.md) asked whether evidence shows each of the 92 current normative rows is implemented. P5 does not re-run that table. It asks whether the implementation is structurally sound, internally coherent, and resistant to misuse, races, and error paths, including where no conformance row exists. [P5-F-001](findings.md#p5-f-001) lies in such a gap: stream semantics at the real socket. Two findings show that a P4 PASS rested on a reading narrower than the current P3 text. [P5-F-002](findings.md#p5-f-002): P3 §11.1.1 requires finite header waiting, but P4 started its transport deadlines only at a frame's first byte (`R-OWNER-023`). [P5-F-003](findings.md#p5-f-003): P3 §11.1 and §11.1.2 tie a fresh budget to replacement of the owning process, but P4 treated each registration as a new owner session (`R-OWNER-006`, `R-OWNER-022`). P5 does not edit the frozen P4 closure; P6 remediation re-verifies those rows.

## Method in brief

Specification-to-code tracing; adversarial reasoning across 34 axes and 12 attacker and fault models; tables rebuilt from source (MAC domains, state transitions, resources, `unsafe`, Win32 errors, panics); review-only Clippy lints; an OSV/RustSec advisory query; dependency source inspection at the locked versions; and executed reproducers for every finding rated MEDIUM or above. Full method: [review-method.md](review-method.md).

## Assurance limitations

- AI-assisted reading can miss defects. Absence of a finding is not proof of absence.
- The state machine and Router concurrency were deepened by P5.2's bounded generated sequences and forced interleavings, which are not exhaustive. P5.3 traced side channels to their primitives but did not measure them or prove them constant-time.
- Not a professional penetration test, cryptographic audit, formal verification, certification, or production-security approval.
- No fuzzing, randomized property testing, formal model, loom-style interleaving exploration, timing measurement, Miri, or sanitizer run was performed.
- Windows only. Linux results come from CI (`unsupported-platform-fails-closed`). NEON code was never executed (it is also unreachable).
- Upstream crates are trusted beyond the security-relevant paths P5.3 inspected in locked source ([deep review §12](dependency-unsafe-deep-review.md#12-dependencies-33)).

## Final finding counts

| Severity | Open | False positive | Accepted limitation | Out of scope |
|---|---|---|---|---|
| CRITICAL | 0 | 1 | 0 | 0 |
| HIGH | 0 | 5 | 0 | 0 |
| MEDIUM | 1 | 3 | 0 | 0 |
| LOW | 2 | 1 | 0 | 0 |
| INFO | 2 | 1 | 6 | 0 |
| **Total** | **5** | **11** | **6** | **0** |

There is no confirmed CRITICAL or HIGH finding. Confirmed OPEN findings, in order of severity:

- **MEDIUM:** P5-F-002, a gap against P3 §11.1.1: admitted connections have no finite first-header wait, so 16 idle peers hold the live-connection cap. A finite bound is required; the timer design and values are left to P6.
- **LOW:** P5-F-001, the owner loop discards readable bytes on hang-up. P5-F-003, in-process re-registration starts a fresh budget, a mismatch with the current P3 process/session policy.
- **INFO:** P5-F-005 (entropy-panic policy across the Router, adapter, and a future ABI) and P5-F-007 (reverse asymmetric completion at the deadline boundary). These may close as owner, hardening, or documentation decisions rather than production changes. P5.3 moved P5-F-004 to ACCEPTED-LIMITATION and P5-F-006 to FALSE-POSITIVE.

No finding is NEEDS-DECISION, and no finding was remediated in P5. False-positive severities are what each candidate would have been if real. Details: [findings.md](findings.md).

## Package contents

| Document | Purpose |
|---|---|
| **[final-synthesis.md](final-synthesis.md)** | **Authoritative P5 closure: coverage, final counts, security conclusions, assurance limits, P6 handoff, reproducer inventory** |
| [review-method.md](review-method.md) | Method, attacker models, finding format, false-positive discipline, phase boundary |
| [assumptions-and-boundaries.md](assumptions-and-boundaries.md) | Core guarantees versus consumer and deployment responsibilities |
| [findings.md](findings.md) | Finding index and every finding, including disproved candidates |
| [coverage.md](coverage.md) | Coverage matrix by review surface, and recommended harnesses |
| [ownership-and-ffi.md](ownership-and-ffi.md) | Ownership, attempt bound, `unsafe` inventory, Win32 error map, R-OWNER-012 |
| [protocol-composition.md](protocol-composition.md) | Parser, commitment, SAS, MAC domain table, completion, CANCEL, R-MAC-001/015 |
| [state-and-routing.md](state-and-routing.md) | State transition table, duplicates, Router, Host |
| [resources-deadlines-transport.md](resources-deadlines-transport.md) | Resource table, limiter math, deadlines, TCP adapter, owner loop |
| [secrets-panics-dependencies.md](secrets-panics-dependencies.md) | Secret lifetime, logging, panics, allocation, side channels, dependencies, static analysis |
| [adversarial-sequences.md](adversarial-sequences.md) | P5.2 generated state-machine, transport, readiness, deadline, and Router-race sequences; F-001, F-002, F-007 evidence |
| [dependency-unsafe-deep-review.md](dependency-unsafe-deep-review.md) | P5.3 locked graph and provenance, crypto call graph, reachable upstream and project `unsafe`, F-004/005/006 dispositions, side channels, secret lifetime, RNG, advisories |
| [reproducers/](reproducers/README.md) | Passing evidence tests, expected-fail known-bug reproducers, and the throwaway patch, each classified |

## Next phase

P5 is complete. The next phase is **P6 — Review Remediation + Protocol Freeze** ([roadmap](../../roadmap/P6-review-remediation-and-protocol-freeze.md)), starting from the disposition table and recommended order in [final synthesis §10](final-synthesis.md#10-p6-handoff). Do not re-run P5; new review work after remediation belongs to P6's follow-up review.
