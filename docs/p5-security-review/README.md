# P5 — Implementation + Protocol Security Review

> **This is an internal / AI-assisted implementation security review.** It is **not** a professional audit, formal verification, certification, or production-security approval. It does not upgrade the conditional protocol argument into a proof, and it grants no release approval.

## Status

**P5 REVIEW IN PROGRESS — FINDINGS RECORDED.** Increment P5.1 set up the review method and completed one broad adversarial pass over every major P4 surface. P5 is not complete. Remediation belongs to [P6](../../roadmap/P6-review-remediation-and-protocol-freeze.md); P5 changes no production behavior.

## Review target

| Item | Value |
|---|---|
| Target | Experimental P4 native Rust security core (`core/`), frozen |
| Reviewed commit | `main` at `e21ff0bab97009cc771bfc90a6019496721baf78` (merge of PR #10). Its tree is byte-identical to the P4 final-freeze commit `5bf0a0b8ab3de0c371568bc05b6bd8a16be8d474`. Production code is that of the final P4 implementation commit `86e77ea` |
| Review branch | `feature/p5-security-review` (single branch and single PR for all of P5) |
| Toolchain | `rustc 1.99.0 (b940084d7 2026-09-28)`, Windows 11 Pro 10.0.26200 |
| Date | 2026-10-02 |

## Normative baseline

The [authoritative P3 profile](../p3-vodozemac-ceremony-profile-draft.md), the [remote session policy](../p3-one-shot-remote-pairing-decision.md), decisions [0001](../decisions/0001-single-native-security-core.md)–[0003](../decisions/0003-windows-account-scoped-ownership.md), the [threat model](../threat-model.md), and the current rows of the [P3 conformance cases](../p3-conformance-cases.md), with the precedence stated in [protocol status](../protocol-status.md).

## Relationship to P4 conformance closure

The [P4 conformance closure](../p4-conformance-closure.md) asked whether evidence shows each of the 92 current normative rows is implemented. P5 does not re-run that table. It asks whether the implementation is structurally sound, internally coherent, and resistant to misuse, races, and error paths, including where no conformance row exists. Two P5 findings ([P5-F-001](findings.md#p5-f-001), [P5-F-002](findings.md#p5-f-002)) lie in such gaps: stream semantics at the real socket, and a connection lifetime that no row specifies. One ([P5-F-003](findings.md#p5-f-003)) questions an interpretation that P4 adopted deliberately. Nothing in P5 contradicts a P4 PASS verdict for its row as written.

## Method in brief

Specification-to-code tracing; adversarial reasoning across 34 axes and 12 attacker and fault models; tables rebuilt from source (MAC domains, state transitions, resources, `unsafe`, Win32 errors, panics); review-only Clippy lints; an OSV/RustSec advisory query; dependency source inspection at the locked versions; and executed reproducers for every finding rated MEDIUM or above. Full method: [review-method.md](review-method.md).

## Assurance limitations

- AI-assisted reading can miss defects. Absence of a finding is not proof of absence.
- The first pass is broad. The state machine, Router concurrency, side channels, and dependency internals are `PARTIAL` ([coverage](coverage.md)).
- No fuzzing, property testing, formal model, or measurement was performed.
- Windows only. Linux results come from CI (`unsupported-platform-fails-closed`).
- Upstream crates (vodozemac, x25519-dalek, rand, getrandom, hkdf, hmac, sha2, base64) were trusted beyond the touchpoints read.

## Current finding counts

| Severity | Open (incl. NEEDS-DECISION) | False positive | Accepted limitation | Out of scope |
|---|---|---|---|---|
| CRITICAL | 0 | 1 | 0 | 0 |
| HIGH | 0 | 5 | 0 | 0 |
| MEDIUM | 1 | 3 | 0 | 0 |
| LOW | 2 | 1 | 0 | 0 |
| INFO | 4 | 0 | 5 | 0 |

There is no confirmed CRITICAL or HIGH finding. Open findings: one MEDIUM availability finding (P5-F-002, NEEDS-DECISION), two LOW findings (P5-F-001 OPEN; P5-F-003 NEEDS-DECISION), and four INFO findings (P5-F-004 to P5-F-007). False-positive severities are what each candidate would have been if real. Details: [findings.md](findings.md).

## Package contents

| Document | Purpose |
|---|---|
| [review-method.md](review-method.md) | Method, attacker models, finding format, false-positive discipline, phase boundary |
| [assumptions-and-boundaries.md](assumptions-and-boundaries.md) | Core guarantees versus consumer and deployment responsibilities |
| [findings.md](findings.md) | Finding index and every finding, including disproved candidates |
| [coverage.md](coverage.md) | Coverage matrix by review surface, and recommended harnesses |
| [ownership-and-ffi.md](ownership-and-ffi.md) | Ownership, attempt bound, `unsafe` inventory, Win32 error map, R-OWNER-012 |
| [protocol-composition.md](protocol-composition.md) | Parser, commitment, SAS, MAC domain table, completion, CANCEL, R-MAC-001/015 |
| [state-and-routing.md](state-and-routing.md) | State transition table, duplicates, Router, Host |
| [resources-deadlines-transport.md](resources-deadlines-transport.md) | Resource table, limiter math, deadlines, TCP adapter, owner loop |
| [secrets-panics-dependencies.md](secrets-panics-dependencies.md) | Secret lifetime, logging, panics, allocation, side channels, dependencies, static analysis |
| [reproducers/](reproducers/README.md) | Reproducer patch and the in-repository evidence test |

## Next increment

Recommended P5.2 (not yet started): **State-machine and transport adversarial sequence review.** It would cover generated message, action, and deadline sequences over `RemoteCeremony`, and a stream model (chunking, EOF, and hang-up placement) over the transport, TCP adapter, and owner loop. This targets the `PARTIAL` state-machine surface and the stream-semantics gap that produced P5-F-001 and P5-F-002.
