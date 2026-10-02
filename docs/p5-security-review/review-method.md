# P5 Review Method

This method was fixed before any conclusion was recorded. It applies to every P5 increment; later increments may add techniques but must not weaken it.

## 1. What is reviewed

- **Target:** the frozen P4 experimental native core as merged to `main` (tree of commit `e21ff0b`, byte-identical to the P4 final-freeze commit `5bf0a0b`). Production Rust sources: every file in `core/src/` outside `#[cfg(test)]` modules, plus `core/src/bin/ownership_probe.rs` (ownership-evidence tooling).
- **Also read:** `core/Cargo.toml`, `core/Cargo.lock`, both CI workflows, `core/tests/security_core.rs`, the unit-test modules where cited, and both vector fixtures.
- **Not reviewed:** a future public SDK, native ABI, Dart or .NET wrapper, TLS, reconnect or resume, discovery, or production listener configuration. None exists in P4. External boundaries are reviewed only for the assumptions the core makes about them ([assumptions and boundaries](assumptions-and-boundaries.md)).

## 2. Normative baseline

The [authoritative profile](../p3-vodozemac-ceremony-profile-draft.md), [remote session policy](../p3-one-shot-remote-pairing-decision.md), decisions [0001](../decisions/0001-single-native-security-core.md), [0002](../decisions/0002-experimental-vodozemac-selection.md), and [0003](../decisions/0003-windows-account-scoped-ownership.md), the [threat model](../threat-model.md), and the current `R-OWNER`, `R-WIRE`, `R-MAC`, and `R-RESOURCE-006`–`009` rows of the [conformance cases](../p3-conformance-cases.md). Precedence is that of [protocol status](../protocol-status.md).

## 3. Techniques

### A. Specification-to-code review

Each security-relevant P3 rule is traced to the code that implements it, read in full. This is not a re-run of the [P4 conformance closure](../p4-conformance-closure.md). P4 asked: *does evidence show the required behavior?* P5 also asks:

- Is the implementation **structurally sound** (invariants hold by construction, not only on tested inputs)?
- Is it **internally coherent** (layers agree about boundaries, ownership, and failure scope)?
- Does it **resist plausible misuse, race, and error paths** (wrong order, stale references, partial OS results, panics, clock faults)?

### B. Adversarial reasoning per axis

The 34 review axes in [coverage](coverage.md) are each examined against the attacker models in §4. For each axis the reviewer writes down the exact property, the code that enforces it, and at least one concrete attempt to break it.

### C. Derived tables

Tables are rebuilt from source, not copied from P4: the MAC domain-separation table, the state-transition table, the resource table, the `unsafe` inventory, the Win32 error map, and the panic inventory. They are in the analysis notes listed in the [README](README.md).

### D. Tooling

- `cargo fmt --check`, `cargo clippy --all-targets -D warnings` (Windows target, and `x86_64-unknown-linux-gnu` as a compile check), and `cargo test`.
- One review-only Clippy pass over production code with stricter lints (`undocumented_unsafe_blocks`, `unwrap_used`, `expect_used`, `panic`, `indexing_slicing`, `arithmetic_side_effects`, `cast_*`, `as_conversions`). Every hit is triaged by hand, and only security-relevant observations are recorded. No code is edited to silence them.
- A dependency advisory query against the public OSV database (which includes RustSec) for every locked crate version, without changing the dependency graph.
- Dependency source inspection of the exact cached crate versions in `Cargo.lock`, limited to the touchpoints the core relies on.

### E. Reproduction

Every candidate MEDIUM or higher finding needs a concrete reproducer where possible (§6). Lower findings are reproduced when that is cheap.

### F. Generated deterministic sequences (added in P5.2)

Bounded, deterministic exploration with no randomness and no new dependency. Generated action sequences run from every honest state against a lockstep honest peer. Duplicate, reorder, and deadline-boundary matrices use hand clocks at −1 ns, exactly, and +1 ns. Stream chunkings and scripted socket-result sequences exercise the transport. Readiness combinations are forced through scripted `WSAPoll`. Router interleavings are forced through the existing pause points and repeated. The oracle checks invariant relationships (terminality, result count, exposure accounting, outputs, honest versus injected input), never a re-implementation of the protocol. A failing sequence is reported with its exact action trace for manual reduction. Method, bounds, and counts: [adversarial sequences](adversarial-sequences.md).

## 4. Attacker and fault models

Taken from the [threat model](../threat-model.md) and P3:

| Model | Capabilities considered |
|---|---|
| Active network MITM | Observe, modify, inject, replay, reorder, delay, drop; run separate legs to each endpoint; choose its own contributions adaptively |
| Unauthenticated remote peer | Any bytes, any frame boundaries, any request IDs; many TCP connections; rotating source address, socket, and connection metadata |
| Replaying or reordering peer | Exact and changed duplicates; messages from other ceremonies, roles, or directions; reflection of the victim's own messages |
| Local untrusted caller of crate plumbing | Holds a `CeremonyExecutor`, a stale `RunRef`, or a stale `FinalAck`, but not a `TrustedAuthority` |
| Stale UI or local callback | Approvals, rejections, or cancels for ended or replaced runs or identities |
| Concurrent threads | Racing reservations, admissions, session closes, deadline polls |
| Same-account competing process | Another process of the same Windows account and authority scope |
| Process crash and replacement | Abnormal termination; restart; in-process re-registration |
| Socket failure mid-transition | Partial reads and writes, EOF, errors, hang-up, during exposure and completion |
| Clock fault | Missing reading, backwards reading, large jumps, suspend |
| Resource exhaustion | Saturating every cap; composing bounded resources |
| Malformed or ambiguous OS results | Unexpected Win32 error codes, short buffers, uncertain release |

**Unsupported environments (documented, not attacked):** VM snapshot or restore, process fork, duplicated or copied authority state, cross-machine use of one identity, administrator/SYSTEM attackers, and attackers controlling the same Windows profile. P5 checks only that the documentation does not claim protection against them.

## 5. Finding format

Each finding has a stable ID `P5-F-NNN` and every field listed in [findings](findings.md#finding-format). Severity measures **impact** under realistic supported assumptions. Confidence measures **certainty that the finding is real**. The two are independent.

Statuses: `OPEN`, `NEEDS-DECISION`, `FALSE-POSITIVE`, `ACCEPTED-LIMITATION`, `OUT-OF-SCOPE`, `DUPLICATE`, `REMEDIATED-IN-P6`. `REMEDIATED-IN-P6` is not used in P5.

## 6. False-positive discipline

Before a finding is recorded:

1. construct the exact attack;
2. name what the attacker controls;
3. state the before and after states;
4. name the claimed security property that breaks;
5. look for an existing invariant that prevents it;
6. try to disprove it.

A suspicious pattern is not a finding. Disproved candidates are recorded with status `FALSE-POSITIVE` when a reasonable reviewer could have filed them, so later reviewers do not re-file them. For any potential MEDIUM or higher finding, the reviewer also checks the P3 requirement, whether it is an already-documented limitation, and whether it belongs to consumer policy.

## 7. Phase boundary

P5 is review, not remediation. Production behavior is not changed in P5. Allowed P5 changes are review documents, review-only evidence tests that do not change production behavior, reproducers, and status wording. Review tests that need crate-private code may live inside existing `#[cfg(test)]` modules (P5.2: one module declaration per file, the code in separate test files), but production visibility is never widened. A reproducer that demonstrates a defect must not make CI red. Each reproducer is exactly one of: a passing evidence test (an OS fact, a characterization, or properties that must stay true after remediation); an `#[ignore]`d expected-fail known-bug reproducer that states the desired invariant; or a patch applied only to a disposable worktree ([reproducers](reproducers/README.md)). Remediation belongs to [P6](../../roadmap/P6-review-remediation-and-protocol-freeze.md).

## 8. Stop rule

A confirmed CRITICAL finding stops deeper review after reproduction, documentation, evidence preservation, and scoping. A HIGH finding does not stop review, but its root cause is traced across the code.

## 9. Assurance limits of this method

This is an **internal, AI-assisted implementation security review**. It is not a professional audit, formal verification, certification, or production-security approval. Manual reading can miss defects. The first pass is broad, so some surfaces are reviewed by reasoning over representative sequences rather than exhaustive exploration, and [coverage](coverage.md) marks those surfaces `PARTIAL`. Test count is not evidence of security.
