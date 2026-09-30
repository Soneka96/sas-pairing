# P4 — Native Security Core

## Status

🔵 **EXPERIMENTAL IMPLEMENTATION AUTHORIZED — NOT STARTED OR COMPLETE.** The owner selected the corrected vodozemac remote profile and owner policy as the experimental baseline and waived the qualified-human-review prerequisite for this phase. F-02 is recorded as a false positive under the stated idealized assumptions; the complete argument remains conditional and is not formally verified. No production-security approval is granted.

## Goal

Implement the reviewed candidate protocol/profile in one native security core, currently intended to be Rust.

## Why this phase exists

One security implementation keeps protocol behavior consistent and reviewable across future language bindings.

## Inputs / prerequisites

The selected experimental profile and owner policy, their documented assumptions and limitations, and deterministic vectors. This is not a production protocol freeze. See [owner decision 0002](../docs/decisions/0002-experimental-vodozemac-selection.md).

## Scope

Implement the specified core behavior and demonstrate conformance to its vectors and requirements. Keep application policy and consumer-specific trust decisions outside the protocol core.

## Out of scope

Independent production cryptography in Dart or .NET; binding or consumer integration before the core is reviewable; and claims that tests establish cryptographic security.

## Deliverables

A native implementation of the reviewed candidate profile and evidence of implementation conformance.

## Security invariants

Preserve one production security implementation, fail-closed behavior, and the exact limits of claims justified by P2/P3.

The implementation and its conformance checks MUST establish exclusive ownership of each pairing authority before any remote ceremony can be exposed. Ownership acquisition must be atomic and uncertainty fails closed. P4 must verify crash/termination handling and safe release before replacement. The owning process shares active remote state, one ceremony guard, and its 10-opportunity budget across roles, threads, and connections. Do not choose a platform-specific locking mechanism as part of this decision.

## Experimental entry requirements

Implement and verify:

- Exact reviewed message ordering and the pinned vodozemac 0.11.0 dependency.
- Fresh, unpredictable, non-reused ephemeral material; assess target RNG, fork, snapshot, restored-state, and RNG-failure limits.
- One owning process per pairing authority, safe acquisition/release, one live ceremony guard, and the shared ten-opportunity process/session budget.
- Atomic guard and opportunity reservation before any cryptographic contribution is released.
- No automatic retries, resumed ceremonies, or reconnect continuations; fresh local authorization for every exposure.
- I1 terminal-state irreversibility and I2 SAS invalidation and stale-approval rejection.
- Fail-closed handling of malformed cryptographic input and any security-critical invariant that cannot be enforced.
- Deterministic-vector validation and conformance checks for the current normative requirements.

No P4 implementation may invent a security decision for an undecided normative detail. Record it as a prerequisite and resolve it before implementing affected behavior. Ownership mechanics remain target-specific P4 work; this document selects no platform mechanism. These requirements are not claimed as already implemented.

## Exit criteria

The implementation conforms to the selected experimental profile and vectors and is ready for the still-required P5 implementation review. Conformance alone is not production readiness.

## STOP conditions

Stop or return to P2/P3 if implementation reveals ambiguity, unsupported assumptions, or a material conflict with the specified security behavior.

## What this unlocks

The P5 post-implementation review of whether the Rust core correctly and safely implements the reviewed construction/profile.
