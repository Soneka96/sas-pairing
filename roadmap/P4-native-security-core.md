# P4 — Native Security Core

## Status

🔴 **BLOCKED** pending qualified independent review of the complete security argument (including F-02), any required remediation, and the explicit P3.6 owner selection/profile freeze.

## Goal

Implement the reviewed candidate protocol/profile in one native security core, currently intended to be Rust.

## Why this phase exists

One security implementation keeps protocol behavior consistent and reviewable across future language bindings.

## Inputs / prerequisites

The explicitly selected, frozen profile, its reviewed security rationale, and deterministic vectors. A favored or review-ready candidate is not sufficient.

## Scope

Implement the specified core behavior and demonstrate conformance to its vectors and requirements. Keep application policy and consumer-specific trust decisions outside the protocol core.

## Out of scope

Independent production cryptography in Dart or .NET; binding or consumer integration before the core is reviewable; and claims that tests establish cryptographic security.

## Deliverables

A native implementation of the reviewed candidate profile and evidence of implementation conformance.

## Security invariants

Preserve one production security implementation, fail-closed behavior, and the exact limits of claims justified by P2/P3.

The implementation and its tests MUST establish exclusive ownership of each pairing authority before any remote ceremony can be exposed. Ownership acquisition must be atomic and uncertainty fails closed. P4 must verify crash/termination handling and that ownership is safely released before a replacement process can acquire it. The one owning process shares active remote state, one ceremony guard, and its 10-opportunity budget across roles, threads, and connections. Do not choose a platform-specific locking mechanism in this specification phase.

## Exit criteria

The implementation conforms to the specified profile and vectors, and is ready to be packaged for independent review. Conformance alone is not production readiness.

## STOP conditions

Stop or return to P2/P3 if implementation reveals ambiguity, unsupported assumptions, or a material conflict with the specified security behavior.

## What this unlocks

The P5 post-implementation review of whether the Rust core correctly and safely implements the reviewed construction/profile.
