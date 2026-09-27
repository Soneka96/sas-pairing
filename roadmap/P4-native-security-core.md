# P4 — Native Security Core

## Status

🟡 Planned; gated on a sufficiently precise P3 profile and vectors.

## Goal

Implement the reviewed candidate protocol/profile in one native security core, currently intended to be Rust.

## Why this phase exists

One security implementation keeps protocol behavior consistent and reviewable across future language bindings.

## Inputs / prerequisites

The P3 candidate profile, security rationale, and deterministic vectors.

## Scope

Implement the specified core behavior and demonstrate conformance to its vectors and requirements. Keep application policy and consumer-specific trust decisions outside the protocol core.

## Out of scope

Independent production cryptography in Dart or .NET; binding or consumer integration before the core is reviewable; and claims that tests establish cryptographic security.

## Deliverables

A native implementation of the reviewed candidate profile and evidence of implementation conformance.

## Security invariants

Preserve one production security implementation, fail-closed behavior, and the exact limits of claims justified by P2/P3.

## Exit criteria

The implementation conforms to the specified profile and vectors, and is ready to be packaged for independent review. Conformance alone is not production readiness.

## STOP conditions

Stop or return to P2/P3 if implementation reveals ambiguity, unsupported assumptions, or a material conflict with the specified security behavior.

## What this unlocks

Preparation of a bounded, reproducible security-review package in P5.
