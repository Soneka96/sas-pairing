# P7 — Native ABI

## Status

🟡 Planned; gated on a reviewed, sufficiently stable native implementation.

## Goal

Expose the reviewed native implementation through a stable language-neutral native boundary.

## Why this phase exists

Future language wrappers need to call the same security implementation without defining its protocol behavior independently.

## Inputs / prerequisites

P4 implementation and P6 review/remediation gate; a stable core boundary supported by the reviewed implementation.

## Scope

Specify and implement the minimum native boundary needed by supported wrappers, including safe lifecycle and error behavior. Preserve any P2/P3 security-required attempt limits, counters, lifetime bounds, replay tracking, and persistence semantics across the boundary without choosing a storage design here.

## Out of scope

Binding-specific public API design, duplicating protocol logic in wrappers, or adding consumer trust policy to the core.

## Deliverables

A stable native boundary with evidence that it preserves the reviewed core behavior.

## Security invariants

Wrappers remain callers of one production security implementation. Boundary failures and missing, invalid, or rolled-back security-required state fail closed.

## Exit criteria

The boundary is usable by intended wrappers and does not undermine the reviewed core's guarantees, including any security-required attempt and persistence constraints.

## What this unlocks

The Dart wrapper in P8 and .NET wrapper in P9.
