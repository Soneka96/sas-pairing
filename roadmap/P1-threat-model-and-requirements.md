# P1 — Threat Model and Protocol Requirements

## Status

✅ Complete. P1 is present in current `main`, merged by PR #1.

## Goal

Define the security problem and the requirements future protocol candidates must justify.

## Why this phase exists

Construction research needs a stable, explicit set of attacker capabilities, ceremony semantics, and security requirements to evaluate.

## Inputs / prerequisites

P0 repository foundation.

## Scope

P1 established participant roles, the active network-attacker model, ceremony and human-approval boundaries, required pairing properties, context binding, replay and concurrency requirements, failure handling, repeated-attempt concerns, and a language-neutral result contract. These are evaluation requirements, not proof that a protocol satisfies them.

## Out of scope

Selecting a construction, primitives, security bound, encoding, wire format, API, or implementation.

## Deliverables

The authoritative [threat model and protocol requirements](../docs/threat-model.md). This phase summary does not replace or duplicate that document.

## Security invariants

Requirements must be justified by a candidate's security analysis and assumptions. Unmet or unjustified requirements cannot be presented as guarantees.

## Exit criteria

The merged threat model records the attacker model, required properties, security boundaries, and unresolved decisions for candidate evaluation.

## What this unlocks

P2 construction evaluation and formal mapping against the documented requirements.
