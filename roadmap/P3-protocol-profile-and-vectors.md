# P3 — Protocol Profile and Deterministic Vectors

## Status

🟡 Planned; gated on a SELECTED P2 outcome.

## Goal

Turn the selected construction into a concrete, language-neutral candidate protocol profile and deterministic conformance vectors.

## Why this phase exists

Implementation and independent review need one precise profile that removes ambiguity while staying within the construction and assumptions justified in P2.

## Inputs / prerequisites

- A documented SELECTED outcome from P2 with evidence, assumptions, limitations, and justified security bound.
- P1 requirements and the authoritative architecture and protocol-status documents.

## Scope

Resolve and document the concrete roles and message ordering; cryptographic primitive and commitment profiles; transcript definition and authentication; domain separation and context binding; SAS derivation and SAS rendering profile; canonical encoding; ceremony state machine; failure and replay semantics; and deterministic positive and negative/mutation vectors. Decide concrete values only when supported by P2 and the profile's security rationale.

## Out of scope

Reopening P2 decisions without recording the evidence that requires it; implementation; language-specific APIs or ABI; consumer-specific policy; and unsupported security claims.

## Deliverables

A reviewed candidate profile, explicit decision records for durable choices as appropriate, and deterministic vectors that independent implementations can consume. Vector correctness is conformance evidence, not proof of cryptographic security.

## Security invariants

Keep the profile application-neutral, fail closed on invalid or ambiguous state, avoid silent downgrade/fallback, and preserve all justified ceremony, role, transcript, context, approval, and attempt constraints.

## Exit criteria

The profile is sufficiently precise for independent implementation and review; all security-sensitive choices trace to P2 evidence; vectors cover positive behavior and meaningful negative or mutation cases.

## STOP conditions

Return to P2 or stop if the selected construction cannot support a required profile decision or if the profile would exceed its evidence.

## What this unlocks

P4 implementation of the reviewed candidate profile in one native security core.
