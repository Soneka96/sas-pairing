# P5 — Implementation and Protocol Security Review

## Status

🟡 Planned; gated on a reviewable P4 implementation and profile.

## Goal

Obtain independent review of the actual implementation against the construction/profile reviewed before implementation.

## Why this phase exists

The P3.5 review assesses whether a proposed composition/profile is defensible enough to select and implement. P5 happens after P4 and assesses whether the actual Rust implementation correctly and safely implements that reviewed construction/profile. Internal analysis and conformance checks do not replace either independent assessment.

## Inputs / prerequisites

The P2 evidence, P3.5 review and P3.6 selection/frozen profile, P4 implementation, vectors, and their documented assumptions and limitations.

## Scope

Make the selected construction rationale, threat model, frozen profile, implementation, vectors, and implementation-focused review questions available in a reproducible form. Record reviewer findings and their severity and rationale.

## Out of scope

Treating tests, vectors, or an informal internal review as independent review; claiming all findings are resolved before P6.

## Deliverables

An implementation security-review package, independent findings, and a record of review scope and limitations.

## Security invariants

No production-readiness claim before independent security review and resolution of required findings.

## Exit criteria

An independent review has assessed whether the actual Rust implementation correctly and safely implements the reviewed construction/profile, with findings recorded for triage. This does not replace the pre-implementation P3.5 construction review.

## STOP conditions

Stop readiness claims if review cannot be obtained, its scope is insufficient for the claim, or a critical issue remains unexplained.

## What this unlocks

Triage and remediation in P6; it does not by itself freeze the protocol or authorize release.
