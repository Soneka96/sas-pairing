# P5 — Security Review

## Status

🟡 Planned; gated on a reviewable P4 implementation and profile.

## Goal

Prepare a focused security-review package and obtain independent external review.

## Why this phase exists

Internal analysis and conformance checks do not replace independent assessment of the construction, profile, and implementation.

## Inputs / prerequisites

The P2 evidence, P3 profile and vectors, P4 implementation, and their documented assumptions and limitations.

## Scope

Make the security rationale, threat model, profile, implementation, vectors, and review questions available in a reproducible form. Record reviewer findings and their severity and rationale.

## Out of scope

Treating tests, vectors, or an informal internal review as independent review; claiming all findings are resolved before P6.

## Deliverables

A review package, independent review findings, and a record of review scope and limitations.

## Security invariants

No production-readiness claim before independent security review and resolution of required findings.

## Exit criteria

An independent review has been completed with findings recorded in a form that can be triaged and addressed.

## STOP conditions

Stop readiness claims if review cannot be obtained, its scope is insufficient for the claim, or a critical issue remains unexplained.

## What this unlocks

Triage and remediation in P6; it does not by itself freeze the protocol or authorize release.
