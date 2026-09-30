# P5 — Implementation and Protocol Security Review

## Status

🟡 Planned; gated on a reviewable P4 implementation and profile.

## Goal

Review the actual implementation against the selected experimental profile, after a reviewable P4 implementation exists.

## Why this phase exists

P5 happens after P4 and examines whether the Rust core correctly implements the selected construction/profile. P3 review was AI-assisted; it did not establish formal or professional assurance. The owner waived a qualified-human-review prerequisite for experimental development and no professional audit is currently planned. P5 does not retroactively claim one occurred.

## Inputs / prerequisites

The P2 evidence, P3 selected experimental profile and owner decisions, P4 implementation, vectors, and their documented assumptions and limitations.

## Scope

Make the selected construction rationale, threat model, profile, implementation, vectors, and implementation-focused review questions available in a reproducible form. Record the review method, scope, limitations, and findings. Any independent or professional review would require separate planning and is not a prerequisite for experimental P4.

## Out of scope

Treating tests, vectors, AI-assisted analysis, or an informal internal review as professional certification; claiming all findings are resolved before P6.

## Deliverables

An implementation security-review package, findings and dispositions, and a record of review scope and limitations.

## Security invariants

No production-readiness claim based solely on P5, and no claim that the experimental owner decision constitutes security approval.

## Exit criteria

The implementation-focused review has a recorded scope, method, limitations, findings, and disposition sufficient to inform P6. The review may not be described as a professional audit unless qualified reviewers actually perform one. This does not upgrade the conditional protocol argument into a proof.

## STOP conditions

Stop any readiness claim that exceeds the evidence, leaves a material finding unexplained, or implies assurance work that was not performed.

## What this unlocks

Triage and remediation in P6; it does not by itself freeze the protocol or authorize release.
