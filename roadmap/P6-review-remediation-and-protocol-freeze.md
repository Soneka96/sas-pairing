# P6 — Review Remediation and Protocol Freeze

## Status

🔵 **NEXT — P5 REVIEW COMPLETE.** Not started. P5 closed with five OPEN findings handed to P6; no remediation has been performed.

## P5 handoff

The [P5 final review synthesis](../docs/p5-security-review/final-synthesis.md#10-p6-handoff) holds the disposition table, the owner decisions each finding needs, the regression evidence to enable, and the recommended order. Full entries are in the [P5 findings](../docs/p5-security-review/findings.md).

| Finding | Severity | Summary | Owner decision needed |
|---|---|---|---|
| [P5-F-002](../docs/p5-security-review/findings.md#p5-f-002) | MEDIUM | No finite connection-level or pre-frame lifetime; 16 idle connections can hold the live-connection cap indefinitely | Timer model and values |
| [P5-F-001](../docs/p5-security-review/findings.md#p5-f-001) | LOW | The Windows owner loop discards readable or pending data on `POLLHUP` | No |
| [P5-F-003](../docs/p5-security-review/findings.md#p5-f-003) | LOW | Same-process re-registration resets the opportunity budget and START limiter, contrary to current P3 policy | Default (keep P3, fix the implementation) or an explicit P3 policy revision |
| [P5-F-005](../docs/p5-security-review/findings.md#p5-f-005) | INFO | Entropy-panic policy and unwind behavior across the Router, adapter, owner loop, and future ABI | Panic policy, with P7 |
| [P5-F-007](../docs/p5-security-review/findings.md#p5-f-007) | INFO | Reverse asymmetric completion at the Initiator's deadline boundary; documentation | Optional boundary rule |

Recommended order: P5-F-002, then P5-F-001 (together with or after P5-F-002), then P5-F-003 (with its owner decision taken early), P5-F-005, and P5-F-007. The P5 expected-fail reproducers for P5-F-001 and P5-F-002 become regression tests as fixes land. The accepted limitations (P5-F-004, P5-F-008 to P5-F-012) stay accepted; P5-F-004 has optional hardening.

## Goal

Address review findings and freeze a protocol candidate only when the evidence supports it.

## Why this phase exists

Review findings may invalidate assumptions, profile decisions, or implementation behavior and must be resolved before downstream interfaces depend on them.

## Inputs / prerequisites

Independent review findings (currently the completed internal, AI-assisted [P5 review](../docs/p5-security-review/README.md)) and the P2–P4 evidence, profile, and implementation.

## Scope

Triage findings, make justified remediations, update affected evidence and vectors, and obtain follow-up review where needed. Significant findings may return the project to P2, P3, or P4.

## Out of scope

Declaring a protocol frozen while material findings or unsupported decisions remain; treating freeze as proof of security.

## Deliverables

Resolved or explicitly dispositioned findings, updated affected artifacts, and a recorded protocol-candidate freeze decision when justified.

## Security invariants

Preserve traceability from requirements through construction, profile, implementation, and review. A significant security change reopens the relevant earlier gate.

## Exit criteria

Required findings are addressed with sufficient evidence and follow-up review. Freeze only when the candidate and its stated claims are stable enough for downstream ABI work.

## STOP conditions

Return to P2/P3/P4 or stop if remediation exposes a fundamental gap, changes security claims materially, or cannot be validated.

## What this unlocks

P7 design and delivery of a stable native boundary around the reviewed implementation.
