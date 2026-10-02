# P6 — Review Remediation and Protocol Freeze

## Status

✅ **COMPLETE — PROTOCOL CANDIDATE FROZEN** (P6.6, [final closure](../docs/p6-remediation/final-closure.md)). P5-F-002, P5-F-001, and P5-F-003 are REMEDIATED-IN-P6 (P6.1, P6.2, P6.3; owner decisions P6-D-001, P6-D-003, P6-D-002); P5-F-005 and P5-F-007 are DISPOSITIONED-IN-P6 (P6.4 with the P6.4.1 correction, P6-D-004, a mandatory P7 ABI panic-containment obligation; P6.5, P6-D-005, the confirmation-time completion boundary with either side possibly the only result holder). **0 OPEN P5 handoff findings remain.** The experimental remote protocol candidate `sas-pairing-vodozemac-profile-draft-01`, version 1, together with the P6 owner decisions and the amended normative conformance cases (still 92 rows), is frozen for P7 native-ABI work. This is an experimental protocol-candidate freeze only, not production approval, professional security audit, or formal verification; the accepted limitations (P5-F-004, P5-F-008 to P5-F-012) stay accepted. All P6 work happened on the one branch `feature/p6-review-remediation-protocol-freeze`, with one pull request at P6 closure. **P7 is unlocked only after that pull request is reviewed and merged;** P7 has not started. Tracking package: [docs/p6-remediation](../docs/p6-remediation/README.md).

| Increment | Scope | State |
|---|---|---|
| P6.1 | P6 package and owner decisions; remediate P5-F-002; record the P5-F-003 decision (implementation later) | Complete ([P5-F-002 record](../docs/p6-remediation/p5-f-002.md)) |
| P6.2 | Remediate P5-F-001 graceful hang-up handling | Complete ([P5-F-001 record](../docs/p6-remediation/p5-f-001.md)) |
| P6.3 | Remediate P5-F-003 process-session accounting reset (P6-D-002) | Complete ([P5-F-003 record](../docs/p6-remediation/p5-f-003.md)) |
| P6.4 | Decide and disposition P5-F-005 entropy-panic / ABI policy (P6-D-004) | Complete ([P5-F-005 record](../docs/p6-remediation/p5-f-005.md)); P7 owns the ABI containment |
| P6.4.1 | Correct P6-D-004 panic-payload disposal (no uncontained payload destructor; Drop-panicking-payload P7 exit test) | Complete; policy correction, F-005 stays DISPOSITIONED-IN-P6 |
| P6.5 | Disposition P5-F-007 reverse asymmetric completion semantics (P6-D-005) | Complete ([P5-F-007 record](../docs/p6-remediation/p5-f-007.md)); confirmation-time boundary kept, no production change |
| P6.6 | Protocol candidate freeze and final P6 closure | Complete ([final closure](../docs/p6-remediation/final-closure.md)); candidate frozen for P7, no production change |

## P5 handoff

The [P5 final review synthesis](../docs/p5-security-review/final-synthesis.md#10-p6-handoff) holds the disposition table, the owner decisions each finding needs, the regression evidence to enable, and the recommended order. Full entries are in the [P5 findings](../docs/p5-security-review/findings.md).

| Finding | Severity | Summary | Owner decision needed (at P5 handoff) | P6 outcome |
|---|---|---|---|---|
| [P5-F-002](../docs/p5-security-review/findings.md#p5-f-002) | MEDIUM | No finite connection-level or pre-frame lifetime; 16 idle connections can hold the live-connection cap indefinitely | Timer model and values | REMEDIATED-IN-P6 (P6.1, P6-D-001) |
| [P5-F-001](../docs/p5-security-review/findings.md#p5-f-001) | LOW | The Windows owner loop discards readable or pending data on `POLLHUP` | No | REMEDIATED-IN-P6 (P6.2, P6-D-003) |
| [P5-F-003](../docs/p5-security-review/findings.md#p5-f-003) | LOW | Same-process re-registration resets the opportunity budget and START limiter, contrary to current P3 policy | Default (keep P3, fix the implementation) or an explicit P3 policy revision | REMEDIATED-IN-P6 (P6.3, P6-D-002: keep P3) |
| [P5-F-005](../docs/p5-security-review/findings.md#p5-f-005) | INFO | Entropy-panic policy and unwind behavior across the Router, adapter, owner loop, and future ABI | Panic policy, with P7 | DISPOSITIONED-IN-P6 (P6.4, P6-D-004; P7 obligation) |
| [P5-F-007](../docs/p5-security-review/findings.md#p5-f-007) | INFO | Reverse asymmetric completion at the Initiator's deadline boundary; documentation | Optional boundary rule | DISPOSITIONED-IN-P6 (P6.5, P6-D-005) |

Owner decisions (final, frozen at P6.6): [P6-D-001](../docs/p6-remediation/decisions.md#p6-d-001--f-002-connection-lifetime) (P5-F-002 timer model and values), [P6-D-002](../docs/p6-remediation/decisions.md#p6-d-002--f-003-owner-session-policy) (P5-F-003: keep current P3 semantics; implemented in P6.3), [P6-D-003](../docs/p6-remediation/decisions.md#p6-d-003--graceful-tcp-hang-up-handling) (P5-F-001 graceful hang-up handling), [P6-D-004](../docs/p6-remediation/decisions.md#p6-d-004--native-panic-containment-policy) (P5-F-005 native panic containment; a mandatory P7 requirement), and [P6-D-005](../docs/p6-remediation/decisions.md#p6-d-005--local-completion-and-final-ack-deadline-boundary) (P5-F-007: keep the confirmation-time completion boundary; either side may be the only result holder).

P5's recommended order, which P6 followed: P5-F-002, then P5-F-001 (together with or after P5-F-002), then P5-F-003 (with its owner decision taken early), P5-F-005, and P5-F-007. The P5 expected-fail reproducers for P5-F-001 and P5-F-002 become regression tests as fixes land. The accepted limitations (P5-F-004, P5-F-008 to P5-F-012) stay accepted; P5-F-004's optional hardening was not done in P6.

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

**Met at P6.6** ([final closure §16](../docs/p6-remediation/final-closure.md#16-freeze-decision)).

## STOP conditions

Return to P2/P3/P4 or stop if remediation exposes a fundamental gap, changes security claims materially, or cannot be validated.

## What this unlocks

P7 design and delivery of a stable native boundary around the reviewed implementation. P7 starts only after the P6 pull request is reviewed and merged.
