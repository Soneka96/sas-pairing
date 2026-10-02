# P6 Review Remediation

> **Pre-alpha. Not production approval.** P6 remediates and dispositions the findings of the internal, AI-assisted P5 review and then decides whether a protocol candidate can be frozen. Nothing here is a professional audit, formal verification, certification, or production-security or release approval.

## Target

| Item | Value |
|---|---|
| Phase | [P6 — Review Remediation and Protocol Freeze](../../roadmap/P6-review-remediation-and-protocol-freeze.md) |
| Branch | `feature/p6-review-remediation-protocol-freeze`: the one branch for every P6 increment, correction, remediation, the protocol freeze, and the P6 closure. One pull request is opened only when P6 is finished and frozen |
| Baseline | `main` at `57131ad4878063baf326fe0b2f7a0eded7a47982`, the merge of the P5 pull request #11 |
| P5 closure | `b892937a6740bee4a877d3beea815cca6d24c48c` ([final synthesis](../p5-security-review/final-synthesis.md)) |
| Implementation under remediation | The experimental P4 native Rust core in `core/`, as reviewed by P5 |
| Normative baseline | The [P3 remote profile](../p3-vodozemac-ceremony-profile-draft.md), owner decisions 0001–0003, the [threat model](../threat-model.md), and the current [P3 conformance cases](../p3-conformance-cases.md) |

## Findings entering P6

P5 closed with five OPEN findings ([P5 findings](../p5-security-review/findings.md)). Their current P6 state:

| Finding | Severity | P6 state | Owner decision | Record |
|---|---|---|---|---|
| [P5-F-002](../p5-security-review/findings.md#p5-f-002) | MEDIUM | **REMEDIATED-IN-P6** (P6.1, `1ce0753`) | [P6-D-001](decisions.md#p6-d-001--f-002-connection-lifetime) | [p5-f-002.md](p5-f-002.md) |
| [P5-F-001](../p5-security-review/findings.md#p5-f-001) | LOW | **REMEDIATED-IN-P6** (P6.2, `c4212f2`) | [P6-D-003](decisions.md#p6-d-003--graceful-tcp-hang-up-handling) | [p5-f-001.md](p5-f-001.md) |
| [P5-F-003](../p5-security-review/findings.md#p5-f-003) | LOW | OPEN; disposition decided, implementation in a later increment | [P6-D-002](decisions.md#p6-d-002--f-003-owner-session-policy) | — |
| [P5-F-005](../p5-security-review/findings.md#p5-f-005) | INFO | OPEN; no decision yet (with P7 planning) | — | — |
| [P5-F-007](../p5-security-review/findings.md#p5-f-007) | INFO | OPEN; no decision yet | — | — |

The six accepted limitations (P5-F-004, P5-F-008 to P5-F-012) and eleven false positives stay as P5 recorded them.

## Increments

| Increment | Scope | State |
|---|---|---|
| P6.1 | Establish this package and the owner decisions; remediate P5-F-002; record the P5-F-003 decision without implementing it | **Complete:** P5-F-002 remediated ([record](p5-f-002.md)); P6-D-002 recorded, P5-F-003 not implemented |
| P6.2 | Remediate P5-F-001 graceful hang-up handling under owner decision P6-D-003, bounded by the P6-D-001 lifetime | **Complete:** P5-F-001 remediated ([record](p5-f-001.md)) |
| P6.3 | Remediate P5-F-003 process-session accounting reset under P6-D-002 | Next |

## Remediation rule

P6 changes production behavior only as the justified remediation of a validated P5 finding, and never as general refactoring or new features. Every remediation keeps one traceable chain:

```text
P3 requirement -> P5 finding -> owner decision -> remediation -> regression evidence
  -> follow-up review -> finding disposition -> protocol-candidate freeze
```

- An owner decision is recorded in [decisions.md](decisions.md) before the code that depends on it.
- P5 documents stay historical evidence. P6 may mark a finding `REMEDIATED-IN-P6` and append its remediation evidence, but never rewrites what P5 observed. The [P5 final synthesis](../p5-security-review/final-synthesis.md) stays a P5 closure snapshot; current status lives here.
- A finding is `REMEDIATED-IN-P6` only when all of these hold: owner decision recorded, production fix, unit and regression tests, the P5 reproducer passing, a follow-up adversarial review, P3 and conformance text synchronized, documentation synchronized, and full CI green.
- P5 known-bug reproducers become regression tests only for the finding being remediated. Reproducers of other findings keep failing until their own remediation.
- No remediation changes the wire format, cryptography, ceremony authentication, or the security accounting (ten-opportunity budget, exposed-ceremony guard, START limiter, authorization seal, pending and preliminary caps, request-ID reservation) unless a recorded owner decision says so and the change is re-analyzed.

## Assurance limits

Everything P5 stated as a limit still applies ([P5 assurance limitations](../p5-security-review/final-synthesis.md#9-assurance-limitations)): AI-assisted review, Windows-only executed evidence (Linux evidence is the CI fail-closed job), bounded deterministic tests rather than exhaustive exploration, fuzzing, or model checking, no formal verification, no professional audit, and the accepted environment assumptions. P6 follow-up reviews are internal and AI-assisted as well.
