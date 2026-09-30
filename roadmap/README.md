# Project roadmap

This roadmap describes phase order and exit gates. The [threat model](../docs/threat-model.md), [protocol status](../docs/protocol-status.md), [architecture](../docs/architecture.md), [ADRs](../docs/decisions/README.md), and [security policy](../SECURITY.md) remain authoritative for their respective topics.

```text
P0 ✅ Repository Foundation
 ↓
P1 ✅ Threat Model and Protocol Requirements
 ↓
P2 ✅ Construction Selection / Formal Mapping
 ↓
P3 ✅ Finalized selected experimental remote specification and owner policy
 ↓
P4 🔵 Experimental Native Rust Security Core authorized
 ↓
P5 🟡 Implementation + Protocol Security Review
 ↓
P6 🟡 Review Remediation + Protocol Freeze
 ↓
P7 🟡 Native ABI
 ↓
P8 🟡 Dart Package
 ↓
P9 🟡 .NET Package
 ↓
P10 🟡 Consumer Integration / DovahLink Example
 ↓
1.0 only after explicit security-readiness criteria are satisfied
```

## Status key

- ✅ Complete
- 🔵 Current / next
- 🟡 Planned
- 🔴 Blocked / STOP

## Planning rule

The roadmap is evidence-driven and may change. Deep planning is limited to the current phase; the next phase is understood well enough to expose dependencies. Later phases remain milestone-level until earlier security decisions resolve. A phase may end in STOP rather than automatically progressing. No dates or delivery estimates are implied.

P0–P3 remote experimental specification finalization are complete. **Historical P2 outcome: SELECTED — Candidate B.** During P3, the owner reopened that choice because a concrete Candidate B profile would require substantial project-owned cryptographic design and proof-mapping/maintenance. This is an ownership decision, not a finding that Candidate B is insecure; it remains a formal reference and possible fallback. Current remote policy permits one owning process per authority, one live exposed ceremony, a shared ten-opportunity process/session budget, and distinct finite pre-exposure resource controls across roles, threads, and connections. The `n_A + n_B - 1` model gives at most 19 pairs only in a joint 10/10 window while both endpoints remain within their respective process sessions; it is not a bound across arbitrary restarts or over a lifetime. **F-02 is a false positive under the stated idealized assumptions:** an attacker may know its own DH secret after an honest public contribution is revealed; the relevant condition is target-SAS unpredictability before the attacker fixes its contribution. The complete argument remains conditional and is not formally verified. AI-assisted reviews are not professional audits. The owner waived the qualified-human-review gate for experimental development, not completed it; no professional audit is currently planned. **Vodozemac 0.11.0 is selected for experimental implementation. P4 is next and authorized, not complete.** No production-security or release approval is granted. The separate local-profile/adapter work remains candidate-only and does not block remote P4. See [protocol status](../docs/protocol-status.md) and [owner decision](../docs/decisions/0002-experimental-vodozemac-selection.md).

## Security gates across phases

- Keep one production security implementation; Dart and .NET wrap the native core.
- Keep the protocol application-neutral. DovahLink is a consumer, not part of the protocol.
- Treat human SAS comparison as part of the security system.
- Make any security-required attempt limits and persistence requirements part of the protocol contract.
- Fail closed; do not silently downgrade or fall back.
- Tests and vectors establish conformance, not cryptographic security.
- Do not treat the experimental-development authorization as production readiness. Any future release requires a separate owner readiness decision and accurate disclosure of assurance limits.
- The owner waived the qualified-human-review gate for experimental P4; no professional audit has occurred or is currently planned.
- Distinguish candidate, research, selected, and STOP outcomes. Do not turn uncertainty into architecture.

## Phases

- [P0 — Repository Foundation](P0-repository-foundation.md)
- [P1 — Threat Model and Protocol Requirements](P1-threat-model-and-requirements.md)
- [P2 — Construction Selection / Formal Mapping](P2-construction-selection.md)
- [P3 — Protocol Profile and Deterministic Vectors](P3-protocol-profile-and-vectors.md)
- [P4 — Native Security Core](P4-native-security-core.md)
- [P5 — Implementation and Protocol Security Review](P5-security-review.md)
- [P6 — Review Remediation and Protocol Freeze](P6-review-remediation-and-protocol-freeze.md)
- [P7 — Native ABI](P7-native-abi.md)
- [P8 — Dart Package](P8-dart-package.md)
- [P9 — .NET Package](P9-dotnet-package.md)
- [P10 — Consumer Integration](P10-consumer-integration.md)

## Review gates

- **P3 — Experimental remote specification:** finalized by this baseline; the selected profile, policy, vectors, applicable conformance cases, limitations, and P4 prerequisites are explicit. No production profile approval is implied.
- **P5 — Post-implementation security review:** after P4, assess the actual implementation against the selected profile and record scope/findings. No qualified professional audit is currently planned or implied by this roadmap.

## 1.0 readiness

P10 does not automatically produce a 1.0 release. Any release requires a separate owner readiness decision and evidence appropriate to its claims. The waived experimental-development review gate does not establish production readiness. Any public release must accurately disclose assurance limitations. Passing tests or vectors alone is insufficient.
