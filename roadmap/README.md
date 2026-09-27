# Project roadmap

This roadmap describes phase order and exit gates. The [threat model](../docs/threat-model.md), [protocol status](../docs/protocol-status.md), [architecture](../docs/architecture.md), [ADRs](../docs/decisions/README.md), and [security policy](../SECURITY.md) remain authoritative for their respective topics.

```text
P0 ✅ Repository Foundation
 ↓
P1 ✅ Threat Model and Protocol Requirements
 ↓
P2 🔵 Construction Selection / Formal Mapping
 ↓
P3 🟡 Protocol Profile + Deterministic Vectors
 ↓
P4 🟡 Native Rust Security Core
 ↓
P5 🟡 Security Review Package + External Review
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

P0 and P1 are complete based on the repository foundation and the P1 merge in current `main`. P2 is the next gate. Pasini–Vaudenay is a research candidate, not a selected construction.

## Security gates across phases

- Keep one production security implementation; Dart and .NET wrap the native core.
- Keep the protocol application-neutral. DovahLink is a consumer, not part of the protocol.
- Treat human SAS comparison as part of the security system.
- Make any security-required attempt limits and persistence requirements part of the protocol contract.
- Fail closed; do not silently downgrade or fall back.
- Tests and vectors establish conformance, not cryptographic security.
- Require independent security review before production-readiness claims.
- Distinguish candidate, research, selected, and STOP outcomes. Do not turn uncertainty into architecture.

## Phases

- [P0 — Repository Foundation](P0-repository-foundation.md)
- [P1 — Threat Model and Protocol Requirements](P1-threat-model-and-requirements.md)
- [P2 — Construction Selection / Formal Mapping](P2-construction-selection.md)
- [P3 — Protocol Profile and Deterministic Vectors](P3-protocol-profile-and-vectors.md)
- [P4 — Native Security Core](P4-native-security-core.md)
- [P5 — Security Review](P5-security-review.md)
- [P6 — Review Remediation and Protocol Freeze](P6-review-remediation-and-protocol-freeze.md)
- [P7 — Native ABI](P7-native-abi.md)
- [P8 — Dart Package](P8-dart-package.md)
- [P9 — .NET Package](P9-dotnet-package.md)
- [P10 — Consumer Integration](P10-consumer-integration.md)

## 1.0 readiness

P10 does not automatically produce a 1.0 release. Production-readiness claims require explicit security-readiness criteria, including a justified protocol and profile, completed required remediation, independent security review, and evidence that the release meets its stated requirements. Passing tests or vectors alone is insufficient.
