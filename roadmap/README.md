# Project roadmap

This roadmap describes phase order and exit gates. The [threat model](../docs/threat-model.md), [protocol status](../docs/protocol-status.md), [architecture](../docs/architecture.md), [ADRs](../docs/decisions/README.md), and [security policy](../SECURITY.md) remain authoritative for their respective topics.

```text
P0 ✅ Repository Foundation
 ↓
P1 ✅ Threat Model and Protocol Requirements
 ↓
P2 ✅ Construction Selection / Formal Mapping
 ↓
P3 ✅/🟡 Candidate Protocol Specification + Review Package (specification substantially review-ready)
 ↓
P3.5 🔴 Pre-implementation Construction Security Review
 ↓
P3.6 🟡 Owner Selection / Candidate Remediation + Profile Freeze
 ↓
P4 🟡 Native Rust Security Core
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

P0, P1, and the historical P2 research phase are complete. **Historical P2 outcome: SELECTED — Candidate B.** During P3, the owner reopened that choice because a concrete Candidate B profile would require substantial project-owned cryptographic design and proof-mapping/maintenance. This is an engineering/security ownership decision, not a finding that Candidate B is insecure; it remains a formal reference and possible fallback. A ceremony based on maintained vodozemac primitives is the **FAVORED CANDIDATE — NOT SELECTED**. Its pre-implementation review package is ready, but the independent review has not occurred and the owner has made no final selection. **P3 candidate specification work is substantially review-ready; security approval and construction selection remain blocked.** P3.5 asks whether the proposed composition/profile is defensible enough to select and implement. P3.6 follows review for candidate remediation as needed and an explicit owner selection/profile-freeze decision. P4 cannot begin until those gates pass. P5 is a separate post-implementation review asking whether the actual Rust implementation correctly and safely implements the reviewed construction/profile. Local profile/adapter gates also remain open. See [protocol status](../docs/protocol-status.md), [review package](../docs/p3-vodozemac-independent-review-package.md), and [AI manager context](../ai/context/project.md).

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
- [P5 — Implementation and Protocol Security Review](P5-security-review.md)
- [P6 — Review Remediation and Protocol Freeze](P6-review-remediation-and-protocol-freeze.md)
- [P7 — Native ABI](P7-native-abi.md)
- [P8 — Dart Package](P8-dart-package.md)
- [P9 — .NET Package](P9-dotnet-package.md)
- [P10 — Consumer Integration](P10-consumer-integration.md)

## Review gates

- **P3.5 — Pre-implementation construction security review:** Is the proposed cryptographic composition/profile defensible enough to select and implement? This occurs before P4.
- **P3.6 — Owner selection and profile freeze:** After review and any candidate remediation, the owner explicitly selects a construction and freezes a sufficiently precise profile before P4.
- **P5 — Post-implementation security review:** Does the actual Rust implementation correctly and safely implement the reviewed construction/profile? This occurs after P4; remediation and final protocol freeze follow in P6.

## 1.0 readiness

P10 does not automatically produce a 1.0 release. Production-readiness claims require explicit security-readiness criteria, including a justified protocol and profile, completed required remediation, independent security review, and evidence that the release meets its stated requirements. Passing tests or vectors alone is insufficient.
