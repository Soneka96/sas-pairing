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
P4 ✅ Experimental Native Rust Security Core (complete; not production-security approved)
 ↓
P5 ✅ Implementation + Protocol Security Review (complete; internal, AI-assisted; not a professional audit)
 ↓
P6 ✅ Review Remediation + Protocol Freeze (complete: P5-F-002, P5-F-001, P5-F-003 remediated; P5-F-005, P5-F-007 dispositioned; experimental protocol candidate frozen for P7; not production-security approved)
 ↓
P7 ✅ Native ABI (complete: P7.1–P7.7; native ABI v1 frozen by P7-D-013 with 25 exports; two-sided public-ABI ceremony proven; P6-D-004 ABI panic containment evidence complete; not production-security approved)
 ↓
P8 ✅ Dart Package (complete: P8.1–P8.6; experimental Dart wrapper over the frozen ABI v1 with lifecycle, Windows network driver, ceremony + SAS, and PairingResult; Windows x64 native library distributed as an unsigned experimental CI artifact per commit; not a release; not production-security approved)
 ↓
P9 ✅ .NET Package (complete: P9.1–P9.6; experimental `SasPairing` net10.0 wrapper over the frozen ABI v1 with lifecycle, Windows network driver, ceremony + SAS, and PairingResult; an experimental NuGet-format package with no native library inside and a separate Windows x64 native library, both unsigned CI artifacts per commit; not published to nuget.org; not a release; not production-security approved)
 ↓
P10 🔵 Consumer Integration / DovahLink Example (in progress: P10.1 complete, consumer boundary + ABI-v1 / portability assessment; P10.2 next after independent review; Windows only)
 ↓
P11 🟡 Android / Cross-Platform Native Support (milestone only; input: the P10.8 portability evidence)
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

P0–P3 remote experimental specification finalization are complete. **Historical P2 outcome: SELECTED — Candidate B.** During P3, the owner reopened that choice because a concrete Candidate B profile would require substantial project-owned cryptographic design and proof-mapping/maintenance. This is an ownership decision, not a finding that Candidate B is insecure; it remains a formal reference and possible fallback. Current remote policy permits one owning process per authority, one live exposed ceremony, a shared ten-opportunity process/session budget, and distinct finite pre-exposure resource controls across roles, threads, and connections. The `n_A + n_B - 1` model gives at most 19 pairs only in a joint 10/10 window while both endpoints remain within their respective process sessions; it is not a bound across arbitrary restarts or over a lifetime. **F-02 is a false positive under the stated idealized assumptions:** an attacker may know its own DH secret after an honest public contribution is revealed; the relevant condition is target-SAS unpredictability before the attacker fixes its contribution. The complete argument remains conditional and is not formally verified. AI-assisted reviews are not professional audits. The owner waived the qualified-human-review gate for experimental development, not completed it; no professional audit is currently planned. **Vodozemac 0.11.0 is selected for experimental implementation. P4 is complete as the experimental native security core, with its [conformance closure](../docs/p4-conformance-closure.md) achieved. The P5 implementation + protocol security review is complete ([final synthesis](../docs/p5-security-review/final-synthesis.md)): 34 / 34 planned surfaces reviewed, no confirmed CRITICAL or HIGH finding, and five OPEN findings (one MEDIUM, two LOW, two INFO) handed to P6. P6 is complete ([final closure](../docs/p6-remediation/final-closure.md)): P6.1 remediated P5-F-002, P6.2 remediated P5-F-001, and P6.3 remediated P5-F-003; P6.4 dispositioned P5-F-005 under P6-D-004 (P7 must contain native panics); P6.5 dispositioned P5-F-007 under P6-D-005 (either side may be the only result holder; no production change); P6.6 froze the experimental remote protocol candidate `sas-pairing-vodozemac-profile-draft-01`, version 1, for P7 native-ABI work. P7 is complete on `feature/p7-native-abi`, started after the P6 pull request was merged: native ABI v1 is frozen by P7-D-013 (version 1, 25 exports, a two-sided public-ABI ceremony proven; [P7 final closure](../docs/p7-native-abi/final-closure.md)), and P8 is complete on `feature/p8-dart-package` (P8.1 the Dart package foundation and the frozen ABI v1 bindings; P8.2 and P8.2.1 the runtime / authority / host lifecycle wrapper; P8.3 Windows listener ownership and the cooperative network driver; P8.4 run and ceremony control with SAS presentation; P8.5 the PairingResult API and result ownership; P8.6 the Windows x64 native artifact distribution as an experimental CI artifact and the final closure; [P8 final closure](../docs/p8-dart-package/final-closure.md)), and P9 is complete on `feature/p9-dotnet-package` (P9.1 the .NET package foundation and the exact ABI v1 interop; P9.2 the Runtime / Authority / Host lifecycle wrapper; P9.3 Windows listener ownership and the cooperative network driver; P9.4 run and ceremony control with SAS presentation; P9.5 the PairingResult API and result ownership; P9.6 the experimental NuGet-format package and the separate Windows x64 native artifact as exact-commit CI artifacts, and the final closure; [P9 final closure](../docs/p9-dotnet-package/final-closure.md)). P10, consumer integration and the DovahLink example, is in progress on `feature/p10-consumer-integration` (started from `main` `b938016`, the P9 pull request #15 merge): P10.1, the consumer boundary and ABI-v1 / portability assessment, is complete under owner decision P10-D-001 with the verdict ABI-V1-P10-B (ABI v1 appears sufficient for the Windows integration, with named experiments before major integration; [P10 package](../docs/p10-consumer-integration/README.md)), and P10.2, the canonical DovahLink Bootstrap mapping and the audit of DovahLink's current authentication and trust, is next after independent review. P10 implements Windows only; P11 (Android / cross-platform native support) follows as a milestone only.** The freeze is an experimental protocol-candidate freeze, not production approval, professional audit, or formal verification. P5 performed no remediation. No production-security or release approval is granted. The separate local-profile/adapter work remains candidate-only. See [protocol status](../docs/protocol-status.md) and [owner decision](../docs/decisions/0002-experimental-vodozemac-selection.md).

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
- P11 — Android / Cross-Platform Native Support ([milestone only](#p11--android--cross-platform-native-support-milestone-only))

## P11 — Android / Cross-Platform Native Support (milestone only)

🟡 Planned, milestone level only ([P10-D-001](../docs/p10-consumer-integration/decisions.md#p10-d-001--consumer-boundary-platform-boundary-and-portability-discipline) item 16). Not planned in depth: no increments exist.

- **Goal:** enable Android pairing while reusing the Rust protocol and cryptography core, the existing Dart wrapper as far as its current API permits, and the P10 consumer / domain integration boundary.
- **Input:** the P10.8 portability evidence and classification (A, B, or C), the [Android blocker register](../docs/p10-consumer-integration/portability-assessment.md#14-concrete-android-blocker-register), and the [questions recorded for P11](../docs/p10-consumer-integration/portability-assessment.md#15-android-questions-recorded-for-p11).
- **Likely investigation areas:** Android native authority ownership; the Android transport carrier; native `.so` packaging; Flutter / Dart loading of the native library; isolate and process lifecycle; and whether any ABI evolution is actually necessary.
- **Not part of this milestone entry:** P11 increments, a Kotlin or JNI cryptography design, a POSIX abstraction, an iOS, macOS, or Linux rollout, or an ABI v2 choice. Those wait for P10.8 evidence and later owner decisions.

## Review gates

- **P3 — Experimental remote specification:** finalized by this baseline; the selected profile, policy, vectors, applicable conformance cases, limitations, and P4 prerequisites are explicit. No production profile approval is implied.
- **P5 — Post-implementation security review:** after P4, assess the actual implementation against the selected profile and record scope/findings. No qualified professional audit is currently planned or implied by this roadmap.

## 1.0 readiness

P10 does not automatically produce a 1.0 release, and Android (P11) is the next expected platform milestone after P10. Any release requires a separate owner readiness decision and evidence appropriate to its claims. The waived experimental-development review gate does not establish production readiness. Any public release must accurately disclose assurance limitations. Passing tests or vectors alone is insufficient.
