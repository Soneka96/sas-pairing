# P10 — Consumer Integration Package

> **Pre-alpha. Not production approval.** P10 integrates the experimental `sas-pairing` packages into DovahLink on Windows. Nothing in P10 is a professional audit, formal verification, production-security approval, release approval, or Android support.

**Status: P10 IN PROGRESS — P10.1 COMPLETE** (consumer boundary + ABI-v1 / portability assessment; documentation only). **P10.2 — Canonical DovahLink Bootstrap Mapping + Current Authentication / Trust Audit** is next and starts only after P10.1 passes independent review. P10.2 must audit DovahLink's **current** authentication before any major integration implementation.

The roadmap and the increment plan are in [roadmap/P10-consumer-integration.md](../../roadmap/P10-consumer-integration.md).

## Documents

| Document | Contents |
|---|---|
| [decisions.md](decisions.md) | [P10-D-001](decisions.md#p10-d-001--consumer-boundary-platform-boundary-and-portability-discipline) (consumer boundary, platform boundary, portability discipline) and the [pending owner decisions](decisions.md#pending-owner-decisions) P10-OD-01 to P10-OD-15 |
| [consumer-boundary.md](consumer-boundary.md) | Responsibility split; verified `sas-pairing` facts A–O; PairingResult, CeremonyIdentity, proof-of-possession, Pair / Reject / Block, durable trust, reconnect, and network-identity boundaries; Bootstrap pre-assessment; DovahLink current-state evidence; the DovahLink boundary matrix; the P10.2 authentication audit contract |
| [portability-assessment.md](portability-assessment.md) | PN / WE / AB classification; authority, network, and cooperative-drive assessments; .NET and Dart integration boundaries with thread and isolate assessments; the ABI-v1 P10 verdict; the Dart future-reuse matrix; experiments E-01 to E-14; P10.8 closure questions; the Android blocker register; contradictions and gaps; the STOP review |

## Baseline

| Item | Value |
|---|---|
| Phase | [P10 — Consumer Integration](../../roadmap/P10-consumer-integration.md) |
| Branch | `feature/p10-consumer-integration`, the one long-lived P10 branch; no per-increment branches; one P10 pull request only after P10 closes |
| `main` baseline | `b938016d1de53d3e269fe0840485fbd3dc715fd7`, the merge of pull request #15 (P9: complete .NET package and Windows x64 native distribution) |
| DovahLink (read only) | `Soneka96/DovahLink` `main` `4a69ee5057029878200b6e16614f67a136e3e032` (merge of DovahLink pull request #117, 2026-10-04), read from a clean local clone whose `main` equals its `origin/main`; P10.1 did not create a branch, commit, or change there |

## Increments

| Increment | Scope | Decision | State |
|---|---|---|---|
| P10.1 | Consumer boundary, platform boundary, ABI-v1 sufficiency, PN / WE / AB classification, Android blocker register, P10 plan | P10-D-001 | Complete; awaiting independent review |
| P10.2 | DovahLink authentication / trust audit with a required verdict; canonical Bootstrap mapping; proof-of-possession boundary | — | Next |
| P10.3 | Host integration (.NET, Windows) | — | Planned |
| P10.4 | Dart / Flutter client integration (Windows) | — | Planned |
| P10.5 | SAS comparison + ceremony-bound approval | — | Planned |
| P10.6 | DovahLink authorization + durable trust | — | Planned |
| P10.7 | Normal trusted reconnect | — | Planned |
| P10.8 | Integration closure + Android portability report | — | Planned |

## P10.1 results

- **Boundary.** `sas-pairing` owns the protocol, cryptography, SAS, transcript, `ceremony_identity`, authenticated Bootstrap and result data, accounting, result lifetime, and failure semantics; DovahLink owns identities and keys, proof of possession, pending authorization, Pair / Reject / Block, KnownHost / KnownDevice, reconnect, sessions, discovery, and UX ([P10-D-001](decisions.md#p10-d-001--consumer-boundary-platform-boundary-and-portability-discipline)). DovahLink's own architecture already draws the same line.
- **ABI-v1 verdict: ABI-V1-P10-B.** ABI v1 appears sufficient for the P10 Windows integration, but named assumptions need P10 experiments before major integration ([portability §9](portability-assessment.md#9-abi-v1-p10-assessment)). The main finding: ABI v1 is listen-only (connections come only from a caller-bound listener's accept), while the DovahLink client connects out to the Host; the proposed answer is an in-process byte-transparent loopback relay in the client adapter (experiment E-02), with a STOP-and-report rule if no safe adapter exists. Second finding: the result returns the peer Bootstrap only as its canonical frame (E-13, P10-OD-13).
- **Portability.** Consumer concepts (identities, Bootstrap bytes, shared context, `ceremony_identity`, the result's meaning, the SAS string, authorization, trust, proof of possession, reconnect) are PN; the listener tokens, WinSock handles, `DuplicateAndClose`, the `WSAPoll` owner loop, the Windows lock-file authority lease, and DLL packaging are WE and can stay below adapters; concrete Android blockers are the non-Windows authority lease and carrier (both fail closed today), the Windows-only carrier entry of the ABI, the Windows listener tokens, and the missing Android artifact ([portability §14](portability-assessment.md#14-concrete-android-blocker-register)).
- **DovahLink facts that shape P10** (not a verdict): pairing today is a Host-generated six-digit code that issues a bearer credential; no Host or Client long-term key exists in DovahLink code; reconnect uses that bearer credential; the public transport is loopback-only; DovahLink has selected, but not implemented, "evidence → pending approval for the exact attempt → Pair / Reject / Block → trust" ([consumer boundary §12](consumer-boundary.md#12-dovahlink-current-state-evidence)).
- **No STOP condition hit** ([portability §17](portability-assessment.md#17-stop-conditions-review)).

## Evidence

### P10.1 evidence

Sources reviewed in this repository (complete reads): `README.md`, `SECURITY.md`, `roadmap/README.md`, `roadmap/P10-consumer-integration.md`, `docs/architecture.md`, `docs/protocol-status.md`, `docs/threat-model.md`, `docs/p6-remediation/final-closure.md`, `docs/p7-native-abi/{final-closure,abi-contract,abi-v1-manifest,decisions}.md`, `docs/p8-dart-package/{final-closure,decisions}.md`, `dart/README.md`, `docs/p9-dotnet-package/final-closure.md`, `ai/context/project.md`; targeted reads of `docs/p9-dotnet-package/decisions.md` and `dotnet/README.md` (threading, gate, socket, and drive rules), `docs/p3-vodozemac-ceremony-profile-draft.md` (§3.1, §4, §11.1.2), and the implementation: `core/src/lib.rs` (module gating, `os_lock` on and off Windows), `core/src/windows_tcp.rs` (`from_accepted`), `dart/lib/src/native/native_library_loader.dart`, `dart/lib` platform checks, `dotnet/src/SasPairing/{SasPairingRuntime,SasPairingHost,SasPairingWindowsListenerSocket,SasPairingCeremonyIdentity}.cs`, and the tooling guards and workflows.

Sources reviewed in DovahLink at `4a69ee5` (read only): `ARCHITECTURE.md`, `AGENTS.md`, `ROADMAP.md` (current position, stages, dependencies), `ai/context/security/identity-and-transport.md`, `ai/context/protocol/security.md`, `ai/context/host/architecture.md` (threading), `ai/context/sdk/architecture.md` (platform ports), `ai/context/flutter/architecture.md` (Redux / SDK ownership), `roadmap/deviations/initial-pairing-security/README.md`, `roadmap/deviations/current-execution-flow.md`, `roadmap/05a-android-wifi-development-path.md` (Android gate); `host/DovahLink.Host/Program.cs`, `Pairing/PairingCoordinator.cs`, `Trust/TrustRecord.cs`, `Trust/CredentialHasher.cs`, `Identity/HostIdentityStore.cs`, `Identity/ClientId.cs`, `Client/Transport/PublicWebSocketListener.cs` and `PublicListenerOptions.cs`, the adapter IPC message set (`host/DovahLink.Host/Adapter/Ipc/`, `adapter/ipc/`); `sdk/dart/dovahlink_client/lib/src/dovahlink_pairing.dart`, `persistence/persisted_known_host.dart`, `persistence/persisted_client_state.dart`, `lib/dovahlink_client_windows.dart`; the Flutter pairing feature file set; and a repository-wide search showing no asymmetric key, X.509, `SslStream`, or SPKI use under `host/`, `sdk/`, or `app/lib`.

Diff gates against the baseline `b938016`: `git diff b938016 -- core`, `-- dart/lib`, and `-- dotnet/src` are empty (no production change); `core/include/sas_pairing.h` and the ABI v1 manifest are unchanged. DovahLink: no branch, commit, or file change.

Checks run for P10.1:

| Check | Result |
|---|---|
| Required files and public status (the `consistency.yml` script, run locally; the four P10 documents added to its required list) | Pass: 45 files present and non-empty; every required README and license phrase present |
| `python tooling/check_markdown_links.py` | Pass: 1,502 internal links in 83 Markdown files, 0 broken |
| `python -m unittest discover -s tooling/tests` | Pass: 111 tests (7 skipped locally because they need the staged CI artifacts; they run in the Windows Dart and .NET jobs) |
| `git diff --check` | Pass |
| GitHub Actions on the P10.1 head `05373ad` (the change to `tooling/tests/**` triggers every workflow) | Green in all seven jobs: `consistency`, `windows-core`, `unsupported-platform-fails-closed`, `dart-package (windows-latest)`, `dart-package (ubuntu-latest)`, `dotnet-package (windows-latest)`, `dotnet-package (ubuntu-latest)` |

The only non-documentation change is the P9 status guard `tooling/tests/test_p9_distribution_contract.py`, whose three P10 assertions now pin "in progress" instead of "next", as P9.1 did for the P8 guard.
