# P10 — Consumer Integration Package

> **Pre-alpha. Not production approval.** P10 integrates the experimental `sas-pairing` packages into DovahLink on Windows. Nothing in P10 is a professional audit, formal verification, production-security approval, release approval, or Android support.

**Status: P10 IN PROGRESS — P10.2 COMPLETE** (canonical DovahLink Bootstrap mapping + current authentication / trust audit; documentation, vectors, and a test-only verifier), awaiting independent review. P10.1 (consumer boundary + ABI-v1 / portability assessment) is complete and accepted. **P10.3 — Host Integration (.NET, Windows)**, now including the Host long-term key, is next and starts only after P10.2 passes independent review.

The roadmap and the increment plan are in [roadmap/P10-consumer-integration.md](../../roadmap/P10-consumer-integration.md).

## Documents

| Document | Contents |
|---|---|
| [decisions.md](decisions.md) | [P10-D-001](decisions.md#p10-d-001--consumer-boundary-platform-boundary-and-portability-discipline) (consumer boundary, platform boundary, portability discipline), [P10-D-002](decisions.md#p10-d-002--canonical-dovahlink-bootstrap-v1-mapping) (canonical Bootstrap mapping), [P10-D-003](decisions.md#p10-d-003--dovahlink-authentication-disposition-and-pop-boundary) (authentication disposition and PoP boundary), and the [pending owner decisions](decisions.md#pending-owner-decisions) P10-OD-01 to P10-OD-16 |
| [consumer-boundary.md](consumer-boundary.md) | Responsibility split; verified `sas-pairing` facts A–O; PairingResult, CeremonyIdentity, proof-of-possession, Pair / Reject / Block, durable trust, reconnect, and network-identity boundaries; Bootstrap pre-assessment; DovahLink current-state evidence; the DovahLink boundary matrix; the P10.2 authentication audit contract |
| [authentication-audit.md](authentication-audit.md) | P10.2 audit of DovahLink's current authentication, trust, and reconnect (CURRENT / TARGET-DESIGN / P10-DECISION labels); Host, Client, and bearer analysis; KnownHost and KnownDevice fields; revoke / block / reset; questions A–AB and AC–AF; the property matrix; the verdict; key existence; surviving controls; the replacement components and their owners |
| [bootstrap-mapping.md](bootstrap-mapping.md) | P10-D-002 specification: exact `applicationIdentity`, `keyAlgorithm`, `publicKey`, and `sharedContext` bytes for Host and Client; UUID encoding; roles; anti-confusion and the rejected nonce design; exact peer-frame comparison (E-13); PoP boundary; cross-channel binding; local completion versus pending Pair; pending authorization; asymmetric completion; mutation fence; initial versus reconnect flows; authority scope; E-05 / E-06; vectors |
| [vectors/dovahlink-bootstrap-v1.json](vectors/dovahlink-bootstrap-v1.json) | DovahLink consumer mapping vectors (not `sas-pairing` conformance vectors), verified by `tooling/tests/test_p10_dovahlink_bootstrap_mapping.py` |
| [portability-assessment.md](portability-assessment.md) | PN / WE / AB classification; authority, network, and cooperative-drive assessments; .NET and Dart integration boundaries with thread and isolate assessments; the ABI-v1 P10 verdict; the Dart future-reuse matrix; experiments E-01 to E-14; P10.8 closure questions; the Android blocker register; contradictions and gaps; the STOP review |

## Baseline

| Item | Value |
|---|---|
| Phase | [P10 — Consumer Integration](../../roadmap/P10-consumer-integration.md) |
| Branch | `feature/p10-consumer-integration`, the one long-lived P10 branch; no per-increment branches; one P10 pull request only after P10 closes |
| `main` baseline | `b938016d1de53d3e269fe0840485fbd3dc715fd7`, the merge of pull request #15 (P9: complete .NET package and Windows x64 native distribution) |
| DovahLink (read only) | `Soneka96/DovahLink` `main` `9f4e925cc8dcba0db37d1bd7d38b39f0927b9387` (merge of DovahLink pull request #118, "Feature/world context foundation", 2026-10-05), fetched directly from GitHub by P10.1.1. P10.1 read `main` `4a69ee5057029878200b6e16614f67a136e3e032` (merge of pull request #117, 2026-10-04) from a local clone; the delta between the two changes no pairing, authentication, or trust fact ([P10.1.1 evidence](#p1011-evidence)). Neither increment created a branch, commit, or change in DovahLink |

## Increments

| Increment | Scope | Decision | State |
|---|---|---|---|
| P10.1 | Consumer boundary, platform boundary, ABI-v1 sufficiency, PN / WE / AB classification, Android blocker register, P10 plan | P10-D-001 | Complete and accepted (P10.1.1 reconciled the DovahLink baseline and the experiment wording) |
| P10.2 | DovahLink authentication / trust audit with a required verdict; canonical Bootstrap mapping; proof-of-possession boundary | P10-D-002, P10-D-003 | Complete; awaiting independent review |
| P10.3 | Host integration (.NET, Windows) + Host long-term key | — | Next, after P10.2 review |
| P10.4 | Dart / Flutter client integration (Windows) + Client long-term key | — | Planned |
| P10.5 | SAS comparison + ceremony-bound approval | — | Planned |
| P10.5A | Authenticated transport (WSS / TLS 1.3 with the Host key) | — | Planned (added by P10.2, owner-approved) |
| P10.6 | DovahLink authorization + durable trust | — | Planned |
| P10.7 | Normal trusted reconnect | — | Planned |
| P10.8 | Integration closure + Android portability report | — | Planned |

## P10.1 results

- **Boundary.** `sas-pairing` owns the protocol, cryptography, SAS, transcript, `ceremony_identity`, authenticated Bootstrap and result data, accounting, result lifetime, and failure semantics; DovahLink owns identities and keys, proof of possession, pending authorization, Pair / Reject / Block, KnownHost / KnownDevice, reconnect, sessions, discovery, and UX ([P10-D-001](decisions.md#p10-d-001--consumer-boundary-platform-boundary-and-portability-discipline)). DovahLink's own architecture already draws the same line.
- **ABI-v1 verdict: ABI-V1-P10-B.** ABI v1 appears sufficient for the P10 Windows integration, but named assumptions need P10 experiments before major integration ([portability §9](portability-assessment.md#9-abi-v1-p10-assessment)). The main finding: ABI v1 is listen-only (connections come only from a caller-bound listener's accept), while the DovahLink client connects out to the Host; an in-process byte-transparent loopback relay in the client adapter is a plausible public-API adapter path, requiring experiment E-02 and unproven until it passes, with a STOP-and-report rule if no safe adapter exists. Second finding: the result returns the peer Bootstrap only as its canonical frame; a consumer-side decode or exact re-encode-and-compare is a plausible public-API adapter path, requiring experiment E-13 and unproven until it passes (P10-OD-13).
- **Portability.** Consumer concepts (identities, Bootstrap bytes, shared context, `ceremony_identity`, the result's meaning, the SAS string, authorization, trust, proof of possession, reconnect) are PN; the listener tokens, WinSock handles, `DuplicateAndClose`, the `WSAPoll` owner loop, the Windows lock-file authority lease, and DLL packaging are WE and can stay below adapters; concrete Android blockers are the non-Windows authority lease and carrier (both fail closed today), the Windows-only carrier entry of the ABI, the Windows listener tokens, and the missing Android artifact ([portability §14](portability-assessment.md#14-concrete-android-blocker-register)).
- **DovahLink facts that shape P10** (not a verdict): pairing today is a Host-generated six-digit code that issues a bearer credential; no Host or Client long-term key exists in DovahLink code; reconnect uses that bearer credential; the public transport is loopback-only; DovahLink has selected, but not implemented, "evidence → pending approval for the exact attempt → Pair / Reject / Block → trust" ([consumer boundary §12](consumer-boundary.md#12-dovahlink-current-state-evidence)).
- **No STOP condition hit** ([portability §17](portability-assessment.md#17-stop-conditions-review)).

## P10.2 results

- **Authentication verdict: 🔴 DOES NOT PROVIDE ADEQUATE AUTHENTICATION — REPLACEMENT REQUIRED** for durable trust and normal reconnect ([audit §16](authentication-audit.md#16-verdict), [P10-D-003](decisions.md#p10-d-003--dovahlink-authentication-disposition-and-pop-boundary)). Trusted reconnect presents a reusable 128-bit bearer credential (SHA-256 verifier on the Host): no challenge, no signature, no session binding, replayable, clonable; nothing authenticates the Host, and the client sends the bearer in `hello` before it sees the Host's unsigned `hostId` claim. No Host or Client long-term key exists (DESIGN EXISTS — IMPLEMENTATION DOES NOT). The six-digit ceremony's replacement is not counted. DovahLink's administrative controls (typed states, session invalidation, fence generation and incarnation, conditional writes, fail-closed DPAPI persistence) are sound and kept.
- **Replacement scope (owner-approved 2026-10-05):** Host key in P10.3, Client key in P10.4, a new transport increment **P10.5A** (WSS / TLS 1.3 with the Host key), Host verification, Client pairing PoP, and key-bound trust in P10.6, fresh-challenge reconnect PoP and the atomic bearer cutover in P10.7; DovahLink slices S3–S7, S9, S10 open as pre-alpha P10 work under DovahLink's own workflow, its production gate closed.
- **Canonical Bootstrap v1 ([P10-D-002](decisions.md#p10-d-002--canonical-dovahlink-bootstrap-v1-mapping), [mapping](bootstrap-mapping.md)):** `applicationIdentity` = `dovahlink.application-identity.v1` ‖ role byte ‖ RFC 9562 UUID bytes (50 bytes); `keyAlgorithm` = `dovahlink.ecdsa-p256.spki-der.v1` for both roles (owner chose P-256 for the Host); `publicKey` = the exact 91-byte P-256 SPKI (the Host's TLS key, the Client's PoP key); `sharedContext` = the independently compiled constant `dovahlink.sas-pairing.bootstrap-v1.pairing`; no per-attempt nonce (`ceremony_identity` is the attempt identity). Client = Initiator, Host = Responder.
- **E-13: exact expected-frame comparison** of the whole authenticated peer frame; no decoder, no wrapper change, no ABI change. E-05, E-06, E-07, E-13 resolved; P10-OD-04, -05, -06 (model), -10, -13 resolved, -14 scope bytes decided (E-11 in P10.3), P10-OD-16 added.
- **ABI-v1 verdict: ABI-V1-P10-B, unchanged** ([portability §9](portability-assessment.md#p102-re-evaluation)): E-02, E-03, E-04 remain unproven; no ABI information gap was found.
- **Vectors:** 15 DovahLink consumer mapping vector groups with a stdlib verifier that first reproduces the frozen core-generated P3 Bootstrap frames; all 14 required mutations (A–N) were killed.
- **No STOP condition hit**; no production change in `sas-pairing` or DovahLink.

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

### P10.1.1 evidence

P10.1.1 (baseline reconciliation and evidence closure) corrects the P10.1 DovahLink baseline and the wording of two experiments. It changes no P10.1 conclusion, no decision, and no production code.

**Live DovahLink `main`.** Fetched directly from `https://github.com/Soneka96/DovahLink.git` (a fresh clone, outside both repositories): `main` = `9f4e925cc8dcba0db37d1bd7d38b39f0927b9387`, the merge of DovahLink pull request #118 ("Feature/world context foundation", 2026-10-05), whose first parent is the P10.1 baseline `4a69ee5057029878200b6e16614f67a136e3e032`.

**Delta `4a69ee5..9f4e925`.** Five commits (`2d3aa08` adapter log-noise reduction, `24bd640` world-context research notes, `3119b13` removal of temporary diagnostics, `73b334b` `player_location` state slice, `efbf632` location and game-time snapshots) and 64 changed files. They add two Snapshot state areas (`player_location`, `game_time`): Adapter capture code (`adapter/capture/`, `adapter/runtime/` character-capture and capture-router), two Host `ILiveCaptureHandler` classes (`GameTimeCaptureHandler.cs`, `PlayerLocationCaptureHandler.cs` under `host/DovahLink.Host/Adapter/Ipc/`), Host state records, catalog tokens 6 and 7 and DI registrations, SDK state modules and `DovahLinkCurrentHost` streams, protocol fixtures and the schema README rows, a world-context research deviation note, and rate-limited Adapter warnings with routine logs lowered to debug. Every changed file was inspected by name and the full diff searched for pairing, authentication, trust, credential, identity, transport, and key terms.

**Pairing / authentication impact: none.** No file changed under `host/DovahLink.Host/{Pairing,Trust,Identity,Client}/`, `adapter/ipc/`, `sdk/dart/dovahlink_client/lib/src/{dovahlink_pairing.dart,persistence/,internal/session/}`, `lib/dovahlink_client_windows.dart`, `app/`, `Program.cs`, `ARCHITECTURE.md`, `AGENTS.md`, `ROADMAP.md`, `ai/context/` (including `security/identity-and-transport.md` and `protocol/security.md`), `roadmap/deviations/{initial-pairing-security/,current-execution-flow.md}`, or `roadmap/05a-android-wifi-development-path.md`, which is every DovahLink source P10.1 cited. The two new `Adapter/Ipc/` files are live-state capture handlers, not IPC message types, so the "no pairing decision message" fact holds. The repository-wide search for asymmetric key, X.509, `SslStream`, ECDSA, or SPKI use under `host/`, `sdk/`, and `app/lib` is still empty at `9f4e925`. Pairing, `clientId` / `hostId`, KnownHost / KnownDevice, credentials, reconnect, revoke / block, Pair / Reject / Block, security-gate documentation, pairing UI, transport security, and long-term keys are unchanged. The current-state table ([consumer boundary §12](consumer-boundary.md#12-dovahlink-current-state-evidence)) and its links are re-pinned to `9f4e925`; the P10.1 evidence above stays as read at `4a69ee5`.

**ABI-v1 verdict: ABI-V1-P10-B, unchanged.** It is not promoted to A, because E-02 (client relay), E-13 (peer Bootstrap decode or exact compare), E-03, and E-04 remain unproven. It is not demoted to C, because no concrete P10 Windows requirement has been shown to be inexpressible through ABI v1.

**Experiment wording.** Statements about the client loopback relay and consumer-side peer-Bootstrap access now describe a plausible public-API adapter path that requires E-02 or E-13 and is unproven until that experiment passes, in this README, [P10-OD-09 and P10-OD-13](decisions.md#pending-owner-decisions), [portability §4, §9, and §17](portability-assessment.md#9-abi-v1-p10-assessment), and the P10.4 scope in the [roadmap](../../roadmap/P10-consumer-integration.md). No ABI change, ABI-v2 proposal, or relay implementation is made.

**P10-D-001 revalidated, unchanged:** Windows-only P10 implementation with a platform-neutral consumer and domain boundary; PN / WE / AB classification; `PairingResult` as local completion only; `CeremonyIdentity` binding to the exact attempt; proof of possession, Pair / Reject / Block, and durable trust owned by DovahLink; normal reconnect separate from SAS; no speculative ABI v2; P10.8 owns the final Android classification.

**Working tree.** The untracked `examples/` directory noted after P10.1 contained only 361 empty directories left by a local .NET consumer restore (no files, never tracked); it was removed, and `git status --short` is empty.

Diff gates against `b938016`: `git diff b938016 -- core`, `-- dart/lib`, and `-- dotnet/src` are empty. DovahLink: no branch, commit, or change; its live `main` was read from a separate scratch clone.

Checks run for P10.1.1:

| Check | Result |
|---|---|
| Required files and public status (the `consistency.yml` script, run locally) | Pass: 45 files present and non-empty; every required README and license phrase present |
| `python tooling/check_markdown_links.py` | Pass: 1,509 internal links in 83 Markdown files, 0 broken |
| `python -m unittest discover -s tooling/tests` | Pass: 111 tests (7 skipped locally because they need the staged CI artifacts; they run in the Windows Dart and .NET jobs) |
| `git diff --check` | Pass |

GitHub Actions on the P10.1.1 head are reported with the increment, because a commit cannot name its own SHA. The change touches only Markdown, so only the repository-consistency and Rust-core workflows trigger (`consistency`, `windows-core`, `unsupported-platform-fails-closed`).

### P10.2 evidence

**Starting state.** `feature/p10-consumer-integration` at `2869089da16655efe26b25ce713ba36161787f96`, `main` `b938016d1de53d3e269fe0840485fbd3dc715fd7`, 3 ahead and 0 behind, no P10 pull request (the public GitHub API lists none for the branch). P10.1 accepted.

**Live DovahLink.** A fresh clone of `https://github.com/Soneka96/DovahLink.git`, outside both repositories, gave `main` = `9f4e925cc8dcba0db37d1bd7d38b39f0927b9387`, the P10.1.1 baseline, so no reconciliation was needed. Nothing was branched, committed, or changed in DovahLink. Sources reviewed: [authentication audit §3](authentication-audit.md#3-sources-reviewed).

**Owner decisions (2026-10-05, taken during P10.2):** ECDSA P-256 for the Host key as well as the Client key (P10-OD-05); the authentication replacement accepted into P10, with authenticated transport as a separate increment (P10.5A); the binary RFC 9562 UUID form of `applicationIdentity` (P10-OD-04).

**Cross-language evidence.** A scratch .NET 10 program (SDK 10.0.401, not committed) imported and re-exported the SPKI of each of the three test keys byte for byte, verified a signature made with each published test scalar, and printed `Guid.ToByteArray()` versus `TryWriteBytes(bigEndian: true)` for both vector UUIDs; vector V04 records the output.

**Vector verifier.** `tooling/tests/test_p10_dovahlink_bootstrap_mapping.py`: 35 tests, green. Its Bootstrap frame encoder first reproduces the core-generated Initiator and Responder frames of `vectors/p3-remote-vodozemac-draft-01.json`.

**Mutations.** Each was applied in place, run against the verifier, and restored (the baseline was green before and after):

| Mutation | Result | Failing tests |
|---|---|---|
| A — `.NET Guid.ToByteArray()` bytes in `applicationIdentity` | Killed | host / client vectors, byte-order trap, role separation, E-13 comparison, binary-form guard |
| B — role byte removed | Killed | same six |
| C — JSON serialization of `applicationIdentity` | Killed | same six plus the one-binary-form test |
| D — SHA-256 fingerprint in place of the SPKI | Killed | `test_every_bootstrap_public_key_is_the_full_canonical_spki`, host vector |
| E — bearer-shaped credential in a Bootstrap field | Killed | `test_bootstrap_fields_carry_no_secret_material`, client vector |
| F — peer-copied `sharedContext` | Killed | `test_a_received_peer_value_never_becomes_the_local_context` |
| G — `request_id` as pending-authorization key | Killed | `test_request_id_is_never_the_authorization_key`, stale-approval test |
| H — local result → `Paired` transition | Killed | `test_local_result_never_becomes_trust_directly` |
| I — bearer labelled as proof of possession | Killed | `test_bearer_material_is_never_proof_of_possession` |
| J — target ECDSA PoP marked implemented | Killed | `test_target_design_is_not_current_implementation` |
| K — endpoint in the durable KnownDevice identity | Killed | `test_durable_identity_never_includes_an_endpoint` |
| L — Bootstrap accepted on `applicationIdentity` only | Killed | `test_every_one_field_change_is_rejected`, `test_one_byte_anywhere_in_the_frame_is_rejected` |
| M — pending authorization keyed by `clientId` | Killed | `test_a_stale_approval_cannot_authorize_a_replacement_ceremony`, request-ID test |
| N — SAS inserted into normal reconnect | Killed | `test_initial_pairing_and_normal_reconnect_are_separate` |

**Diff gates** against `b938016`: `git diff b938016 -- core`, `-- dart/lib`, and `-- dotnet/src` are empty; the header and the ABI v1 manifest are unchanged. P10.2 adds no export, result field, wrapper decoder, or ABI version.

Checks run for P10.2:

| Check | Result |
|---|---|
| Required files and public status (the `consistency.yml` script, run locally; the two new documents and the vector file added to its required list) | Pass: 48 files present and non-empty; every required README and license phrase present |
| `python tooling/check_markdown_links.py` | Pass: 1,599 internal links in 85 Markdown files, 0 broken |
| `python -m unittest discover -s tooling/tests` | Pass: 146 tests (7 skipped locally because they need the staged CI artifacts) |
| `git diff --check` | Pass |
| GitHub Actions on the analysis head `25ee176` (the change to `tooling/tests/**` triggers every workflow) | Green in all seven jobs: `consistency`, `windows-core`, `unsupported-platform-fails-closed`, `dart-package (windows-latest)`, `dart-package (ubuntu-latest)`, `dotnet-package (windows-latest)`, `dotnet-package (ubuntu-latest)` |

Commits: `2f16681` (`docs: audit dovahlink authentication and map bootstrap`), `25ee176` (`test: freeze dovahlink bootstrap mapping vectors`). GitHub Actions on this evidence commit are reported with the increment, because a commit cannot name its own SHA.
