# P8 Final Closure — Dart Package + Windows x64 Native Distribution

> **Pre-alpha. Not production approval.** P8 wraps the frozen native ABI v1 in an experimental Dart package and distributes the Windows x64 native library as an experimental CI artifact. Closing P8 closes the Dart wrapper phase. It is not production deployment approval, a professional or independent security audit, formal verification, certification, a stable or signed release, or a pub.dev publication.

**P8 COMPLETE — DART PACKAGE + WINDOWS X64 NATIVE DISTRIBUTION.** This is the authoritative P8 closure summary. Details live in the [P8 package](README.md) (contracts and per-increment evidence), the [decisions](decisions.md) (P8-D-001 to P8-D-006), the [package README](../../dart/README.md) (consumer documentation), and the frozen [native ABI v1 manifest](../p7-native-abi/abi-v1-manifest.md), which P8 consumes and does not change.

## 1. Phase status

| Item | Value |
|---|---|
| Phase | [P8 — Dart Package](../../roadmap/P8-dart-package.md): **COMPLETE** (P8.1–P8.6, including the P8.2.1 correction) |
| Package | `dart/`: `sas_pairing` 0.1.0-dev.1, pure Dart, `publish_to: none`, one runtime dependency (`ffi`) |
| Native boundary | Native ABI v1, frozen by [P7-D-013](../p7-native-abi/decisions.md#p7-d-013--abi-v1-final-freeze-and-wrapper-handoff); unchanged by P8 |
| Distribution | One experimental Windows x64 CI artifact per exact commit (P8-D-006) |
| Next phase | **P9 — .NET Package** (not started) |

## 2. Baseline

`main` at `80ecbb1931b556f18000de70a37cac8c6b47aaa6` (merge of the P7 pull request #13). P8 started there on 2026-10-03.

## 3. Final branch and head

| Item | Value |
|---|---|
| Branch | `feature/p8-dart-package`, the one long-lived P8 branch; one ready-for-review pull request at closure, not merged by this work |
| P8.6 start | `87240ba` (P8.5 closure; 23 commits ahead of `main`, 0 behind; all five CI jobs green) |
| P8.6 commits | `deaa586` (`docs: define p8 dart artifact distribution contract`), `61c4fe8` (`build: package tested windows x64 dart native artifact`), `363d90a` (`test: verify p8 distribution and final package invariants`) |
| Last code and test head | `363d90a`, all five CI jobs green on that exact head, its distribution artifact uploaded and confirmed (section 18) |
| Final head | The closure commit `docs: close p8 dart package` (documentation, status, and the current-documentation guard test), all five CI jobs green on that exact head with its own exact-SHA artifact, reported in the P8 pull request |

## 4. Increments

| Increment | Scope | Decision | Closure |
|---|---|---|---|
| P8.1 | Package foundation: generated private raw FFI of ABI v1, the process-lifetime loader (explicit path, 64-bit gate, symbol preflight, ABI version 1), consistency tests, Windows and Linux CI | P8-D-001 | `37c986a` |
| P8.2 | Runtime / Authority / Host lifecycle wrapper, status and exception model, explicit consuming `close()`, native-cascade mirroring, FATAL and contract latches | P8-D-002 | `ea3ce92` |
| P8.2.1 | Correction: public `SasPairingInitializationException`; `READY` valid only with 1–10 remaining | P8-D-002 (A, H, K, M) | `c74d607` |
| P8.3 | Windows listener ownership transfer, cooperative bounded drive, event mapping, connections, `RUN_UNTRACKED` guidance | P8-D-003 | `da2d02d` |
| P8.4 | Runs by exact native handle, the explicit trusted-local ceremony steps, SAS presentation and ceremony-identity binding, a real two-endpoint ceremony | P8-D-004 | `4877db4` |
| P8.5 | Runtime-owned `SasPairingResult`, explicit snapshot reads, result data after native FATAL, explicit and cascade destruction | P8-D-005 | `87240ba` |
| P8.6 | Windows x64 native artifact distribution, integrity and provenance metadata, licenses and dependency inventory, documentation cleanup, P8-wide freeze audit, final closure | P8-D-006 | this closure |

## 5. Decisions

| Decision | Subject |
|---|---|
| [P8-D-001](decisions.md#p8-d-001--dart-native-binding-and-loader-architecture) | Pure-Dart package; generated private bindings of exactly ABI v1; one process-lifetime image from an explicit absolute path; no unload, reload, or reset; one owner isolate |
| [P8-D-002](decisions.md#p8-d-002--dart-lifecycle-ownership-and-fail-closed-state) | Lifecycle objects, explicit consuming close mirroring the native cascade, FATAL and contract latches, public initialization errors (P8.2.1) |
| [P8-D-003](decisions.md#p8-d-003--dart-windows-listener-cooperative-drive-and-connection-lifetime) | Listener transfer token, one bounded drive per call, every event delivered also with `out_failure`, connection lifetime, `RUN_UNTRACKED` close guidance |
| [P8-D-004](decisions.md#p8-d-004--dart-run-identity-explicit-ceremony-control-and-sas-binding) | Run identity by exact handle, one native call per ceremony step, `WRITE_PENDING` status versus flag, SAS presentation as display data, decisions bound to the presented identity |
| [P8-D-005](decisions.md#p8-d-005--dart-pairingresult-ownership-data-access-and-local-completion) | Runtime-owned results, delivery without reading, explicit snapshot reads, data access after FATAL but not after a contract violation, local completion only |
| [P8-D-006](decisions.md#p8-d-006--dart-native-artifact-distribution-and-p8-final-closure) | One experimental Windows x64 CI artifact per exact commit, tested as the distributed copy; integrity metadata, not a signature; licenses and inventory; no release, tag, or publication; loader unchanged; P8 closure |

## 6. Final public Dart surface

`package:sas_pairing/sas_pairing.dart` exports, by explicit `show` lists and nothing else:

- **Lifecycle and errors:** `SasPairingRuntime`, `SasPairingAuthority`, `SasPairingHost`, `SasPairingAuthorityState`, `SasPairingAuthorityStatus`, `SasPairingStatus` (48 frozen values), `SasPairingInitializationException`, `SasPairingInitializationFailure`, `SasPairingNativeException`, `SasPairingClosedException`, `SasPairingContractException`, `SasPairingRunEndedException`.
- **Network:** `SasPairingBootstrap`, `SasPairingWindowsListenerSocket`, `SasPairingHostNetworkState`, `SasPairingConnection`, `SasPairingDriveBatch`, `SasPairingDriveFailure`, `SasPairingEvent`, `SasPairingEventKind`, `SasPairingStepKind`, `SasPairingProtocolEvent`, `SasPairingEventReason`, `SasPairingDeadlineKind`, `SasPairingCancelState`, `SasPairingCancelReason`.
- **Ceremony:** `SasPairingRun`, `SasPairingLocalAction`, `SasPairingLocalEvent`, `SasPairingSasPresentation`, `SasPairingCeremonyIdentity`.
- **Results:** `SasPairingResult`, `SasPairingResultData`, `SasPairingPeerRole`.

No raw handle, socket getter, `Pointer`, `DynamicLibrary`, generated record or binding, loader, protocol frame, cryptographic primitive, result field number, final-ACK control, or trust API is public (`public_api_test.dart`, `package_scope_test.dart`). P8.6 changed no file under `dart/lib/` (`git diff 87240ba -- dart/lib` is empty).

## 7. Loader and one-image model

`SasPairingRuntime.create(nativeLibraryPath: ...)` is the only loading entry. The loader requires an 8-byte pointer width, an absolute path to an existing file (canonicalized), makes exactly one `DynamicLibrary.open`, preflights all 25 exports, and requires `sas_pairing_abi_version() == 1`. Pre-load failures may be retried; post-load failures are permanent for the process. Once ready, every later initialization returns the identical library without reading its path. Nothing is searched, discovered, or downloaded (`distribution_scope_test.dart`), the library is never closed, unloaded, reloaded, or replaced, and recovery from `SAS_PAIRING_FATAL` is an OS process restart. One Dart owner isolate holds all native access; cross-isolate enforcement is not claimed.

## 8. Lifecycle ownership

```text
SasPairingRuntime ── runtime_destroy cascades everything below, results included
  ├── SasPairingAuthority ── authority_release cascades its hosts
  │     └── SasPairingHost ── host_destroy ends its network, connections, and runs
  │           ├── listener + owner loop (network state)
  │           └── SasPairingConnection ── SasPairingRun (exact native run handles)
  └── SasPairingResult (runtime-owned; survives every networking parent and FATAL)
```

Each `close()` is consuming and idempotent: exactly one native cleanup call, then the local cascade, whatever the call returned. Dart mirrors the native cascade and never issues a child cleanup call itself (host, authority, runtime, and result cascades are call-counted in tests). There is no `Finalizer` or `NativeFinalizer`.

## 9. Network model

Windows only. The application binds a WinSock listening socket and hands it over once through `SasPairingWindowsListenerSocket` (transferred exactly when the native slot reads `SAS_PAIRING_SOCKET_INVALID`). `drive()` and `recheckAfterResume()` make one bounded native call each (capacity 17): there is no loop, timer, stream, isolate, callback, or background driver. Every event is delivered in native order, also when the owner loop failed (`batch.failure`); `RUN_UNTRACKED` sets `shouldCloseConnection`, and the application closes the connection after consuming the batch.

## 10. Run, ceremony, and SAS model

A run is one exact native run handle, never a request ID. Each ceremony method is exactly one native call that chains, drives, and retries nothing: authorization ≠ exposure, MATCH ≠ BOOTSTRAP_MAC, BOOTSTRAP_MAC ≠ INITIATOR_FINISH, and no final-ACK API exists (the native adapter confirms it). Status `writePending` means the action did not run; the action flag `writePending` means it ran and its frame waits for a drive. The SAS presentation is display data; the application compares and decides, and `approveSas`, `rejectSas`, and `cancelSas` take only the presented `SasPairingCeremonyIdentity`. Statuses are outcomes, never trust verdicts.

## 11. Result model

A `SasPairingResult` is one runtime-owned local verified completion of this endpoint, delivered by a drive event without being read. It survives run endings, connection close, detach, owner-loop failure, host and authority close, and native FATAL; `read()` (one info and four exact-length copies) stays allowed after native FATAL and is refused after a Dart-observed contract violation; `close()` is always allowed. It never means bilateral success, peer completion, or persisted trust, and the package trusts, persists, and enrolls nothing.

## 12. Native artifact distribution contract

| Item | Contract (P8-D-006) |
|---|---|
| Artifact | `sas_pairing_core.dll`, Windows x64 (`x86_64-pc-windows-msvc`, PE32+ AMD64), ABI v1, exactly 25 exports |
| Channel | GitHub Actions artifact `sas-pairing-dart-windows-x64-abi1-<full commit SHA>` from push runs of the `Dart package` workflow; experimental CI artifact; 90-day retention; download needs a GitHub sign-in |
| Bundle | Exactly `sas_pairing_core.dll`, `ARTIFACT-MANIFEST.json`, `SHA256SUMS.txt`, `README.md`, `LICENSE-MIT`, `LICENSE-APACHE`, `THIRD-PARTY-NOTICES.md`, `sas_pairing.h`, `abi-v1-manifest.md` |
| Manifest | `schema_version` 1, `bundle_name`, `git_commit`, `dart_package_version`, `core_crate_version`, `abi_version` 1, `export_count` 25, `platform` `windows`, `architecture` `x86_64`, `rust_target`, `library_file`, `library_sha256`, `security_status` `experimental-pre-alpha`, `code_signed` `false` |
| Integrity | SHA-256 of the eight other files; the DLL line equals `library_sha256`; integrity relative to trusted metadata, not a signature, publisher authenticity, or a secure-build proof |
| Signing | **Unsigned.** No signing step exists |
| Tested copy | Staged right after the build; every Windows Dart test (full suite, ABI smoke, real lifecycle, real network, real ceremony + results) loads the staged DLL by absolute path; re-verified (byte identity with the build output) before upload |
| Not created | No Git tag, GitHub Release, or pub.dev publication, and no automation for them (`test_p8_distribution_contract.py`) |
| Consumer discipline | Dart source and artifact from the same exact commit; verify checksums; extract once; absolute path; keep resident; never replace or reload |

## 13. Windows x64 support scope

The Windows x64 artifact is the only P8 pairing artifact. On Windows the lifecycle, listener transfer, cooperative drive, events, connections, runs, the explicit ceremony steps, SAS presentation, and results work against the real DLL, and a complete two-endpoint ceremony through the public Dart API is proven against the staged distribution copy.

## 14. Unsupported-platform scope

Linux x64 builds the same ABI v1 library; Dart loads it, binds all 25 symbols, reads ABI version 1, creates a runtime, and sees authority registration fail closed with `unsupportedPlatform`; the network, ceremony, and result wrappers are tested there against the deterministic fake. That is compilation, binding, and fail-closed evidence, **not** Linux pairing support, and the `.so` is never distributed. No Windows ARM64, Windows x86, macOS, Android, or iOS support is claimed. 32-bit processes are refused before any library is opened.

## 15. Security invariants

- The native Rust core is the only protocol and cryptography implementation: no SAS, MAC, hash, key agreement, request ID, ceremony identity, frame, transcript, final ACK, deadline, or attempt accounting in Dart (scope-tested).
- Dart keeps no opportunity budget, START limiter, exposure guard, authoritative write-pending state, protocol state machine, or retry or refund accounting; `queryStatus()` is the only budget view.
- No automatic approval, action chaining, final-ACK confirmation, trust persistence, enrollment, or trust verdict.
- No finalizer, background driver, timer, stream, isolate, or callback.
- Exactly one native image per process, explicit absolute path, no discovery or download, FATAL → process restart.

## 16. P7 wrapper-handoff closure

All eleven obligations of [ABI contract §21](../p7-native-abi/abi-contract.md#21-wrapper-handoff-p8-p9) are **COMPLETE** ([P8 package handoff table](README.md#p7-wrapper-handoff)):

| # | Obligation | State |
|---:|---|---|
| 1 | Bind exactly ABI v1 (`sas_pairing_abi_version() == 1`) | **Complete** (P8.1) |
| 2 | One resident native image; no unload, reload, reset, or copy | **Complete** (P8.1; preserved by P8.6) |
| 3 | `SAS_PAIRING_FATAL` requires an OS process restart | **Complete** (P8.2) |
| 4 | Caller-memory contract | **Complete** (P8.2–P8.5) |
| 5 | Listener handoff through the in/out slot | **Complete** (P8.3) |
| 6 | Cooperative bounded drive; every event consumed, also with `out_failure` | **Complete** (P8.3) |
| 7 | SHOULD close a connection after `RUN_UNTRACKED` | **Complete** (P8.3) |
| 8 | Explicit ceremony steps, `WRITE_PENDING`, exact `ceremony_identity` binding | **Complete** (P8.4) |
| 9 | No frames in Dart; no final-ACK confirmation | **Complete** (P8.1, P8.4) |
| 10 | A result is local completion only | **Complete** (P8.5) |
| 11 | Comparison UX and trust policy stay with the application; no status is a trust verdict | **Complete** (P8.2, P8.4) |

## 17. Real two-endpoint evidence

One child process over the real DLL (in CI, the **staged distribution copy**) runs two authorities, two hosts, and two loopback listeners joined by a test-only byte-transparent relay, driven only through the public Dart API: explicit Initiator start, authorization, exposure (each authority `busy` 0, then `ready` 9 afterwards), equal SAS presentations and 32-byte identities, explicit MATCH, BOOTSTRAP_MAC, and INITIATOR_FINISH (a Responder finish refused with `notInitiator`), one local result per endpoint, then both results read after every connection, listener, host, and authority is gone: identity equal to the presentation, opposite peer roles, equal 16-byte request IDs, profile `sas-pairing-vodozemac-profile-draft-01` version 1, the fixture shared context, and 136-byte peer Bootstraps; result A destroyed explicitly and result B by the runtime.

## 18. Test and CI evidence

| Item | Result |
|---|---|
| Dart tests | 557 (Windows with the real staged DLL: 556 passed, 1 Linux-only skipped): the 549 of P8.5 unchanged plus 8 distribution-scope tests; `dart format` clean; `dart analyze --fatal-infos` clean |
| Tooling tests | `python3 -m unittest discover -s tooling/tests`: the packaging tool (synthetic PE images and, in the Windows Dart job, the real staged DLL), the workflow, package, and current-documentation guards |
| Staged-artifact tests (Windows CI and locally) | ABI smoke (25 symbols, version 1), real lifecycle, real network (3 scenarios), real two-endpoint ceremony + results, and the full suite, all against `dist/sas-pairing-dart-windows-x64-abi1/sas_pairing_core.dll` |
| Packaging evidence on `363d90a` | Staged and verified (PE AMD64, 25 exports, byte identity), tested, re-verified, uploaded; see the [P8.6 evidence](README.md#p86-evidence) for the artifact ID, size, and digest |
| CI jobs | `dart-package (windows-latest)`, `dart-package (ubuntu-latest)`, `windows-core`, `unsupported-platform-fails-closed`, `consistency`: green on `363d90a` and required green on the final head |
| Mutations | P8.6 mutations A–L, each killed by its guard ([P8.6 evidence](README.md#p86-evidence)); the earlier increments' mutations are recorded in their evidence sections |

## 19. Native-diff and ABI-freeze evidence

`git diff 80ecbb1931b556f18000de70a37cac8c6b47aaa6 -- core` and `git diff 87240ba -- core` are empty: P8 changed no native file. The generated bindings regenerate from `core/include/sas_pairing.h` with the pinned `ffigen` 22.0.0 with zero diff (CI on Windows and Linux). `abi::tests::freeze` (3 passed): ABI version 1, 25 exports, 48 statuses, the frozen record sizes and alignments, and the frozen integer namespaces are unchanged; the export audit of both the build DLL and the staged DLL lists exactly the 25 manifest exports.

## 20. Accepted limitations

- Windows x64 only; a CI artifact, not a stable release; unsigned; no pub.dev publication; finite (90-day) artifact retention, download behind a GitHub sign-in; the build is not claimed reproducible.
- An explicit absolute DLL path is required; the application creates and binds the WinSock listener and schedules every drive; there is no automatic network driver.
- Exactly one native image per process; `SAS_PAIRING_FATAL` requires a process restart; one Dart owner isolate, not enforced across isolates; no protection against hostile in-process code.
- A result is local completion only; there is no automatic trust persistence.
- No production-security approval, professional audit, or formal verification; the protocol argument stays conditional, as recorded by P5–P7.

## 21. Next phase

**P9 — .NET Package** is next, under the same [ABI contract §21](../p7-native-abi/abi-contract.md#21-wrapper-handoff-p8-p9) handoff. It has not started; P8 created no P9 branch or code.
