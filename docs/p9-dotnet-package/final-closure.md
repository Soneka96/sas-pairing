# P9 Final Closure — .NET Package + Windows x64 Native Distribution

> **Pre-alpha. Not production approval.** P9 wraps the frozen native ABI v1 in an experimental .NET package and distributes it, with the Windows x64 native library as a separate artifact, as experimental CI artifacts. Closing P9 closes the .NET wrapper phase. It is not production deployment approval, a professional or independent security audit, formal verification, certification, a stable or signed release, public-release or 1.0 readiness, or a nuget.org publication.

**P9 COMPLETE — .NET PACKAGE + WINDOWS X64 NATIVE DISTRIBUTION.** This is the authoritative P9 closure summary. Details live in the [P9 package](README.md) (contracts and per-increment evidence), the [decisions](decisions.md) (P9-D-001 to P9-D-006), the [package README](../../dotnet/README.md) (consumer documentation) and [changelog](../../dotnet/CHANGELOG.md), and the frozen [native ABI v1 manifest](../p7-native-abi/abi-v1-manifest.md), which P9 consumes and does not change.

## 1. Phase status

| Item | Value |
|---|---|
| Phase | [P9 — .NET Package](../../roadmap/P9-dotnet-package.md): **COMPLETE** (P9.1–P9.6) |
| Package | `dotnet/`: `SasPairing` 0.1.0-dev.1 (package ID, assembly, and namespace), `net10.0` only, no runtime package dependency, packable, not published |
| Native boundary | Native ABI v1, frozen by [P7-D-013](../p7-native-abi/decisions.md#p7-d-013--abi-v1-final-freeze-and-wrapper-handoff); unchanged by P9 |
| Distribution | Two experimental CI artifacts per exact commit: the managed NuGet-format package and the separate Windows x64 native bundle (P9-D-006) |
| Pull request | The ONE final P9 pull request is opened by the owner after independent review; none was opened by the P9 work, and nothing is merged by it |
| Next phase | **P10 — Consumer Integration / DovahLink Example** (not started) |

## 2. Baseline

`main` at `03afc8dd6ef8c473ef648ec7e06cee5042d0083a` (merge of the P8 pull request #14). P9 started there on 2026-10-04.

## 3. Final branch and head

| Item | Value |
|---|---|
| Branch | `feature/p9-dotnet-package`, the one long-lived P9 branch; 0 commits behind `main`; unmerged |
| P9.6 start | `24cb89d3ecbfe00616118b5ae996c38dd849ec55` (P9.5 closure; 20 commits ahead of `main`, 0 behind; its exact-head CI green, the `windows-core` job on its second attempt) |
| P9.6 commits | `cbb141b` (`docs: define p9 dotnet distribution contract`), `79f96e6` (`build: package dotnet and windows native artifacts`), `c290c32` (`test: verify p9 distribution and package invariants`) |
| Implementation and distribution head | `c290c321d0e19a5fb876a068eea139e8b9c088da`, every triggered workflow green on that exact head, both of its exact-SHA artifacts uploaded and confirmed ([P9.6 evidence](README.md#p96-evidence)) |
| Final head | The closure commit `docs: close p9 dotnet package` (documentation, status, and the current-documentation guards). Its own `.NET package` run builds, tests, packs, verifies, and uploads both final artifacts (the P9 documentation is in the workflow's path filters); its SHA, jobs, and artifact IDs are reported with the final P9 pull request |

## 4. Increments

| Increment | Scope | Decision | Closure |
|---|---|---|---|
| P9.1 | .NET package foundation: solution, `SasPairing` and `SasPairing.Tests` (`net10.0`), private exact ABI v1 constants, records, and 25-export function table, the explicit-path process-lifetime loader, consistency and scope guards, Windows and Linux CI | P9-D-001 | `352807a` |
| P9.2 | Runtime / Authority / Host lifecycle wrapper, public errors (48 statuses), FATAL and contract latches, binary authority scope | P9-D-002 | `88a5612` |
| P9.3 | Windows listener handoff (P9-D-003 W/X), cooperative bounded drive and recheck, events, connections, `RUN_UNTRACKED` guidance | P9-D-003 | `05be3a0` |
| P9.4 | Runs by exact native handle, the explicit trusted-local ceremony steps, SAS presentation (`DecimalDisplay`) and ceremony-identity binding, a real two-endpoint ceremony | P9-D-004 | `340d4f8` |
| P9.5 | Runtime-owned `SasPairingResult`, coherent snapshot reads, data access after FATAL but not after a contract violation, explicit and cascade destruction | P9-D-005 | `24cb89d` |
| P9.6 | Managed NuGet-format package and separate Windows x64 native artifact, integrity and license metadata, Release assembly identity, staged-DLL testing, local-feed consumer smoke, documentation cleanup, P9-wide freeze audit, final closure | P9-D-006 | this closure |

## 5. Decisions

| Decision | Subject |
|---|---|
| [P9-D-001](decisions.md#p9-d-001--net-abi-v1-binding-and-loader-architecture) | One `net10.0` library; private exact ABI v1 interop (exact C names, `delegate* unmanaged[Cdecl]` table); one process-lifetime image from an explicit absolute path; never `NativeLibrary.Free`; no default resolution |
| [P9-D-002](decisions.md#p9-d-002--net-lifecycle-ownership-public-errors-and-fail-closed-state) | `IDisposable` runtime, authority, and host mirroring the native cascade with one cleanup call each; public statuses and exceptions; process-wide FATAL and contract-violation latches; restart-only recovery |
| [P9-D-003](decisions.md#p9-d-003--net-windows-listener-cooperative-drive-event-and-connection-ownership) | The listener token over a package-owned `DuplicateAndClose` descriptor (W/X), the in/out slot deciding ownership, one bounded drive and recheck, every event before `out_failure`, connections, `RUN_UNTRACKED` guidance |
| [P9-D-004](decisions.md#p9-d-004--net-run-identity-explicit-ceremony-control-and-sas-binding) | One run object per exact native run, nine explicit trusted-local steps with no chaining, status 205 versus the `WritePending` flag, read-only SAS presentation (`DecimalDisplay`), decisions bound to the exact 32-byte identity, no final-ACK API |
| [P9-D-005](decisions.md#p9-d-005--net-pairingresult-ownership-reads-and-immutable-snapshots) | Runtime-owned results, one consuming destroy, no child destroy in the runtime cascade, one coherent read at source-proven lengths, immutable detached snapshots, local completion only |
| [P9-D-006](decisions.md#p9-d-006--net-managed-package-native-artifact-distribution-and-p9-closure) | Two separate exact-commit CI artifacts (managed package without native library; Windows x64 native bundle), Release assembly identity, staged DLL tested, integrity not signature, licenses and inventory, no nuget.org, release, or tag, loader unchanged, P9 closure |

## 6. .NET package metadata

| Item | Value |
|---|---|
| Package ID / assembly / namespace | `SasPairing` |
| Version | `0.1.0-dev.1` (`VersionPrefix` 0.1.0, `VersionSuffix` dev.1); P9 closure is not a stable release |
| Target framework | `net10.0` only (no multi-targeting, `netstandard`, or Windows-specific TFM); SDK 10.0.401 pinned by `dotnet/global.json` |
| Packable | Yes (`dotnet pack`); `SasPairing.Tests` and `SasPairing.PackageSmoke` are not packable |
| License | `MIT OR Apache-2.0` (license expression) |
| README | `dotnet/README.md`, packed as `README.md` |
| Repository | `https://github.com/Soneka96/sas-pairing` (`git`), with the exact CI commit as `RepositoryCommit` |
| Dependencies | None (one empty `net10.0` dependency group) |
| Publication | None: not on nuget.org, GitHub Packages, or any feed |

## 7. Final public .NET API

Namespace `SasPairing`, exactly 33 public types (reflection allowlist of every member; unchanged by P9.6):

- **Lifecycle and errors:** `SasPairingRuntime` (`static Create(string nativeLibraryPath)`, `RegisterAuthority`, `IsDisposed`, `Dispose`), `SasPairingAuthority`, `SasPairingHost`, `SasPairingAuthorityState`, `SasPairingAuthorityStatus`, `SasPairingStatus` (48 frozen values), `SasPairingInitializationException`, `SasPairingInitializationFailure`, `SasPairingNativeException`, `SasPairingContractException`.
- **Network:** `SasPairingBootstrap`, `SasPairingWindowsListenerSocket`, `SasPairingHostNetworkState`, `SasPairingConnection`, `SasPairingDriveBatch`, `SasPairingDriveFailure`, `SasPairingEvent`, `SasPairingEventKind`, `SasPairingStepKind`, `SasPairingProtocolEvent`, `SasPairingEventReason`, `SasPairingDeadlineKind`, `SasPairingCancelState`, `SasPairingCancelReason`.
- **Ceremony:** `SasPairingRun`, `SasPairingLocalAction`, `SasPairingLocalEvent`, `SasPairingSasPresentation` (`CeremonyIdentity`, `DecimalDisplay`), `SasPairingCeremonyIdentity`, `SasPairingRunEndedException`.
- **Results:** `SasPairingResult`, `SasPairingResultData`, `SasPairingPeerRole`.

No raw native handle, `nint`/`nuint`/`ulong` handle, pointer, function pointer, `SafeSocketHandle`, `NativeAbiV1`, ABI record, `NativeRunRef`, `NativeResultRef`, result field selector, raw SAS byte, final-ACK control, trust verdict, or loader is public (`PublicSurfaceTests`, `ArchitectureTests`, `DistributionScopeTests`).

## 8. Loader model

`SasPairingRuntime.Create(nativeLibraryPath)` is the only loading entry. The loader requires a 64-bit process and a fully qualified path to an existing file (canonicalized), makes exactly one `NativeLibrary.Load` of it, preflights all 25 exports by exact name, binds the function table, and requires `sas_pairing_abi_version() == 1`. Pre-load failures may be retried; post-load failures are permanent and keep the image (no alternate image after ready or poison). Once ready, later initializations return the identical binding. Nothing is searched, discovered, resolved from `runtimes/`, or downloaded, the image is never freed (`NativeLibrary.Free` never appears in production code), and recovery from `SAS_PAIRING_FATAL` is an OS process restart. P9.6 added no loading path (`DistributionScopeTests`).

## 9. Lifecycle ownership

```text
SasPairingRuntime ── runtime_destroy cascades everything below, results included (no child destroy)
  ├── SasPairingAuthority ── authority_release cascades its hosts
  │     └── SasPairingHost ── host_destroy ends its listener / network context, connections, and runs
  │           └── SasPairingConnection ── SasPairingRun (exact native run handles; run references)
  └── SasPairingResult (runtime-owned; survives every lower parent and FATAL)
```

Each `Dispose` is consuming and idempotent: exactly one native cleanup call, then the local mirror of the native cascade, whatever the call returned; no child cleanup call is duplicated (host, authority, runtime, and result cascades are call-counted in tests). No wrapper of a stateful native handle has a finalizer or a `SafeHandle`; the only `SafeHandle` use is the frozen P9-D-003 W/X invalidation of the package-owned handoff descriptor.

## 10. Windows socket and network model

The application creates, binds, and listens. `SasPairingWindowsListenerSocket.FromSocket` (Windows only) moves the caller's socket into a package-owned descriptor with `Socket.DuplicateAndClose(Environment.ProcessId)` + `new Socket(SocketInformation)` (P9-D-003 W/X; invalidating the caller's own `SafeSocketHandle` makes .NET 10 `Socket.Dispose` hang), and only that descriptor is offered to native; the in/out slot decides ownership before any status is thrown, and after adoption the descriptor's handle is invalidated without closing it. `Drive()` is one bounded native drive and `RecheckAfterResume()` one recheck: no background driver, task, timer, or loop. Every event of an `OK` call is delivered in native order before a non-zero `out_failure` fails the host closed; `RUN_UNTRACKED` sets `ShouldDisposeConnection` and the package never disposes it itself. Pairing networking is Windows-only.

## 11. Run, ceremony, and SAS model

A run is one exact native run handle (the request ID is routing metadata only). Each ceremony method is exactly one native call that chains, drives, and retries nothing: `AuthorizeExposure` ≠ `ExposeKey` (exposure is the native spending step), MATCH (`ApproveSas`) ≠ BOOTSTRAP_MAC, BOOTSTRAP_MAC ≠ INITIATOR_FINISH, and no final-ACK API exists. Status 205 means the action did not run; the action's `WritePending` flag means it ran and its frame waits for a drive. `SasPairingSasPresentation.DecimalDisplay` (`NNNN NNNN NNNN`) is display data; the application compares and decides, passing the exact presented `SasPairingCeremonyIdentity` to `ApproveSas`, `RejectSas`, or `CancelSas`. No protocol frame or cryptography exists in C#.

## 12. PairingResult model

A `SasPairingResult` is THIS endpoint's local verified completion of one ceremony, delivered once by its drive event and owned by the runtime: it survives connection close, detach, owner-loop failure, host and authority disposal, and FATAL. `Read()` (one info and exactly one copy per field at source-proven lengths) stays allowed after native FATAL and is refused after a contract violation; `Dispose()` (one consuming destroy) is always allowed; the runtime cascade makes no child destroy. Snapshots are immutable, detached, exact bytes. A result never means bilateral success, peer completion, or trust, and the package trusts, persists, and enrolls nothing.

## 13. Managed NuGet distribution contract

| Item | Contract (P9-D-006) |
|---|---|
| Artifact | `sas-pairing-dotnet-nuget-<full commit SHA>` from push runs of the Windows `.NET package` job; 90-day retention; download needs a GitHub sign-in |
| Bundle | Exactly `SasPairing.0.1.0-dev.1.nupkg`, `ARTIFACT-MANIFEST.json`, `SHA256SUMS.txt`, `README.md` (no `.snupkg`) |
| Package | Packed from the tested Release build (`dotnet pack -c Release --no-build`, `RepositoryCommit` = the CI commit): the nuspec, `lib/net10.0/SasPairing.dll`, `lib/net10.0/SasPairing.xml`, `README.md`, and the NuGet metadata parts only |
| No native library | No `sas_pairing_core.dll`, `.so`, native binary, `runtimes/*/native` entry, build or tool hook, test assembly, or dependency (`package_dotnet_nuget.py`, its tests, and the real-package tests) |
| Assembly identity | The packed `SasPairing.dll` is byte-identical to the built Release assembly and to the copy the tests loaded |
| Manifest | `schema_version` 1, `bundle_name`, `git_commit`, `package_id`, `package_version`, `target_framework`, `nupkg_file`, `nupkg_sha256`, `assembly_sha256`, `native_bundle_name`, `security_status` `experimental-pre-alpha`, `published_to_nuget` false, `native_library_bundled` false |
| Consumer proof | `SasPairing.PackageSmoke` restores the package from the staged bundle as its only source (a `PackageReference`, never a `ProjectReference`) and runs the public lifecycle against the staged DLL |

## 14. Native Windows x64 distribution contract

| Item | Contract (P9-D-006) |
|---|---|
| Artifact | `sas-pairing-dotnet-windows-x64-abi1-<full commit SHA>`; 90-day retention |
| Bundle | Exactly `sas_pairing_core.dll`, `ARTIFACT-MANIFEST.json`, `SHA256SUMS.txt`, `README.md`, `LICENSE-MIT`, `LICENSE-APACHE`, `THIRD-PARTY-NOTICES.md`, `sas_pairing.h`, `abi-v1-manifest.md` |
| DLL | `x86_64-pc-windows-msvc`, PE32+ AMD64 DLL, exactly the 25 exports, ABI version 1; a byte-for-byte copy of the build output |
| Manifest | `schema_version` 1, `bundle_name`, `git_commit`, `dotnet_package_version`, `core_crate_version`, `abi_version` 1, `export_count` 25, `platform` `windows`, `architecture` `x86_64`, `rust_target`, `library_file`, `library_sha256`, `security_status` `experimental-pre-alpha`, `code_signed` false |
| Signing | **Unsigned.** No signing step exists; a checksum is integrity metadata, not a signature |
| Tested copy | Staged right after the build; every Windows .NET test (full suite, ABI smoke, real lifecycle, network, ceremony, and result) and the consumer smoke load the staged DLL by absolute path; both bundles are re-verified before upload |
| Licensing | Project licenses copied byte for byte; third-party inventory from `cargo metadata --locked` (no package without license metadata; not legal advice) |

## 15. Same-commit rule

Consumers take the `.nupkg` and the native Windows bundle from the **same exact commit**, verify both checksums, and never mix wrapper and core artifacts of different commits. The runtime ABI checks (25 exports, ABI version exactly 1) remain authoritative; same-commit pairing is the operational discipline of the experimental distribution.

## 16. Supported and unsupported platforms

| Platform | State |
|---|---|
| Windows x64 | The only pairing platform and the only distributed native artifact; lifecycle, listener, drive, ceremony, and results proven through the public API against the staged DLL |
| Linux x64 | CI builds and loads `libsas_pairing_core.so` (ABI 1, 25 exports), creates a runtime, and sees authority registration fail closed with `UnsupportedPlatform`; every fake, FFI, surface, and scope test runs. **Not** pairing support, and no `.so` is distributed |
| Windows ARM64, Windows x86, macOS, iOS, Android | Not supported, not distributed, no claim |
| 32-bit processes | Refused before any library is opened |

The managed package can be referenced on any platform .NET 10 supports; that is not pairing support.

## 17. Security boundaries

- The native Rust core is the only protocol and cryptography implementation: no SAS, MAC, hash, key agreement, frame, transcript, final ACK, deadline, or attempt accounting in C# (source-scanned).
- No authority-accounting duplication: no opportunity budget, START limiter, exposure guard, write-pending state, or refund logic; `GetStatus()` is the only budget view.
- No automatic approval, step chaining, final-ACK confirmation, trust persistence, enrollment, or trust verdict.
- No finalizer for a stateful native handle, no background driver, timer, task, or thread.
- Exactly one native image per process, explicit absolute path, no discovery or download, FATAL → OS process restart.
- Distribution artifacts are unsigned, experimental CI artifacts with integrity metadata only.

## 18. Full real Windows evidence

Against the staged distribution DLL `dist/sas-pairing-dotnet-windows-x64-abi1/sas_pairing_core.dll` (CI and locally): the ABI smoke (25 exports by exact name, ABI version 1; 6 of 6), the public lifecycle (4 of 4), the public network (socket transfer surviving the caller's `Socket` and every finalizer, accept and peer close, manual close, listener replacement, recheck; 5 of 5), the public two-endpoint ceremony (2 of 2), and the public PairingResult reads against the frozen P3 vector fixture (2 of 2), all with nothing skipped; and the local-feed package consumer (`Create`, `RegisterAuthority`, `GetStatus` `Ready 10`, `CreateHost`, deterministic `Dispose`) with the packed assembly.

## 19. Test and CI evidence

| Item | Result |
|---|---|
| .NET tests (Release) | 687, all passing, 0 skipped (682 of P9.5 + 5 `DistributionScopeTests`); `dotnet build -c Release -warnaserror` 0 warnings, 0 errors (`latest-recommended` analyzers as errors, no suppression); `dotnet format --verify-no-changes` clean |
| Tooling tests | `python -m unittest discover -s tooling/tests`: the P8 tool and guards, the two P9 tools on synthetic PE images and packages (every mutation fails verification), the P9 workflow, package, consumer-smoke, and current-documentation guards, and, in the Windows .NET job, the real staged DLL and package |
| Packaging evidence | Both bundles staged and verified (PE AMD64, 25 exports, DLL identity, packed-assembly identity), tested, re-verified, uploaded; the implementation head's artifact IDs, sizes, and digests are in the [P9.6 evidence](README.md#p96-evidence) |
| CI jobs | `dotnet-package (windows-latest)`, `dotnet-package (ubuntu-latest)`, `windows-core`, `unsupported-platform-fails-closed`, `consistency`, `dart-package (windows-latest)`, `dart-package (ubuntu-latest)`: green on the implementation head and required green on the final head |
| Mutations | P9.6 mutations A–R, each killed by its guard ([P9.6 evidence](README.md#p96-evidence)); earlier increments' mutations are in their evidence sections |

## 20. Native-diff and ABI-freeze evidence

`git diff 03afc8dd6ef8c473ef648ec7e06cee5042d0083a -- core` and `git diff 24cb89d -- core` are empty: P9 changed no native file or header. `git diff 03afc8dd6ef8c473ef648ec7e06cee5042d0083a -- dart` is empty: P9 changed no Dart file. `abi::tests::freeze` (3 passed): ABI version 1, 25 exports, 48 statuses, the frozen layouts, namespaces, and scalar constants unchanged; the .NET consistency tests compare every constant, record, export, and signature with the header and the manifest; the export audit of both the build DLL and the staged DLL lists exactly the 25 manifest exports.

## 21. P7 wrapper-handoff closure

All eleven obligations of [ABI contract §21](../p7-native-abi/abi-contract.md#21-wrapper-handoff-p8-p9) are **COMPLETE** for .NET ([P9 package handoff table](README.md#p7-wrapper-handoff)):

| # | Obligation | State |
|---:|---|---|
| 1 | Bind exactly ABI v1 (`sas_pairing_abi_version() == 1`) | **Complete** (P9.1) |
| 2 | One resident native image; never `NativeLibrary.Free`; no unload, reload, reset, or copy | **Complete** (P9.1; preserved by P9.6) |
| 3 | `SAS_PAIRING_FATAL` requires an OS process restart | **Complete** (P9.2) |
| 4 | Caller-memory contract (pointers, buffers, no retained pointer) | **Complete** (P9.2–P9.5) |
| 5 | Listener handoff through the in/out slot | **Complete** (P9.3, W/X) |
| 6 | Cooperative bounded drive; every event consumed, also with `out_failure` | **Complete** (P9.3) |
| 7 | SHOULD close a connection after `RUN_UNTRACKED` | **Complete** (P9.3) |
| 8 | Explicit ceremony steps, `WRITE_PENDING`, exact `ceremony_identity` binding | **Complete** (P9.4) |
| 9 | No frames in C#; no final-ACK confirmation | **Complete** (P9.1, P9.4) |
| 10 | A result is local completion only | **Complete** (P9.5) |
| 11 | Comparison UX and trust policy stay with the application; no status is a trust verdict | **Complete** (P9.2, P9.4) |

## 22. Accepted limitations

- Windows x64 only; CI artifacts, not a stable release; the DLL and the package are unsigned; no nuget.org publication; finite (90-day) retention, download behind a GitHub sign-in; builds not claimed reproducible; a checksum in the same artifact detects corruption, not replacement.
- An explicit absolute DLL path is required and the native bundle is obtained separately; the application creates and binds the listener and schedules every drive; no automatic network driver.
- Exactly one native image per process; `SAS_PAIRING_FATAL` requires a process restart; no protection against hostile in-process code; one `SasPairing` assembly instance in the default load context.
- A result is local completion only; no automatic trust persistence or enrollment.
- No production-security approval, professional audit, or formal verification; the protocol argument stays conditional, as recorded by P5–P7.

## 23. Next phase

**P10 — Consumer Integration / DovahLink Example** is next ([roadmap](../../roadmap/P10-consumer-integration.md)). It has not started; P9 created no P10 branch or code, and P10 is planned in depth only when it starts.
