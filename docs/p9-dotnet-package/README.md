# P9 — .NET Package

> **Pre-alpha, experimental.** P9 builds the .NET binding of the frozen sas-pairing native ABI v1. It is not production-security approved, not audited, and not formally verified. The protocol is implemented only by the native Rust core; C# binds C.

**Status: P9 IN PROGRESS — P9.1 COMPLETE.** P9.2 (Runtime / Authority / Host lifecycle wrapper, [P9-D-002](decisions.md#p9-d-002--net-lifecycle-ownership-public-errors-and-fail-closed-state)) is in progress. Roadmap: [P9 — .NET Package](../../roadmap/P9-dotnet-package.md). Decisions: [decisions.md](decisions.md). Package: [`dotnet/`](../../dotnet/README.md).

## Baseline

| Item | Value |
|---|---|
| Branch | `feature/p9-dotnet-package`, the one long-lived P9 branch; every increment (P9.1–P9.6) lands on it; one pull request at P9 closure, none per increment |
| Baseline | `main` at `03afc8dd6ef8c473ef648ec7e06cee5042d0083a` (merge of the P8 pull request #14) |
| Native boundary | [native ABI v1](../p7-native-abi/abi-v1-manifest.md), frozen by [P7-D-013](../p7-native-abi/decisions.md#p7-d-013--abi-v1-final-freeze-and-wrapper-handoff); declarations in [`sas_pairing.h`](../../core/include/sas_pairing.h); unchanged by P9 |
| Reference wrapper | The P8 Dart package ([P8 final closure](../p8-dart-package/final-closure.md)): evidence for wrapper semantics only; nothing in `dotnet/` is generated from or depends on `dart/` |

## Increments

| Increment | Scope | Decisions | State |
|---|---|---|---|
| P9.1 | .NET package foundation + exact ABI v1 interop: solution, `SasPairing` library and `SasPairing.Tests` projects (`net10.0`), private exact ABI v1 constants, records, and 25-export function table, explicit-path process-lifetime loader (64-bit gate, symbol preflight, ABI version 1, permanent post-load failure), header and manifest consistency tests, architecture and scope guards, Windows and Linux CI | [P9-D-001](decisions.md#p9-d-001--net-abi-v1-binding-and-loader-architecture) | **Complete** ([evidence](#p91-evidence)) |
| P9.2 | Runtime / Authority / Host lifecycle wrapper and the public initialization error surface | [P9-D-002](decisions.md#p9-d-002--net-lifecycle-ownership-public-errors-and-fail-closed-state) | In progress |
| P9.3 | Windows listener ownership handoff and cooperative network driver | — | Planned |
| P9.4 | Runs, trusted-local ceremony control, and SAS presentation | — | Planned |
| P9.5 | PairingResult API and result ownership | — | Planned |
| P9.6 | .NET / native distribution and final P9 closure | — | Planned |

## P7 wrapper handoff

The mandatory obligations of [ABI contract §21](../p7-native-abi/abi-contract.md#21-wrapper-handoff-p8-p9) and where P9 meets them.

| # | Obligation | P9 state |
|---|---|---|
| 1 | Bind exactly ABI v1; check `sas_pairing_abi_version() == 1` before any other call | P9.1: the loader preflights all 25 exports and requires version `1` before publishing the binding; `0` and any other value fail permanently |
| 2 | One native image, retained for the process lifetime; never `NativeLibrary.Free`; no unload, reload, reset, or alternate copy | P9.1: one `NativeLibrary.Load` from an explicit path, retained; no free or reset path exists; a second initialization opens nothing |
| 3 | Tell consumers that `SAS_PAIRING_FATAL` needs an OS process restart | Planned (P9.2, public status and error surface); P9.1 post-load initialization failures already say to restart the process |
| 4 | Caller-memory contract | Planned (P9.2–P9.5); P9.1 fixes the exact record layouts and pointer-sized types it rests on |
| 5 | Listener handoff through the in/out slot | Planned (P9.3) |
| 6 | Cooperative bounded drive; consume every event, also when `out_failure` is not OK | Planned (P9.3) |
| 7 | SHOULD close a connection after `RUN_UNTRACKED` | Planned (P9.3) |
| 8 | Explicit ceremony steps, `WRITE_PENDING` handling, decisions bound to the exact `ceremony_identity` | Planned (P9.4) |
| 9 | Never construct, parse, or send frames; never confirm a final ACK | P9.1: no protocol code exists in C# (scope-guarded); later increments keep it so |
| 10 | A result is local verified completion only | Planned (P9.5) |
| 11 | Own the comparison UX and trust policy; no status is a trust verdict | P9.1: statuses are raw private values with no trust meaning; the public mapping is planned for P9.2 and P9.4 |

## Package layout (P9.1)

```text
dotnet/
  SasPairing.sln
  global.json                  .NET SDK 10.0.401, rollForward latestPatch; Microsoft.Testing.Platform runner
  Directory.Build.props        net10.0, nullable, warnings as errors, latest-recommended analyzers, deterministic, locked restore
  .editorconfig                C# formatting and style checked by dotnet format
  src/SasPairing/
    SasPairing.csproj          package SasPairing 0.1.0-dev.1, IsPackable false, no package dependency
    Interop/                   every P9.1 source file; internal only
      AbiV1Constants.cs        the 145 frozen constants (version, 48 statuses, 84 namespace values, 11 handle and scalar values)
      AbiV1Structs.cs          the six frozen records
      AbiV1Exports.cs          the 25 export names and the private function table
      NativeAbiV1.cs           the one verified binding (image, table, version)
      NativeLibraryLoader.cs   the loader state machine, the platform seam, the real platform
      NativeInitializationFailure.cs   failure categories and the internal initialization exception
  tests/SasPairing.Tests/      xUnit v3 tests; Support/ parses the header and the manifest
```

The library exports no public type in P9.1: there is no pairing API yet.

## Loader contract (P9-D-001)

`NativeAbiV1Loader.Process.Initialize(path)` is the one internal entry. It requires an 8-byte pointer width, a fully qualified path to an existing file (canonicalized), makes exactly one `NativeLibrary.Load`, preflights the 25 exports by exact name, binds the function table, and requires `sas_pairing_abi_version() == 1`. Pre-load failures may be retried; post-load failures are permanent for the process and keep the image. Once ready, every later call returns the identical binding without reading its path. Nothing is searched, discovered, or downloaded, and the image is never freed, unloaded, reloaded, or replaced. One `SasPairing` assembly instance in the default load context owns the one image; another load context is outside the supported model.

## Platform scope

| Platform | Native ABI v1 in .NET | Pairing |
|---|---|---|
| Windows (x64) | The real `sas_pairing_core.dll`, built from the same commit in CI, loads through the production loader, exports all 25 symbols, and reports ABI version 1 | Supported by P7 (Windows TCP carrier); no .NET pairing API exists yet (P9.2–P9.5) |
| Linux (x64) | The real `libsas_pairing_core.so` loads, exports all 25 symbols, and reports ABI version 1, in CI only | Not supported: P7 fails pairing operations closed with `SAS_PAIRING_UNSUPPORTED_PLATFORM`; loading the library is not pairing support |
| Other | Not tested | Not supported; no claim |
| 32-bit processes | Refused before any library is opened | Not supported |

## Evidence

### P9.1 evidence

P9.1 — .NET package foundation + exact ABI v1 interop, under [P9-D-001](decisions.md#p9-d-001--net-abi-v1-binding-and-loader-architecture). Commits on `feature/p9-dotnet-package`: `9f0148c` (`docs: define p9 dotnet interop foundation`), `d1fb72e` (`feat: add dotnet abi v1 interop foundation`), `cee36e5` (`test: verify dotnet abi v1 bindings and loader`), then the closure commit `docs: close p9.1 dotnet interop foundation`.

| Item | Result |
|---|---|
| Starting state | `main` at `03afc8dd6ef8c473ef648ec7e06cee5042d0083a` (P8 pull request #14 merged; P8 final closure present); the branch existed locally at exactly that commit, clean, not on the remote; no P9 pull request |
| Toolchain | .NET SDK 10.0.401 (runtime 10.0.12) locally; `dotnet/global.json` pins `10.0.401` with `rollForward: latestPatch` and selects the Microsoft.Testing.Platform test runner; CI installs it with `actions/setup-dotnet@v6` from that file |
| Projects | `src/SasPairing` (library, `net10.0`, `SasPairing` 0.1.0-dev.1, `IsPackable` false, no package dependency) and `tests/SasPairing.Tests` (xUnit v3 4.0.1 on Microsoft.Testing.Platform 2.4.0); `packages.lock.json` committed for both, restored with `--locked-mode` |
| Interop surface | 145 constants (2 version, 48 statuses, 84 namespace values, 6 handle invalid values, the `nuint` socket invalid value, 4 `nuint` scalar limits); 6 records; 25 function-table fields; all internal, all under `Interop/` |
| Records (x64) | bytes view 16/8, bootstrap view 64/8, event 128/8, result info 56/4, action 24/8, SAS presentation 56/4; all 37 manifest field offsets and sizes equal, no padding; measured with `sizeof`, `Marshal.SizeOf`, `Marshal.OffsetOf`, pointer arithmetic, and alignment probes |
| Unsafe audit | 5 `unsafe` declarations, all under `Interop/`, each preceded by a `// UNSAFE:` justification: the bytes-view record (raw pointer), 3 records with inline arrays (5 fixed buffers), and the function table (25 unmanaged function pointers); no unsafe block or method elsewhere |
| Tests | 60, all passing: `AbiV1ConstantsTests` 8, `AbiV1LayoutTests` 9, `AbiV1ExportTests` 9, `NativeLoaderTests` 13, `NativeArtifactTests` 6, `ArchitectureTests` 15. Locally on Windows with `SAS_PAIRING_NATIVE_LIBRARY` set: 60 passed, 0 skipped; without it, the 4 artifact-dependent tests are skipped locally (under `CI=true` they fail instead) |
| Build and analysis | `dotnet build --no-restore -warnaserror`: 0 warnings, 0 errors, `latest-recommended` built-in analyzers enforced as errors (probed: a deliberate CA2201 violation fails the build); no `NoWarn`, no suppression |
| Format | `dotnet format --verify-no-changes`: clean (probed: injected whitespace drift is reported) |
| Fresh clone | A fresh clone of the test head reproduced the CI sequence locally (locked restore, format, build, 60 of 60 tests, 6 of 6 artifact tests) |
| Real Windows DLL | `core/target/release/sas_pairing_core.dll` built from the same commit with `--release --features native-abi`, loaded through `NativeAbiV1Loader.Process`: ABI version 1, all 25 exports found by exact name, each function-table field equal to its export's address, the same binding returned for the same path, another path, and a bare name; a real-platform loader opened it once across repeated initialization |
| Real Linux `.so` | `libsas_pairing_core.so` built in the Ubuntu job, loaded through the same production loader: ABI version 1 and all 25 exports (CI). This proves ABI loading only, not Linux pairing support |
| Real post-load poisoning | A real foreign image (`kernel32.dll` on Windows, `libc.so.6` on Linux) through a real-platform loader: `MissingSymbol` (25 of 25), image retained, and neither the same path nor the real artifact path ever loaded again (one open) |
| Header and manifest | Constants, types, record fields, export names, order, signatures (return and parameter types, `Cdecl` unmanaged convention) parsed from `core/include/sas_pairing.h` and `docs/p7-native-abi/abi-v1-manifest.md` and compared exactly; no missing or extra constant or export |
| Native diff gate | `git diff 03afc8dd6ef8c473ef648ec7e06cee5042d0083a -- core` is empty (and `-- dart` is empty) |
| CI (`cee36e5`) | All seven triggered jobs green: `dotnet-package (windows-latest)` and `dotnet-package (ubuntu-latest)` (every step, including locked restore, format, build, 60 tests with nothing skipped, the real native ABI v1 smoke with 6 of 6, and the ABI v1 freeze test), `windows-core`, `unsupported-platform-fails-closed`, `consistency`, `dart-package (windows-latest)`, `dart-package (ubuntu-latest)` |

Mutations (each applied alone, built, run against the full suite with the real DLL, then restored byte-for-byte; the suite was green again afterwards):

| Mutation | Killed by |
|---|---|
| A: required ABI version 1 → 2 | 13 tests, including `TheAbiVersionIsExactlyOneAndZeroIsInvalid`, `EveryHeaderDefineMatchesTheDeclaredConstantAndType`, and the real-artifact load |
| B: `SAS_PAIRING_FATAL` 900 → 901 | `AllFortyEightStatusesExistExactlyOnceWithTheirFrozenValues`, `EveryHeaderDefineMatchesTheDeclaredConstantAndType` |
| B2: `SAS_PAIRING_WRITE_PENDING` 205 → 299 | the same two tests |
| C: one export removed from the function table | 6 tests, including `TheFunctionTableHasExactlyOneFieldPerFrozenExport` and `EverySignatureMatchesTheHeaderThroughTheMapping` |
| C2: one export removed from the names list | 14 tests, including both names-versus-manifest and names-versus-header tests |
| D: `sas_pairing_future_magic` added to the expected exports | 11 tests, including the manifest, header, and table comparisons and the real-artifact load |
| E: event `request_id` 64 → 56 (record 128 → 120) | `RequiredX64SizesAndAlignments`, `SizesAndAlignmentsMatchTheManifest`, `FieldOrderOffsetsAndSizesMatchTheManifest`, `FieldTypesFollowTheHeaderThroughTheMapping` |
| E2: event fields `connection` and `run` swapped | `FieldOrderOffsetsAndSizesMatchTheManifest`, `CriticalOffsetsMeasuredByPointerArithmetic`, `FieldTypesFollowTheHeaderThroughTheMapping` |
| F: bytes-view `size_t len` as `ulong` (still 8 bytes) | `FieldTypesFollowTheHeaderThroughTheMapping` |
| F2: `sas_pairing_authority_register` `size_t` parameter as `ulong` | `EverySignatureMatchesTheHeaderThroughTheMapping`, `PointerSizedParametersAreNuintNeverUlong` |
| G: `NativeLibrary.Free` added to production | `ProductionNeverReleasesTheNativeImage` |
| H: `NativeLibrary.Load("sas_pairing_core")` added | `TheOnlyNativeLibraryLoadIsTheExplicitCanonicalPathInTheLoader`, `ProductionUsesNoDefaultLibraryResolution` |
| H2: `[DllImport("sas_pairing_core")]` added | `ProductionUsesNoDefaultLibraryResolution` |
| I: a second load allowed after a post-load failure | 5 tests, including the missing-symbol, binding, and version state-machine tests and the real foreign-image test |
| J: the function table made `public` | `TheAssemblyExportsNoPublicType`, `NoProductionTypeIsDeclaredPublic`, `NoRawInteropConceptIsVisibleOutsideTheAssembly`, `TheTableIsInternalAndSealed` |

One test defect was found and fixed by the mutation runs before commit: an exception on a worker thread of the concurrency test ended the test host instead of failing the test (mutation A ran 55 of 60 tests); worker exceptions are now captured and asserted.
