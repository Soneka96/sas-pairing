# P9 — .NET Package

> **Pre-alpha, experimental.** P9 builds the .NET binding of the frozen sas-pairing native ABI v1. It is not production-security approved, not audited, and not formally verified. The protocol is implemented only by the native Rust core; C# binds C.

**Status: P9 IN PROGRESS — P9.2 COMPLETE.** P9.1 (.NET package foundation + exact ABI v1 interop) and P9.2 (Runtime / Authority / Host lifecycle wrapper, [P9-D-002](decisions.md#p9-d-002--net-lifecycle-ownership-public-errors-and-fail-closed-state)) are complete. Next: P9.3 (Windows listener ownership + cooperative network driver), not started. Roadmap: [P9 — .NET Package](../../roadmap/P9-dotnet-package.md). Decisions: [decisions.md](decisions.md). Package: [`dotnet/`](../../dotnet/README.md).

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
| P9.2 | Runtime / Authority / Host lifecycle wrapper: the first public types (`IDisposable` runtime, authority, and host with native-cascade ownership), the public initialization, native-status (48 values), native, and contract error model, process-wide `FATAL` and contract-violation latches, exact binary authority scope, `READY` 1–10 status validation, Windows and Linux real-library lifecycle tests | [P9-D-002](decisions.md#p9-d-002--net-lifecycle-ownership-public-errors-and-fail-closed-state) | **Complete** ([evidence](#p92-evidence)) |
| P9.3 | Windows listener ownership handoff and cooperative network driver | — | Next (not started) |
| P9.4 | Runs, trusted-local ceremony control, and SAS presentation | — | Planned |
| P9.5 | PairingResult API and result ownership | — | Planned |
| P9.6 | .NET / native distribution and final P9 closure | — | Planned |

## P7 wrapper handoff

The mandatory obligations of [ABI contract §21](../p7-native-abi/abi-contract.md#21-wrapper-handoff-p8-p9) and where P9 meets them.

| # | Obligation | P9 state |
|---|---|---|
| 1 | Bind exactly ABI v1; check `sas_pairing_abi_version() == 1` before any other call | P9.1: the loader preflights all 25 exports and requires version `1` before publishing the binding; `0` and any other value fail permanently |
| 2 | One native image, retained for the process lifetime; never `NativeLibrary.Free`; no unload, reload, reset, or alternate copy | P9.1: one `NativeLibrary.Load` from an explicit path, retained; no free or reset path exists; a second initialization opens nothing |
| 3 | Tell consumers that `SAS_PAIRING_FATAL` needs an OS process restart | P9.2: `SasPairingNativeException.ProcessRestartRequired` is true exactly for status 900; the wrapper latches it process-wide and refuses every later normal operation locally (cleanup still runs); no reset, reload, or re-initialize exists; post-load initialization failures also require a restart |
| 4 | Caller-memory contract | P9.2 for the lifecycle: stack-local output slots passed for one synchronous call, the binary scope pinned for one call with its exact length (null with length 0 when empty), nothing retained, no native allocation; P9.3–P9.5 for the rest |
| 5 | Listener handoff through the in/out slot | Planned (P9.3) |
| 6 | Cooperative bounded drive; consume every event, also when `out_failure` is not OK | Planned (P9.3) |
| 7 | SHOULD close a connection after `RUN_UNTRACKED` | Planned (P9.3) |
| 8 | Explicit ceremony steps, `WRITE_PENDING` handling, decisions bound to the exact `ceremony_identity` | Planned (P9.4) |
| 9 | Never construct, parse, or send frames; never confirm a final ACK | P9.1: no protocol code exists in C# (scope-guarded); later increments keep it so |
| 10 | A result is local verified completion only | Planned (P9.5) |
| 11 | Own the comparison UX and trust policy; no status is a trust verdict | P9.2: the public `SasPairingStatus` (48 values) and the exceptions describe operation outcomes only, with no trust, attack, or compromise property (reflection-checked); the comparison UX is P9.4 |

## Package layout (P9.2)

```text
dotnet/
  SasPairing.sln
  global.json                  .NET SDK 10.0.401, rollForward latestPatch; Microsoft.Testing.Platform runner
  Directory.Build.props        net10.0, nullable, warnings as errors, latest-recommended analyzers, deterministic, locked restore
  .editorconfig                C# formatting and style checked by dotnet format
  src/SasPairing/
    SasPairing.csproj          package SasPairing 0.1.0-dev.1, IsPackable false, no package dependency
    SasPairingRuntime.cs       P9.2 public lifecycle: runtime (Create, RegisterAuthority, Dispose)
    SasPairingAuthority.cs     authority (GetStatus, CreateHost, Dispose) and the status snapshot check
    SasPairingHost.cs          host (Dispose)
    SasPairingStatus.cs        the 48 public statuses (each other public type also has its own root file)
    NativeProcessContext.cs    internal: the process context (binding, lifecycle service, FATAL and contract latches) and its source
    Interop/                   internal only: the P9.1 raw ABI v1 interop and loader, and the P9.2 lifecycle-native service
      AbiV1Constants.cs        the 145 frozen constants (version, 48 statuses, 84 namespace values, 11 handle and scalar values)
      AbiV1Structs.cs          the six frozen records
      AbiV1Exports.cs          the 25 export names and the private function table
      NativeAbiV1.cs           the one verified binding (image, table, version)
      NativeLibraryLoader.cs   the loader state machine, the platform seam, the real platform
      NativeInitializationFailure.cs   failure categories and the internal initialization exception
      INativeLifecycleApi.cs   the private seven-export lifecycle service interface
      FfiNativeLifecycleApi.cs its production implementation over the function table (the only P9.2 unsafe code)
  tests/SasPairing.Tests/      xUnit v3 tests; Support/ parses the header and the manifest and holds the fakes
```

P9.2 exports exactly ten public types, all in namespace `SasPairing`: `SasPairingRuntime`, `SasPairingAuthority`, `SasPairingHost`, `SasPairingAuthorityState`, `SasPairingAuthorityStatus`, `SasPairingStatus`, `SasPairingInitializationFailure`, `SasPairingInitializationException`, `SasPairingNativeException`, and `SasPairingContractException`. There is no pairing API yet.

## Loader contract (P9-D-001)

`NativeAbiV1Loader.Process.Initialize(path)` is the one internal entry. It requires an 8-byte pointer width, a fully qualified path to an existing file (canonicalized), makes exactly one `NativeLibrary.Load`, preflights the 25 exports by exact name, binds the function table, and requires `sas_pairing_abi_version() == 1`. Pre-load failures may be retried; post-load failures are permanent for the process and keep the image. Once ready, every later call returns the identical binding without reading its path. Nothing is searched, discovered, or downloaded, and the image is never freed, unloaded, reloaded, or replaced. One `SasPairing` assembly instance in the default load context owns the one image; another load context is outside the supported model.

## Lifecycle contract (P9-D-002)

`SasPairingRuntime.Create(path)` initializes the one P9.1 process loader (translating its failure into `SasPairingInitializationException` by an exhaustive switch, with no inner private exception), obtains the one process context, and calls `sas_pairing_runtime_create`; `RegisterAuthority(ReadOnlySpan<byte>)`, `GetStatus()`, and `CreateHost()` follow. Each requires `OK` and a non-zero handle or a valid status snapshot (`Ready` 1–10, `Busy` 0, `Exhausted` 0), else `SasPairingContractException`. Admission of a normal operation: disposed check (`ObjectDisposedException`), then the contract latch, then the `FATAL` latch, then the one native call. Cleanup (`Dispose`) is never admission-checked: one native call per object (`host_destroy`, `authority_release`, `runtime_destroy`), after which the object and every descendant are disposed locally whatever the status, and a failure is then thrown once. Disposing and re-creating a runtime reuses the image, the context, and both latches, and resets no security accounting.

## Platform scope

| Platform | Native ABI v1 in .NET | Pairing |
|---|---|---|
| Windows (x64) | The real `sas_pairing_core.dll`, built from the same commit in CI, loads through the production loader, exports all 25 symbols, and reports ABI version 1; the runtime, authority, and host lifecycle runs through the public API | Supported by P7 (Windows TCP carrier); no .NET pairing API exists yet (P9.3–P9.5) |
| Linux (x64) | The real `libsas_pairing_core.so` loads, exports all 25 symbols, and reports ABI version 1; a runtime is created and authority registration fails closed with `UnsupportedPlatform`, in CI only | Not supported: P7 fails pairing operations closed with `SAS_PAIRING_UNSUPPORTED_PLATFORM`; loading the library or creating a runtime is not pairing support |
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

### P9.2 evidence

P9.2 — Runtime / Authority / Host lifecycle wrapper, under [P9-D-002](decisions.md#p9-d-002--net-lifecycle-ownership-public-errors-and-fail-closed-state). Commits on `feature/p9-dotnet-package`: `1f814ed` (`docs: define p9 dotnet lifecycle contract`), `2c9b49d` (`feat: add dotnet runtime authority host lifecycle`), `a40d3f1` (`test: verify dotnet lifecycle ownership`), then the closure commit `docs: close p9.2 dotnet lifecycle`.

| Item | Result |
|---|---|
| Starting state | `feature/p9-dotnet-package` at `352807a50acba7607fc71e3d665967904f1b445c` (P9.1 closure), clean, 4 ahead and 0 behind `main` at `03afc8dd6ef8c473ef648ec7e06cee5042d0083a`; no P9 pull request |
| Source recheck | The seven lifecycle exports in `core/src/abi` (`mod.rs`, `runtime.rs`, `authority.rs`, `hosting.rs`) and `core/src/lib.rs`: one runtime per process (`ALREADY_INITIALIZED`, never replaced, no platform gate); destroy removes the runtime from its slot and then destroys hosts and releases authorities; release destroys the authority's hosts, removes its handle, then runs the core release, consuming handle and hosts whatever is returned; host destroy invalidates the handle whatever is returned; status `READY` 1–10 (core `MAX_OPPORTUNITIES = 10`), `BUSY` 0, `EXHAUSTED` 0; create, register, status, and host create are normal (refused with `FATAL` after a contained panic), destroy, release, and host destroy are cleanup (allowed); on non-Windows the OS ownership lease returns `UnsupportedPlatform` after the empty-scope check (`InvalidScope`) |
| Public surface | Exactly ten public types in namespace `SasPairing` (reflection allowlist of every public member); no public constructor on the wrappers or the exceptions; no public `ulong`, `long`, `nint`, `nuint`, pointer, function pointer, `SafeHandle`, interop, binding, loader, context, or lifecycle-service type; no member named for a handle, pointer, trust verdict, reset, reload, or close |
| Lifecycle service | `INativeLifecycleApi` has exactly seven methods; `FfiNativeLifecycleApi` calls exactly the seven lifecycle fields of the function table (source-checked); no code outside `Interop/` calls an export, and the table is used outside `Interop/` only to build the production service |
| Unsafe audit | 6 `unsafe` declarations, all under `Interop/`, each preceded by a `// UNSAFE:` justification (the 5 of P9.1 plus `FfiNativeLifecycleApi`); no public lifecycle type is `unsafe` and no `fixed`, `stackalloc`, `Marshal`, or `NativeLibrary` exists outside `Interop/` |
| Tests | 131, all passing: the P9.1 classes 61 (`AbiV1ConstantsTests` 8, `AbiV1LayoutTests` 9, `AbiV1ExportTests` 9, `NativeLoaderTests` 13, `NativeArtifactTests` 6, `ArchitectureTests` 16) and the P9.2 classes 70 (`LifecycleOwnershipTests` 17, `FailClosedStateTests` 22, `PublicInitializationTests` 14, `PublicSurfaceTests` 6, `FfiNativeLifecycleApiTests` 7, `NativeLifecycleArtifactTests` 4). Of the 60 P9.1 tests, 56 are unchanged and 4 architecture guards were deliberately moved to P9.2 (the empty public allowlist became the exact ten-type allowlist; "only `Interop/`" became the exact file layout; "no public type declaration" became "public types only in their own root files"; "no high-level wrapper" became "no wrapper of a later increment"); one guard was added (only the three lifecycle wrappers are `IDisposable`; no finalizer, `SafeHandle`, or `CriticalFinalizerObject` anywhere). `NativeArtifactTests` only gained the shared real-native collection and an internal path helper |
| Build and analysis | `dotnet build --no-restore -warnaserror`: 0 warnings, 0 errors, `latest-recommended` analyzers as errors; one analyzer finding during development (CA1822 on `SasPairingContractException.ProcessRestartRequired`) was fixed in code, not suppressed; no `NoWarn` or suppression |
| Format | `dotnet format --verify-no-changes`: clean |
| Fake lifecycle | Exact arguments of all seven calls; one `host_destroy` per host, one `authority_release` and zero `host_destroy` per authority, one `runtime_destroy` and zero release or destroy per runtime; descendants disposed locally; consuming failures (`OwnershipUncertain`, `InvalidHandle`, unknown 777) with the object and its descendants disposed and no retry; idempotent `Dispose`; concurrent `Dispose` makes one call; `ObjectDisposedException` with zero native calls; `READY` 1, 4, 10 accepted and the sequence 1, 10, 4, 10 accepted; ten impossible success outputs latch the contract violation and later normal work makes zero native calls while cleanup still runs; unknown status 777 preserved (`KnownStatus` null, not fatal, not latched); `FATAL` from a normal or a cleanup call latches, later normal work (including `Create`) makes zero native calls, cleanup still runs; admission order disposed → contract → fatal; no handle or scope byte in `ToString` or a message |
| Initialization | All seven loader categories driven through the real P9.1 loader state machine into the public exception (exact type, category, restart class, message detail, no inner exception, no lifecycle service built); exhaustive by-name translation (an untranslated category throws); pre-load retry succeeds afterwards with one load; post-load `AbiVersionMismatch` stays permanent with no alternate image; runtime recreation reuses one context and one image; after `FATAL` and runtime disposal a new `Create` makes no load and no native call |
| FFI boundary | `FfiNativeLifecycleApi` over the real function table bound to recording `[UnmanagedCallersOnly]` fakes: exact handles; output slots non-null, aligned, zeroed on entry, and (for status) two distinct slots initialized to `INVALID` and 0; raw status and outputs returned uninterpreted; a scope slice `00 80 FF 00 41` arrives as exactly those 5 bytes at the caller's own pinned address (no copy, no conversion, no terminator) and does not overlap the output slot; an empty span and an empty slice arrive as a null pointer with length 0 |
| Real Windows DLL | Through the public API against `sas_pairing_core.dll` built from the same commit: `Create`; a unique binary scope (with `00`, `80`, `FF`) registers; `GetStatus` is `Ready` 10; hosts A and B created; A disposed; still `Ready` 10; the authority disposed, B disposed by the cascade; the same scope registers again; runtime disposal cascades; a second live runtime is `AlreadyInitialized`; recreation reuses the same image and context; an empty scope is `InvalidScope`; a duplicate registration is `AlreadyRegistered` |
| Real Linux `.so` | Through the public API against `libsas_pairing_core.so` (CI): `Create` succeeds; registration fails closed with `UnsupportedPlatform` (103, not a restart); runtime disposal works; empty scope `InvalidScope`; a second live runtime `AlreadyInitialized`. This is not Linux pairing support |
| Native diff gate | `git diff 352807a -- core` and `git diff 03afc8dd6ef8c473ef648ec7e06cee5042d0083a -- core` are empty; `git diff 03afc8dd6ef8c473ef648ec7e06cee5042d0083a -- dart` is empty |
| CI (`a40d3f1`) | All five triggered jobs green: `dotnet-package (windows-latest)` and `dotnet-package (ubuntu-latest)` (every step: locked restore, format, build, the full suite with its `Passed!`, `failed: 0`, and `skipped: 0` guards, the real native ABI v1 smoke with 6 of 6, the new real native lifecycle step through the public API with 4 of 4 and nothing skipped, and the ABI v1 freeze test), `windows-core`, `unsupported-platform-fails-closed`, and `consistency`. The Dart workflow was not path-triggered (no `dart/` change) |
| CI (closure head) | The closure commit changes documentation only; `dotnet/README.md` is under the .NET path filter, so `dotnet-package (windows-latest)`, `dotnet-package (ubuntu-latest)`, `windows-core`, `unsupported-platform-fails-closed`, and `consistency` run on it again (the Dart workflow is not path-triggered); they are verified green after the push and reported with the P9.2 acceptance |

Mutations (each applied alone, built, run against the full suite with the real DLL, then restored byte-for-byte; the suite was green again afterwards):

| Mutation | Killed by |
|---|---|
| A: the private `NativeInitializationException` escapes `Runtime.Create` | 9 tests: `EveryLoaderFailureBecomesThePublicExceptionWithItsRestartClassAndMessage` (all 7 categories), `APreLoadFailureMayBeRetriedAndALaterValidInitializationCreatesARuntime`, `APostLoadFailureIsPermanentAndNoAlternateImageIsLoaded` |
| B: `AbiVersionMismatch` reports `ProcessRestartRequired = false` | `EveryLoaderFailureBecomesThePublicExceptionWithItsRestartClassAndMessage`, `TheTranslationIsExhaustiveOneToOneAndByName`, `APostLoadFailureIsPermanentAndNoAlternateImageIsLoaded` |
| C: a second `Host.Dispose` calls native again | 10 tests, including `HostDisposeMakesExactlyOneDestroyCallAndIsIdempotent`, `ConcurrentDisposeMakesOneNativeCall`, the three consuming-failure tests, and the real Windows lifecycle |
| C2: a second `Runtime.Dispose` calls native again | `RuntimeDisposeMakesOneDestroyCallAndNoDescendantCallAndInvalidatesTheWholeTree`, `AFailedRuntimeDestroyIsConsumingAndNeverRetried`, the real Windows lifecycle |
| D: `Authority.Dispose` disposes each host before `authority_release` | `AuthorityDisposeMakesOneReleaseCallAndNoHostCallAndInvalidatesItsHosts`, `AFailedAuthorityReleaseIsConsumingAndNeverRetried` (3 cases) |
| E: `Runtime.Dispose` disposes each authority before `runtime_destroy` | `RuntimeDisposeMakesOneDestroyCallAndNoDescendantCallAndInvalidatesTheWholeTree`, `AFailedRuntimeDestroyIsConsumingAndNeverRetried` |
| F: disposed guard removed from `Authority.GetStatus` | `EveryNormalOperationOnADisposedWrapperFailsLocallyWithoutANativeCall`, `AdmissionOrderIsDisposedThenContractThenFatal`, the real Windows lifecycle |
| F2: disposed guard removed from `Runtime.RegisterAuthority` | `EveryNormalOperationOnADisposedWrapperFailsLocallyWithoutANativeCall`, the real recreation test |
| G: a normal operation admitted after native `FATAL` | 7 tests, including `NativeFatalFromANormalOperationLatchesAndRefusesEveryLaterNormalOperationLocally` (3 cases), `RecreatingTheRuntimeNeverClearsEitherLatch`, `AfterFatalAndRuntimeDisposalANewCreateFailsLocallyWithNoLoadAndNoNativeCall` |
| H: `READY` validated as `remaining > 0` | `AnImpossibleSuccessOutputLatchesTheContractViolationAndOnlyCleanupContinues` (`READY + 11`, `READY + uint.MaxValue`) |
| I: the scope round-tripped through UTF-8 text | `RegisterAuthorityPassesTheRuntimeHandleAndTheExactBinaryScope`, `ProductionImplementsNoCryptographyProtocolNetworkingOrThreads` |
| I2: the scope length cut at the first NUL (C-string logic) | `ANonEmptyScopeIsTheExactSpanBytesAndLengthPinnedInPlace` |
| J: `public ulong NativeHandle` on `SasPairingRuntime` | `EveryPublicMemberIsExactlyTheIntendedP92Surface`, `NoPublicMemberExposesARawInteropConceptOrATrustVerdict` |
| K: unknown status 777 treated as success | `AnUnknownStatusIsAPreservedFailureThatIsNeitherSuccessNorFatal`, `AFailedAuthorityReleaseIsConsumingAndNeverRetried` (777 case) |
| L: `OK` + handle 0 builds a wrapper | `AnImpossibleSuccessOutputLatchesTheContractViolationAndOnlyCleanupContinues` (the three zero-handle cases) |

Two test defects were found and fixed before commit: the disposed-object name assertion expected the short type name (`ObjectDisposedException.ObjectName` is the full name), and the member-name guard flagged the mandated enum value `UnsupportedPointerWidth` (enum values are now checked for trust-verdict names only). Mutation A was first expressed as a bare `throw;`, which did not compile; it was re-expressed as a never-matching catch filter so that the private exception genuinely escapes.
