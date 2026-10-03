# P8 — Dart Package

> **Pre-alpha, experimental.** P8 builds the Dart binding of the frozen sas-pairing native ABI v1. It is not production-security approved, not audited, and not formally verified. The protocol is implemented only by the native Rust core; Dart binds C.

**Status: P8 IN PROGRESS — P8.2 COMPLETE (with the P8.2.1 correction); P8.3 in progress.** Roadmap: [P8 — Dart Package](../../roadmap/P8-dart-package.md). Decisions: [decisions.md](decisions.md). Package: [`dart/`](../../dart/README.md).

## Baseline

| Item | Value |
|---|---|
| Branch | `feature/p8-dart-package`, the one long-lived P8 branch; one pull request at P8 closure |
| Baseline | `main` at `80ecbb1931b556f18000de70a37cac8c6b47aaa6` (merge of the P7 pull request #13) |
| Native boundary | [native ABI v1](../p7-native-abi/abi-v1-manifest.md), frozen by [P7-D-013](../p7-native-abi/decisions.md#p7-d-013--abi-v1-final-freeze-and-wrapper-handoff); declarations in [`sas_pairing.h`](../../core/include/sas_pairing.h); unchanged by P8 |

## Increments

| Increment | Scope | Decisions | State |
|---|---|---|---|
| P8.1 | Dart package foundation: pure-Dart package `sas_pairing`, generated private raw FFI of ABI v1 (25 functions, constants, records), the process-lifetime native-library loader (explicit path, 64-bit gate, symbol preflight, ABI version 1), layout and manifest consistency tests, Windows and Linux CI | [P8-D-001](decisions.md#p8-d-001--dart-native-binding-and-loader-architecture) | **Complete** ([evidence](#p81-evidence)) |
| P8.2 | Runtime / Authority / Host lifecycle wrapper: public lifecycle objects, status and exception model, explicit consuming `close()`, native-cascade mirroring, FATAL and contract-violation latches; P8.2.1: public initialization errors and the `READY` 1–10 bound | [P8-D-002](decisions.md#p8-d-002--dart-lifecycle-ownership-and-fail-closed-state) | **Complete** ([evidence](#p82-evidence), [P8.2.1](#p821-evidence)) |
| P8.3 | Windows listener ownership and cooperative network driver: Bootstrap value model, listening-socket ownership handoff, attach and detach, bounded host drive and resume recheck, event mapping, connection wrappers, `RUN_UNTRACKED` close guidance | [P8-D-003](decisions.md#p8-d-003--dart-windows-listener-cooperative-drive-and-connection-lifetime) | In progress |
| Later | Ceremony control and SAS presentation, runs and results, native artifact distribution, final P8 closure | — | Planned |

## P7 wrapper handoff

The mandatory obligations of [ABI contract §21](../p7-native-abi/abi-contract.md#21-wrapper-handoff-p8-p9) and where P8 meets them.

| # | Obligation | P8 state |
|---:|---|---|
| 1 | Bind exactly ABI v1; check `sas_pairing_abi_version() == 1` before any other call | P8.1: the loader preflights all 25 exports and requires version `1` before publishing the library; `0` and any other value fail permanently |
| 2 | One native image, retained for the process lifetime; no close, unload, reload, reset, or alternate copy | P8.1: one `DynamicLibrary.open` from an explicit path, retained strongly; no such API exists; a second initialization opens nothing |
| 3 | Tell consumers that `SAS_PAIRING_FATAL` needs an OS process restart | P8.2: `SasPairingNativeException.processRestartRequired` (true exactly for 900); the process FATAL latch refuses every later normal operation without a native call, cleanup stays allowed, no reset API; documented ([package README](../../dart/README.md)) |
| 4 | Caller-memory contract | P8.2 (lifecycle): the private lifecycle service allocates aligned, typed, distinct output slots and an exact scope copy for each call and frees them before returning; no pointer outlives a call; later increments extend it to the drive and record calls |
| 5 | Listener handoff through the in/out slot | Later increment (bound and symbol-checked only) |
| 6 | Cooperative bounded drive; consume every event, also when `out_failure` is not OK | Later increment (bound only; no drive loop, timer, or isolate exists) |
| 7 | SHOULD close a connection after `RUN_UNTRACKED` | Later increment |
| 8 | Explicit ceremony steps, `WRITE_PENDING` handling, decisions bound to the exact `ceremony_identity` | Later increment |
| 9 | Never construct, parse, or send frames; never confirm a final ACK | P8.1: no protocol code exists in Dart (guarded by a scope test); permanent |
| 10 | A result is local verified completion only | Later increment |
| 11 | Own the comparison UX and trust policy; no status is a trust verdict | P8.2: `SasPairingStatus` mirrors the 48 frozen values; exceptions carry the exact code (unknown codes preserved); no trust, malice, or authorization property exists |

## Package layout (P8.2)

```text
dart/
  pubspec.yaml                 sas_pairing 0.1.0-dev.1, publish_to: none, runtime dep ffi
  analysis_options.yaml        package:lints/recommended + strict analyzer modes
  ffigen.yaml                  explicit ABI v1 generation filter
  lib/
    sas_pairing.dart           public entrypoint: exports the P8.2 lifecycle, status, and
                               exception types by explicit show lists
    src/
      lifecycle.dart           SasPairingRuntime / Authority / Host, AuthorityState / Status
      status.dart              SasPairingStatus (48 frozen values)
      exceptions.dart          Initialization / Native / Closed / Contract exceptions
      native/                  private: never exported
        abi_v1.dart            frozen ABI v1 tables (exports, values, record sizes)
        native_library_loader.dart   process-lifetime loader (P8.1, unchanged)
        native_lifecycle_api.dart    NativeLifecycleApi: the seven lifecycle exports, all FFI memory
        native_process_context.dart  per-image process context: FATAL and contract latches
        generated/
          sas_pairing_bindings.g.dart  generated raw FFI (SasPairingNativeBindings)
  test/                        manifest, binding, layout, loader, initialization, lifecycle
                               (fake), FFI marshalling, status, public API, real-artifact,
                               scope tests
```

## Lifecycle contract (P8-D-002)

```text
SasPairingRuntime                 runtime_create / runtime_destroy (close)
  └── SasPairingAuthority         authority_register / authority_status / authority_release (close)
        └── SasPairingHost        host_create / host_destroy (close)
```

- **Normal** operations (`SasPairingRuntime.create`, `registerAuthority`, `queryStatus`, `createHost`) check the wrapper is open (else `SasPairingClosedException`), then the process latches, then make one native call; success needs `SAS_PAIRING_OK` and, for creations, a nonzero handle.
- **Cleanup** (`close()` on each wrapper) is locally idempotent and consuming: the first call marks the wrapper closed, makes exactly one native cleanup call, then invalidates children locally, whatever the result; a failure is thrown once and never retried. Cleanup is never refused by a latch.
- **Cascade.** Native authority release and runtime destroy already clean up their children, so Dart issues no child cleanup call: closing an authority makes one `authority_release`; closing a runtime makes one `runtime_destroy`; every child wrapper is then closed.

| First `close()` of | Native calls | Local effect |
|---|---|---|
| Host | 1 × `sas_pairing_host_destroy` | host closed and removed from its authority; authority stays open |
| Authority | 1 × `sas_pairing_authority_release`, 0 × host destroy | authority and all of its hosts closed; removed from its runtime; runtime stays open |
| Runtime | 1 × `sas_pairing_runtime_destroy`, 0 × authority release, 0 × host destroy | runtime, all authorities, and all hosts closed |

- **Latches** (in the package-private process context of the loaded image, below every runtime, never cleared): status 900 from any lifecycle call sets the FATAL latch; an `OK` output that breaks a frozen success invariant (zero handle, authority state `INVALID` or unknown, `READY` with a remaining count outside 1–10, `BUSY`/`EXHAUSTED` with nonzero remaining) sets the contract latch. The bound validates one returned snapshot; Dart keeps no budget, decrement, or expected next value. Either refuses every later normal operation, including `SasPairingRuntime.create`, without a native call; recovery is an OS process restart.
- **Initialization failures** (P8.2.1). A loader failure inside `SasPairingRuntime.create` is translated at one package-private boundary into the public `SasPairingInitializationException` (category `SasPairingInitializationFailure`, message preserved, no native status). Pre-load failures (pointer width, invalid path, OS load failure) have `processRestartRequired == false` and may be retried after correcting the cause; post-load failures (missing export, version query 0, version mismatch, verification failure) have `processRestartRequired == true` and fail every later `create` in the process. The private loader types are never exported.
- **Runtime recreation** reuses the same loaded image (the loader opens nothing once ready) and resets nothing: not the latches, the authority opportunity budget, the START limiter, or any process-session state.

## Real-native test topology

`dart test` runs each test file in its own isolate of one VM process. To keep the one-owner-isolate rule (P8-D-001 N), only `test/native_artifact_test.dart` loads the real library into the test process, and it calls only the version query there. The P8.2 real lifecycle scenarios run in child OS processes (`dart run test/support/lifecycle_child.dart <scenario> <artifact>`), each with a single isolate that is its native owner; the test process never registers an authority. Every Windows scenario uses unique, non-text scopes (a literal, the child's process ID, and the bytes `00 80 FF`). All other lifecycle tests use a deterministic fake of the private lifecycle service and load nothing; the production loader has no test reset.

Regenerating the raw bindings (requires libclang; on Windows the default LLVM install, on Linux `libclang-dev`):

```bash
cd dart && dart run ffigen --config ffigen.yaml
```

After regeneration `git diff` must be empty; CI regenerates on Windows and Linux and fails on any difference.

## Loader contract (P8-D-001)

- **Explicit path.** `NativeLibraryLoader.initialize(libraryPath: ...)` takes an absolute path to an existing file; nothing is discovered.
- **Order.** Pointer width 8 → path validation and canonicalization → one `DynamicLibrary.open` → retain → preflight the 25 exports → build the generated bindings → `sas_pairing_abi_version()` → require `1` → ready.
- **States.** *Uninitialized* (also after a failure before an image was loaded: pointer width, path, OS load error; a retry is allowed). *Ready* (the one retained library; every later `initialize` returns the identical object without reading its path argument). *Permanently failed* (an image was loaded but lacks an export, reports version `0`, reports another version, or failed to bind: the image stays referenced, nothing else is ever opened, and the error says to restart the OS process).
- **No escape hatch.** No close, unload, reload, reset, replace, or fatal-recovery API, in production or tests.

## Isolate contract

Dart statics are isolate-local, so the loader is a singleton per isolate, not per OS process. The supported model: **one Dart owner isolate per OS process holds all direct sas-pairing native access.** Other isolates do not open the library or call the bindings; they communicate with the owner at a higher layer, or do not use the native package. `DynamicLibrary.open` of the same file shares one image within the VM process, but a second isolate opening a different copy would break the P7-D-002 one-image invariant, and nothing in Dart can prevent that. P8.1 builds no cross-isolate façade.

## Platform scope

| Platform | Native ABI v1 in Dart | Pairing |
|---|---|---|
| Windows (x64) | The real `sas_pairing_core.dll` loads, binds, and reports ABI version 1; the P8.2 runtime, authority, and host lifecycle works against it | Supported by P7 (Windows TCP carrier); the Dart network API starts in P8.3 |
| Linux (x64) | The real `libsas_pairing_core.so` loads, binds, and reports ABI version 1; a runtime can be created and closed | Not supported: authority registration fails closed with `SasPairingStatus.unsupportedPlatform` (`SAS_PAIRING_UNSUPPORTED_PLATFORM`) as P7 defines |
| 32-bit processes | Refused before any library is opened | Not supported |

## Evidence

### P8.1 evidence

Commits on `feature/p8-dart-package`: `36222c8` (`docs: define p8 dart binding foundation`), `799fab8` (`feat: add dart native abi v1 bindings`), `67139a7` (`test: verify dart abi v1 foundation`; CI green on that exact head), then the closure commit `docs: close p8.1 dart binding foundation`.

| Item | Result |
|---|---|
| Toolchain | Dart SDK 3.13.4 (stable), locally and pinned in CI; package constraint `^3.11.0`; `ffi` ^2.2.0; dev `ffigen` 22.0.0 (exact), `lints` ^6.1.0, `test` ^1.32.0; no Flutter |
| Generation | `dart run ffigen --config ffigen.yaml` from `dart/`, header `../core/include/sas_pairing.h`, output `lib/src/native/generated/sas_pairing_bindings.g.dart` (1,259 lines, LF); local regeneration byte-identical (Windows, libclang 19.1.5); CI regeneration with `git diff --exit-code` passes on Linux (Ubuntu `libclang-dev`) and Windows |
| Bound exports | Exactly the 25 frozen functions; every generated native signature equals the header declaration (C `const` has no FFI counterpart) |
| Type mapping | `int32_t` → `Int32`, `uint32_t` → `Uint32`, `uint64_t` → `Uint64` (all six handle types), `uint8_t` → `Uint8`, `uintptr_t` → `UintPtr` (`sas_pairing_socket_t`), `size_t` → `Size`, pointers → `Pointer<T>`; 21 ABI typedefs checked against manifest §6 |
| Constants | 145 generated constants (2 version, 48 statuses, 84 namespace values, 11 handle-invalid and scalar values), each mirrored by name and value in `abi_v1.dart` and compared with the manifest row by row; `SAS_PAIRING_SOCKET_INVALID` (`UINTPTR_MAX`) is `-1` as a 64-bit Dart `int` |
| Records | `sas_pairing_bytes_view_t` 16, `sas_pairing_bootstrap_view_t` 64, `sas_pairing_event_t` 128, `sas_pairing_result_info_t` 56, `sas_pairing_action_t` 24, `sas_pairing_sas_presentation_t` 56 (`sizeOf` equals the frozen size); all 37 manifest field offsets and sizes measured from memory; fixed arrays 64 / 32 / 14 / 2; no padding |
| Real artifact | Windows `sas_pairing_core.dll` (local and CI) and Linux `libsas_pairing_core.so` (CI): the production loader opens it from the explicit path, all 25 symbols resolve by exact name, `sas_pairing_abi_version()` = 1; a second initialization returns the identical retained object |
| Fresh-process states | Child processes with the real loader: a missing path then the artifact → pre-load failure, then ready (version 1); a foreign real library (kernel32.dll / libc.so.6) then the artifact → permanent `missingSymbol` failure naming all 25 exports, and the artifact is never opened |
| Dart tests | 48 passed (manifest 7, generated bindings 6, record layout 4, loader state machine 19, real artifact 5, scope 7); `dart format` clean; `dart analyze --fatal-infos` clean, generated file included |
| Mutations (temporary, reverted) | Each made its test fail: status `SAS_PAIRING_FATAL` 900 → 901; an export removed from the ffigen filter; a fake export added to the ffigen filter; a fake export added to the Dart export list; required ABI version 1 → 2 (real-artifact smoke fails); event size expectation 128 → 120; generated `request_id` length 64 → 63; a `close()` call in the loader (scope test) |
| Native regression | `git diff 80ecbb1 -- core` is empty; `abi::tests::freeze` 3 passed locally and in the Dart workflow; the unchanged `Rust security core` and `Repository consistency` workflows are green on the same head |

### P8.2 evidence

Commits on `feature/p8-dart-package`: `dd2054e` (`docs: define p8 dart lifecycle contract`), `8547e1b` (`feat: add dart runtime authority host lifecycle`), `2363592` (`test: verify dart lifecycle ownership`), `67445f7` (`test: allow freed lifecycle output slots to be reused`; CI green on that exact head), then the closure commit `docs: close p8.2 dart lifecycle`. CI on `2363592` failed in both `dart test` jobs: an FFI marshalling test wrongly required two consecutive calls to receive distinct output-slot addresses, although each call frees its slot and the allocator may reuse it. Reproduced in a fresh clone, the assertion was narrowed to slots of one call (plus a scope/output non-overlap check); no library code changed.

| Item | Result |
|---|---|
| Public surface | `package:sas_pairing/sas_pairing.dart` exports, by explicit `show` lists, exactly `SasPairingRuntime`, `SasPairingAuthority`, `SasPairingHost`, `SasPairingAuthorityState`, `SasPairingAuthorityStatus`, `SasPairingStatus`, `SasPairingNativeException`, `SasPairingClosedException`, `SasPairingContractException`; nothing from `lib/src/native/`; no public handle, pointer, binding, or loader |
| Native boundary | Exactly the seven lifecycle exports, called only from `NativeLifecycleApi` (source-scanned); `git diff 37c986a -- core` is empty |
| Fake lifecycle tests | 40 (`lifecycle_test.dart`): runtime 9, authority 12, host 7, parent cascade 4, FATAL latch 5, unknown status 2, no handle or scope in text 1 |
| Cascade call counts | Host close: 1 `host_destroy`. Authority close: 1 `authority_release`, 0 `host_destroy`, all hosts closed. Runtime close: 1 `runtime_destroy`, 0 `authority_release`, 0 `host_destroy`, every authority and host closed. Second `close()`: 0 calls |
| Cleanup errors | `authority_release` → `OWNERSHIP_UNCERTAIN`: exception, authority and hosts closed, 1 call, no retry; `host_destroy` → `OWNERSHIP_UNCERTAIN`: exception, host closed, authority open, 1 call; `runtime_destroy` → `INVALID_HANDLE`: exception, runtime and children closed |
| FATAL latch | A normal call returning 900 latches; the four normal operations then throw status 900 with no native call; host, authority, and runtime close still make their one cleanup call (also when it returns 900); `SasPairingRuntime.create` over a fake loader after FATAL: no second `DynamicLibrary.open` (`opened` stays 1) and no `runtime_create`; only 900 latches (901, 999, 899, −900, 777 do not) |
| Contract latch | `OK` with handle 0 (runtime, authority, host), state `INVALID`, unknown states 4 and `0xFFFFFFFF`, `READY` with 0, `BUSY`/`EXHAUSTED` with nonzero remaining: `SasPairingContractException`, later normal work refused without a native call, explicit cleanup still allowed |
| Unknown status | 777 (normal) and 31337 (cleanup): `SasPairingNativeException` with the exact integer, `knownStatus == null`, `processRestartRequired == false`, no latch |
| FFI marshalling | 7 tests (`native_lifecycle_api_test.dart`) over the real generated bindings with Dart callbacks as the C exports: scope bytes `00 80 FF 00 41 00` and a 1,024-byte non-text scope arrive exactly with their full length; an empty scope is a null pointer with length 0; aligned, typed, nonzero output slots; two distinct status slots; 64-bit handle bit patterns preserved |
| Status model | 5 tests (`status_test.dart`): 48 enum values equal the private ABI table by name and code (no duplicates); `fromCode` round-trips and returns null for unknown codes; only `fatal` requires a restart; the observed normal/cleanup split of the seven exports equals manifest §2 fatal classes |
| Public API and scope | `public_api_test.dart` 5 tests; `package_scope_test.dart` 10 tests (updated, not removed: entrypoint exports only the lifecycle surface; no unload/reload/reset or recovery, finalizer, timer, isolate, stream, socket, listener, drive, Bootstrap, connection, run, result, presentation, crypto, randomness, or text conversion; only three `close()` declarations and no child-by-child call; FFI memory only in the lifecycle service) |
| Real Windows lifecycle | Child process over the real `sas_pairing_core.dll` (local and CI): runtime created; a second `create` → `alreadyInitialized` (3); authority with a binary scope (literal + PID + `00 80 FF`) → `ready`, 10; same scope again → `alreadyRegistered` (101); empty scope → `invalidScope` (100); hosts A and B; close A → authority open, `ready`, 10; close authority → host B closed by the cascade, `queryStatus` → `SasPairingClosedException`; re-registration → `ready`, 10; runtime close with two live authorities and three hosts → all closed; recreated runtime → same loaded image, re-registration `ready`, 10 |
| Real Linux lifecycle | Child process over the real `libsas_pairing_core.so` (CI only; no local Linux): runtime created and closed; registration → `unsupportedPlatform` (103); empty scope → `invalidScope` (100); recreated runtime → `unsupportedPlatform` again. No Linux pairing support is claimed |
| Dart tests | 110 (Windows: 109 passed, 1 Linux-only skipped; Linux: the Windows-only test skipped): manifest 7, generated bindings 6, record layout 4, loader 19, real artifact 7, scope 10, lifecycle 40, FFI marshalling 7, status 5, public API 5; `dart format` clean; `dart analyze --fatal-infos` clean |
| Mutations (temporary, reverted) | Each made its test fail: a `Finalizer` in the lifecycle (scope test); a public `int get nativeHandle` (public API test); host invalidation removed from authority close; child invalidation removed from runtime close; a second runtime close and a second host close calling native; runtime close calling `authority.close()` first; authority close calling `host.close()` first; a normal call entering native after FATAL; `busy` 105 → 115 (status consistency); scope length cut at the first NUL; scope round-tripped through a `String` (marshalling tests) |
| Native regression | `abi::tests::freeze` 3 passed locally and in the Dart workflow; the unchanged `Rust security core` and `Repository consistency` workflows green on the same head |

### P8.2.1 evidence

Corrective increment after independent review of P8.2, on the same branch from `ea3ce92`: `45cf6d4` (`fix: harden p8.2 public initialization and status bounds`), then the closure commit `docs: close p8.2.1 lifecycle correction`. No native file changed.

| Item | Result |
|---|---|
| Findings | (1) `SasPairingRuntime.create` could throw the private P8.1 `NativeLibraryInitializationException`, which a consumer of the public entrypoint cannot name or catch by type; (2) `queryStatus()` accepted `READY` with any remaining count above 0, although a successful `READY` reports 1–10 |
| Public surface | The entrypoint now also exports `SasPairingInitializationException` and `SasPairingInitializationFailure` (explicit `show` list); still nothing from `lib/src/native/`; `NativeLibraryInitializationException` and `NativeLoadFailure` added to the prohibited public names |
| Mapping | Exhaustive switch, private → public, same seven names: `unsupportedPointerWidth`, `invalidLibraryPath`, `openFailed` (restart false); `missingSymbol`, `abiVersionQueryFailed`, `abiVersionMismatch`, `verificationFailed` (restart true) |
| Initialization tests | 12 (`initialization_test.dart`, fake loader seam): the category and restart table against every private value; each of the seven failures reaching the `create` boundary is the public type (never the private one) with the right category, restart class, and loader message, no lifecycle service, and an image retained exactly when restart is required; invalid path then a valid path → runtime created, one open; ABI mismatch then another path → the same public failure, one open only; a non-loader error passes untranslated |
| Public API tests | 11 (`public_api_test.dart`, +6): consumer-visible types; the restart table; the real `SasPairingRuntime.create` (this isolate's process loader, nothing loaded) with an empty, relative, missing absolute, and non-library path → `SasPairingInitializationException` (`invalidLibraryPath` ×3, `openFailed`), restart false; an architecture check that `exceptions.dart` knows nothing of the loader, the public exception holds only `failure` and `message`, no doc comment in `lifecycle.dart` names a private loader type, and in code they appear only in the import and the one translation boundary used by `create` |
| `READY` bound | `READY` 1 and 10 → `ready`; `READY` 0, 11, 500, and `0xFFFFFFFF` → `SasPairingContractException`, contract latch set, later `queryStatus`, `createHost`, `registerAuthority`, and runtime create refused with no native call, host/authority/runtime cleanup still one native call each; `BUSY` and `EXHAUSTED` still require 0; a sequence 1, 10, 4 is accepted (no snapshot is compared with an earlier one) |
| Lifecycle regression | `lifecycle_test.dart` 41 (40 unchanged + 1 bounds test; the impossible-state table gained three `READY` rows); real Windows and Linux lifecycle children unchanged |
| Mutations (temporary, reverted) | Each made its tests fail: (A) `create` without the translation boundary → the four public `create` tests and the architecture test; (B) `abiVersionMismatch` with restart false → initialization and public restart tests; (C) `READY` accepted for `remaining > 0` → the impossible-state test at `READY` 11; (D) upper bound `< 10` → the bounds test and every test whose default fake answers `READY` 10; (E) `NativeLibraryInitializationException` exported from the entrypoint → public API and scope export tests |
| Native boundary | `git diff ea3ce92 -- core` and `git diff 80ecbb1 -- core` empty |
| Dart tests | 128 (Windows with the real DLL: 127 passed, 1 Linux-only skipped): manifest 7, generated bindings 6, record layout 4, loader 19, initialization 12, real artifact 7, scope 10, lifecycle 41, FFI marshalling 7, status 5, public API 11; `dart format` clean; `dart analyze --fatal-infos` clean |

## Nonclaims

P8 does not claim production readiness, security approval, an audit, formal verification, Linux or other non-Windows pairing support, cross-isolate enforcement of the one-image rule, protection against hostile in-process code, or recovery from `SAS_PAIRING_FATAL` without a process restart.
