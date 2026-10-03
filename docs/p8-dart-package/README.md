# P8 — Dart Package

> **Pre-alpha, experimental.** P8 builds the Dart binding of the frozen sas-pairing native ABI v1. It is not production-security approved, not audited, and not formally verified. The protocol is implemented only by the native Rust core; Dart binds C.

**Status: P8 IN PROGRESS — P8.1 in progress.** Roadmap: [P8 — Dart Package](../../roadmap/P8-dart-package.md). Decisions: [decisions.md](decisions.md). Package: [`dart/`](../../dart/README.md).

## Baseline

| Item | Value |
|---|---|
| Branch | `feature/p8-dart-package`, the one long-lived P8 branch; one pull request at P8 closure |
| Baseline | `main` at `80ecbb1931b556f18000de70a37cac8c6b47aaa6` (merge of the P7 pull request #13) |
| Native boundary | [native ABI v1](../p7-native-abi/abi-v1-manifest.md), frozen by [P7-D-013](../p7-native-abi/decisions.md#p7-d-013--abi-v1-final-freeze-and-wrapper-handoff); declarations in [`sas_pairing.h`](../../core/include/sas_pairing.h); unchanged by P8 |

## Increments

| Increment | Scope | Decisions | State |
|---|---|---|---|
| P8.1 | Dart package foundation: pure-Dart package `sas_pairing`, generated private raw FFI of ABI v1 (25 functions, constants, records), the process-lifetime native-library loader (explicit path, 64-bit gate, symbol preflight, ABI version 1), layout and manifest consistency tests, Windows and Linux CI | [P8-D-001](decisions.md#p8-d-001--dart-native-binding-and-loader-architecture) | In progress |
| P8.2 | Runtime / Authority / Host lifecycle wrapper | — | Next |
| Later | Listener handoff, cooperative drive and events, connections and runs, ceremony control and SAS presentation, results, native artifact distribution, final P8 closure | — | Planned |

## P7 wrapper handoff

The mandatory obligations of [ABI contract §21](../p7-native-abi/abi-contract.md#21-wrapper-handoff-p8-p9) and where P8 meets them.

| # | Obligation | P8 state |
|---:|---|---|
| 1 | Bind exactly ABI v1; check `sas_pairing_abi_version() == 1` before any other call | P8.1: the loader preflights all 25 exports and requires version `1` before publishing the library; `0` and any other value fail permanently |
| 2 | One native image, retained for the process lifetime; no close, unload, reload, reset, or alternate copy | P8.1: one `DynamicLibrary.open` from an explicit path, retained strongly; no such API exists; a second initialization opens nothing |
| 3 | Tell consumers that `SAS_PAIRING_FATAL` needs an OS process restart | P8.1: documented ([package README](../../dart/README.md)); surfaced by the high-level API from P8.2 |
| 4 | Caller-memory contract | P8.2+ (P8.1 makes no stateful call); the record layouts it will use are verified in P8.1 |
| 5 | Listener handoff through the in/out slot | Later increment (bound and symbol-checked only) |
| 6 | Cooperative bounded drive; consume every event, also when `out_failure` is not OK | Later increment (bound only; no drive loop, timer, or isolate exists) |
| 7 | SHOULD close a connection after `RUN_UNTRACKED` | Later increment |
| 8 | Explicit ceremony steps, `WRITE_PENDING` handling, decisions bound to the exact `ceremony_identity` | Later increment |
| 9 | Never construct, parse, or send frames; never confirm a final ACK | P8.1: no protocol code exists in Dart (guarded by a scope test); permanent |
| 10 | A result is local verified completion only | Later increment |
| 11 | Own the comparison UX and trust policy; no status is a trust verdict | P8.1 mirrors raw status values only, with no interpretation |

## Package layout (P8.1)

```text
dart/
  pubspec.yaml                 sas_pairing 0.1.0-dev.1, publish_to: none, runtime dep ffi
  analysis_options.yaml        package:lints/recommended + strict analyzer modes
  ffigen.yaml                  explicit ABI v1 generation filter
  lib/
    sas_pairing.dart           public entrypoint: exports nothing yet
    src/native/
      abi_v1.dart              frozen ABI v1 tables (exports, values, record sizes)
      native_library_loader.dart  process-lifetime loader
      generated/
        sas_pairing_bindings.g.dart  generated raw FFI (SasPairingNativeBindings)
  test/                        manifest, binding, layout, loader, real-artifact, scope tests
```

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
| Windows (x64) | The real `sas_pairing_core.dll` loads, binds, and reports ABI version 1 | Supported by P7 (Windows TCP carrier); the Dart API for it starts in later increments |
| Linux (x64) | The real `libsas_pairing_core.so` loads, binds, and reports ABI version 1 | Not supported: pairing operations fail closed (`SAS_PAIRING_UNSUPPORTED_PLATFORM`) as P7 defines |
| 32-bit processes | Refused before any library is opened | Not supported |

## Evidence

Recorded per increment at its closure.

## Nonclaims

P8 does not claim production readiness, security approval, an audit, formal verification, Linux or other non-Windows pairing support, cross-isolate enforcement of the one-image rule, protection against hostile in-process code, or recovery from `SAS_PAIRING_FATAL` without a process restart.
