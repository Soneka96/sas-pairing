# P8 — Dart Package

## Status

🔵 **P8 IN PROGRESS — P8.4 COMPLETE; P8.5 next.** Its native prerequisite is met: P7 is complete and native ABI v1 is frozen ([P7 final closure](../docs/p7-native-abi/final-closure.md), [P7-D-013](../docs/p7-native-abi/decisions.md#p7-d-013--abi-v1-final-freeze-and-wrapper-handoff)). Work happens on the one branch `feature/p8-dart-package` from `main` at `80ecbb1` (the P7 pull request merge), with one pull request at P8 closure. Package: [docs/p8-dart-package](../docs/p8-dart-package/README.md); decisions: [P8-D-001](../docs/p8-dart-package/decisions.md#p8-d-001--dart-native-binding-and-loader-architecture), [P8-D-002](../docs/p8-dart-package/decisions.md#p8-d-002--dart-lifecycle-ownership-and-fail-closed-state), [P8-D-003](../docs/p8-dart-package/decisions.md#p8-d-003--dart-windows-listener-cooperative-drive-and-connection-lifetime), [P8-D-004](../docs/p8-dart-package/decisions.md#p8-d-004--dart-run-identity-explicit-ceremony-control-and-sas-binding).

| Increment | Scope | State |
|---|---|---|
| P8.1 | Dart package foundation and the frozen native ABI v1 bindings: pure-Dart package `sas_pairing`, generated private raw FFI, process-lifetime loader (explicit path, 64-bit gate, symbol preflight, ABI version 1), consistency tests, Windows and Linux CI ([P8-D-001](../docs/p8-dart-package/decisions.md#p8-d-001--dart-native-binding-and-loader-architecture)) | **Complete** ([evidence](../docs/p8-dart-package/README.md#p81-evidence)) |
| P8.2 | Runtime / Authority / Host lifecycle wrapper: public lifecycle objects, status and exception model, explicit consuming `close()` mirroring the native cascade, process FATAL and contract-violation latches; P8.2.1 correction: public `SasPairingInitializationException` for native-library initialization failures and the `READY` 1–10 bound ([P8-D-002](../docs/p8-dart-package/decisions.md#p8-d-002--dart-lifecycle-ownership-and-fail-closed-state)) | **Complete** ([evidence](../docs/p8-dart-package/README.md#p82-evidence), [P8.2.1](../docs/p8-dart-package/README.md#p821-evidence)) |
| P8.3 | Windows listener ownership + cooperative network driver: Bootstrap value model, listening-socket ownership handoff, attach and detach, bounded host drive and resume recheck, event mapping, connection wrappers, `RUN_UNTRACKED` close guidance ([P8-D-003](../docs/p8-dart-package/decisions.md#p8-d-003--dart-windows-listener-cooperative-drive-and-connection-lifetime)) | **Complete** ([evidence](../docs/p8-dart-package/README.md#p83-evidence)) |
| P8.4 | Run + ceremony control + SAS presentation: public runs (exact native handle, never request ID), the local Initiator start, the explicit trusted-local ceremony steps, SAS presentation and ceremony-identity binding, `WRITE_PENDING` status versus flag; a real two-endpoint Windows ceremony through the public API ([P8-D-004](../docs/p8-dart-package/decisions.md#p8-d-004--dart-run-identity-explicit-ceremony-control-and-sas-binding)) | **Complete** ([evidence](../docs/p8-dart-package/README.md#p84-evidence)) |
| P8.5 | PairingResult API + result ownership | Next |
| Later | Native artifact distribution, P8 closure | Planned |

## Goal

Create an idiomatic Dart/Flutter wrapper over the native implementation.

## Why this phase exists

Dart consumers need a usable package while sharing the same reviewed protocol implementation.

## Inputs / prerequisites

The P7 native boundary and its supported platform behavior: the frozen native ABI v1 ([ABI contract](../docs/p7-native-abi/abi-contract.md), [ABI v1 manifest](../docs/p7-native-abi/abi-v1-manifest.md), [`sas_pairing.h`](../core/include/sas_pairing.h)). Networking is supported on Windows only (the Windows TCP carrier); elsewhere pairing operations fail closed with `SAS_PAIRING_UNSUPPORTED_PLATFORM`.

**Mandatory ABI v1 prerequisite ([P7-D-013](../docs/p7-native-abi/decisions.md#p7-d-013--abi-v1-final-freeze-and-wrapper-handoff), [ABI contract §21](../docs/p7-native-abi/abi-contract.md#21-wrapper-handoff-p8-p9)).** The Dart wrapper binds exactly ABI v1 and checks `sas_pairing_abi_version() == 1`; loads one native image and retains its `DynamicLibrary` for the process lifetime, with no unload, reload, reset, or alternate copy; treats `SAS_PAIRING_FATAL` as requiring an OS process restart; keeps the caller-owned pointer and buffer contracts (non-null aligned outputs, explicit capacities and lengths, no retained pointers, no Rust allocation to free); hands listening sockets over through the in/out ownership slot and never touches a socket whose slot reads `SAS_PAIRING_SOCKET_INVALID`; drives with the bounded cooperative drive and recheck and consumes every returned event, also when `out_failure` is not `SAS_PAIRING_OK`; and never changes, renumbers, or reinterprets any frozen value, layout, or ownership rule.

**Mandatory loader prerequisite ([P7-D-002](../docs/p7-native-abi/decisions.md#p7-d-002--native-library-residency-and-loader-lifetime), [ABI contract §14](../docs/p7-native-abi/abi-contract.md#14-native-library-loading-and-residency)).** The Dart wrapper loads the native library once and retains the `DynamicLibrary` for the process lifetime. It exposes no close, unload, or reload, including as recovery, and loads no alternate copy of the library. It tells consumers that after `SAS_PAIRING_FATAL` the only recovery is restarting the process.

**Mandatory ceremony-control handoff ([P7-D-009](../docs/p7-native-abi/decisions.md#p7-d-009--connection--run-reference-semantics), [P7-D-011](../docs/p7-native-abi/decisions.md#p7-d-011--trusted-local-ceremony-action-abi), [P7-D-012](../docs/p7-native-abi/decisions.md#p7-d-012--sas-presentation-identity-binding-and-local-action-statuses), [ABI contract §20](../docs/p7-native-abi/abi-contract.md#20-trusted-local-ceremony-control)).** When a drive event carries `SAS_PAIRING_EVENT_FLAG_RUN_UNTRACKED`, the Dart wrapper SHOULD close that connection (`sas_pairing_connection_close`): the run exists in the core but has no run handle, so no trusted local ceremony action can target it. The native library does not close it itself and never evicts another run. The wrapper keeps every local step explicit (exposure authorization never exposes, MATCH never emits BOOTSTRAP_MAC, BOOTSTRAP_MAC never emits INITIATOR_FINISH), treats `SAS_PAIRING_WRITE_PENDING` as "drive, then retry if still appropriate", sends no protocol bytes and confirms no final ACK itself (the library writes every frame and confirms the final ACK), binds every MATCH, MISMATCH, and CANCEL to the exact presented 32-byte `ceremony_identity` (never a request ID or handle), owns the SAS comparison UX, presents a result as local verified completion only, and never maps a status to a trust verdict.

## Scope

Provide the Dart-facing wrapper and verify that it correctly uses the native core. If the native contract requires consumer-provided persistence, preserve that contract and its security-required state across ceremonies and restarts.

## Out of scope

Independent Dart production cryptography or moving consumer-specific trust and authorization policy into the pairing protocol.

## Deliverables

A Dart/Flutter package that delegates security-sensitive protocol work to the native core.

## Security invariants

No independent production cryptography; wrapper behavior must preserve the core's fail-closed contract and must not bypass or reset security-required attempt or persistence constraints.

## Exit criteria

The wrapper can be used by Dart/Flutter consumers and its behavior is consistent with the native core.

## What this unlocks

P9 is next in the planned work order but remains independently gated on P7; P10 follows when both wrappers are ready.
