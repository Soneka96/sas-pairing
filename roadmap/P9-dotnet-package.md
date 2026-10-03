# P9 — .NET Package

## Status

🟡 Planned. Its native prerequisite is met: P7 is complete and native ABI v1 is frozen ([P7 final closure](../docs/p7-native-abi/final-closure.md), [P7-D-013](../docs/p7-native-abi/decisions.md#p7-d-013--abi-v1-final-freeze-and-wrapper-handoff)). Not started; P8 comes first in the planned order.

## Goal

Create an idiomatic .NET wrapper over the same native implementation.

## Why this phase exists

.NET consumers need a usable package without introducing a second production protocol implementation.

## Inputs / prerequisites

The P7 native boundary and its supported platform behavior: the frozen native ABI v1 ([ABI contract](../docs/p7-native-abi/abi-contract.md), [ABI v1 manifest](../docs/p7-native-abi/abi-v1-manifest.md), [`sas_pairing.h`](../core/include/sas_pairing.h)). Networking is supported on Windows only (the Windows TCP carrier); elsewhere pairing operations fail closed with `SAS_PAIRING_UNSUPPORTED_PLATFORM`.

**Mandatory ABI v1 prerequisite ([P7-D-013](../docs/p7-native-abi/decisions.md#p7-d-013--abi-v1-final-freeze-and-wrapper-handoff), [ABI contract §21](../docs/p7-native-abi/abi-contract.md#21-wrapper-handoff-p8-p9)).** The .NET wrapper binds exactly ABI v1 and checks `sas_pairing_abi_version() == 1`; loads one native image and retains its `NativeLibrary` handle for the process lifetime and never calls `NativeLibrary.Free` during supported use, with no unload, reload, reset, or alternate copy; treats `SAS_PAIRING_FATAL` as requiring an OS process restart; keeps the caller-owned pointer and buffer contracts (non-null aligned outputs, explicit capacities and lengths, no retained pointers, no Rust allocation to free); hands listening sockets over through the in/out ownership slot and never touches a socket whose slot reads `SAS_PAIRING_SOCKET_INVALID`; drives with the bounded cooperative drive and recheck and consumes every returned event, also when `out_failure` is not `SAS_PAIRING_OK`; and never changes, renumbers, or reinterprets any frozen value, layout, or ownership rule.

**Mandatory loader prerequisite ([P7-D-002](../docs/p7-native-abi/decisions.md#p7-d-002--native-library-residency-and-loader-lifetime), [ABI contract §14](../docs/p7-native-abi/abi-contract.md#14-native-library-loading-and-residency)).** The .NET wrapper loads the native library once and retains its `NativeLibrary` or module handle for the process lifetime. It never calls `NativeLibrary.Free` during supported use, exposes no reload or reset as recovery, and loads no alternate copy of the library. It tells consumers that after `SAS_PAIRING_FATAL` the only recovery is restarting the process.

**Mandatory ceremony-control handoff ([P7-D-009](../docs/p7-native-abi/decisions.md#p7-d-009--connection--run-reference-semantics), [P7-D-011](../docs/p7-native-abi/decisions.md#p7-d-011--trusted-local-ceremony-action-abi), [P7-D-012](../docs/p7-native-abi/decisions.md#p7-d-012--sas-presentation-identity-binding-and-local-action-statuses), [ABI contract §20](../docs/p7-native-abi/abi-contract.md#20-trusted-local-ceremony-control)).** When a drive event carries `SAS_PAIRING_EVENT_FLAG_RUN_UNTRACKED`, the .NET wrapper SHOULD close that connection (`sas_pairing_connection_close`): the run exists in the core but has no run handle, so no trusted local ceremony action can target it. The native library does not close it itself and never evicts another run. The wrapper keeps every local step explicit (exposure authorization never exposes, MATCH never emits BOOTSTRAP_MAC, BOOTSTRAP_MAC never emits INITIATOR_FINISH), treats `SAS_PAIRING_WRITE_PENDING` as "drive, then retry if still appropriate", sends no protocol bytes and confirms no final ACK itself (the library writes every frame and confirms the final ACK), binds every MATCH, MISMATCH, and CANCEL to the exact presented 32-byte `ceremony_identity` (never a request ID or handle), owns the SAS comparison UX, presents a result as local verified completion only, and never maps a status to a trust verdict.

## Scope

Provide the .NET-facing wrapper and verify that it correctly uses the native core. If the native contract requires consumer-provided persistence, preserve that contract and its security-required state across ceremonies and restarts.

## Out of scope

Independent C# production cryptography or moving consumer-specific trust and authorization policy into the pairing protocol.

## Deliverables

A .NET package that delegates security-sensitive protocol work to the native core.

## Security invariants

No independent production cryptography; wrapper behavior must preserve the core's fail-closed contract and must not bypass or reset security-required attempt or persistence constraints.

## Exit criteria

The wrapper can be used by .NET consumers and its behavior is consistent with the native core.

## What this unlocks

Consumer integration examples and the DovahLink example in P10.
