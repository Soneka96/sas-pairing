# P9 — .NET Package

## Status

🔵 In progress — **P9 IN PROGRESS — P9.5 COMPLETE**: P9.1 (.NET package foundation + exact ABI v1 interop, [evidence](../docs/p9-dotnet-package/README.md#p91-evidence)), P9.2 (Runtime / Authority / Host lifecycle wrapper, [evidence](../docs/p9-dotnet-package/README.md#p92-evidence)), P9.3 (Windows listener ownership + cooperative network driver, [evidence](../docs/p9-dotnet-package/README.md#p93-evidence)), P9.4 (run + ceremony control + SAS presentation, [evidence](../docs/p9-dotnet-package/README.md#p94-evidence)), and P9.5 (PairingResult API + ownership, [evidence](../docs/p9-dotnet-package/README.md#p95-evidence)) are complete; P9.6 (.NET / native distribution + final P9 closure) is next and not started. Its native prerequisite is met: P7 is complete and native ABI v1 is frozen ([P7 final closure](../docs/p7-native-abi/final-closure.md), [P7-D-013](../docs/p7-native-abi/decisions.md#p7-d-013--abi-v1-final-freeze-and-wrapper-handoff)). P8, the Dart package, is complete ([P8 final closure](../docs/p8-dart-package/final-closure.md)) and merged. P9 work: [P9 package](../docs/p9-dotnet-package/README.md), [decisions](../docs/p9-dotnet-package/decisions.md).

## Increment plan

P9 is built in six increments on **one long-lived branch**, `feature/p9-dotnet-package`, created from `main` at `03afc8dd6ef8c473ef648ec7e06cee5042d0083a` (the merge of the P8 pull request #14). Every increment lands on that branch; there is no branch or pull request per increment, and exactly **one P9 pull request** is opened at the final P9 closure. Each increment closes only with its exact head green in CI. Only the current increment is designed in depth; later increments are milestone boundaries.

| Increment | Milestone | Boundary |
|---|---|---|
| P9.1 | .NET package foundation + exact ABI v1 interop | Solution and projects (`SasPairing`, `SasPairing.Tests`, `net10.0`), private exact ABI v1 constants, records, and 25-export function table, explicit-path process-lifetime loader, consistency, scope, and public-surface guards, Windows and Linux CI. No public pairing API ([P9-D-001](../docs/p9-dotnet-package/decisions.md#p9-d-001--net-abi-v1-binding-and-loader-architecture)) |
| P9.2 | Runtime / Authority / Host lifecycle wrapper | First public types: `IDisposable` runtime, authority, and host over the seven lifecycle exports with native-cascade ownership; the public initialization, status (48 values), native, and contract error model; process-wide `SAS_PAIRING_FATAL` and contract-violation latches (process restart only); exact binary authority scope; `READY` 1–10 status validation. Complete ([P9-D-002](../docs/p9-dotnet-package/decisions.md#p9-d-002--net-lifecycle-ownership-public-errors-and-fail-closed-state)) |
| P9.3 | Windows listener + cooperative network driver | Listening-socket handoff through the in/out slot over a package-owned duplicate descriptor, attach and repeatable detach, one bounded drive and one resume recheck, the frozen event model, `IDisposable` connections, owner-loop failure, `RUN_UNTRACKED` guidance, internal exact run and runtime-owned result references. Complete ([P9-D-003](../docs/p9-dotnet-package/decisions.md#p9-d-003--net-windows-listener-cooperative-drive-event-and-connection-ownership)) |
| P9.4 | Run + ceremony control + SAS presentation | One public run per exact native run handle (unknown request ID for a local start, learned once), the nine explicit trusted-local ceremony steps with no chaining or driving, the local-action model and its per-method contracts, status 205 versus the `WritePending` flag, read-only SAS presentation, decisions bound to the exact 32-byte `ceremony_identity`, known-ended runs refused locally, a real two-endpoint Windows ceremony through the public API. Complete ([P9-D-004](../docs/p9-dotnet-package/decisions.md#p9-d-004--net-run-identity-explicit-ceremony-control-and-sas-binding)) |
| P9.5 | PairingResult API + ownership | One public runtime-owned `IDisposable` result per exact native result handle, delivered only by its drive event (duplicate deliveries refused for the runtime's lifetime); survival of every teardown below the runtime and of `FATAL`; one consuming destroy, and no child destroy in the runtime cascade; one coherent read (one info and exactly one copy per field at the source-proven lengths, no negotiation), admitted after `FATAL` but not after a contract violation; immutable detached snapshots of exact binary fields and the PEER's role; local completion only. Complete ([P9-D-005](../docs/p9-dotnet-package/decisions.md#p9-d-005--net-pairingresult-ownership-reads-and-immutable-snapshots)) |
| P9.6 | .NET/native distribution + final P9 closure | NuGet and native artifact distribution decision, documentation and status cleanup, P9-wide audit, final closure, the one P9 pull request |

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
