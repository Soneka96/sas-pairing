# P9 — .NET Package

## Status

🟡 Planned; gated on the native implementation and boundary.

## Goal

Create an idiomatic .NET wrapper over the same native implementation.

## Why this phase exists

.NET consumers need a usable package without introducing a second production protocol implementation.

## Inputs / prerequisites

The P7 native boundary and its supported platform behavior.

**Mandatory loader prerequisite ([P7-D-002](../docs/p7-native-abi/decisions.md#p7-d-002--native-library-residency-and-loader-lifetime), [ABI contract §14](../docs/p7-native-abi/abi-contract.md#14-native-library-loading-and-residency)).** The .NET wrapper loads the native library once and retains its `NativeLibrary` or module handle for the process lifetime. It never calls `NativeLibrary.Free` during supported use, exposes no reload or reset as recovery, and loads no alternate copy of the library. It tells consumers that after `SAS_PAIRING_FATAL` the only recovery is restarting the process.

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
