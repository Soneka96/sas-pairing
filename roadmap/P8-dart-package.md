# P8 — Dart Package

## Status

🟡 Planned; gated on the native implementation and boundary.

## Goal

Create an idiomatic Dart/Flutter wrapper over the native implementation.

## Why this phase exists

Dart consumers need a usable package while sharing the same reviewed protocol implementation.

## Inputs / prerequisites

The P7 native boundary and its supported platform behavior.

**Mandatory loader prerequisite ([P7-D-002](../docs/p7-native-abi/decisions.md#p7-d-002--native-library-residency-and-loader-lifetime), [ABI contract §14](../docs/p7-native-abi/abi-contract.md#14-native-library-loading-and-residency)).** The Dart wrapper loads the native library once and retains the `DynamicLibrary` for the process lifetime. It exposes no close, unload, or reload, including as recovery, and loads no alternate copy of the library. It tells consumers that after `SAS_PAIRING_FATAL` the only recovery is restarting the process.

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
