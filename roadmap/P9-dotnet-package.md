# P9 — .NET Package

## Status

🟡 Planned; gated on the native implementation and boundary.

## Goal

Create an idiomatic .NET wrapper over the same native implementation.

## Why this phase exists

.NET consumers need a usable package without introducing a second production protocol implementation.

## Inputs / prerequisites

The P7 native boundary and its supported platform behavior.

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
