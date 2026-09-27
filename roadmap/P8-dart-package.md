# P8 — Dart Package

## Status

🟡 Planned; gated on the native implementation and boundary.

## Goal

Create an idiomatic Dart/Flutter wrapper over the native implementation.

## Why this phase exists

Dart consumers need a usable package while sharing the same reviewed protocol implementation.

## Inputs / prerequisites

The P7 native boundary and its supported platform behavior.

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

The .NET wrapper in P9 and consumer integration examples in P10.
