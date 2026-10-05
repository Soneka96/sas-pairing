# P10 — Consumer Integration

## Status

🔵 Next (not started). Its package prerequisite is met: the experimental Dart package (P8, [final closure](../docs/p8-dart-package/final-closure.md)) and .NET package (P9, [final closure](../docs/p9-dotnet-package/final-closure.md)) wrap the frozen native ABI v1, with Windows x64 as the only pairing platform. P10 is planned in depth only when it starts.

## Goal

Provide integration examples and integrate with the original consumer, DovahLink.

## Why this phase exists

Examples help consumers adopt the reusable pairing library without making one application's policy part of the protocol.

## Inputs / prerequisites

The reviewed native implementation, supported wrappers, and their documented security contract.

## Scope

Demonstrate pairing integration and the boundary between protocol results and each consumer's trust, reconnect, authorization, and application policy. Where the selected protocol requires consumer-provided persistence or attempt enforcement, show that integration preserves those constraints.

## Out of scope

Moving DovahLink-specific trust, reconnect, discovery, authorization, or application policy into `sas-pairing`.

## Deliverables

Consumer integration examples and a DovahLink integration that follows the library's application-neutral contract.

## Security invariants

Human comparison remains part of the security system. Pairing does not silently grant durable trust or application authorization.

## Exit criteria

The examples and consumer integration use the reviewed packages without weakening protocol-required constraints or implying unsupported identity/context guarantees.

## STOP conditions

Stop if integration requires weakening a security requirement or moving consumer policy into the protocol boundary.

## What this unlocks

Readiness assessment for a possible 1.0 release. P10 completion alone does not authorize 1.0.
