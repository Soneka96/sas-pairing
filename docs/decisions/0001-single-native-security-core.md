# 0001 — Use one native security core

## Status

Accepted as the intended implementation architecture. The P4 experimental native Rust security core is implemented; a public native API/ABI and the Dart and .NET bindings do not yet exist.

Status update (P8 closure, 2026-10-04): the native ABI v1 now exists and is frozen ([P7 final closure](../p7-native-abi/final-closure.md)), and the experimental Dart binding exists as a wrapper around the one core ([P8 final closure](../p8-dart-package/final-closure.md)); the .NET binding (P9) does not yet exist. The decision is unchanged.

## Context

The project intends to support Dart and .NET consumers while keeping security-sensitive protocol behavior consistent and reviewable. Separate production cryptographic implementations would multiply the code that needs review and risk divergent behavior.

## Decision

Implement the production pairing protocol once in a native core. Provide Dart and .NET APIs as wrappers around that core, not as independent production cryptography. Rust is the current intended implementation language for the core, but this ADR does not make Rust an irreversible cryptographic design decision.

## Security consequences

One implementation can concentrate security review and conformance testing. Native bindings introduce ABI and lifecycle concerns that will need their own design and testing before wrappers are implemented. This architecture does not itself establish protocol security.

## Alternatives considered

- Independent Dart and C# protocol implementations: rejected because they duplicate security-sensitive behavior.
- Selecting wrapper APIs or a native ABI before a protocol and core API exist: deferred as premature.
