# Architecture

The project separates a reusable pairing protocol from application policy and platform concerns. The following boundaries describe intended ownership; they do not imply that these components exist yet.

## Security core

The future core owns the pairing protocol state machine, cryptographic ceremony, canonical protocol bytes, SAS derivation, key derivation that belongs directly to the pairing construction, and verification of cryptographic pairing messages.

The core does not own application trust databases, authorization policy, user interface, device names, network discovery, application-specific blocking or revocation, or long-term application session state.

## Dart wrapper

The experimental Dart package ([`dart/`](../dart/README.md), complete in P8) provides an idiomatic Dart API over the native core through the frozen native ABI v1. It does not implement an independent production cryptographic protocol. Its Windows x64 native library is distributed separately as an experimental CI artifact and loaded from an explicit absolute path ([P8 final closure](p8-dart-package/final-closure.md)).

## .NET wrapper

The future .NET package provides an idiomatic C# API over the same native core. It does not implement an independent production cryptographic protocol.

## Consumer application

The consumer supplies identity and application-context values for the ceremony to authenticate and bind. Supplying a value does not make it trusted or authenticated; only values explicitly covered by the selected protocol may be described as authenticated and bound. The protocol will define which context fields receive that protection; this document does not freeze them.

The consumer owns application identity semantics, authorization, pair / reject / block behavior, durable trust, user interface, discovery, and network transport unless a future protocol specification explicitly requires otherwise. Network endpoint or address and display name are not identities. The core must not encode any one consumer's trust-store or domain concepts.

## Attempt constraints and product policy

The protocol/security contract defines any maximum attempts, cooldowns, ceremony limits, lifetime or session bounds, persistent counters, or other constraints required by its security argument. Enforcement may require consumer-provided storage or integration, but a consumer cannot bypass a required constraint while still claiming the same protocol security guarantees. Exact constraints remain unresolved until the protocol is selected.

Consumers may present cooldowns in their UX and apply stricter limits, product-specific abuse handling, administrative lockouts, and additional rate limiting. Consumer policy may make the protocol stricter, not weaken its security-required minimums.

## Intended data flow

```text
Consumer identity and context
             |
             v
Dart or .NET wrapper ---- native security core
             |                    |
       consumer UI / policy   pairing ceremony and SAS
```

The exact API boundary, native interface, and transport responsibilities remain open until protocol requirements are settled.
