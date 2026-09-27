# Architecture

The project separates a reusable pairing protocol from application policy and platform concerns. The following boundaries describe intended ownership; they do not imply that these components exist yet.

## Security core

The future core owns the pairing protocol state machine, cryptographic ceremony, canonical protocol bytes, SAS derivation, key derivation that belongs directly to the pairing construction, and verification of cryptographic pairing messages.

The core does not own application trust databases, authorization policy, user interface, device names, network discovery, application-specific blocking or revocation, or long-term application session state.

## Dart wrapper

The future Dart package provides an idiomatic Dart API over the native core. It does not implement an independent production cryptographic protocol.

## .NET wrapper

The future .NET package provides an idiomatic C# API over the same native core. It does not implement an independent production cryptographic protocol.

## Consumer application

The consumer supplies the identity and authenticated context that the protocol needs to bind, and owns application identity semantics, authorization, pair / reject / block behavior, durable trust, application retry policy, user interface, discovery, and network transport unless a future protocol specification explicitly requires otherwise.

Network endpoint or address and display name are not identities. The core must not encode any one consumer's trust-store or domain concepts.

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
