# Initial threat model contract

This document records the intended problem and security boundary. It is not a completed threat model and does not select a cryptographic construction.

## Scenario

Two devices want to establish trust over a network that may be controlled by an active attacker. A user can see both device displays and compare a short alphanumeric value, for example:

```text
7K3-M2Q8D
```

The user compares the values without typing them. The SAS is neither a password nor a bearer credential. This value is illustrative only; it does not select an alphabet, length, grouping, or entropy value.

## Attacker capabilities

Assume an attacker can intercept, modify, replay, delay, reorder, drop, and create network messages, and can attempt to conduct separate ceremonies with each device. Network endpoint and address do not establish identity. A display name is not identity. A public-key claim alone is not proof of possession.

## Intended properties

- Resist an active man-in-the-middle during initial pairing, subject to the eventual construction and human-comparison assumptions.
- Bind a successful pairing result to one exact ceremony; stale human approval must not authorize a different ceremony.
- Keep each party's long-term private keys under that party's control; they never leave their owner.
- Allow the consuming application to provide identity and context data for the protocol to authenticate and bind. Supplied data is not trusted merely because the application supplied it; the protocol must define and verify what becomes authenticated.
- Fail closed when ceremony state or human approval is ambiguous.

## Assumptions and scope

Human comparison is part of the security system, not a perfect channel. People may compare only part of a SAS, check only its beginning or end, approve accidentally, confuse glyphs, or be unable to see displays at a useful distance. Repeated mismatches and attacker-induced ceremonies can create fatigue and encourage careless approval. Accessibility, including screen readers, and localization also affect whether comparison is reliable.

The eventual profile must account for realistic human comparison behavior when specifying SAS length, alphabet, grouping, rendering, retry constraints, and UX requirements. This work does not attempt to mathematically solve those human factors. Endpoint compromise, malicious operating systems, coerced users, compromised displays, and application authorization policy need explicit treatment in the full threat model.

## Unresolved

No final cryptographic construction, key agreement or KEM, commitment scheme, context encoding, SAS length or alphabet, grouping or rendering, security-required attempt bound, wire format, key lifetime, or recovery behavior is specified here. The protocol/security contract must define any attempt, cooldown, ceremony, lifetime, or persistent-counter constraints its security argument requires; exact values and enforcement integration remain open. These questions require protocol requirements, primary-source analysis, and review before implementation. This document makes no claim that the target properties have been achieved.
