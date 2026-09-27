# P3 — Protocol Profile and Deterministic Vectors

## Status

🔵 In progress — P3.1 profile foundation drafted; security-sensitive profile decisions and vectors remain.

## Goal

Define the selected remote construction as a concrete, language-neutral profile with deterministic conformance vectors, and specify the separate same-device local profile. Do not implement production cryptography in P3.

## Why this phase exists

Implementation and independent review need one precise profile that removes ambiguity while staying within the construction and assumptions justified in P2.

## Inputs / prerequisites

- P2's selected Candidate B remote construction, evidence, assumptions, limitations, and justified security bound.
- P1 requirements and the authoritative architecture and protocol-status documents.

## Scope

**Remote Candidate B profile:** define a deterministic mapping between generic Initiator/Responder roles and Candidate B's S/R positions; exact bootstrap message schemas; canonical encoding; authenticated/fixed protocol, profile, and version negotiation with downgrade prevention; SID generation and lifecycle; commitment instantiation; random-oracle/hash profile; SAS bit length and rendering; full-comparison UX contract; bilateral confirmation semantics; aggregate attempt/retry budget; persistence across restart; stale approval handling; cancellation; timeout; concurrent ceremonies; terminal-state handling; and deterministic vectors. Any consumer-specific Host/Client mapping is a non-normative integration example, not a generic protocol role. Preserve the ideal-OOB assumptions and human-error limits; do not present the theorem as a guarantee against human mistakes or atomic durable storage. Carry the exact authenticated public-key bytes unchanged into later pinning/proof-of-possession checks; do not silently replace an identity key, and require explicit re-pairing under a new trust epoch for identity changes.

**Same-device local profile:** define the OS-authentication primitive/interface, local authorization rule, locality establishment, remote exclusion, ceremony/session identifier, explicit ceremony-specific approval by the authorizing participant, stale/replay behavior, compatible bootstrap-result semantics, and interaction with Always require SAS. Do not treat same machine, loopback, IP, hostname, discovery name, process name, or LAN proximity as proof. Do not claim resistance to an attacker controlling the trusted OS/user boundary enough to impersonate or control the authorized participant. Do not select low-level APIs without evidence.

## Out of scope

Reopening P2 decisions without recording the evidence that requires it; implementation; language-specific APIs or ABI; consumer-specific policy; and unsupported security claims.

## Deliverables

A reviewed candidate profile, explicit decision records for durable choices as appropriate, and deterministic vectors that independent implementations can consume. Vector correctness is conformance evidence, not proof of cryptographic security.

## Security invariants

Keep the profile application-neutral, fail closed on invalid or ambiguous state, avoid silent downgrade/fallback, and preserve all justified ceremony, role, transcript, context, approval, and attempt constraints.

## Exit criteria

The profile is sufficiently precise for independent implementation and review; all security-sensitive choices trace to P2 evidence; vectors cover positive behavior and meaningful negative or mutation cases.

## STOP conditions

Return to P2 or stop if the selected construction cannot support a required profile decision or if the profile would exceed its evidence.

## What this unlocks

P4 implementation planning for the reviewed and specified security profiles in one native security core, subject to security review gates.
