# P1 — Threat Model and Protocol Requirements

## Status

✅ Complete. Clarified for the owner-approved authenticated-bootstrap result contract and separate same-device profile requirements.

## Goal

Define the security problem and the requirements future protocol candidates must justify.

## Why this phase exists

Construction research needs a stable, explicit set of attacker capabilities, ceremony semantics, and security requirements to evaluate.

## Inputs / prerequisites

P0 repository foundation.

## Scope

P1 establishes participant roles, the active network-attacker model, ceremony and human-approval boundaries, required pairing properties, context binding, replay and concurrency requirements, failure handling, repeated-attempt concerns, and a language-neutral result contract. A reusable shared key is not mandatory; mutually authenticated bootstrap data bound to the exact ceremony, roles, and authenticated security-relevant context is sufficient. Public-key bytes do not imply proof of possession. A separately justified OS-authenticated same-device profile may omit human SAS only under its specified trust predicate; metadata claims such as loopback, IP, or hostname do not establish it. These are requirements, not proof that any production protocol or local profile has been implemented.

## Out of scope

Selecting a construction, primitives, security bound, encoding, wire format, API, or implementation.

## Deliverables

The authoritative [threat model and protocol requirements](../docs/threat-model.md). This phase summary does not replace or duplicate that document.

## Security invariants

Requirements must be justified by a candidate's security analysis and assumptions. Unmet or unjustified requirements cannot be presented as guarantees.

## Exit criteria

The threat model records the attacker model, accepted result contract, profile requirements, security boundaries, and unresolved profile decisions. Remote pairing over untrusted networks still requires an active-attacker-resistant construction.

## What this unlocks

P2 construction selection and formal mapping against the documented requirements; P2 selects Candidate B for the remote profile.
