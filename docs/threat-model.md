# Threat model and protocol requirements

## Purpose and status

This document defines the security problem and requirements that a future candidate protocol must satisfy. It defines **what** pairing must guarantee, not the cryptographic construction or implementation that provides those guarantees. A candidate must justify each claimed property against its construction, security analysis, and stated assumptions; listing a requirement here does not mean this project currently meets it.

This project is pre-alpha. No production protocol or production cryptography has been selected or implemented. Pasini–Vaudenay SAS-based authenticated key agreement remains a research candidate. Shortcake is evidence and implementation reference material only unless separately evaluated. No key-agreement or KEM profile, commitment construction, final SAS encoding, wire format, or API is selected here. `sas-pairing` remains application-neutral; DovahLink is an original consumer/example, not part of the protocol core.

The terms **MUST**, **MUST NOT**, and **SHOULD** state requirements for evaluating a future protocol and its consumers. They are not claims about existing capabilities.

## Actors and roles

- **Endpoint / participant:** One device or process taking part in a pairing ceremony. A participant has a local protocol role and local application inputs; neither fact by itself establishes an identity.
- **Initiator:** The participant that starts a particular protocol run. Initiator is a protocol role, not a trusted identity or proof that the participant is entitled to pair.
- **Responder:** The participant that joins that run. Responder is likewise a protocol role, not a trusted identity or proof of entitlement.
- **Consumer / application:** Software that invokes pairing, may supply application context, presents or coordinates the human comparison, and decides whether and how to establish application-level trust from the result. Consumer-supplied values are inputs, not authenticated facts merely because the consumer supplied them.
- **Human approver:** A person acting for the intended pairing who compares the SAS shown for both participants in the same live ceremony and explicitly approves that ceremony after a match. The protocol does not establish the approver's identity or make the human comparison a perfect authenticated channel.
- **Network attacker:** An active attacker with the capabilities described below. The attacker need not control either endpoint to attack the network exchange.

Roles identify protocol behavior only. A network endpoint or address is not identity; a display name is not identity; and a public-key claim alone is not proof of possession. If a pairing result claims that a peer controls or owns a specific public key, the selected protocol MUST establish proof of control of the corresponding private key. Unless that proof has been established, the result MUST NOT describe the public-key relationship as authenticated proof of possession or authenticated ownership.

## Attacker model and security boundary

Assume the attacker may observe, intercept, modify, replay, reorder, delay, drop, inject, and create messages; initiate repeated ceremonies; create separate sessions to each participant; and attempt an active man-in-the-middle attack. The network provides no trusted identity, ordering, delivery, or freshness.

The attacker model is not weakened by excluding endpoint compromise. The protocol alone cannot protect against a compromised endpoint or operating system, malicious local software with equivalent privileges, a compromised display or input surface, a coerced user, or an attacker who controls the trusted human comparison itself. These are out of scope for the protocol's network guarantees and must not be described as attacks the protocol defeats.

## Pairing ceremony and identity

One **pairing ceremony** is one logically distinct protocol run, from its accepted start through its terminal outcome. Each run must be distinguishable in protocol state from every previous, retried, concurrent, or attacker-created run. This is a requirement on candidate protocols, not a choice of identifier or mechanism.

A retry is a new ceremony. Concurrent ceremonies are separate ceremonies even when they involve the same participants or context. An attacker-created run is not interchangeable with the run the user intended to approve. Messages, approval, and results must be attributable to the exact ceremony to which they belong.

Successful pairing MUST apply only to the exact ceremony whose SAS the human compared and whose approval was accepted. A candidate MUST explain how both participants agree on that same ceremony and how its identity is bound to the role, peer, applicable context, and protocol state required by the construction. A participant MUST NOT infer agreement from matching addresses, display names, arrival order, or an unbound public-key claim.

## Human approval and the SAS

The human approver compares the SAS displayed for both participants for the intended, active ceremony. A **match** means the approver determines that the two displayed values are the same, according to the comparison procedure presented by the consumer. The protocol must not silently treat a partial comparison or a consumer's automatic matching as equivalent to an explicit human comparison and approval.

Approval authorizes completion of that one ceremony, subject to all protocol checks. It MUST NOT authorize another or later ceremony, a different peer or role, an unbound context, application permissions, or durable application trust by itself. The consumer makes its own trust and authorization decisions from the pairing result.

The SAS is a value for human comparison. It is **not** a PIN, password, bearer token, or secret that must remain confidential. Its security purpose and required handling must be justified by the selected protocol and SAS security model. No numeric minimum SAS guessing/security target has yet been justified; selecting one remains a required research and decision gate. A final SAS profile MUST NOT be selected until that target and the repeated-attempt assumptions are justified. The approximately 40-bit Crockford Base32 direction remains only a candidate, not the security target. This document does not select an alphabet, bit length, grouping, or rendering scheme.

Human comparison is part of the security system, not a perfect channel. A candidate's security analysis and consumer guidance must account for partial comparison, misread characters, accidental approval, fatigue, repeated attacker-induced ceremonies, accessibility needs, and localization or rendering differences. The design must not claim a stronger human-comparison assurance than its comparison procedure reasonably supports.

## Required properties of successful pairing

A future protocol may claim successful pairing only if its security argument justifies, under explicit assumptions, that:

- both participants accept the same exact ceremony and compatible terminal outcome;
- protocol roles are bound so that messages, SAS, approval, and result cannot be reassigned across initiator and responder roles;
- each participant is bound to the peer participating in that ceremony, without treating an address, display name, or unsupported public-key assertion as identity or proof of possession;
- the run is fresh and cannot be completed using stale ceremony state or stale approval;
- the transcript and relevant protocol context are bound wherever required by the construction, including negotiated choices whose change could weaken security;
- an active man-in-the-middle attack is resisted to the bound justified by the construction, SAS model, human-comparison assumptions, and allowed attempts;
- downgrade, ambiguity, or an unmet security requirement does not silently produce success; and
- any long-term private key material used by a participant remains under that participant's control and is not disclosed by the protocol.

These are evaluation requirements, not established results. The exact security bound and the construction needed to support it remain unresolved. If a candidate cannot justify a property, the documentation must narrow the claim or reject that candidate; it must not turn an aspiration into a guarantee.

## Application context

A consumer may supply values describing application-specific context or asserting application identity. They are inputs. Supplying, displaying, or locally trusting a value does not make it authenticated, correct, or shared by the peer, and binding an application assertion does not by itself prove a real-world identity. A selected value becomes cryptographically meaningful only if the eventual protocol explicitly and unambiguously binds it as required by its security analysis, and the participants verify the relevant binding.

The candidate specification must state which context, if any, it binds and how differing or absent values affect success. A context value not covered by that specification MUST NOT be represented as authenticated by pairing. Context binding must not be inferred from transport metadata, display names, or application-side intent. This generic protocol does not define consumer-specific fields or DovahLink concepts.

## Replay and freshness

Candidate protocols must justify freshness and reject or render ineffective, as applicable:

- messages replayed from an old or already terminal ceremony;
- approval replayed from an old ceremony, including after a retry;
- messages or approval replayed after the ceremony has expired;
- data from one concurrent ceremony accepted as data for another;
- messages, state, approval, or results replayed across initiator and responder roles; and
- messages, state, approval, or results replayed across distinct cryptographically bound application contexts, or across application contexts where those contexts are part of the selected protocol binding.

Duplicate or reordered delivery must not cause a stale or incomplete run to become successful. No concrete nonce, counter, timestamp, transcript format, or cryptographic mechanism is selected here.

## Concurrent ceremonies

Multiple ceremonies may coexist. Every accepted message, human approval, and pairing result MUST remain associated with one exact ceremony and its participants, roles, and applicable context. Approval for ceremony A must never authorize ceremony B; messages from A must never satisfy B's protocol state; and participants must not confuse one ceremony's identity with another's. A candidate must justify these properties without relying on user-visible ordering alone. This document sets no arbitrary concurrency limit.

## Cancellation, disconnect, expiry, and errors

- **Peer disconnect:** A disconnect must not cause incomplete or stale state to count as success. A candidate must specify whether safe continuation is possible; continuation, if supported, must remain bound to the same exact ceremony and all freshness requirements. Otherwise the ceremony is abandoned.
- **Application cancellation:** Cancellation terminates the local ceremony. Its later messages or approval must not revive it or authorize a new ceremony.
- **Human rejection:** Rejection terminates that ceremony without a successful pairing result. A later attempt is a new ceremony.
- **Expiry:** An expired ceremony cannot succeed or be resumed as if fresh. Exact lifetime values remain for later security analysis.
- **Malformed input:** Malformed or invalid protocol input must not be interpreted permissively in a way that weakens a security requirement or advances ambiguous state to success.
- **Ambiguous state:** Conflicting, missing, or uncertain security-sensitive state fails closed. Recovery must not accidentally make stale state valid again.

The protocol and consumer behavior must not report success until the required checks and approval for that ceremony have completed. Failure, cancellation, and expiry handling must not leak a stale approval into another run.

## Repeated attempts and required state

SAS security must account for repeated attacker attempts, including attacker-induced ceremonies and repeated guesses. A security analysis must state the relevant attempt assumptions and resulting bound; this document does not invent a numeric retry limit.

If that bound requires attempt limits, cooldowns, persistent counters, ceremony caps, lifetime bounds, failure accounting, or other enforcement, those are protocol/security requirements. A consumer cannot omit or bypass a required constraint and still claim the same security bound. Applications may impose stricter limits.

Depending on the selected construction and its analysis, security-required state that may need to survive process or application restarts includes attempt and failure accounting, cooldown or lockout state, replay or terminal-ceremony tracking, and lifetime or ceremony-bound state. This is a list of possible requirements, not a storage design or API. No TrustStore or application trust database is specified here.

## Pairing result contract

A successful result must represent that the requirements claimed by the selected protocol were met for one exact ceremony, including the peer/role and any context the protocol actually authenticated and bound. It must let a consumer make its own application-level trust decision without implying that unsupported identity or context claims were verified. The result must distinguish authenticated-and-bound information from consumer-supplied or otherwise unverified information as required by the eventual protocol contract.

The result does not itself establish application authorization, permanent trust, or guarantees beyond those justified by the selected protocol. This contract is language-neutral and does not freeze Rust types, a C ABI, Dart or .NET APIs, a wire format, or a trust-storage model.

## Unresolved decisions

The protocol, its security proof and bound, key agreement or KEM, commitment construction, context encoding and binding profile, SAS derivation and encoding, attempt and lifetime parameters, persistence requirements, wire format, state machine, and result/API shapes remain unresolved. No production cryptography exists yet. Requirements here do not select a candidate or justify a claim; each candidate and parameter must be separately evaluated and reviewed before implementation.
