# Threat model and protocol requirements

## Purpose and status

This document defines the security problem and requirements that a future candidate protocol must satisfy. It defines **what** pairing must guarantee, not the cryptographic construction or implementation that provides those guarantees. A candidate must justify each claimed property against its construction, security analysis, and stated assumptions; listing a requirement here does not mean this project currently meets it.

This project is pre-alpha. P2 historically selected Candidate B, but the owner reopened the remote-construction choice during P3; no production remote construction is currently selected, and no production protocol profile or production cryptography has been implemented. P1 states requirements and does not select primitives, commitment construction, final SAS encoding, wire format, or API. Shortcake is evidence and implementation reference material only unless separately evaluated. `sas-pairing` remains application-neutral; DovahLink is an original consumer/example, not part of the protocol core.

**Current project status:** P2 originally selected Candidate B as the abstract construction. The owner later reopened the implementation-direction choice because concrete instantiation would require substantial project-owned cryptographic design and proof-mapping/maintenance. This was an engineering/security ownership decision, not a finding that Candidate B is insecure; Candidate B remains a formal reference and possible fallback. A ceremony composed from maintained vodozemac primitives is the **FAVORED CANDIDATE — NOT SELECTED** because it may reduce custom-crypto ownership. It still requires project-specific analysis and independent review. No remote construction is ready for final selection; see [current protocol status](protocol-status.md). The P1 requirements and P2 history below do not imply a current production profile selection.

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

The remote protocol alone cannot protect against a compromised endpoint, a compromised display or input surface, a coerced user, or an attacker who controls the trusted human comparison itself. The separate same-device profile also does not claim to resist an attacker who has compromised the trusted local OS/user security boundary enough to impersonate or control the authorized local participant. These limits do not weaken the remote network-attacker model and must not be described as attacks either profile defeats.

## Pairing ceremony and identity

One **pairing ceremony** is one logically distinct protocol run, from its accepted start through its terminal outcome. Each run must be distinguishable in protocol state from every previous, retried, concurrent, or attacker-created run. This is a requirement on candidate protocols, not a choice of identifier or mechanism.

A retry is a new ceremony. Concurrent ceremonies are separate ceremonies even when they involve the same participants or context. An attacker-created run is not interchangeable with the run the user intended to approve. Messages, approval, and results must be attributable to the exact ceremony to which they belong.

Successful pairing MUST apply only to the exact ceremony whose SAS the human compared and whose approval was accepted. A candidate MUST explain how both participants agree on that same ceremony and how its identity is bound to the role, peer, applicable context, and protocol state required by the construction. A participant MUST NOT infer agreement from matching addresses, display names, arrival order, or an unbound public-key claim.

## Human approval and the SAS

The human approver compares the SAS displayed for both participants for the intended, active ceremony. A **match** means the approver determines that the two displayed values are the same, according to the comparison procedure presented by the consumer. The protocol must not silently treat a partial comparison or a consumer's automatic matching as equivalent to an explicit human comparison and approval.

Approval authorizes completion of that one ceremony, subject to all protocol checks. It MUST NOT authorize another or later ceremony, a different peer or role, an unbound context, application permissions, or durable application trust by itself. The consumer makes its own trust and authorization decisions from the pairing result.

The SAS is a value for human comparison. It is **not** a PIN, password, bearer token, or secret that must remain confidential. Its security purpose and required handling must be justified by the selected protocol and SAS security model. P1 selects no numeric SAS guessing/security target; each candidate profile MUST state an explicit aggregate target and enforceable maximum opportunity count for its defined accounting epoch before it can claim an aggregate bound. A final SAS profile MUST NOT be selected until the target, opportunity bound, accounting scope, and repeated-attempt assumptions are justified. This document does not select an alphabet, bit length, grouping, or rendering scheme.

Human comparison is part of the security system, not a perfect channel. A candidate's security analysis and consumer guidance must account for partial comparison, misread characters, accidental approval, fatigue, repeated attacker-induced ceremonies, accessibility needs, and localization or rendering differences. The design must not claim a stronger human-comparison assurance than its comparison procedure reasonably supports.

## Pairing profiles and selection policy

Remote pairing over an untrusted network requires a construction that meets the applicable active-attacker requirements. P2 historically selected Candidate B for this remote authenticated-bootstrap result, but the owner later reopened the implementation-direction choice; no construction is currently selected. The current favored candidate is a ceremony built from maintained vodozemac primitives, pending project-specific analysis and independent review. The same eventually selected remote protocol and authenticated wire/profile semantics must apply to Windows-to-Windows and mobile-to-Windows pairing; transport and UI integration may differ. The intended remote UX is compare-only: both participants display and compare the entire SAS for the exact ceremony, with no manual transcription. A participant may return a local successful result only after verifying all required peer authentication and confirmation evidence for that exact ceremony; one participant pressing a local button alone is insufficient. Network loss may cause asymmetric observation of completion: one participant may have enough authenticated evidence to return a result while the other does not receive the final required message and returns no success. If both return success, their results MUST describe the same compatible ceremony, roles, peer bootstrap data, and bound context. UI labels are not protocol fields.

A separate same-device profile may skip human SAS comparison only when an approved profile establishes a genuinely local connection using an OS-authenticated primitive, authorizes the connecting principal, and excludes remote network peers. The Host still receives a ceremony-specific local request and must explicitly approve that ceremony. Same machine, loopback, IP address, hostname, discovery name, or process name alone MUST NOT select this path. The exact local primitive, authorization rule, locality proof, remote exclusion, and replay protection remain profile work; until established, use the remote SAS profile.

The intended default policy is **Automatic**: use an approved same-device authenticated-local profile only when its complete security predicate is established; otherwise use the currently selected remote SAS profile. Until a remote construction is selected and approved, this describes intended policy rather than an available production path. **Always require SAS** uses the currently selected remote SAS profile even when an approved local path is available. For remote pairing, no preference or convenience setting may bypass the selected remote SAS profile. The local profile's OS/user boundary assumption is limited to the protection it actually establishes.

## Required properties of successful pairing

A future protocol may claim successful pairing only if its security argument justifies, under explicit assumptions, that:

- a participant reports success only after verifying all required authentication and confirmation evidence for that exact ceremony and accepting its own required local approval;
- if both participants report success, their results are mutually compatible and identify the same exact ceremony, roles, peer bootstrap data, and bound context; the protocol MUST NOT allow conflicting successful results;
- stale ceremony state, the wrong peer, role, bootstrap, or context cannot produce success; one local approval alone is insufficient. Message loss may leave one participant with a local successful result while the other returns no success; simultaneous success, distributed atomic commit, and atomic durable trust persistence are not guaranteed;
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

Multiple ceremonies may coexist subject to a profile's resource policy. Every accepted message, human approval, and pairing result MUST remain associated with one exact ceremony and its participants, roles, and applicable context. Approval for ceremony A must never authorize ceremony B; messages from A must never satisfy B's protocol state; and participants must not confuse one ceremony's identity with another's. A candidate must justify these properties without relying on user-visible ordering alone. Attacker-created concurrent ceremony state MUST have a global resource bound that is not keyed solely to unauthenticated peer identity or labels. This generic requirement selects no numeric concurrency limit.

## Cancellation, disconnect, expiry, and errors

- **Peer disconnect:** A disconnect must not cause incomplete or stale state to count as success. A candidate must specify whether safe continuation is possible; continuation, if supported, must remain bound to the same exact ceremony and all freshness requirements. Otherwise the ceremony is abandoned.
- **Application cancellation:** Cancellation terminates the local ceremony. Its later messages or approval must not revive it or authorize a new ceremony.
- **Human rejection:** Rejection terminates that ceremony without a successful pairing result. A later attempt is a new ceremony.
- **Expiry:** An expired ceremony cannot succeed or be resumed as if fresh. Exact lifetime values remain for later security analysis.
- **Malformed input:** Malformed or invalid protocol input must not be interpreted permissively in a way that weakens a security requirement or advances ambiguous state to success.
- **Resource-bounded input:** Remotely supplied protocol data MUST be bounded before unbounded allocation. A declared length MUST be validated against applicable limits, and aggregate size arithmetic MUST be checked before allocating or retaining its payload. Transport-layer limits alone are insufficient.
- **Ambiguous state:** Conflicting, missing, or uncertain security-sensitive state fails closed. Recovery must not accidentally make stale state valid again.

The protocol and consumer behavior must not report success until the required checks and approval for that ceremony have completed. Failure, cancellation, and expiry handling must not leak a stale approval into another run.

## Repeated attempts and required state

SAS security must account for repeated attacker attempts, including attacker-induced ceremonies and repeated guesses. A security analysis must state an explicit aggregate target and enforceable maximum opportunities per accounting epoch; P1 does not prescribe numeric values. Each profile MUST define a SAS attempt as the point before which its accounting is reserved: security-significant attempts MUST be counted before the adversary receives information sufficient to derive its candidate SAS. The exact message or event boundary is profile-specific.

All SAS opportunities within a defined local security-accounting scope MUST share a common global local attempt budget. Before successful pairing, peer identity claims and other peer-supplied labels are not trustworthy, so a per-peer counter alone cannot provide this foundation. Optional narrower peer, context, transport, or identity limits may supplement the global budget but MUST NOT replace it. Concurrent SAS opportunities count individually and reservations against the common budget MUST be atomic.

If the claimed bound depends on attempt accounting, each attempt MUST be atomically and durably reserved before releasing the key material that creates its SAS opportunity. An uncertain or failed reservation MUST fail closed before that release. Recovery may conservatively spend an attempt that was not ultimately exposed, but MUST NOT forget an attempt that may have been exposed. Security-required accounting cannot be optional consumer behavior: the shared security protocol/core owns its semantics and enforcement, while an application or platform may provide the required persistence mechanism.

Accounting required by the claim MUST survive ordinary process crash/restart, device reboot, and application update. Profile-specific attempt limits and accounting epochs are normative security behavior, not optional consumer policy. The epoch scope MUST be explicit and MUST NOT rely on untrusted peer-supplied identity. Any reset/recovery MUST preserve the stated claim: it cannot silently replenish the budget or be triggered solely by the untrusted network. If a claim spans backup restore or storage rollback, the deployment requires rollback-resistant or monotonic state. Otherwise, restoring older accounting state begins or re-enters a different accounting epoch and the claim must say so. Uninstall/reinstall cannot silently preserve a lifetime claim without an external durable anchor. The exhaustion and reset behavior and exact rollback scope remain profile decisions; a numeric attempt limit is meaningless without defining its accounting epoch.

Resource/denial-of-service controls and human fatigue controls are distinct from SAS-security accounting. Resource controls may begin at an earlier event, such as accepting a start message, without that event counting as a SAS guess. Resource rejection before the profile's SAS exposure boundary MUST NOT charge a SAS attempt. UX controls such as warnings, cooldowns, or limits on simultaneously displayed comparisons may supplement security policy but MUST NOT substitute for its SAS-attempt counter unless formally justified. Applications may impose stricter resource or UX limits.

## Pairing result contract

A participant may return a local successful pairing result only after it has verified all required peer authentication and confirmation evidence for the same exact ceremony and accepted its own required local approval. The result MUST contain mutually authenticated bootstrap data bound to that ceremony, explicit participant roles, and all security-relevant context carried in the authenticated messages. The exact encoding is profile work. A reusable shared pairing key is not required. Authenticated public-key bytes mean only that the peer supplied those exact bytes as part of the successfully authenticated ceremony; they do not prove possession, ownership, or control of the corresponding private key.

If both participants return successful results, those results MUST refer to the same compatible ceremony, roles, peer bootstrap data, and bound context. Network loss may cause asymmetric observation of completion: one participant may have enough authenticated evidence to return success while the other does not receive the final required message and therefore returns no success. This does not permit conflicting successful results, stale-ceremony success, acceptance of different peers, roles, or context, or success from one local button press alone. The protocol does not guarantee simultaneous local success or atomic durable trust persistence.

The consumer decides whether and when to persist trust or authorize application behavior. The result does not itself establish application authorization, durable trust, or guarantees beyond those justified by the profile. This contract is language-neutral and does not freeze Rust types, a C ABI, Dart or .NET APIs, a wire format, or a trust-storage model. Participants' durable writes are not assumed to be atomic.

## Unresolved decisions

The exact production profile encodings, construction selection, context and mismatch rules, SAS derivation and rendering, aggregate attempt/lifetime limits, persistence, wire format, and state machine remain unresolved. No production protocol or production cryptography exists yet. P2 historically selected Candidate B, but the owner later reopened the implementation direction for engineering/security ownership reasons; the current vodozemac candidate is favored for investigation but remains unselected. This requirements document does not turn historical P2 research or candidate work into a current production selection or readiness claim.
