# Protocol Profile v1 — Draft Foundation

> **DRAFT / P3 / NOT PRODUCTION READY**
>
> This document defines a specification surface for future P3 decisions. It does not select unresolved cryptographic parameters, define an implementable wire profile, or authorize implementation.

**Current status:** P2 originally selected Candidate B as the abstract construction. The owner later reopened the implementation-direction choice because concrete instantiation would require substantial project-owned cryptographic design and proof-mapping/maintenance; this is not a finding that Candidate B is insecure. Candidate B remains a formal reference and possible fallback. The separate vodozemac profile is the **FAVORED CANDIDATE — NOT SELECTED**, pending project-specific analysis and independent review. This foundation preserves the historical Candidate B direction; it does not describe a currently selected production profile. See [current protocol status](protocol-status.md).

## 1. Purpose and security boundary

This draft's remote profile describes the construction historically selected in [P2](construction-selection.md), Candidate B, to authenticate the exact peer-supplied, role-positioned bootstrap message for one pairing ceremony, after successful protocol checks and the required full SAS comparison. The owner later reopened that implementation-direction decision; this is not the current selected production profile. It does not establish a reusable shared pairing secret.

Successful pairing means only that the remote profile authenticated the exact bootstrap messages supplied by the participants for this ceremony, including those message fields that the final profile requires and validates. It does not establish that supplied identity claims are externally true, that a participant possesses the private key corresponding to supplied public-key bytes, that an endpoint is uncompromised, or that human comparison is perfect. A later transport or authentication protocol must prove possession of the exact pinned identity key when that property is needed. Consumer authorization and durable trust remain consumer decisions.

The project is pre-alpha. This draft is not production-ready and makes no production security claim.

## 2. Participants and protocol roles

- **Initiator:** the generic participant that starts a ceremony.
- **Responder:** the generic participant that joins that ceremony.
- **Consumer:** the application invoking the protocol, providing any selected context, and deciding how to use a successful result.
- **Human approver:** the person comparing the complete displayed SAS for the intended active ceremony and explicitly approving it.

Candidate B uses **S** (Sender) and **R** (Receiver) for its role-positioned inputs `m_S` and `m_R`. A concrete profile must define one deterministic mapping between Initiator/Responder and S/R, bind it in the authenticated messages, and use it consistently in both directions. The theorem authenticates the exact role-positioned messages; it does not select application roles or identity semantics. Any consumer-specific mapping, such as Host/Client, is a non-normative integration choice and must not redefine the generic protocol roles.

## 3. Ceremony identity and lifecycle

A **ceremony** is one logically distinct protocol execution with its own identifier (SID), role assignment, messages, human comparison, approvals, and terminal outcome. Its identifier is a binding and routing value, not an identity or proof of freshness by itself.

The eventual profile MUST ensure that:

- each accepted ceremony is distinguishable from every other ceremony, including retries, concurrent runs, runs after restart, and attacker-created runs, with collisions or reuse handled safely;
- a retry creates a new ceremony and cannot reuse messages, SAS approval, or terminal state from the prior run;
- every message, callback, human decision, and result is associated with the exact active ceremony, roles, peer inputs, and selected context to which it belongs;
- a stale callback, approval, duplicate, or delayed message cannot advance another ceremony or revive a terminal one; and
- success and failure are terminal. In particular, a terminal failure can never later transition to success.

The P2 paper's `sid` is supplied by the environment/caller or sampled by the Sender when absent, and is used in its commitment, SAS, OOB, and authentication contexts. P2 explicitly leaves application-level uniqueness, restart-safe freshness, and stale-state handling to the profile. This draft selects no SID byte format, generation mechanism, unpredictability claim, or randomness size.

## 4. Authenticated bootstrap message model

The final profile MUST define canonical, role-positioned S and R messages and authenticate their exact bytes under Candidate B. At minimum, the authenticated and validated content must bind:

- a protocol and domain identifier;
- the protocol/profile version and any version or suite choice that can affect security;
- the sender's protocol role and the complementary peer role;
- the ceremony SID;
- the exact peer bootstrap identity material required by the consumer;
- the exact peer public-key bytes, if supplied; and
- each security-relevant application-context value explicitly selected by the consumer and accepted by the profile.

The final profile must define required and optional fields, canonical encoding, validation, and whether context values must be equal or otherwise compatible. A value is not protected merely because an application supplied or displayed it. The theorem authenticates arbitrary role-positioned message contents but does not determine their application meaning or make participants agree on a context that they do not check.

Three claims MUST remain distinct:

1. **Authenticated as exact supplied bytes:** the bytes were included in the peer's message authenticated for this ceremony.
2. **Externally verified true:** a separate validation process established that the claim is true. Candidate B does not do this.
3. **Proof of possession:** the peer demonstrated control of the private key corresponding to the supplied public-key bytes. Candidate B does not do this.

The profile and result MUST NOT upgrade claim 1 into claim 2 or 3.

## 5. Successful result contract

On success, each participant receives a language-neutral result describing the completed ceremony. Semantically, it must expose enough information for a consumer to identify:

- the ceremony SID and the local and peer protocol roles;
- the profile and version used;
- the exact peer bootstrap message as authenticated, including exact public-key bytes if supplied; and
- the security-relevant context authenticated for that ceremony.

Consumers may expose decoded fields in addition to the message, but must preserve the exact authenticated message representation in the result. The result says that these exact message contents were authenticated in this ceremony. It does not imply a reusable shared secret, external verification of an identity claim, proof of long-term-key possession, application authorization, or durable trust. The result contract does not prescribe language APIs, data structures, or persistence behavior.

## 6. Required high-level state behavior

The implementation profile MUST provide behavior equivalent to these states and transitions; names and internal architecture are not prescribed.

| State or event | Required behavior |
|---|---|
| Creation | Allocate a fresh ceremony identity and fixed role assignment. Reject ambiguous or invalid profile inputs before exchanging messages. |
| Message exchange | Accept only well-formed messages for the active SID, expected role, version, and message position. Bind each accepted message to this ceremony. |
| SAS ready | Reach this state only after the required Candidate B exchanges and checks succeed. Display the complete SAS for this ceremony; do not treat partial comparison as approval. |
| Human confirmation | Require explicit local approval for the exact active ceremony after full comparison. Bind approval to its SID and the resulting terminal transition. |
| Bilateral completion | Report success only when the exact messages, required comparison, and bilateral completion/confirmation conditions are satisfied by both participants for this ceremony. |
| SAS mismatch or human rejection | Fail this ceremony. No successful result is produced; another attempt is a new ceremony. |
| Cancellation, timeout, or disconnect | Abort or safely continue only if the final profile justifies same-ceremony freshness and state. A canceled or expired ceremony cannot resume as fresh. |
| Replay, stale approval, or unexpected message | Reject or ignore without advancing state. Never transfer the event to a different SID or revive terminal state. |
| Malformed or ambiguous input | Fail closed; do not permissively parse, downgrade, or advance toward success. |
| Terminal success or failure | Remain terminal. A failure cannot become success, and late messages or callbacks cannot change the result. |

Candidate B models synchronous, immediate ideal OOB equality comparison, not arbitrary asynchronous UI callbacks or durable application state. The profile must preserve the theorem's conditions or provide separate evidence for any changed behavior.

## 7. Historical remote Candidate B profile requirements — not current selection

The remote profile MUST use the same protocol semantics for Windows, Android, and future remote clients. Transport and user-interface integration may differ. Both participants display and compare the complete SAS for the exact ceremony without manual transcription, and pairing requires bilateral completion. It cannot silently select the same-device profile or downgrade on failure.

Before implementation, P3 must define the exact message/profile encoding, role mapping, ceremony lifecycle, required context checks, completion behavior, and a construction and parameter profile supported by security evidence. It must preserve the analyzed Candidate B construction rather than silently modifying it.

The P2 evidence and its limits are binding constraints on this draft:

- Theorem 3's ideal per-SID misbinding parameter is `2^-t`; it is not a deployed-system error rate or an aggregate multi-ceremony bound.
- The security argument assumes a computationally hiding and binding commitment, the specified random-oracle SAS construction, honest endpoints, synchronous ideal OOB comparison, and zero human comparison error. Its composed bounds include additional construction advantages and negligible terms.
- The proof's ideal functionality allows one online forgery attempt per SID. It does not set a total budget across SIDs, cooldowns, persistent counters, or restart policy.
- The theorem does not prove human reliability, durable terminal-state behavior, atomic consumer persistence, long-term identity ownership, or proof of possession.
- A successful conformance vector can demonstrate implementation agreement, but cannot establish cryptographic security.

The final profile may claim no more than the reviewed construction and its justified assumptions establish.

## 8. Same-device profile boundary

A separate same-device profile may omit SAS only after a reviewed profile establishes all of the following:

- genuine same-device locality through an approved, OS-authenticated security boundary;
- an authenticated local principal and required local authorization;
- exclusion of remote and network peers;
- authorization for this exact ceremony, resistant to stale requests and replay; and
- result semantics compatible with the generic pairing result contract.

The local participant must explicitly approve the exact ceremony. Loopback, IP address, hostname, discovery name, process name, same-machine observation, or LAN proximity alone is insufficient to activate this profile. The profile must state the trusted OS/user boundary and must not claim resistance to an attacker able to control that boundary. No OS primitive or authorization rule is selected here; the production remote profile also remains unselected pending the current candidate's security review and an explicit owner decision.

## 9. Unresolved decisions — evidence required

No choice below is implied by examples, familiar defaults, or this draft. Each remains **UNRESOLVED — EVIDENCE REQUIRED**.

| Decision | Why it is security-relevant | Evidence required before selection |
|---|---|---|
| Concrete Candidate B commitment instantiation | Hiding and binding are proof assumptions; the paper's abstract interface is not any convenient commitment API. | Analyze a concrete construction against the paper's exact assumptions and parameters; obtain cryptographic review. |
| Concrete random-oracle/hash construction and domain separation | The SAS proof uses a specified random-oracle input and truncation; substitutions or ambiguous inputs can invalidate the mapping. | Map the exact construction, encoding, domain separation, and parameter choices to the analyzed theorem and review them. |
| SAS entropy/bit length | It determines the ideal per-SID guessing term and contributes to aggregate attack risk. | Set a target from the full theorem bound, deployment/session assumptions, and justified aggregate attempt budget. |
| SAS alphabet | Character confusion and representation affect human comparison reliability and usable entropy. | Human-factors and accessibility evidence tied to the selected entropy and comparison method. |
| SAS rendering and grouping | Rendering can create ambiguity, omission, or partial-comparison behavior. | Usability, accessibility, and localization review; verify that the display preserves full comparison. |
| Retry and total attempt budget | Per-SID bounds do not bound repeated ceremonies or global attacker work. | Derive a maximum from the selected construction parameters, deployment lifetime, and aggregate security target. |
| Cooldown values | Cooldowns affect achievable repeated attempts and availability. | Show how values enforce the justified attempt bound without relying on unmodeled behavior. |
| Persistent attempt-counter rules | Restart or rollback can reset security-required accounting. | Define persistence, update, rollback, and multi-process semantics from the aggregate bound; review failure behavior. |
| Canonical binary/wire encoding | Ambiguous or noncanonical inputs can make parties authenticate different meanings or bypass validation. | Specify a deterministic encoding, parsing rules, test vectors, and security review of all bound fields. |
| Exact SID encoding and freshness mechanism | The formal SID is an input; uniqueness and restart-safe freshness are application obligations. | Define collision/reuse handling and lifecycle guarantees across retries, concurrency, restarts, and peers; justify any randomness size. |
| Same-device OS primitive and authorization | Locality, principal identity, and remote exclusion depend on platform security semantics and configuration. | Platform-specific primary documentation, threat analysis, and independent review of the chosen OS boundary. |
| Deterministic vector format and coverage | Vectors enable conformance checks but not security proof; underspecified formats impair interoperability. | Define a stable, language-neutral representation after the profile and construction parameters are selected. |
| Context fields and mismatch rules | Authenticated bytes do not guarantee peers selected or interpreted the same application context. | Consumer-neutral field requirements, equality/compatibility rules, and tests for absent, mismatched, and malformed values. |
| Timeout, expiry, and terminal-state persistence | The paper does not model cancellation, restart-safe approval, or durable terminal state. | Lifecycle and storage analysis that preserves ceremony freshness and does not overclaim atomicity or liveness. |

## 10. Status and next gate

This is the P3 profile foundation only. P3 remains incomplete until security-sensitive decisions are justified, the remote and same-device profiles are sufficiently precise for review, and deterministic vectors cover positive and meaningful negative cases. No production implementation or readiness claim follows from this draft.

The original next-step note for this foundation was Candidate B commitment/hash research. That recommendation is historical and is superseded by the current project-level next action in [AI manager context](../ai/context/project.md). The Candidate B instantiation STOP remains in force.
