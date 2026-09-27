# P2 — Construction Selection / Formal Mapping

## Status

🔵 Current / next phase.

**Outcome: RESEARCH CONTINUES.** See the [construction mapping](../docs/construction-selection.md). P2 remains current; P3 is gated. Jarecki–Saxena’s Enc-AKA theorem is the strongest direct key-agreement result, but only for `m_i = null`, `m_j = K`. Theorem 1’s arbitrary-message Enc-MCA authentication result does not itself prove context-to-key binding. FGSW Theorem 5.1 supplies generic, role-asymmetric post-AKE key confirmation under Match-security/key-secrecy and KDF/MAC assumptions, but confirms the base AKE SID and does not cover Candidate C’s external context. P1’s context requirement is ambiguous; the research note distinguishes agreed context, key-context association, and consumer trust without changing P1. The context-binding classification is **NEW PROOF REQUIRED**. The single remaining blocker is a proof or established composition theorem binding both participants’ generic context inputs to Candidate C’s same fresh key while preserving its key secrecy, authentication, and concurrency guarantees. Čagalj–Čapkun–Hubaux’s DH-SC remains outside P1 due its ideal-commitment and concurrency assumptions.

## Goal

Evaluate candidate SAS-AKE and directly relevant SAS/OOB constructions against P1 and determine whether any candidate can be justified for this project. The focused Enc-MCA/Enc-AKA context-to-key question is **NEW PROOF REQUIRED** and is the single remaining P2 proof blocker. Terminal-result wording remains a P1 clarification item, not a second construction proof blocker: under the proposed clarification, local completion may differ under message loss, while two partnered sessions that both succeed must agree. No construction is selected until the context-to-key result is established.

## Why this phase exists

The requirements describe what a protocol must establish. Research and explicit mapping are needed before choosing a construction or turning unresolved questions into architecture.

## Inputs / prerequisites

- Completed [P1 threat model](../docs/threat-model.md).
- Current [protocol status](../docs/protocol-status.md), [architecture](../docs/architecture.md), and [single-core ADR](../docs/decisions/0001-single-native-security-core.md).
- Primary research and the assumptions and proofs of each candidate construction.

## Scope

Map each candidate's construction, security result, assumptions, and composition to P1, including:

- active man-in-the-middle resistance and its justified bound;
- ceremony freshness and binding;
- initiator/responder role binding;
- replay and unknown-key-share resistance;
- transcript binding and authentication;
- SAS derivation, security bound, and repeated-attempt assumptions;
- commitment requirements;
- key-agreement or KEM assumptions;
- application-context binding;
- proof-of-possession composition and key confirmation; and
- assumptions inherited from the academic construction, including any human-comparison assumptions.

Record gaps and evidence with references. Treat an unmet requirement as a gap, not an implicit design choice.

## Out of scope

- Production cryptography or Rust protocol code.
- Selecting a KEM for convenience.
- Freezing the SAS alphabet or rendering, wire format, or state-machine profile.
- Designing an ABI, FFI, Dart API, or .NET API.
- Claiming Pasini–Vaudenay is selected before the mapping supports that conclusion.

## Deliverables

A concise construction comparison and requirement-by-requirement mapping, with citations to primary sources, explicit assumptions, unresolved gaps, and a recorded phase outcome. Any proposed direction remains a candidate until the evidence supports selection.

## Security invariants

The analysis must distinguish proven properties from assumptions and project requirements. It must not claim security beyond the construction's justified bound or the human comparison procedure. Tests or interoperation do not substitute for a security argument.

## Exit criteria

P2 ends with exactly one of these outcomes:

### SELECTED

Evidence justifies a construction/profile direction against P1, states its assumptions and limitations, and supports proceeding to P3.

### RESEARCH CONTINUES

A candidate remains promising, but evidence is insufficient to select it. Identify the unanswered questions and research needed; do not proceed as though the selection were made.

### STOP

A critical assumption or security requirement cannot currently be justified. Record why the project cannot safely proceed and what evidence or change could reopen the phase.

## STOP conditions

Stop if a critical P1 property cannot be mapped to a justified construction, if a required assumption cannot be supported, or if available evidence cannot distinguish a candidate from an unsupported security claim. Do not resolve these gaps by inventing protocol details.

## What this unlocks

Only a SELECTED outcome unlocks P3's language-neutral candidate profile. RESEARCH CONTINUES and STOP do not authorize protocol implementation.
