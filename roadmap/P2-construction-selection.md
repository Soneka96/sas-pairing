# P2 — Construction Selection / Formal Mapping

## Status

🔵 Current / next phase.

**Outcome: RESEARCH CONTINUES.** See the [construction mapping](../docs/construction-selection.md). P2 remains current; P3 is gated. The current P1 audit classifies the reusable shared-key requirement as **AMBIGUOUS**: P1 neither requires that output explicitly nor says authenticated bootstrap messages alone suffice. Candidate B is **PROMISING** if P1 accepts mutual SAS authentication of peer-supplied data without a reusable key; its theorem authenticates exact messages under a unique SID but does not equate contexts, return a shared key, or prove long-term key possession. Candidate C remains the direct-key option if P1 requires that output; its context-to-key result remains **NEW PROOF REQUIRED** only if C is pursued. Candidate A and all prior A–D findings remain documented. Candidate D’s one-active-session assumption would require a profile that rejects attacker-created parallel instances and clarification of P1’s current coexistence clause; its ideal-commitment assumption remains a serious blocker. P1 is not edited.

## Goal

Evaluate candidate SAS-AKE and directly relevant SAS/OOB constructions against P1 and determine whether any candidate can be justified for this project. The result shape and shared-key requirement need P1 clarification before selection. Candidate B has no identified new proof obligation for its basic authenticated-message result, provided the profile defines encoding, role/SID binding, mismatch behavior, attempt limits, human/OOB assumptions, and result correlation. A key-control claim requires a separately justified proof of possession. Candidate C’s context-to-key question and Candidate D’s commitment-instantiation gap remain candidate-specific. Terminal/lifecycle wording also needs to distinguish paired protocol outputs from durable application completion. No construction is selected until the authoritative requirement and applicable proof/profile gaps are resolved.

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

A concise comparison of Candidates A–D and requirement-by-requirement mappings, with citations to primary sources, exact functionality, assumptions, unresolved proof/profile gaps, and a recorded phase outcome. Any proposed direction remains a candidate until the evidence supports selection.

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
