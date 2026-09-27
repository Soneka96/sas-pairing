# P2 — Construction Selection / Formal Mapping

## Status

✅ Complete — Candidate B selected for the authenticated-bootstrap result contract.

**Outcome: SELECTED — Candidate B for the remote authenticated-bootstrap profile, subject to the P3 profile requirements.** P1 now accepts mutual authentication of exact role-positioned bootstrap messages for one ceremony, including security-relevant context carried in those messages, without requiring a reusable shared pairing key. Candidate B's theorem returns the peer's exact message after the synchronous exact SAS comparison; it authenticates public-key bytes only as peer-supplied values and does not prove private-key possession. Candidate C remains evidence for the shared-key alternative; Candidate A/C/D/E research remains preserved and Candidate E is not selected. TLS is post-pairing transport/authentication. A separate OS-authenticated same-device profile is not Candidate B without SAS and remains P3 work. Windows and mobile clients use the same remote protocol. See the [construction mapping](../docs/construction-selection.md) and [protocol status](../docs/protocol-status.md) for the detailed theorem, assumptions, limitations, and lifecycle analysis.

## Goal

The construction evaluation is complete. Candidate B is selected for mutual authentication of role-positioned bootstrap messages under its published assumptions and explicit profile requirements. Candidate C, D, and E retain their candidate-specific findings; the product flow does not relax the security model. Construction selection does not mean a production protocol has been implemented or is ready for production.

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
- Production protocol code or cryptographic claims beyond the selected theorem/profile mapping.

## Deliverables

A concise comparison of Candidates A–E and requirement-by-requirement mappings, with citations to primary sources, exact functionality, assumptions, unresolved proof/profile gaps, current wrapper/license and bounded-reuse findings, and the recorded phase outcome. Preserve the evidence and limitations for all candidates, including those not selected.

## Security invariants

The analysis must distinguish proven properties from assumptions and project requirements. It must not claim security beyond the construction's justified bound or the human comparison procedure. Tests or interoperation do not substitute for a security argument.

## Exit criteria

P2 ends with exactly one of these outcomes:

### SELECTED

Evidence justifies a construction/profile direction against P1, states its assumptions and limitations, and supports proceeding to P3.

### RESEARCH CONTINUES (alternative outcome; not the current P2 status)

A candidate remains promising, but evidence is insufficient to select it. Identify the unanswered questions and research needed; do not proceed as though the selection were made.

### STOP

A critical assumption or security requirement cannot currently be justified. Record why the project cannot safely proceed and what evidence or change could reopen the phase.

## STOP conditions

Stop if a critical P1 property cannot be mapped to a justified construction, if a required assumption cannot be supported, or if available evidence cannot distinguish a candidate from an unsupported security claim. Do not resolve these gaps by inventing protocol details.

## What this unlocks

The current outcome is SELECTED and unlocks P3 profile work. RESEARCH CONTINUES and STOP are alternative phase outcomes and do not authorize protocol implementation.
