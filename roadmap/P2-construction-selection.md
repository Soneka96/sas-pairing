# P2 — Construction Selection / Formal Mapping

## Status

✅ Complete — Candidate B selected for the authenticated-bootstrap result contract.

**Outcome: CONDITIONAL SELECTION — Candidate B with explicit profile for the proposed authenticated-bootstrap result contract.** P1's historical text remains unchanged and ambiguous about requiring a reusable shared key; this P2 decision treats the proposed clarification below as the result contract under evaluation, pending its adoption into P1. This is a completed P2 decision for that contract, not a silent P1 revision. Theorem 3 already supports arbitrary role-positioned message bytes and returns the peer's exact message after the synchronous SAS comparison. Profile rules must define canonical encoding, Host/Client role mapping, unique SID/ceremony lifecycle, context equality checks, total retry accounting, exact OOB semantics, and consumer persistence. Public-key bytes are authenticated only as peer-supplied values; the result does not claim that the key claim is true or that the peer possesses the private key. TLS 1.3 proof of possession applies to later connections. Candidate C's direct-key/context gap remains conditional if a shared-key requirement returns. Candidate A/C/D/E research remains documented; Candidate E is not selected. No same-machine shortcut is selected; Windows local/remote and mobile use the same protocol. See the [construction mapping](../docs/construction-selection.md) and [protocol status](../docs/protocol-status.md) for the detailed theorem, trace, implementation, and lifecycle analysis.

**Proposed P1 clarification (not applied in this P2 change):** “Successful pairing MUST establish a mutually authenticated bootstrap result for the exact pairing ceremony and the security-relevant context carried in the authenticated messages. A reusable shared pairing key is not required unless the selected construction exposes one with established guarantees. If a result includes a public key without a separately justified proof of possession, it MUST describe that value only as peer-supplied and authenticated for this ceremony; it MUST NOT claim that the peer owns or controls the corresponding private key. A later TLS connection may establish current control of the pinned key only by verifying the corresponding TLS 1.3 proof of possession. The consumer decides whether and when the authenticated bootstrap result establishes durable trust.”

## Goal

The evaluation is complete. Candidate B is selected only for mutual authentication of role-positioned bootstrap messages under its published assumptions and the explicit profile requirements. Candidate C, D, and E retain their conditional findings; the Windows-first product flow does not relax the security model.

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

A concise comparison of Candidates A–E and requirement-by-requirement mappings, with citations to primary sources, exact functionality, assumptions, unresolved proof/profile gaps, current wrapper/license and bounded-reuse findings, and the recorded phase outcome. Any proposed direction remains a candidate until the evidence supports selection.

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
