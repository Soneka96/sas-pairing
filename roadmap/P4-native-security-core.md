# P4 — Native Security Core

## Status

🔵 **EXPERIMENTAL IMPLEMENTATION IN PROGRESS — OWNERSHIP, CODEC, CRYPTO FOUNDATION, BOUNDED KEY-EXCHANGE, LOCAL SAS APPROVAL, BOOTSTRAP_MAC APPROVAL-AUTHENTICATION, AUTHENTICATED-COMPLETION, AUTHENTICATED-CANCEL, CEREMONY-DEADLINE, CORE PRE-EXPOSURE RESOURCE-CONTROL, START-ADMISSION-LIMITER, SESSION-BOUND ROUTING, AND SOCKET-FREE TRANSPORT-ADMISSION INCREMENTS IMPLEMENTED; P4 NOT COMPLETE.** The Windows Rust foundation derives account-scoped lock ownership from the process token SID and Windows profile API, with canonical identity encoding unchanged. The owner accepted account-scoped authorities in decision 0003. Same-session process checks and the cross-session ownership verification below are complete. The owner selected the corrected vodozemac remote profile and owner policy as the experimental baseline and waived the qualified-human-review prerequisite for this phase. F-02 is recorded as a false positive under the stated idealized assumptions; the complete argument remains conditional and is not formally verified. No production-security approval is granted.

## First implementation step

Build and verify the Rust authority-ownership and exposure-admission foundation before implementing protocol messages: canonical local authority identity registration; one OS-backed exclusive owner lease; one shared active-ceremony guard; and one shared volatile ten-opportunity counter. Reservation must require fresh authorization for that exact ceremony and acquire the guard plus opportunity with one atomic outcome before any public contribution can be released. Keep protocol message handling out of this first slice.

The initial increment implements this step's reservation foundation and a real Windows file-lock lease. Same-session process contention, forced termination, normal release, distinct authorities, shared guard/budget, authorization, and reservation lifecycle checks pass. The same-account cross-session ownership requirement is complete based on the owner-run manual verification dated 2026-09-30 (see [core verification record](../core/README.md#cross-session-verification-manual-completed-2026-09-30)); this is not automated CI. Later increments added the canonical P3 codec and private vodozemac primitives. The current bounded owner-gated state machine covers START through SAS establishment plus a crate-private, `ceremony_identity`-bound SAS presentation with local approve/reject/cancel and I1/I2 invalidation on every terminal path. After local approval the core emits one vodozemac-authenticated `BOOTSTRAP_MAC` and verifies the peer's against its retained ceremony state, in either arrival order. The three-message authenticated finish handshake (`INITIATOR_FINISH`, `RESPONDER_FINISH_ACK`, `INITIATOR_FINISH_ACK`) then yields a crate-private, local, ceremony-scoped `PairingResult` at each role's own success point. For the Initiator that point is an explicit local send-boundary confirmation of its exact `INITIATOR_FINISH_ACK`, not merely producing it; the Responder's is verifying that ACK. This is not atomic bilateral success or delivery confirmation, and a final ACK lost after sending leaves only the Initiator with a result. After SAS establishment, local reject/cancel is terminal immediately and returns a best-effort vodozemac-authenticated `CANCEL` (`CancelAuthFrame / 0x34`, `CancelMacContext / 0x38`, outer purpose `cancel`) without waiting for any send or peer receipt, and a verified peer `CANCEL` ends the run with no result, dropping the session before the guard is released and never refunding the opportunity; invalid or pre-SAS `CANCEL` is terminal protocol failure. The P3 §11.3 ceremony deadlines are enforced over an injected monotonic clock: a non-extendable 5-minute absolute deadline and a 60-second machine/protocol inactivity deadline, suspended only while the complete SAS awaits a human decision. Expiry is terminal with no result and no refund; after shared SAS establishment it returns a best-effort authenticated `CANCEL` with reason `0x03`, and before it is local-only failure. Deadlines are checked before every state-advancing operation and through a crate-private poll, but no scheduler exists: the future host/adapter must drive that poll. The honest Initiator generates exactly 16 raw request-ID bytes with the OS CSPRNG and atomically reserves them in the authority's active local Initiator namespace before START can be emitted, regenerating internally on collision and releasing the reservation exactly once at local terminal cleanup or drop; the ID remains routing/correlation data only, incoming peer IDs remain canonical opaque 1–64 bytes, and fixed IDs are test-only. The core-owned P3 §11.1.1 pre-exposure controls are implemented in the authority's shared state: at most 4 accepted-but-unexposed Responder runs and 2 concurrent expensive preliminary operations (Responder ephemeral generation and commitment, Responder pre-exposure DH, Initiator ephemeral generation) per authority, refused immediately with one generic `ResourceLimited` status, and a fixed 60-second pending resource lifetime from admission that nothing refreshes or suspends, distinct from the ceremony's 60-second inactivity deadline. Each slot and permit is released exactly once. The authority-wide START admission limiter is implemented exactly as frozen in P3 §11.1.1 and R-OWNER-034–039: a burst token bucket (capacity and initial credit 4, exactly 1 token per 5 seconds, integer whole-token-plus-remainder arithmetic with no hidden credit while full) and an independent cap of 12 limiter-admitted STARTs in the rolling window `(now - 60 s, now]`, decided atomically in the authority's shared-state critical section against one authority-scoped monotonic clock (never a ceremony clock), charging both components or neither, refusing with the generic `ResourceLimited`, failing closed without mutation on an unusable clock, and never refunding an admission. A shared outer-frame parser gives a crate-private structural START-candidate boundary, so the limiter is charged before the preliminary permit and before any bootstrap semantic validation, and semantically invalid STARTs stay charged. None of this spends, refunds, or resets an SAS opportunity or touches the exposed-ceremony guard. A crate-private per-authority router binds pre-establishment state to an opaque, volatile local session handle plus the request ID (P3 §4/§11.2), never the request ID alone: the same ID on another session is an independent, separately charged run; later frames reach only the run under their own session and exact request ID, with no request-ID-only lookup or fallback; an exact duplicate START for a routed key is ignored without limiter charge, slot, ephemeral, output, or deadline change; a changed START terminally fails that key's run and is never a new candidate; an atomic per-key claim keeps concurrent STARTs from creating two runs; routed Initiators are registered under their generated ID before START is returned; a structurally routable non-START frame naming no route on its live session is session-fatal (it reaches no run and the whole session is torn down, other sessions untouched), as now clarified in P3 §11.2 and R-WIRE-016; session close is synchronized (OPEN → CLOSING → CLOSED with per-operation leases), so it returns only after in-flight START admission, routed Initiator creation, and run operations for that session have unwound and released their permits, pending slots, and request-ID reservations, and no `ACCEPT` or START is returned for a closing session (R-OWNER-040); and routes are removed only after the run's own terminal or success cleanup, on session teardown (no CANCEL, no refund, no limiter reset), and on router drop. The session handle is local routing isolation only, never authentication, trust, or part of any wire, transcript, MAC, or result. A crate-private, socket-free transport model implements the P3 §11.1.1 transport controls in the authority's shared state: at most 4 pending adapter accept-work permits and 16 live unauthenticated connections per authority, shared by every router (the cap is rechecked atomically when a permit becomes live); each connection mapped to exactly one fresh Router session; at most 4 retained incomplete frames per authority and 1 per connection; bounded incremental frame assembly that takes boundaries from the codec's own header check and wire-type field-count table and rejects any declaration exceeding the 65,536-byte maximum before buffering its payload; a non-extendable 10-second whole-frame deadline and a 2-second no-progress deadline on one injected monotonic clock, enforced before new bytes are accepted and by an explicit poll; and one synchronous failure/close path that tears the Router session down (waiting for a teardown already in progress) before releasing the live count, and keeps that count held for good if Router cleanup is uncertain. It models the adapter's work queue only; no OS listener backlog, kernel buffering, real read, or real disconnect behavior is claimed. Timer scheduling, real sockets/listeners and transport sending/receiving integration, actual disconnect notification, a host adapter, reconnect/resume (not supported), public SDK/consumer integration, full P3 conformance, and production-security approval remain future work.

## Goal

Implement the selected experimental protocol/profile in one native security core, currently intended to be Rust.

## Why this phase exists

One security implementation keeps protocol behavior consistent and reviewable across future language bindings.

## Inputs / prerequisites

The selected experimental profile and owner policy, their documented assumptions and limitations, and deterministic vectors. This is not a production protocol freeze. See [owner decision 0002](../docs/decisions/0002-experimental-vodozemac-selection.md).

## Scope

Implement the specified core behavior and demonstrate conformance to its vectors and requirements. Keep application policy and consumer-specific trust decisions outside the protocol core.

## Out of scope

Independent production cryptography in Dart or .NET; binding or consumer integration before the core is reviewable; and claims that tests establish cryptographic security.

## Deliverables

A native implementation of the selected experimental profile and evidence of implementation conformance.

## Security invariants

Preserve one production security implementation, fail-closed behavior, and the exact limits of claims justified by P2/P3.

The implementation and its conformance checks MUST establish exclusive ownership of each pairing authority before any remote ceremony can be exposed. Ownership acquisition must be atomic and uncertainty fails closed. P4 must verify crash/termination handling and safe release before replacement. The owning process shares active remote state, one ceremony guard, and its 10-opportunity budget across roles, threads, and connections. The Windows account-scoped ownership policy is accepted in decision 0003; implementation verification remains required.

## Experimental entry requirements

Implement and verify:

- Exact reviewed message ordering and the pinned vodozemac 0.11.0 dependency.
- Fresh, unpredictable, non-reused ephemeral material; assess target RNG, fork, snapshot, restored-state, and RNG-failure limits.
- One owning process per pairing authority, safe acquisition/release, one live ceremony guard, and the shared ten-opportunity process/session budget.
- Atomic guard and opportunity reservation before any cryptographic contribution is released.
- No automatic retries, resumed ceremonies, or reconnect continuations; fresh local authorization for every exposure.
- I1 terminal-state irreversibility and I2 SAS invalidation and stale-approval rejection.
- Fail-closed handling of malformed cryptographic input and any security-critical invariant that cannot be enforced.
- Deterministic-vector validation and conformance checks for the current normative requirements.
- The finite pre-exposure transport/core caps, admission limits, and cleanup invariants in the authoritative profile, kept separate from SAS accounting.

No P4 implementation may invent a security decision for an undecided normative detail. Record it as a prerequisite and resolve it before implementing affected behavior. Windows account-scoped ownership is accepted in decision 0003; the distinct-session ownership verification requirement is complete in the tested configuration. Remaining experimental P4 requirements are not claimed as implemented. Experimental P4 does not require a qualified professional audit, which is not currently planned.

## Exit criteria

The implementation conforms to the selected experimental profile and vectors and is ready for the still-required P5 implementation review. Conformance alone is not production readiness.

## STOP conditions

Stop or return to P2/P3 if implementation reveals ambiguity, unsupported assumptions, or a material conflict with the specified security behavior.

## What this unlocks

The P5 post-implementation review of whether the Rust core correctly and safely implements the reviewed construction/profile.
