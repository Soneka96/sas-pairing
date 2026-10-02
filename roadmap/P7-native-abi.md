# P7 — Native ABI

## Status

🟡 Planned; gated on a reviewed, sufficiently stable native implementation.

## Goal

Expose the reviewed native implementation through a stable language-neutral native boundary.

## Why this phase exists

Future language wrappers need to call the same security implementation without defining its protocol behavior independently.

## Inputs / prerequisites

P4 implementation and P6 review/remediation gate; a stable core boundary supported by the reviewed implementation.

### P6 handoff requirements (mandatory)

P6 decision [P6-D-004 — Native Panic Containment Policy](../docs/p6-remediation/decisions.md#p6-d-004--native-panic-containment-policy) dispositioned [P5-F-005](../docs/p5-security-review/findings.md#p5-f-005) (`Sas::new()` entropy panic) to this phase ([disposition record](../docs/p6-remediation/p5-f-005.md)). The core does not recover from panics. P7 owns their containment:

- **No escape:** every native export runs its Rust work inside a Rust `catch_unwind` boundary, and no Rust panic or unwind crosses `extern "C"` or an equivalent boundary. Foreign callers are never relied on to catch a Rust panic. `extern "C-unwind"` is not the supported API. Prefer one central dispatch mechanism that mechanically covers every export (create/open, destroy/close, drive/poll, receive/send, local authorization, exposure, approve/reject, presentation and result access, callbacks, later helpers).
- **Rust-owned threads:** any native background, worker, or callback thread has the same containment at its thread root and marks the relevant context fatal. A worker never dies silently while ABI calls continue.
- **Fatal state:** a caught panic permanently poisons the affected native context. P7's handle design names the containment unit; the default is the enclosing runtime or authority context that owns the panicking core state. Later calls return the same stable fatal-state error without entering the core: no retry, resumed ceremony, recreated run, fresh ephemeral, refund, or automatic re-registration.
- **Error semantics:** the fatal error is bounded, language-neutral, and distinct from every ordinary error (invalid state, resource limited, exhausted, ownership unavailable, timeout, protocol rejection). It carries no panic payload, Rust type name, file path, panic string, secret, or address. Diagnostics, if any, are not API semantics and expose no secrets.
- **Destruction:** a fatal handle can still be destroyed without running pairing logic. Destroy does best-effort Rust cleanup, invalidates the handle, never reactivates pairing, and never resets the process session.
- **No same-process accounting reset:** a panicked authority stays fatal for the rest of its process session. Close-and-reopen, release-and-reacquire, or re-registration in the same process is never recovery and never fresh accounting (P6-D-002). Recovery is to restart the native owning process, establish a fresh process session, and safely reacquire ownership. Wrapper documentation must say so.
- **Build configuration:** the supported native artifact used by the Dart and .NET wrappers uses an unwind-compatible panic strategy (`catch_unwind` cannot recover from `panic = "abort"`), set explicitly and checked in CI. A test fails if the supported artifact moves to `panic = "abort"` while claiming containment.

## Scope

Specify and implement the minimum native boundary needed by supported wrappers, including safe lifecycle and error behavior, and the P6-D-004 panic containment above (catch inside Rust at every export and Rust-owned thread root, permanent fatal state, stable fatal error, destroyable fatal handles, unwind-compatible supported build). Preserve any P2/P3 security-required attempt limits, counters, lifetime bounds, replay tracking, and persistence semantics across the boundary without choosing a storage design here.

## Out of scope

Binding-specific public API design, duplicating protocol logic in wrappers, or adding consumer trust policy to the core.

## Deliverables

A stable native boundary with evidence that it preserves the reviewed core behavior.

## Security invariants

Wrappers remain callers of one production security implementation. Boundary failures and missing, invalid, or rolled-back security-required state fail closed.

No Rust panic escapes a native export, and wrappers never receive a Rust unwind or panic payload as control flow. A caught panic never creates a `PairingResult`, success, approval, peer identity, refund, new opportunity, or fresh process session. It permanently poisons the affected context, so later operations fail without re-entering the core, and the fatal handle can still be destroyed. No same-process path resets authority accounting (P6-D-004, P6-D-002).

## Exit criteria

The boundary is usable by intended wrappers and does not undermine the reviewed core's guarantees, including any security-required attempt and persistence constraints.

P7 MUST NOT be marked complete unless:

- a deterministic test shows: injected core panic → the ABI call returns the fatal error → the host process survives → the next ABI operation returns the fatal-state error → the core operation is not retried → no fresh authority accounting appears → destroy succeeds and the handle becomes invalid;
- every export is shown to be covered by the containment mechanism, as is every Rust-owned thread root if any exist;
- a build/CI test pins the supported artifact's unwind-compatible panic strategy and fails if it becomes `panic = "abort"`;
- no same-process re-registration or handle re-creation yields fresh accounting after a fatal panic.

## What this unlocks

The Dart wrapper in P8 and .NET wrapper in P9.
