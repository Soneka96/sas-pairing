# P7 — Native ABI

## Status

🔵 **IN PROGRESS — P7.2 COMPLETE (authority lifecycle + core error mapping; P7.1 ABI foundation accepted after the P7.1.1 loader-lifetime correction).** Started 2026-10-02 from `main` at `5becd09` (the merge of the P6 pull request #12) on the one P7 branch `feature/p7-native-abi`; there is one P7 pull request, opened only at P7 closure. The prerequisites held: the P6 protocol candidate is frozen ([P6 final closure](../docs/p6-remediation/final-closure.md): `sas-pairing-vodozemac-profile-draft-01`, version 1, with owner decisions P6-D-001 to P6-D-005), and the P6 pull request is merged. Package: [docs/p7-native-abi](../docs/p7-native-abi/README.md) ([ABI contract](../docs/p7-native-abi/abi-contract.md), [decisions](../docs/p7-native-abi/decisions.md)).

| Increment | Scope | State |
|---|---|---|
| P7.1 | Native ABI foundation + runtime/panic containment ([P7-D-001](../docs/p7-native-abi/decisions.md#p7-d-001--native-runtime-handle-and-fatal-containment-unit)) | **Complete** (`b0aaee1`, `6b1b602`, `3dade72`, and the closure commit; [evidence](../docs/p7-native-abi/README.md#p71-evidence)). The P6-D-004 handoff is PARTIAL / FOUNDATION COMPLETE: the end-to-end exit test below still needs a core-entering export |
| P7.1.1 | Native library lifetime / reload semantics ([P7-D-002](../docs/p7-native-abi/decisions.md#p7-d-002--native-library-residency-and-loader-lifetime)) | **Complete** (documentation and header comments only; [evidence](../docs/p7-native-abi/README.md#p711-evidence)). P7.1 is accepted |
| P7.2 | Authority lifecycle + core error mapping ([P7-D-003](../docs/p7-native-abi/decisions.md#p7-d-003--authority-handles-ownership-and-lifecycle), [P7-D-004](../docs/p7-native-abi/decisions.md#p7-d-004--stable-core-error-mapping)) | **Complete** (`286a4ff`, `2197322`, and the closure commit; [evidence](../docs/p7-native-abi/README.md#p72-evidence)). Opaque authority handles owned by the runtime, register/release/status, cascading runtime destroy, every core error mapped explicitly. P6-D-004: real core panic containment complete; consumed-accounting preservation evidence remains for a later ceremony increment |
| P7.3 | Hosting context + bounded network driving (recommended next) | Not started |

## Goal

Expose the reviewed native implementation through a stable language-neutral native boundary.

## Why this phase exists

Future language wrappers need to call the same security implementation without defining its protocol behavior independently.

## Inputs / prerequisites

P4 implementation and the completed P6 review/remediation gate (the frozen experimental protocol candidate and its merged P6 pull request); a stable core boundary supported by the reviewed implementation. P7 wraps the frozen candidate and does not change its wire bytes, cryptography, ceremony authentication, result semantics, or security accounting; any such change needs an owner decision and reopens the relevant earlier gate. The process-session accounting of [P6-D-002](../docs/p6-remediation/decisions.md#p6-d-002--f-003-owner-session-policy) and the local-completion result semantics of [P6-D-005](../docs/p6-remediation/decisions.md#p6-d-005--local-completion-and-final-ack-deadline-boundary) (either side may be the only `PairingResult` holder; a result is not a bilateral commit) must be preserved and documented across the boundary.

### P6 handoff requirements (mandatory)

P6 decision [P6-D-004 — Native Panic Containment Policy](../docs/p6-remediation/decisions.md#p6-d-004--native-panic-containment-policy) dispositioned [P5-F-005](../docs/p5-security-review/findings.md#p5-f-005) (`Sas::new()` entropy panic) to this phase ([disposition record](../docs/p6-remediation/p5-f-005.md)). The core does not recover from panics. P7 owns their containment:

- **No escape:** every native export runs its Rust work inside a Rust `catch_unwind` boundary, and no Rust panic or unwind crosses `extern "C"` or an equivalent boundary. Foreign callers are never relied on to catch a Rust panic. `extern "C-unwind"` is not the supported API. Prefer one central dispatch mechanism that mechanically covers every export (create/open, destroy/close, drive/poll, receive/send, local authorization, exposure, approve/reject, presentation and result access, callbacks, later helpers).
- **Rust-owned threads:** any native background, worker, or callback thread has the same containment at its thread root and marks the relevant context fatal. A worker never dies silently while ABI calls continue.
- **Fatal state:** a caught panic permanently poisons the affected native context. P7's handle design names the containment unit; the default is the enclosing runtime or authority context that owns the panicking core state. Later calls return the same stable fatal-state error without entering the core: no retry, resumed ceremony, recreated run, fresh ephemeral, refund, or automatic re-registration.
- **Error semantics:** the fatal error is bounded, language-neutral, and distinct from every ordinary error (invalid state, resource limited, exhausted, ownership unavailable, timeout, protocol rejection). It carries no panic payload, Rust type name, file path, panic string, secret, or address. Diagnostics, if any, are not API semantics and expose no secrets.
- **Panic-payload disposal (P6.4.1):** a caught panic payload cannot execute an uncontained destructor, because dropping it can panic again outside `catch_unwind` and abort the host. On `Err(payload)` the containment path marks the context fatal first, does not expose the payload, intentionally suppresses its destruction (for example `std::mem::forget` in an internal helper; the requirement is that the destructor does not run), and then returns the fatal error. The payload is never downcast, formatted, serialized, or returned as part of correctness, and no nested `catch_unwind` around a drop is used. The leak is accepted only on this catastrophic, process-restart path. P7 installs no custom panic hook that panics or otherwise defeats containment.
- **Destruction:** a fatal handle can still be destroyed without running pairing logic. Destroy does best-effort Rust cleanup, invalidates the handle, never reactivates pairing, and never resets the process session.
- **No same-process accounting reset:** a panicked authority stays fatal for the rest of its process session. Close-and-reopen, release-and-reacquire, or re-registration in the same process is never recovery and never fresh accounting (P6-D-002). Recovery is to restart the native owning process, establish a fresh process session, and safely reacquire ownership. Wrapper documentation must say so.
- **Build configuration:** the supported native artifact used by the Dart and .NET wrappers uses an unwind-compatible panic strategy (`catch_unwind` cannot recover from `panic = "abort"`), set explicitly and checked in CI. A test fails if the supported artifact moves to `panic = "abort"` while claiming containment.

## Scope

Specify and implement the minimum native boundary needed by supported wrappers, including safe lifecycle and error behavior, and the P6-D-004 panic containment above (catch inside Rust at every export and Rust-owned thread root, permanent fatal state, no payload destructor run on the containment path, stable fatal error, destroyable fatal handles, unwind-compatible supported build). Preserve any P2/P3 security-required attempt limits, counters, lifetime bounds, replay tracking, and persistence semantics across the boundary without choosing a storage design here.

## Out of scope

Binding-specific public API design, duplicating protocol logic in wrappers, or adding consumer trust policy to the core.

## Deliverables

A stable native boundary with evidence that it preserves the reviewed core behavior.

## Security invariants

Wrappers remain callers of one production security implementation. Boundary failures and missing, invalid, or rolled-back security-required state fail closed.

No Rust panic escapes a native export, and wrappers never receive a Rust unwind or panic payload as control flow. A caught panic payload cannot execute an uncontained destructor: the context is marked fatal and the payload's destruction is suppressed before the fatal error is returned. A caught panic never creates a `PairingResult`, success, approval, peer identity, refund, new opportunity, or fresh process session. It permanently poisons the affected context, so later operations fail without re-entering the core, and the fatal handle can still be destroyed. No same-process path resets authority accounting (P6-D-004, P6-D-002).

**Loader lifetime ([P7-D-002](../docs/p7-native-abi/decisions.md#p7-d-002--native-library-residency-and-loader-lifetime)).** The ABI state (handles, fatal state, and from P7.2 authority accounting) is module state of the loaded library image, so its process-lifetime guarantees hold only under a supported loader invariant: exactly one native library image per OS process, resident from stateful use until process exit, never unloaded and reloaded and never duplicated from another path, with OS process restart as the only recovery from fatal. Unload/reload and copied images are outside the supported contract, never a reset or recovery. P8 and P9 loaders must retain exactly one supported native image for the process lifetime and expose no reload/reset mechanism.

## Exit criteria

The boundary is usable by intended wrappers and does not undermine the reviewed core's guarantees, including any security-required attempt and persistence constraints.

P7 MUST NOT be marked complete unless:

- a deterministic test shows: injected core panic → the ABI call returns the fatal error → the host process survives → the next ABI operation returns the fatal-state error → the core operation is not retried → no fresh authority accounting appears → destroy succeeds and the handle becomes invalid;
- the deterministic panic containment tests cover both an ordinary panic payload and a Drop-panicking custom payload (a `PanicOnDrop` type whose `Drop` panics, raised with `panic_any` through the core test seam or ABI test path): the original panic is caught → the context becomes fatal → the payload destructor is not executed → the ABI returns the stable fatal error → the host process stays alive → the next ABI operation returns the fatal-state error without re-entering the core → destroy remains possible;
- every export is shown to be covered by the containment mechanism, as is every Rust-owned thread root if any exist;
- a build/CI test pins the supported artifact's unwind-compatible panic strategy and fails if it becomes `panic = "abort"`;
- no same-process re-registration or handle re-creation yields fresh accounting after a fatal panic;
- the loader invariant (P7-D-002) is normative in the ABI contract and header, and the P8 and P9 handoffs preserve it.

## What this unlocks

The Dart wrapper in P8 and .NET wrapper in P9.
