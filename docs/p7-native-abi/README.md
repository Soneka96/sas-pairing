# P7 Native ABI

> **Pre-alpha. Not production approval.** P7 exposes the frozen experimental protocol candidate through a language-neutral native boundary for the future Dart and .NET wrappers. Nothing here is a professional audit, formal verification, certification, or production-security or release approval.

## Status

**P7 IN PROGRESS.** P7.1 (native ABI foundation and runtime/panic containment) is in progress. P7 must not be marked complete before every [completion gate](#completion-gates) holds.

## Target

| Item | Value |
|---|---|
| Phase | [P7 — Native ABI](../../roadmap/P7-native-abi.md) |
| Branch | `feature/p7-native-abi`: the one branch for every P7 increment, correction, and the P7 closure. One pull request is opened only when P7 is finished and frozen |
| Baseline | `main` at `5becd0913db8760a82fd26c1b2ad4f91c7fb33c1`, the merge of the P6 pull request #12 |
| Frozen candidate | `sas-pairing-vodozemac-profile-draft-01`, version 1 ([P6 final closure](../p6-remediation/final-closure.md)) |
| Contract | [ABI contract](abi-contract.md), [`core/include/sas_pairing.h`](../../core/include/sas_pairing.h) |
| Decisions | [decisions.md](decisions.md) |

P7 wraps the frozen candidate. It changes no wire bytes, cryptography, ceremony authentication, result semantics, deadlines, or security accounting; such a change would need an owner decision and would reopen the relevant earlier gate.

## Architecture

```text
sas-pairing-core (one crate, one protocol implementation)
  ├── reviewed protocol core (crate-private Host, Router, transport, Windows adapter, owner loop)
  └── abi module (feature `native-abi`)
        └── extern "C" exports → cdylib (sas_pairing_core.dll / libsas_pairing_core.so)
```

The ABI lives inside the core crate so later increments can call the reviewed crate-private core directly, without widening it into a public Rust API and without a second implementation of any state machine. The crate builds `rlib` and `cdylib`; exports exist only with `native-abi`.

## Increments

| Increment | Scope | State |
|---|---|---|
| P7.1 | ABI version, C type conventions, initial status namespace, opaque runtime handle, runtime create/destroy, central panic containment, permanent fatal state, payload-destructor suppression, unwind-only native build, checked-in header, CI, this package; [P7-D-001](decisions.md#p7-d-001--native-runtime-handle-and-fatal-containment-unit) | In progress |
| P7.2 | Authority lifecycle and core error mapping | Next after P7.1 |
| Later | Ceremony operations, network driving, SAS presentation, MATCH/REJECT, results, the real-core panic exit test, final header, P7 closure | Planned |

## Mandatory P6 handoff

| Obligation | Source | State |
|---|---|---|
| Every export runs inside a Rust `catch_unwind` boundary; no panic crosses `extern "C"`; no `C-unwind` | P6-D-004 items 3–4 | P7.1: one central dispatcher covers all current exports; later exports must use it |
| Caught panic → permanent fatal state; later operations return the fatal error without entering the core | P6-D-004 item 5 | P7.1: process-wide fatal unit (P7-D-001); create refuses after fatal |
| Payload destructor never runs; mark fatal → suppress destruction → return the fatal error; no payload inspection | P6-D-004 item 14 (P6.4.1) | P7.1: implemented and tested with a Drop-panicking payload |
| Fatal handle stays destroyable; destroy never reactivates or resets | P6-D-004 item 7 | P7.1: implemented for the runtime handle |
| Stable fatal error distinct from ordinary errors, carrying no payload data | P6-D-004 items 8–9 | P7.1: `SAS_PAIRING_FATAL = 900` |
| Unwind-compatible supported artifact, pinned and checked in CI | P6-D-004 item 12 | P7.1: `[profile.release] panic = "unwind"`, `compile_error!` guard, negative CI check |
| Rust-owned thread roots contained | P6-D-004 item 11 | Not applicable yet: P7.1 starts no thread |
| Real core panic → ABI fatal → host survives → next operation fatal without core re-entry → no fresh accounting → destroy works (ordinary and Drop-panicking payloads) | P6-D-004 item 13; P7 exit criteria | **Open:** P7.1 proves the primitive and the runtime lifecycle; the end-to-end test needs an export that enters the core (later increment) |
| No same-process accounting reset through any ABI path | P6-D-002 | P7.1 has no accounting; process-wide fatal unit prepared; to be shown with authorities (P7.2+) |
| Results presented as local verified completion, never a bilateral commit | P6-D-005 | Later increment (result access) |

## Completion gates

P7 is complete only when all of these hold:

- every planned native operation is exported through the central containment boundary, and the header is final;
- the P6-D-004 exit test passes through a real core-entering export, with both an ordinary and a Drop-panicking payload;
- every export (and any Rust-owned thread root) is shown to be covered;
- the unwind-only artifact is pinned in CI;
- no same-process re-registration or handle re-creation yields fresh accounting after a fatal panic (P6-D-002);
- result semantics are documented as local verified completion (P6-D-005);
- CI is green on the closure head, and the one P7 pull request is opened.
