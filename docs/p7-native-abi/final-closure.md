# P7 Final Closure — Native ABI v1 Frozen

> **Pre-alpha. Not production approval.** P7 exposes the frozen experimental protocol candidate through a language-neutral native boundary. The ABI v1 freeze is an interface freeze for the Dart (P8) and .NET (P9) wrappers. It is not production deployment approval, a professional or independent security audit, formal verification, certification, or release approval.

**P7 COMPLETE — NATIVE ABI V1 FROZEN.** This is the authoritative P7 closure summary. Details live in the [P7 package](README.md) (per-increment evidence), the [ABI contract](abi-contract.md) (normative rules), the [decisions](decisions.md) (P7-D-001 to P7-D-013), the [ABI v1 manifest](abi-v1-manifest.md) (frozen values), and [`core/include/sas_pairing.h`](../../core/include/sas_pairing.h) (declarations).

## 1. Baseline and head

| Item | Value |
|---|---|
| Phase | [P7 — Native ABI](../../roadmap/P7-native-abi.md) |
| Branch | `feature/p7-native-abi`, the one long-lived P7 branch; one pull request at closure, not merged by this work |
| Baseline | `main` at `5becd0913db8760a82fd26c1b2ad4f91c7fb33c1` (merge of the P6 pull request #12) |
| Wrapped candidate | `sas-pairing-vodozemac-profile-draft-01`, version 1 ([P6 final closure](../p6-remediation/final-closure.md)); unchanged by P7 |
| P7.7 start | `f709ee6` (P7.6 closure; 27 commits ahead of `main`, 0 behind) |
| Last code and test head | `04ba09b` (`test: harden native abi v1 freeze evidence`), CI green on that exact head |
| Final head | The closure commit `docs: freeze p7 native abi v1` (documentation only), CI green on that exact head |

## 2. Increments

| Increment | Scope | Decisions |
|---|---|---|
| P7.1 | ABI foundation: version, types, status namespace, opaque runtime handle, runtime lifecycle, central panic containment, permanent fatal, payload-destructor suppression, unwind-only build | P7-D-001 |
| P7.1.1 | Native library residency and loader lifetime (documentation and header) | P7-D-002 |
| P7.2 | Authority lifecycle and the core error mapping | P7-D-003, P7-D-004 |
| P7.3 | Hosting contexts and Router lifetime | P7-D-005 |
| P7.4 | Windows listener ownership and the owner-loop lifetime bridge | P7-D-006, P7-D-007 |
| P7.5 | Bounded network drive, connection and run references, events, results | P7-D-008, P7-D-009, P7-D-010 |
| P7.6 | Trusted local ceremony control, SAS presentation, local-action statuses | P7-D-011, P7-D-012 |
| P7.7 | Final hardening, two-sided public-ABI evidence, ABI v1 freeze | P7-D-013 |

## 3. Decisions

| Decision | Subject |
|---|---|
| [P7-D-001](decisions.md#p7-d-001--native-runtime-handle-and-fatal-containment-unit) | One runtime per process; the runtime is the fatal unit; caught panic → permanent fatal; opaque never-reused handles |
| [P7-D-002](decisions.md#p7-d-002--native-library-residency-and-loader-lifetime) | One native image per process, resident until exit; no unload/reload or copied image; restart is the only recovery |
| [P7-D-003](decisions.md#p7-d-003--authority-handles-ownership-and-lifecycle) | Authority handles owned by the runtime; reserve-then-core; release and destroy cascades |
| [P7-D-004](decisions.md#p7-d-004--stable-core-error-mapping) | One exhaustive core-error mapping (100–107, 200–202) |
| [P7-D-005](decisions.md#p7-d-005--hosting-context-ownership-and-router-lifetime) | Hosts own one boxed Router each; cascades before authority release |
| [P7-D-006](decisions.md#p7-d-006--windows-listener-ownership-and-responder-configuration) | Caller-bound listener handed over through an in/out slot at one adoption point |
| [P7-D-007](decisions.md#p7-d-007--owner-loop--router-lifetime-bridge) | The one owner-loop → Router lifetime extension and its teardown order |
| [P7-D-008](decisions.md#p7-d-008--bounded-drive-and-foreign-event-model) | Bounded drive, fixed 128-byte events, every refusal before network progress |
| [P7-D-009](decisions.md#p7-d-009--connection--run-reference-semantics) | Connection handles; exact-`RunRef` run handles, at most 32 per connection, `RUN_UNTRACKED` |
| [P7-D-010](decisions.md#p7-d-010--pairingresult-ownership-and-foreign-access) | Runtime-owned results, lossless delivery, data access after fatal, local completion only |
| [P7-D-011](decisions.md#p7-d-011--trusted-local-ceremony-action-abi) | Nine explicit trusted-local actions, one owner-loop call each, nothing chained |
| [P7-D-012](decisions.md#p7-d-012--sas-presentation-identity-binding-and-local-action-statuses) | SAS presentation, exact `ceremony_identity` binding, statuses 204–226 and 405 |
| [P7-D-013](decisions.md#p7-d-013--abi-v1-final-freeze-and-wrapper-handoff) | ABI v1 final freeze, wrapper obligations, evolution rules |

## 4. The frozen ABI v1

Every value is in the [ABI v1 manifest](abi-v1-manifest.md), which is machine-checked against the Rust implementation, the header, and the built library.

- **Version:** `SAS_PAIRING_ABI_VERSION = 1`; `sas_pairing_abi_version()` returns 1 in every state (0 only if the query itself caught a panic). Not the protocol profile version (`sas-pairing-vodozemac-profile-draft-01`, version 1) and not the crate version (0.1.0).
- **Exports:** exactly 25, `extern "C"`, never `C-unwind`; an ordinary build exports none. Lifecycle: `sas_pairing_abi_version`, `sas_pairing_runtime_create`, `sas_pairing_runtime_destroy`, `sas_pairing_authority_register`, `sas_pairing_authority_release`, `sas_pairing_authority_status`, `sas_pairing_host_create`, `sas_pairing_host_destroy`. Network: `sas_pairing_host_attach_windows_listener`, `sas_pairing_host_detach_listener`, `sas_pairing_host_drive`, `sas_pairing_host_recheck_after_resume`, `sas_pairing_connection_close`. Results: `sas_pairing_result_info`, `sas_pairing_result_copy`, `sas_pairing_result_destroy`. Ceremony control: `sas_pairing_connection_start_initiator`, `sas_pairing_run_authorize_exposure`, `sas_pairing_run_expose_key`, `sas_pairing_run_presentation`, `sas_pairing_run_approve_sas`, `sas_pairing_run_emit_bootstrap_mac`, `sas_pairing_run_reject_sas`, `sas_pairing_run_cancel_sas`, `sas_pairing_run_emit_initiator_finish`.
- **Status namespace:** 48 `int32_t` values, no duplicate: 0; 1–4; 100–107; 200–226; 300; 400–405; 900. Every core `Error` and `CeremonyError` has exactly one value through exhaustive mappings; wrappers treat unknown non-zero values as failure; no status is a trust verdict.
- **Handle model:** six opaque `uint64_t` kinds (runtime, authority, host, connection, run, result) from one monotonic process-lifetime counter: `0` never valid, every value issued once to one kind, never reused, wrapped, or reset; exhaustion fails closed, and the drive (17 values) and local-start (1 value) preflights run before any work. A socket (`uintptr_t`, invalid `UINTPTR_MAX`) is an OS resource, not a handle.
- **Records:** `sas_pairing_bytes_view_t` and `sas_pairing_bootstrap_view_t` (input views, pointer-sized words), `sas_pairing_event_t` (128 bytes, align 8), `sas_pairing_result_info_t` (56, 4), `sas_pairing_action_t` (24, 8), `sas_pairing_sas_presentation_t` (56, 4): no padding, outputs written whole from zero, reserved fields and request-ID tail bytes zero, views never retained.
- **Integer namespaces:** 13 `uint32_t` namespaces with 84 explicit values, `0` invalid or none.

## 5. Runtime model

- **Loader invariant (P7-D-002):** exactly one supported native image per OS process; keep it resident until process exit; no unload/reload recovery; no copied or alternate image; `FATAL` recovery is a process restart. Every process-lifetime guarantee holds only under this invariant.
- **Fatal and panic model (P7-D-001, P6-D-004):** one central containment boundary (`dispatch` → `contain`) around every export; on a caught panic the fatal marker is set first, the payload's destructor is suppressed (never dropped, downcast, or formatted), and `SAS_PAIRING_FATAL` is returned. Fatal is permanent for the process. Each export keeps its frozen fatal class: 16 normal (refused without entering the core), 5 cleanup (runtime destroy, authority release, host destroy, listener detach, connection close), 3 result data (info, copy, destroy), 1 constant (version). The supported artifact is `panic = "unwind"`; `panic = "abort"` does not build.
- **Ownership and cleanup:** the runtime owns authorities, hosts (each with its boxed Router and optional network context of owner loop, connections, and bindings), and results. Teardown ends connection and run handles, then the owner loop and its connections, then the Router, then the authority's registration, then results (runtime destroy); a cleanup failure never restores a handle. Exactly one lifetime extension (`router_for_owner_loop`) bridges the owner loop to its host's Router.
- **Result semantics (P7-D-010, P6-D-005):** a result handle owns one immutable local verified completion, delivered once on the normal drive path and never dropped; it survives connection close, listener detach, host destroy, authority release, and fatal until result or runtime destroy. It never means peer completion, bilateral commit, durable shared trust, or common knowledge; either side may be the only result holder.
- **Ceremony-control semantics (P7-D-011, P7-D-012):** authorization ≠ exposure; MATCH ≠ BOOTSTRAP_MAC; BOOTSTRAP_MAC ≠ INITIATOR_FINISH; a local action ≠ a transport write; the final ACK is confirmed by the adapter alone. Decisions name the exact 32-byte `ceremony_identity`; `WRITE_PENDING` refuses mutating actions before core work while the presentation stays readable; run handles name exact `RunRef`s (a stale handle never reaches a replacement under a reused request ID; `RUN_ENDED` once, then `INVALID_HANDLE`); at most 32 run handles per connection, nothing evicted, remote overflow reported `RUN_UNTRACKED` with run 0, and a local start refused before the core when no handle could be issued.
- **Windows transport scope:** a caller-bound listener (the ABI never binds or chooses an address), the reviewed cooperative owner loop (at most one readiness wait of at most 250 ms, one socket operation per existing connection, one accept, 17 events per drive), adapter-owned outbound frames and final-ACK confirmation; no Rust thread, callback, or second transport. Other platforms build the same 25 exports and fail closed for authority, listener, drive, connection, and ceremony operations; that is not platform support.

## 6. P6 handoff closure

| Obligation | State |
|---|---|
| P6-D-004 native panic containment | **P6-D-004 ABI PANIC CONTAINMENT EVIDENCE COMPLETE.** Real core panics contained through `sas_pairing_authority_register` (P7.2) and through `sas_pairing_run_expose_key` after the core consumed an opportunity (P7.6, re-run in P7.7): `FATAL`, host alive, `PanicOnDrop` destructor never run, remaining stays 9, no core re-entry, cleanup available, fatal never reset. The P6 decision document is unchanged |
| P6-D-002 process-session accounting | Preserved: no ABI path (release, re-registration, runtime destroy and re-create, host churn, listener replacement, connection churn, completion, reject, cancel, timeout, fatal) refreshes the budget, START limiter, or process session |
| P6-D-005 local completion | Preserved: results are local completion only; both asymmetric directions keep evidence (the two-sided lost-final-ACK run for I-only; `p5_f007_final_ack_deadline_boundary_end_to_end` for R-only) |
| P5-F-005 (dispositioned to P7) | Discharged by the P6-D-004 evidence above |

## 7. Two-sided public-ABI evidence

Two independent endpoint processes, each with its own runtime and authority and each written as a foreign consumer (its own C declarations mirrored from the header, nothing of the crate), completed a real ceremony with each other through only the 25 exports, joined by a byte-transparent relay that never parses, builds, or changes a frame (`abi::tests::two_sided`). Both showed the same SAS and `ceremony_identity` and returned compatible results (peer roles, profile and version, shared context, request ID, each other's authenticated Bootstrap). Negative runs: reject and cancel (the undecided peer receives a verified CANCEL), connection close, listener detach, first-frame deadline, and a lost final ACK (the Initiator is the only result holder). **ABI v1 is sufficient for two-sided wrappers**: no export, status, or layout was missing.

## 8. Concurrency and lifecycle evidence

Every handle allocation and every stateful operation runs under the one runtime slot, so preflights stay valid and teardown serializes with drives and actions (P7.2–P7.6 race tests: concurrent creates, destroys, registrations, host and listener operations, drives against every teardown, local actions against drives and teardowns, two starts and two authorizations racing). Subprocess children isolate the process-global fatal state. P7.7 stability: the two-sided suite 15 of 15 isolated runs and 5 of 5 full `abi::tests` runs. The intermittent P7.6 observation in the frozen P5 router race test did not reproduce: 100 of 100 isolated runs of `p5_router_race_002_close_versus_start_admission`, 20 of 20 runs of all nine router-race tests, and 3 of 3 full default suites; no production race or test-isolation defect was found.

## 9. Unsafe audit summary

44 documented `unsafe` blocks, 10 `unsafe fn` with safety contracts, 18 `unsafe extern "C"` exports, and 25 `#[unsafe(no_mangle)]` attributes in `core/src/abi`: FFI reads and writes of validated caller memory, contract markers, forwarding, one raw socket adoption, and the one owner-loop lifetime bridge. Exactly one Router lifetime extension; no `transmute`, `Box::leak`, stored raw Router pointer, or self-referential trick. Pointer validity beyond null, alignment, length, wrap, and overlap checks is a caller precondition.

## 10. CI

Three jobs on every push: `consistency` (required files, public status, repository-wide Markdown links and anchors); `windows-core` (fmt, clippy default and all features, core tests, native-ABI tests, the two-sided step, ordinary build without ABI exports, release native build, artifact check, exact export audit, C11 and C++17 consumers); `unsupported-platform-fails-closed` (the same checks on Linux plus fail-closed steps for authority, listener, network drive, ceremony control, and every export's fatal class, `.so` export audits, gcc C11/C++17 consumers, and the negative `panic = "abort"` build). Green on the last code head `04ba09b` and on the closure head.

## 11. Accepted limitations

- The protocol candidate is experimental; its security argument remains conditional and AI-assisted review was not a professional audit.
- Pairing networking is supported only on Windows (the Windows TCP carrier); other platforms fail closed for pairing.
- Arbitrary invalid non-null pointers and non-socket integers passed as sockets are caller-contract violations the library cannot detect; the ABI is not a sandbox against hostile in-process code.
- Hostile in-process module loading (unloading, reloading, or loading a copy of the library) is outside the supported loader contract and is not detected.
- One native image must stay resident for the process lifetime.
- `SAS_PAIRING_FATAL` is permanent for the process; recovery requires an OS process restart.
- A result is local completion only; there is no distributed commit, and either side may be the only result holder.
- No consumer trust policy is encoded by any ABI status; wrappers and applications own UX and policy.
- The ceremony deadlines (60 s inactivity, 5 min absolute) cannot be shortened through the public ABI, so their two-sided expiry is evidenced one-sided with a test clock (P7.6), not between two public-ABI endpoints.
- A drive holds the runtime slot for up to its 250 ms readiness wait, so other calls on the same runtime wait that long plus bounded work.
- Miri cannot run the WinSock path; the aliasing argument for the lifetime bridge is reasoned, not machine-checked.
- The intermittent P5 router-race observation from P7.6 was not reproduced in 100 isolated, 20 grouped, and 3 full-suite runs; it is recorded as unreproduced, not as explained.
- `RUN_UNTRACKED` is reported, not acted on: closing the connection is the wrapper's job (SHOULD).

## 12. Explicit nonclaims

P7 does not claim: production deployment approval; release approval; formal verification; a professional or independent security audit or certification; platform support beyond Windows networking; protection against hostile in-process code, invalid caller pointers, or loader tampering; recovery from `FATAL` without a process restart; bilateral success, durable trust, or common knowledge from a result; any trust verdict from a status; or any semantic-versioning policy beyond P7-D-013 item 14.

## 13. P8 / P9 handoff

Mandatory for both wrappers ([P7-D-013](decisions.md#p7-d-013--abi-v1-final-freeze-and-wrapper-handoff) item 13, [ABI contract §21](abi-contract.md#21-wrapper-handoff-p8-p9), [P8](../../roadmap/P8-dart-package.md), [P9](../../roadmap/P9-dotnet-package.md)):

- bind exactly ABI v1 and check `sas_pairing_abi_version() == 1`;
- load one native image and keep it for the process lifetime: P8 retains its `DynamicLibrary`; P9 retains its `NativeLibrary` handle and never calls `NativeLibrary.Free` during supported use; no unload, reload, reset, or alternate copy;
- treat `SAS_PAIRING_FATAL` as requiring an OS process restart;
- keep the caller-owned pointer and buffer contracts;
- transfer listening sockets through the in/out slot and never touch a socket whose slot reads `SAS_PAIRING_SOCKET_INVALID`;
- drive cooperatively with the bounded drive and recheck, and consume every returned event, also when `out_failure` is not `SAS_PAIRING_OK`;
- SHOULD close a connection after `RUN_UNTRACKED` (the native library does not);
- keep every ceremony step an explicit call; treat `WRITE_PENDING` as "drive, then retry if still appropriate";
- bind MATCH, MISMATCH, and CANCEL to the exact presented `ceremony_identity`;
- never construct, parse, or send protocol frames in Dart or .NET, and never confirm a final ACK;
- present a result as local completion only; own the comparison UX and every trust policy.

**Next phase: P8 — Dart Package (not started).**
