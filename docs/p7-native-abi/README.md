# P7 Native ABI

> **Pre-alpha. Not production approval.** P7 exposes the frozen experimental protocol candidate through a language-neutral native boundary for the future Dart and .NET wrappers. Nothing here is a professional audit, formal verification, certification, or production-security or release approval.

## Status

**P7 IN PROGRESS — P7.6 COMPLETE.** P7.1 established the ABI version, type conventions, status namespace, opaque runtime handle, runtime lifecycle, and the central panic containment ([evidence](#p71-evidence)). The P7.1.1 correction fixed the loader boundary those process-lifetime guarantees depend on: one native library image per process, resident until process exit, never unloaded or reloaded as recovery ([P7-D-002](decisions.md#p7-d-002--native-library-residency-and-loader-lifetime), [evidence](#p711-evidence)). P7.2 brought real core state across the ABI: opaque authority handles owned by the runtime, register, release, and status around `TrustedAuthority`, a cascading runtime destroy, and one explicit mapping of every core error ([P7-D-003](decisions.md#p7-d-003--authority-handles-ownership-and-lifecycle), [P7-D-004](decisions.md#p7-d-004--stable-core-error-mapping), [evidence](#p72-evidence)). P7.2 contained a real panic inside `TrustedAuthority::register`, reached through `sas_pairing_authority_register`, with both payload kinds; P7.6 closed the remaining consumed-accounting evidence, so the P6-D-004 handoff is now **P6-D-004 ABI PANIC CONTAINMENT EVIDENCE COMPLETE**. P7.3 fixed the hosting hierarchy before any networking: opaque host handles, each a runtime-owned hosting context that records its parent authority and owns one real core `Router` in a `Box<Router>`, several hosts per authority sharing its accounting, host create and destroy, and cascades on authority release and runtime destroy ([P7-D-005](decisions.md#p7-d-005--hosting-context-ownership-and-router-lifetime), [evidence](#p73-evidence)). P7.4, narrowed from the earlier "listener + owner loop + bounded drive/event" scope, added Windows listener ownership and the owner-loop lifetime bridge: a caller-bound listening socket moves to a host through an in/out slot at one linearization point (every earlier failure leaves it with the caller), the host's Responder Bootstrap is copied into the core's `Bootstrap::new`, the reviewed owner loop is stored in the host over its boxed router through one audited lifetime extension, and every path ends the loop and its connections before the router and every router before the authority; attach and detach change no accounting, and nothing is driven ([P7-D-006](decisions.md#p7-d-006--windows-listener-ownership-and-responder-configuration), [P7-D-007](decisions.md#p7-d-007--owner-loop--router-lifetime-bridge), [evidence](#p74-evidence)). P7.5 exposed the existing bounded owner loop without a second transport: drive and resume-recheck exports that make every refusal (caller memory, an event capacity of 17, fatal, handles, a listener, and a non-consuming 17-handle preflight) before any network progress and translate each `OwnerStep` exhaustively into fixed 128-byte event records; stable opaque connection handles and exact-`RunRef` run handles (at most 32 per connection, owner-selected; nothing evicted), invalidated by CLOSED events, explicit connection close, and every teardown; owner-loop failures reported in `out_failure` with every earlier event kept; and every `PairingResult` moved losslessly into runtime-owned result handles that survive connection, listener, host, and authority teardown and stay readable after fatal, as local completion only ([P7-D-008](decisions.md#p7-d-008--bounded-drive-and-foreign-event-model), [P7-D-009](decisions.md#p7-d-009--connection--run-reference-semantics), [P7-D-010](decisions.md#p7-d-010--pairingresult-ownership-and-foreign-access), [evidence](#p75-evidence)). P7.6 exposed the reviewed trusted-local ceremony chain through nine explicit exports (25 in all): local Initiator start (refused before the core at 32 run handles or without a handle value: never an untracked local run), exposure authorization from the host's own authority (spends nothing), key exposure (the core's one spending step), the read-only SAS presentation (exact 32-byte identity and 14-byte decimal display, also while a write is pending), MATCH, MISMATCH, and CANCEL bound to the exact `ceremony_identity`, and own BOOTSTRAP_MAC and INITIATOR_FINISH, one reviewed owner-loop call each and nothing chained; frames stay adapter-owned and the final ACK adapter-confirmed; a fixed 24-byte action record, `WRITE_PENDING` backpressure, `RUN_ENDED` for stale exact runs, `CONNECTION_ENDED`, and one exhaustive ceremony-error mapping (statuses 204–226, 405); the P8/P9 `RUN_UNTRACKED` handoff is now SHOULD-close ([P7-D-011](decisions.md#p7-d-011--trusted-local-ceremony-action-abi), [P7-D-012](decisions.md#p7-d-012--sas-presentation-identity-binding-and-local-action-statuses), [evidence](#p76-evidence)). Next: P7.7 — Native ABI Final Hardening + Freeze (not started). P7 must not be marked complete before every [completion gate](#completion-gates) holds.

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
| P7.1 | ABI version, C type conventions, initial status namespace, opaque runtime handle, runtime create/destroy, central panic containment, permanent fatal state, payload-destructor suppression, unwind-only native build, checked-in header, CI, this package; [P7-D-001](decisions.md#p7-d-001--native-runtime-handle-and-fatal-containment-unit) | **Complete:** `b0aaee1` (contract), `6b1b602` (implementation, tests, CI), `3dade72` (CI YAML correction: the `abi::` test filter ended a plain scalar with a colon, so `rust-core.yml` did not parse on `6b1b602`), and the closure commit |
| P7.1.1 | Native library lifetime / reload semantics: loader experiments, [P7-D-002](decisions.md#p7-d-002--native-library-residency-and-loader-lifetime), the [loading and residency](abi-contract.md#14-native-library-loading-and-residency) contract section, header warning, P8/P9 loader handoffs. Documentation and header comments only; no `core/src` change | **Complete** (`docs: define native abi loader lifetime`; [evidence](#p711-evidence)). P7.1 is accepted |
| P7.2 | Authority lifecycle and core error mapping: opaque authority handles from the shared counter, runtime ownership of `TrustedAuthority`, register/release/status exports, cascading runtime destroy, authority/runtime concurrency, the core error mapping, and the real-core panic tests; [P7-D-003](decisions.md#p7-d-003--authority-handles-ownership-and-lifecycle), [P7-D-004](decisions.md#p7-d-004--stable-core-error-mapping) | **Complete:** `286a4ff` (decisions and contract), `2197322` (implementation, header, tests, CI), and the closure commit ([evidence](#p72-evidence)) |
| P7.3 | Hosting context foundation and Router lifetime: opaque host handles from the shared counter, a runtime-owned host context per Router (`Box<Router>` over the parent authority's executor), several hosts per authority, host create/destroy, cascades on authority release and runtime destroy, no networking; [P7-D-005](decisions.md#p7-d-005--hosting-context-ownership-and-router-lifetime). Narrowed from the earlier "hosting context + bounded network driving" recommendation: the owner loop borrows the Router, so the hierarchy is fixed first | **Complete:** `ffa6f8f` (decision and contract), `94e3834` (implementation, header, tests), and the closure commit ([evidence](#p73-evidence)) |
| P7.4 | Windows listener ownership + owner-loop lifetime bridge: ownership transfer of a caller-bound listening socket through an in/out slot, the Responder Bootstrap views, the one contained `WindowsOwnerLoop<'static>` → boxed Router lifetime extension, attach/detach/replacement, cleanup order on every path, panic and ownership-transfer safety; [P7-D-006](decisions.md#p7-d-006--windows-listener-ownership-and-responder-configuration), [P7-D-007](decisions.md#p7-d-007--owner-loop--router-lifetime-bridge). Narrowed: `drive_once` events carry `ConnectionRef`s, `RunRef`s, `TcpEvent`s, and one-shot `PairingResult`s that no ABI call may drop, so driving waits for their representation (P7.5) | **Complete:** `c1aa00e` (decisions and contract), `96af6af` (implementation, header, tests, CI), corrections `465f3ef`, `0d420ed`, `b2e205b`, `8827498`, `98a75e9`, `613a00b` ([CI corrections](#ci-corrections)), and the closure commit ([evidence](#p74-evidence)) |
| P7.5 | Bounded network drive + connection/run/event/result ABI: the bounded `drive_once` and `recheck_after_resume` exports, a fixed event array, opaque connection and run handles and their invalidation, lossless `PairingResult` delivery and result access, the `OwnerEvent`/`TcpEvent`/`HostEvent` representation and the error translation, explicit connection close, event-buffer and handle-capacity preflight; outbound bytes stay adapter-owned; [P7-D-008](decisions.md#p7-d-008--bounded-drive-and-foreign-event-model), [P7-D-009](decisions.md#p7-d-009--connection--run-reference-semantics), [P7-D-010](decisions.md#p7-d-010--pairingresult-ownership-and-foreign-access) | **Complete:** `ed9b5a6` (decisions and contract), `7e87e2d` (implementation, header, tests, CI), and the closure commit ([evidence](#p75-evidence)) |
| P7.6 | Ceremony control + SAS / authorization ABI: local Initiator START, exposure authorization, key exposure, SAS presentation, exact `ceremony_identity` input, MATCH, REJECT, CANCEL, BOOTSTRAP_MAC and INITIATOR_FINISH emission, precise local-action status mapping, and the consumed-accounting part of the P6-D-004 exit test; [P7-D-011](decisions.md#p7-d-011--trusted-local-ceremony-action-abi), [P7-D-012](decisions.md#p7-d-012--sas-presentation-identity-binding-and-local-action-statuses) | **Complete:** `00bbf3c` (decisions and contract), `8b9ae06` (implementation, header, tests, CI), `fd5e030` (consumed-accounting panic evidence), and the closure commit ([evidence](#p76-evidence)) |
| P7.7 (next) | Native ABI final hardening + freeze: full two-sided ABI end-to-end ceremony tests, lifecycle and concurrency audit, final closure of the panic exit criterion, header and ABI v1 freeze, exact export audit, documentation and roadmap closure, final CI, and the one P7 pull request | Planned |

## Mandatory P6 handoff

| Obligation | Source | State |
|---|---|---|
| Every export runs inside a Rust `catch_unwind` boundary; no panic crosses `extern "C"`; no `C-unwind` | P6-D-004 items 3–4 | P7.1: one central dispatcher; P7.2: all six exports use it; P7.3: all eight; P7.4: all ten; P7.5: all sixteen; P7.6: all twenty-five (source-scan test) |
| Caught panic → permanent fatal state; later operations return the fatal error without entering the core | P6-D-004 item 5 | P7.1: process-wide fatal unit (P7-D-001); create refuses after fatal. P7.2: register and status refuse after fatal before any handle check, with a test-only core-entry counter showing no re-entry. P7.3: host create refuses after fatal without cloning an executor or building a router (test-only per-thread construction counter); a panic right after the real `Router::new` is contained with both payload kinds. P7.4: listener attach refuses after fatal before adopting the socket, without entering the core or building a loop; a panic right after socket adoption is contained with both payload kinds, with exactly one socket owner. P7.5: drive and recheck refuse after fatal without calling the owner loop (test-only per-thread call counter); a panic in the middle of a real drive returns `FATAL` with no success reported, and later drives never run the loop. P7.6: all nine trusted local actions refuse after fatal without an owner-loop call (test-only per-thread counter) |
| Payload destructor never runs; mark fatal → suppress destruction → return the fatal error; no payload inspection | P6-D-004 item 14 (P6.4.1) | P7.1: implemented and tested with a Drop-panicking payload |
| Fatal handle stays destroyable; destroy never reactivates or resets | P6-D-004 item 7 | P7.1: runtime handle. P7.2: authority release and the cascading runtime destroy stay allowed as cleanup after fatal and never clear it. P7.3: host destroy is cleanup too. P7.4: listener detach is cleanup and closes an adopted socket after fatal. P7.5: connection close is cleanup; existing results stay readable and destroyable through a separate data path that never enters the core |
| Stable fatal error distinct from ordinary errors, carrying no payload data | P6-D-004 items 8–9 | P7.1: `SAS_PAIRING_FATAL = 900` |
| Unwind-compatible supported artifact, pinned and checked in CI | P6-D-004 item 12 | P7.1: `[profile.release] panic = "unwind"`, `compile_error!` guard, negative CI check |
| Rust-owned thread roots contained | P6-D-004 item 11 | Not applicable yet: no increment starts a thread. The owner loop is cooperative and synchronous and runs only inside the caller's drive and recheck calls (P7.5; a source-scan test forbids threads in the ABI) |
| Real core panic → ABI fatal → host survives → next operation fatal without core re-entry → no fresh accounting → destroy works (ordinary and Drop-panicking payloads) | P6-D-004 item 13; P7 exit criteria | **P6-D-004 ABI PANIC CONTAINMENT EVIDENCE COMPLETE (P7.6).** P7.6: a real panic inside `RemoteCeremony::expose_key` after the core reserved the guard and burned one opportunity (the existing test hook `Point::InitiatorReserved`), reached through `sas_pairing_run_expose_key`, is contained with an ordinary and a `PanicOnDrop` payload: `FATAL`, process fatal, host alive, payload destructor never run, 9 remaining (never restored to 10), no core or owner-loop re-entry by any later normal call, cleanup available ([details](#p76-evidence)). Earlier record (P7.2): REAL CORE PANIC CONTAINMENT COMPLETE; A panic inside `TrustedAuthority::register`, reached through `sas_pairing_authority_register`, is caught in Rust with an ordinary and a `PanicOnDrop` payload: fatal, `FATAL`, host alive, payload destructor never run, no core re-entry, cleanup allowed, no fresh accounting through the ABI. Not yet shown: a panic during an ABI operation that itself consumed an opportunity, because no ceremony export exists ([details](#p72-evidence)). P7.5 adds a contained panic in the middle of a real drive (fatal, no false success, accounting unchanged), but no P7.5 export consumes an opportunity, so this stayed for the P7.6 authorization and exposure exports, which closed it |
| No same-process accounting reset through any ABI path | P6-D-002 | P7.2: release, re-registration, runtime destroy, and a new runtime keep the same process session, budget, and exhaustion (opportunities spent through the core's own reserve path in tests); a fatal process cannot register again. P7.3: host creation and destruction, and release or runtime destroy with live hosts, change no budget, guard, or session. P7.4: listener attach, detach, replacement, and the cascades over attached listeners change no budget, START limiter, guard, or session; exhaustion stays. P7.5: drive, recheck, connection close, and result access consume or refund nothing; a completed ceremony's opportunity stays consumed through close, detach, host destroy, release, fatal, and runtime destroy. P7.6: authorization spends nothing, exposure spends exactly one, and reject, cancel, deadlines, every teardown, a contained panic, and re-registration never refund it; local starts never touch the START limiter |
| Loader lifetime invariant established before authority lifecycle: one native image per process, resident until process exit, no unload/reload or copied image as reset or recovery | P6-D-002, P6-D-004 via [P7-D-002](decisions.md#p7-d-002--native-library-residency-and-loader-lifetime) | P7.1.1: normative in the contract and header; a host obligation, not enforced by the library. P8 and P9 must carry it into their loaders. P7.2: authority process-session accounting now crosses the ABI and depends on it (contract §15.6); still no self-pinning or shared-memory accounting. P7.3: host handles and routers are module state under the same invariant (contract §16.8). P7.4: listeners and owner loops too (contract §17.10). P7.5: connection and run references and results too |
| Results presented as local verified completion, never a bilateral commit | P6-D-005 | P7.5: result handles own one immutable local completion each (P7-D-010); the contract and header say a result never means the peer completed; a test shows the ABI Initiator holding a result the peer never gets. P7.6: local actions add no bilateral-success concept; the Initiator's result still appears only after the adapter's complete local write of the final ACK |

## Completion gates

P7 is complete only when all of these hold:

- every planned native operation is exported through the central containment boundary, and the header is final;
- the P6-D-004 exit test passes through a real core-entering export, with both an ordinary and a Drop-panicking payload;
- every export (and any Rust-owned thread root) is shown to be covered;
- the unwind-only artifact is pinned in CI;
- no same-process re-registration or handle re-creation yields fresh accounting after a fatal panic (P6-D-002);
- result semantics are documented as local verified completion (P6-D-005);
- the P8 and P9 handoffs keep the loader invariant of P7-D-002: exactly one native image retained for the process lifetime, and no unload, reload, or reset mechanism;
- CI is green on the closure head, and the one P7 pull request is opened.

## P7.1 evidence

Verified on Windows (`rustc 1.99.0`) at `6b1b602` (`3dade72` changes only the CI filter spelling); Linux is covered by CI.

### Tests (`abi::tests`, feature `native-abi`)

| Area | Tests | What they show |
|---|---|---|
| Constants and header | `abi_constants_are_frozen`, `version_export_reports_abi_version_one`, `export_signatures_are_pinned`, `header_matches_the_rust_abi`, `manifest_pins_the_supported_native_artifact` | ABI version 1, invalid version 0, exact status values, 64-bit handle, handle 0 invalid; the header's version, status defines, typedefs, and exact declarations match Rust, and its declared functions equal the `no_mangle` functions in the sources; release profile `panic = "unwind"`, `rlib` + `cdylib`, the feature |
| Export coverage | `every_export_runs_inside_the_central_panic_boundary` | All three exports start with `dispatch(`; `catch_unwind` appears only in `panic_boundary.rs`; no panic hook, no `C-unwind` |
| Handles | `handles_start_at_one_and_are_never_repeated`, `the_handle_counter_fails_closed_instead_of_wrapping`, `create_after_handle_exhaustion_fails_closed_without_a_runtime`, `a_destroyed_handle_never_aliases_a_later_runtime` | Strictly increasing from 1; `UINT64_MAX` is issued once, then allocation fails forever; exhaustion installs no runtime and is not fatal; stale handles never alias |
| Containment primitive | `contain_returns_the_value_and_stays_healthy_without_a_panic`, `contain_catches_an_ordinary_panic_and_marks_fatal` (Test A), `contain_never_runs_a_drop_panicking_payload_destructor` (Test B) | Ordinary panic caught, fatal set, `FATAL` (or version `0`) returned, the test process continues; `panic_any(PanicOnDrop)` caught, fatal set, `FATAL` returned, destructor counter stays 0 |
| Fatal lifecycle (local state) | `a_fatal_state_blocks_create_but_not_destroy`, `a_panic_that_poisons_the_runtime_slot_still_allows_destroy` | Fatal blocks create, destroy works once, fatal survives destroy; a panic that poisons the runtime lock still leaves destroy possible |
| Real exports, isolated processes | `runtime_lifecycle_through_the_exports`, `concurrent_creates_admit_exactly_one_runtime`, `an_ordinary_panic_makes_the_process_permanently_fatal`, `a_drop_panicking_payload_is_contained_at_an_export`, `only_a_new_process_has_a_clean_abi_state` | Each re-runs this test binary with one `#[ignore]`d child test against the real process-global state (no reset hook). Null and misaligned output pointers give `INVALID_ARGUMENT` with nothing written; create; `ALREADY_INITIALIZED` with output 0; destroy; duplicate, zero, random, and stale destroys give `INVALID_HANDLE`; a new handle after a normal destroy. 32 rounds of 16 threads racing create admit exactly one runtime each, with 32 distinct handles, and racing destroys succeed exactly once; a 120 s child deadline turns a hang into a failure. An injected panic at an export-shaped `extern "C"` seam returns `FATAL`; afterwards create returns `FATAL` with output 0, the version query still returns 1, the fatal runtime is destroyed once, and create stays `FATAL`. With a `PanicOnDrop` payload the child survives, which it could not if the destructor ran (that panic would cross `extern "C"` and abort it). A fresh process creates normally |

Counts: `cargo test --features native-abi --lib abi::tests` gives 20 passed and 5 ignored (the child bodies). The full suite with the feature gives 435 unit tests passed (8 ignored: the 3 P5 deep runs and the 5 children), 2 + 9 integration tests, and 1 doc test, 0 failed. Without the feature it is unchanged at 415 unit (3 ignored), 2 + 9 integration, and 1 doc test, 0 failed.

### Mutation checks (temporary, not committed)

| Mutation | Result |
|---|---|
| A: `mem::forget(payload)` replaced by `drop(payload)` | Fails: `contain_never_runs_a_drop_panicking_payload_destructor`, and `a_drop_panicking_payload_is_contained_at_an_export`, whose child aborted (`0xc0000409`, "panic in a function that cannot unwind") |
| B: the handle counter stops advancing (handle reuse) | Fails: 6 tests, including the stale-handle, lifecycle, and concurrency tests ("handle 1 issued twice") |
| C: the singleton check removed (a second create replaces the active runtime) | Fails: 3 tests, including the concurrency test (16 of 16 creates returned `OK`) |
| D: `CARGO_PROFILE_RELEASE_PANIC=abort`, and separately `RUSTFLAGS="-C panic=abort"`, on the `native-abi` release build | The build fails with the guard's `compile_error!` (the `native-abi` feature requires `panic = "unwind"`); the same abort build without the feature still succeeds; the normal native build succeeds after restoring |

All sources were restored byte for byte (SHA-256 checked).

### Artifact

`cargo build --manifest-path core/Cargo.toml --release --features native-abi` produces `core/target/release/sas_pairing_core.dll` and `sas_pairing_core.dll.lib`. `llvm-readobj --coff-exports` lists exactly `sas_pairing_abi_version`, `sas_pairing_runtime_create`, and `sas_pairing_runtime_destroy`; a release build without the feature exports none. A throwaway C program (`clang -std=c11 -Wall -Wextra -Werror -pedantic`, linked against the import library) ran the lifecycle against the DLL and passed, and the header also parses as C++17.

### Unsafe audit

| Site | Why | Precondition and justification |
|---|---|---|
| `mod.rs`, `sas_pairing_runtime_create`: one `unsafe` block, `out_runtime.write(value)`, used for the entry `0` and the final handle | The only way to fill the caller's output slot | Runs only after the null and alignment checks. The caller guarantees (the `# Safety` section and the header) that a non-null pointer addresses one writable, caller-owned `uint64_t`, not accessed concurrently, for the whole call. `u64` has no invalid bit patterns and no destructor; the write covers exactly one `u64`; nothing is retained after return |
| `pub unsafe extern "C" fn sas_pairing_runtime_create` | Marks the raw-pointer precondition in Rust | Not a block; carries the `# Safety` contract above |
| `#[unsafe(no_mangle)]` × 3 | Edition 2024 marks symbol export as unsafe | The obligation is symbol uniqueness: every name carries the `sas_pairing_` prefix, and the header test pins the exact set |
| Tests: three `unsafe` calls of `sas_pairing_runtime_create` | Exercise the export | A live, aligned, exclusive `u64`; a null pointer; a deliberately misaligned pointer that is rejected before any write |

No other `unsafe` was added.

### Frozen-core check

Outside `core/src/abi`, `git diff 5becd09..3dade72` changes only `core/src/lib.rs` (two lines: the feature-gated `mod abi;`), `core/Cargo.toml` (`[lib]` crate types, the `native-abi` feature, `[profile.release] panic = "unwind"`; no dependency change, `Cargo.lock` unchanged), `core/README.md`, the new header, CI, and the P7 documents. There is no wire, vector, cryptography, profile, ceremony, result, accounting, deadline, transport, or P6 decision change.

### Verification

| Check | Result |
|---|---|
| `cargo fmt --manifest-path core/Cargo.toml -- --check` | Pass |
| `cargo clippy --manifest-path core/Cargo.toml --all-targets -- -D warnings` | Pass (Windows; also `--target x86_64-unknown-linux-gnu`) |
| `cargo clippy --manifest-path core/Cargo.toml --all-targets --all-features -- -D warnings` | Pass (Windows; also `--target x86_64-unknown-linux-gnu`) |
| `cargo test --manifest-path core/Cargo.toml`, with and without `--features native-abi` | Pass (counts above) |
| `cargo build --manifest-path core/Cargo.toml --release --features native-abi` | Pass |
| Repository consistency script, `git diff --check`, relative links of the P7 documents | Pass |
| GitHub Actions on `3dade72`: Repository consistency; Rust security core `windows-core` (now also native-ABI clippy, tests, and release build) and `unsupported-platform-fails-closed` (also native-ABI clippy, tests, release build, and the negative `panic = "abort"` build check) | Pass |

## P7.1.1 evidence

P7.1 wrote its guarantees for the OS process, but the state behind them is module state of the loaded library image (`static PROCESS: AbiState` in `core/src/abi/mod.rs`). A module static lives only as long as its image, so P7.1.1 tested what unloading and duplicating the image do to it before authority state enters the ABI.

**Setup.** The release artifact from `cargo build --manifest-path core/Cargo.toml --release --features native-abi` at `cbf0ea3` (`sas_pairing_core.dll`, SHA-256 `4f1d61e4da2a8b0d822444f2eb8a3e4f3c3969d5efa9bc28659f1bfa01bbe459`). A throwaway C host in a scratch directory outside the repository (clang 19.1.5, `-std=c11 -Wall -Wextra -Werror`), using only `LoadLibraryW`, `GetProcAddress`, and `FreeLibrary`; each run is a fresh OS process. Nothing from the experiments is committed, and the copied DLL was deleted afterwards. Windows 11 Pro 26200, rustc 1.99.0.

| Run | Calls | Observed |
|---|---|---|
| Control (one resident image) | load; create; destroy; create | `OK` handle 1; destroy `OK`; `OK` handle 2. H2 ≠ H1 |
| A: same DLL unload/reload | load; create H1; destroy H1; `FreeLibrary`; load the same path; create H2 | H1 = 1. `FreeLibrary` returned 1 and `GetModuleHandleW(path)` was then null (image unmapped). After the reload, create returned `OK` with **H2 = 1**: the handle counter restarted |
| A, variant: live runtime abandoned | load; create H1; create again; `FreeLibrary` (H1 never destroyed); reload; create | `OK` 1, then `ALREADY_INITIALIZED`; after the reload, create returned `OK` with handle 1: the single-runtime slot restarted too |
| B: two independent images | load the original; load a byte-identical copy (`sas_pairing_core_copy.dll`, another path); create through each, then a second create through each | Distinct `HMODULE`s; image A `OK` handle 1; image B `OK` handle 1 while A's runtime was still live; each image's second create `ALREADY_INITIALIZED`. Two independent runtimes in one OS process |

**Empirically shown:** module unload and reload resets the handle counter and the runtime slot without an OS process restart, and two images of the library each keep their own. So P7.1's "never reused in the OS process" and "one runtime per OS process" hold per resident image, not per process, unless the loader is constrained.

**Structural conclusion (no experiment).** The fatal marker (`FatalState`) is a field of the same `PROCESS` static as the counter and the slot. The release DLL has no export that can panic, and P7.1.1 adds none (no debug ABI was built for this), so a fatal reload was not run. Because unloading ends the image that holds `PROCESS` and a reload builds a new one, a reloaded or copied image would start without the fatal marker, exactly as the counter and slot did. The same holds for the core's authority registry (`REGISTRY` in `core/src/lib.rs`), which P7.2 will bring under the ABI.

**Decision.** The owner selected a supported loader invariant, [P7-D-002](decisions.md#p7-d-002--native-library-residency-and-loader-lifetime): one image per process, resident until process exit, no unload/reload, no copied image, process restart as the only recovery. The library does not enforce it (no self-pinning, no new status code); P8 and P9 carry it as a loader obligation.

| Scenario | Classification |
|---|---|
| One resident image: create H1, destroy, create H2 | Supported; H2 ≠ H1 |
| Panic → fatal → destroy → create again | Supported; create returns `SAS_PAIRING_FATAL` |
| Fatal → unload the image → reload it | Outside the supported ABI contract; not recovery |
| Load the DLL, then load a copied DLL | Outside the supported ABI contract |
| The Dart wrapper reopens the library after `FATAL` | Forbidden wrapper behavior (P8 handoff) |
| The .NET wrapper calls `NativeLibrary.Free` after `FATAL`, then reloads | Forbidden wrapper behavior (P9 handoff) |
| The OS process exits and a new one starts | Supported recovery: fresh native state, and a fresh process session once authority ownership is safely acquired |

**Unchanged:** `git diff cbf0ea3 -- core/src` is empty. ABI version `1`, the three exports, every status value, the handle type, and every header declaration are unchanged; the header changed only in comments.

| Check | Result |
|---|---|
| `cargo fmt --manifest-path core/Cargo.toml -- --check` | Pass |
| `cargo clippy --manifest-path core/Cargo.toml --all-targets --all-features -- -D warnings` | Pass |
| `cargo test --manifest-path core/Cargo.toml` | Pass |
| `cargo test --manifest-path core/Cargo.toml --features native-abi --lib abi::tests` | Pass: 20 passed, 5 ignored (the child bodies), including the header consistency test |
| `cargo build --manifest-path core/Cargo.toml --release --features native-abi` | Pass |
| Repository consistency script, `git diff --check`, relative links and anchors of the changed documents | Pass |

## P7.2 evidence

Verified on Windows 11 (`rustc 1.99.0`) at `2197322`; Linux is covered by CI. Decisions: [P7-D-003](decisions.md#p7-d-003--authority-handles-ownership-and-lifecycle) (authority handles, ownership, lifecycle) and [P7-D-004](decisions.md#p7-d-004--stable-core-error-mapping) (core error mapping); contract [§15](abi-contract.md#15-authorities) and [§3](abi-contract.md#3-status-codes).

### Source recheck (before implementing)

`TrustedAuthority::register` (`core/src/lib.rs`) rejects an empty scope or one over `u32::MAX` bytes, builds the canonical identity (domain, big-endian length, scope), takes the process-wide `REGISTRY` lock, and either reactivates an existing `ProcessSession` (fails `AlreadyRegistered` when `Active`, `OwnershipUncertain` when `Uncertain` or when runtime resources are still held or the accounting is poisoned, then acquires the OS lease anew) or acquires the lease first and creates a fresh session (ten opportunities, a fresh START limiter and clock). `release` needs the only reference (`Busy` otherwise) and runs `State::end`, which `Drop` also runs: release the lease, then mark the session `Inactive` (or `Uncertain`). Sessions are never evicted. `Status` lives on `CeremonyExecutor::status` (`Busy` while the exposed-ceremony guard is held, `Exhausted` at zero, else `Ready { remaining }`). The core `Error` has eleven variants. The existing per-thread `test_hook` mechanism supported a new point without a second hook system.

### Surface

Six exports, all entering through `dispatch`: `sas_pairing_abi_version`, `sas_pairing_runtime_create`, `sas_pairing_runtime_destroy`, `sas_pairing_authority_register`, `sas_pairing_authority_release`, `sas_pairing_authority_status`. ABI version `1`; every P7.1 value and signature unchanged; new typedefs `sas_pairing_authority_t` (`uint64_t`) and `sas_pairing_authority_state_t` (`uint32_t`); new status values 100–107 and 200–202; `<stddef.h>` for `size_t`.

### Implementation

| Part | Where | What |
|---|---|---|
| Handles | `runtime.rs` | The P7.1 `HandleCounter` issues runtime and authority values alike (`AbiState::allocate_handle`) |
| Ownership | `runtime.rs` | `Runtime.authorities: BTreeMap<NonZeroU64, TrustedAuthority>`; `Runtime::destroy` drops the map (the core's own `Drop` per authority) |
| Admission | `runtime.rs` `AbiState::with_runtime` | Normal: fatal check, slot lock (poisoned → mark fatal, `FATAL`), fatal recheck, runtime handle. Cleanup: lock (poison tolerated), runtime handle. The operation runs while the slot is held |
| Destroy | `runtime.rs` `AbiState::destroy` | Takes the runtime out of the slot and destroys it before releasing the slot |
| Register / release / status | `authority.rs` | Reserve handle → `TrustedAuthority::register` → install; remove → `TrustedAuthority::release`; `executor().status()` → `authority_state`. Core calls go through `enter_core`, which counts entries in test builds only |
| Mapping | `status.rs` `map_core_error` | One exhaustive, wildcard-free `match` |
| Raw arguments | `mod.rs` | Null/misaligned outputs, null scope with a length, length over `isize::MAX`, wrapping scope range, scope overlapping `out_authority`, and `out_state == out_remaining` are rejected before any write |

### Tests (`abi::tests` and `abi::tests::authority`, feature `native-abi`)

| Area | Tests | What they show |
|---|---|---|
| Constants, header, coverage | `abi_constants_are_frozen`, `export_signatures_are_pinned`, `header_matches_the_rust_abi`, `every_export_runs_inside_the_central_panic_boundary` | All 17 status values pinned and distinct; the four authority-state values; the header's typedefs (exact set), defines, and six exact declarations equal the Rust ABI and the `no_mangle` set; exactly six exports, each starting with `dispatch(`; `catch_unwind` only in `panic_boundary.rs`; no panic hook, no `C-unwind` |
| Mapping | `every_core_error_maps_to_its_frozen_abi_value`, `core_status_translates_to_fixed_authority_states` | All eleven variants → 100–107/200–202 by exact equality, one value each; a wildcard-free `match` in the test also stops compiling if the core gains a variant. `Ready{n}` → (1, n), `Busy` → (2, 0), `Exhausted` → (3, 0) |
| Order and fatal (local state) | `authority_operations_reject_unknown_and_foreign_handles`, `a_fatal_state_refuses_normal_authority_operations_before_any_handle_check`, `a_poisoned_runtime_slot_makes_normal_operations_fatal_but_admits_cleanup` | Zero, random, stale, and runtime-as-authority handles give `INVALID_HANDLE` without a core session; fatal precedes handle checks for register and status; release stays admitted; a poisoned slot alone turns normal operations fatal |
| Handles | `handle_exhaustion_fails_before_the_core_is_entered`, `authority_handles_share_the_runtime_counter_and_failures_burn_a_value`, `the_last_handle_value_can_name_an_authority_then_registration_fails_closed` | At `UINT64_MAX` exhaustion, register fails with `HANDLES_EXHAUSTED` and the core registry has no session for the scope (Linux too). Runtime 1, empty scope burns 2, authority 3, duplicate burns 4, authority 5, re-registration 6, next runtime 7. `UINT64_MAX` itself can name an authority |
| Export lifecycle (child) | `authority_lifecycle_through_the_exports` | Every raw-argument rejection writes nothing and enters no core; empty scope (null or not) → `INVALID_SCOPE` with output 0; register → handle ≠ runtime; same scope → `ALREADY_REGISTERED`; a second scope coexists; status `READY`/10; bad status outputs write nothing; six wrong-handle combinations give `INVALID_HANDLE` for status and release; release → handle invalid at once, second release `INVALID_HANDLE`, the other authority untouched; re-register → a newer handle, **the same process-session accounting allocation**, registration `Active`; destroy invalidates all child handles and leaves both sessions `Inactive`; a new runtime sees none of the old handles and registers the scope under a new handle; a runtime without authorities destroys normally |
| P6-D-002 across the ABI (child) | `abi_lifecycle_never_refreshes_process_session_accounting` | One opportunity spent through the core's authorize/reserve path → `READY`/9; an exposed ceremony → `BUSY`/0; terminate → `READY`/8; release + re-register → new handle, `READY`/8; runtime destroy + new runtime + register → `READY`/8, same session; a scope spent to zero is `EXHAUSTED` and stays `EXHAUSTED` after release and re-registration |
| Release errors (child) | `a_failed_release_never_restores_the_handle` | Release while an executor shares the registration → `BUSY`, handle gone, registration ends when the holder drops, re-register gets a new handle; an uncertain lease release (test fault `FAIL_NEXT_RELEASE`) → `OWNERSHIP_UNCERTAIN`, handle gone, the scope fails `OWNERSHIP_UNCERTAIN` for the process, also after runtime destroy and re-creation |
| Cross-process (child + 2 grandchildren) | `another_process_cannot_register_a_held_authority` | Process A holds the scope; process B gets `OWNERSHIP_UNAVAILABLE` with output 0 and creates no session; after A releases, process C registers (`READY`/10) and releases; A then registers again under a new handle |
| Races (children) | `concurrent_registrations_of_one_scope_admit_exactly_one`, `different_scopes_coexist_under_one_runtime`, `register_racing_runtime_destroy_never_outlives_the_runtime`, `release_racing_runtime_destroy_releases_exactly_once`, `status_racing_release_sees_a_live_or_no_authority` | 24 rounds × 16 threads on one scope: exactly one `OK`, the rest `ALREADY_REGISTERED` with output 0, 24 distinct handles. 8 scopes concurrently: 8 distinct handles; releasing one leaves the others `READY`. The three pairwise races run 24 rounds each, with the barrier roles swapped every other round; locally each saw both admission orders 12/12. Every outcome was one of the allowed ones; afterwards the scope is never left `Active`, handles are invalid, and nothing deadlocked (120 s child deadline) |
| Real core panic (children) | `a_real_core_panic_is_contained_and_fatal`, `a_real_core_drop_panicking_payload_is_never_dropped` | See below |
| Unsupported platform (child, Linux) | `authority_registration_fails_closed_on_unsupported_platforms` | Runtime create `OK`; a valid scope enters the core twice (entry counter +2) and returns `UNSUPPORTED_PLATFORM` with output 0; no session; empty scope `INVALID_SCOPE`; destroy `OK`. Also run as its own CI step that requires exactly one passed test |
| P7.1 fatal children, extended | `an_ordinary_panic_makes_the_process_permanently_fatal`, `a_drop_panicking_payload_is_contained_at_an_export` | After a panic that does not poison the slot, register and status return `FATAL` for valid, zero, and unknown runtimes with no core entry; release still validates handles |

Counts: `cargo test --features native-abi --lib abi::tests` gives 39 passed and 18 ignored (the child bodies) on Windows. The full suite with the feature gives 454 unit tests passed (21 ignored: 3 P5 deep runs and 18 children), 2 + 9 integration, and 1 doc test, 0 failed. Without the feature: unchanged at 415 unit (3 ignored), 2 + 9 integration, and 1 doc test, 0 failed. On Linux the authority tests that need OS ownership are not compiled; the six platform-neutral ones and the unsupported-platform child run.

### Real core panic (P6-D-004)

**Hook point.** `TrustedAuthority::register` (`core/src/lib.rs`), after `register_with` has returned a complete registration (OS lease held, process session `Active`, registry lock already released) and before it is returned to the caller: `#[cfg(test)] test_hook::fire(Point::AuthorityRegistered)`. The point is safe because no core lock is held there: a panic unwinds through the new registration's own `Drop`, which releases the lease and marks the session `Inactive` (inside `register_with` the registry guard is still held, so that `Drop` would try to lock the registry mutex its own thread holds). The hook is per thread and exists only in test builds; it is not part of the ABI.

**Sequence** (each payload kind in its own child process): create runtime; register scope H (authority `A`); spend one opportunity of H through the core; install a hook that counts and panics (ordinary `panic!`, or `panic_any(PanicOnDrop)` whose `Drop` counts and panics); `sas_pairing_authority_register(runtime, P)`.

| Check | Ordinary | `PanicOnDrop` |
|---|---|---|
| Hook fired (panic raised inside the core) | 1 | 1 |
| Core entries for the call | 1 | 1 |
| Return, `*out_authority` | `FATAL`, 0 | `FATAL`, 0 |
| Process fatal | set | set |
| Payload destructor runs | — | 0 (the child would abort with `0xc0000409` otherwise) |
| Scope P after the unwind | session `Inactive`, 10 remaining: the registration was made and its `Drop` cleaned it up | same |
| Next normal operations ×3: status(A), register(P), register(H), runtime create | all `FATAL`, outputs `INVALID`/0; core entries unchanged; hook count still 1 | same |
| Version query | 1 | 1 |
| H's accounting after fatal | `Active`, 9 | `Active`, 9 |
| Cleanup: release(A), release(A) again, destroy, destroy again | `OK`, `INVALID_HANDLE`, `OK`, `INVALID_HANDLE`; fatal still set | same |
| After cleanup: create, register(H) | `FATAL`, `FATAL`; H `Inactive` with 9 remaining and the same accounting allocation | same |
| Host process | survived; test passed | survived; test passed |

**Remaining P6-D-004 work.** REAL CORE PANIC CONTAINMENT COMPLETE; CONSUMED-ACCOUNTING PRESERVATION EVIDENCE REMAINS FOR A LATER CEREMONY INCREMENT. The tests above spend an opportunity through the core's own reserve path (test-side) and show it stays spent across the fatal path, but no ABI operation consumes an opportunity yet, so "a panic during an ABI ceremony operation that consumed an opportunity leaves it consumed" cannot be shown until a ceremony export exists. No opportunity consumption was faked.

### Mutation checks (temporary, not committed)

Run with `cargo test --features native-abi --lib abi::tests --no-fail-fast`; every source restored byte for byte (SHA-256 checked).

| Mutation | Result |
|---|---|
| A: swap `OwnershipUnavailable` and `OwnershipUncertain` in `map_core_error` | Fails: 3 tests: the mapping table (`OwnershipUnavailable` gave 104), the release-error child (uncertain release gave 102), and the cross-process child (contender got 104) |
| B: release leaves the authority in the map (returns `OK` without removing or releasing) | Fails: 10 tests, including the lifecycle, accounting, release-error, cross-process, same-scope, different-scope, status/release, burn, and both real-core panic children |
| C: normal admission behaves like cleanup (no fatal gate, poison tolerated) | Fails: 7 tests: both real-core panic children (status after fatal returned `OK`, `READY`, 9: the core was re-entered), both P7.1 fatal children and the clean-state test (register after fatal was admitted), and the local fatal and poisoned-slot tests |
| D: `mem::forget(payload)` replaced by `drop(payload)` | Fails: 3 tests; both `PanicOnDrop` children (P7.1 seam and real core) aborted with `0xc0000409` ("panic in a function that cannot unwind"), and the local payload test |
| E: runtime destroy leaves its authorities alive (stashed and re-attached to the next runtime) | Fails: 7 tests: the lifecycle, accounting, different-scope, register/destroy, and release/destroy children, and the two local handle tests (the destroyed runtime's authorities stayed `Active`) |

### Artifact and header

`cargo build --manifest-path core/Cargo.toml --release --features native-abi`: `llvm-readobj --coff-exports core/target/release/sas_pairing_core.dll` lists exactly the six exports above (no test hook, panic injector, or Rust-mangled symbol). A release build without the feature exports nothing. A throwaway C program (clang 19.1.5, `-std=c11 -Wall -Wextra -Werror -pedantic`, linked against the import library, not committed) ran: version 1; runtime create (1); empty scope → `INVALID_SCOPE`, output 0; register (3) and duplicate → `ALREADY_REGISTERED` (2 and 4 burned); status `READY`/10; release `OK`, second release `INVALID_HANDLE`; status after release `INVALID_HANDLE` with `INVALID`/0; re-register (5); destroy; status `INVALID_HANDLE`. The header also parses as strict C11 and C++17 (`-Werror -pedantic`).

### Unsafe audit (new in P7.2)

| Site | Why | Precondition, prior validation, lifetime |
|---|---|---|
| `mod.rs`, `sas_pairing_authority_register`: `out_authority.write(value)` (one block, used for the entry `0` and the handle) | Fill the caller's output slot | After the null, alignment, and overlap checks. The caller guarantees one writable, caller-owned, unaliased `uint64_t` for the call. Plain `u64` write; nothing retained |
| `mod.rs`, `sas_pairing_authority_register`: `slice::from_raw_parts(scope, scope_len)` | Read the caller's scope bytes | Only for `scope_len > 0`, after the non-null check, `scope_len ≤ isize::MAX`, no address wrap, no overlap with the output. `u8` needs no alignment. The caller guarantees `scope_len` readable bytes left unmutated for the call. The slice lives only until `register_authority` returns; the core copies the bytes into its identity; no reference escapes |
| `mod.rs`, `sas_pairing_authority_status`: `out_state.write`, `out_remaining.write` (one block, used for the zeroing and the result) | Fill the caller's two output slots | After null, alignment, and distinctness checks (two aligned `u32` slots at different addresses cannot overlap). Caller-owned, writable, unaliased for the call; nothing retained |
| `pub unsafe extern "C" fn` × 2 (register, status) | Mark the raw-pointer preconditions | Not blocks; `# Safety` sections match the header. Release takes no pointer and is a safe `extern "C" fn` |
| `#[unsafe(no_mangle)]` × 3 | Symbol export (edition 2024) | `sas_pairing_` prefix; the header test pins the exact set |
| Tests | Exercise the exports | Live, aligned, exclusive slots and slices; or pointers the export rejects before any access (null, misaligned, an over-long length, `ptr::without_provenance` near the top of the address space, overlapping ranges) |

No unchecked pointer arithmetic: range checks compare addresses as integers (`addr()`, `checked_add`). No Rust allocation, reference, `Box`, `Arc`, `String`, or `Vec` crosses the boundary; authority handles are integers.

### Frozen-core check

`git diff 600e0a7 -- core/src ':!core/src/abi'` touches two files:

| File | Change | Classification |
|---|---|---|
| `core/src/test_hook.rs` | New variant `Point::AuthorityRegistered` | Test-only: the whole module is `#[cfg(test)] mod test_hook;` |
| `core/src/lib.rs`, `TrustedAuthority::register` | `Self::register_with(scope, system_clock)` became `let authority = Self::register_with(scope, system_clock)?;` + a `#[cfg(test)]` hook statement + `Ok(authority)` | Test-only hook. In non-test builds the function returns the same value on every path (the `?` converts `Error` to `Error` by identity); no production behavior change |

Everything else is `core/src/abi/*` (production ABI and its tests), the header, `core/README.md`, CI, and documents. No change to the ceremony, cryptography, protocol codec, deadlines, router, transport, owner loop, START limiter, process-session behavior, or any P6 decision.

### Verification

| Check | Result |
|---|---|
| `cargo fmt --manifest-path core/Cargo.toml -- --check` | Pass |
| `cargo clippy --manifest-path core/Cargo.toml --all-targets -- -D warnings`, and with `--all-features` | Pass (Windows; also `--target x86_64-unknown-linux-gnu`) |
| `cargo test --manifest-path core/Cargo.toml`, with and without `--features native-abi` | Pass (counts above) |
| `cargo build --manifest-path core/Cargo.toml --release --features native-abi` | Pass |
| Repository consistency script, `git diff --check`, Markdown links and anchors | Pass |
| GitHub Actions on `2197322` | Pass: Repository consistency; Rust security core `windows-core` (fmt, both clippy runs, core tests, native-ABI tests including the real-core panic children, release build, artifact check) and `unsupported-platform-fails-closed` (the same, plus the new step that requires the unsupported-platform authority test to run and pass exactly once, and the negative `panic = "abort"` check) |

## P7.3 evidence

Verified on Windows 11 (`rustc 1.99.0`) at `94e3834`; Linux is covered by CI. Decision: [P7-D-005](decisions.md#p7-d-005--hosting-context-ownership-and-router-lifetime); contract [§16](abi-contract.md#16-hosting-contexts).

### Why P7.3 was narrowed

The earlier recommendation combined the hosting context with listener ownership, the owner-loop lifetime, bounded driving, and connection, run, and event representation. The source shows two separate problems. `Router` (`core/src/router.rs`) owns every run of one authority and holds a `CeremonyExecutor` clone; several routers of one authority are allowed, and the authority's controls stay in its shared state. `WindowsOwnerLoop<'r>` (`windows_owner_loop.rs`) owns an already-bound listener and its accepted connections but borrows `&'r Router`, and so do `AcceptPermit<'r>`, `TransportConnection<'r>`, `HostConnection<'r>`, and `WindowsTcpConnection<'r>`. An ABI object that owns both a router and a loop borrowing it is self-referential. P7.3 therefore fixes only the parent hierarchy (runtime → authority → host → router) and its destroy semantics, and leaves the borrow bridge, listener handoff, `drive_once`, and the event and error representation to P7.4.

### Source recheck (before implementing)

`Router::new(executor)` allocates a router ID from a process-wide counter with `checked_add` and returns `RouteError::Ceremony(CeremonyError::Owner(Error::OwnershipUncertain))` on exhaustion, its only failure; it builds an empty session table and opens no session. `Router::authority()` returns the executor. The router has no `Drop` of its own: dropping it drops its table, whose runs release their own resources. `TrustedAuthority::release` uses `Arc::try_unwrap` and returns `Busy` while any executor clone is alive, so a live router would make every release `BUSY`; that is why release must drop the authority's hosts first.

### Surface

Eight exports, all entering through `dispatch`: the six of P7.2 plus `sas_pairing_host_create(runtime, authority, *out_host)` and `sas_pairing_host_destroy(runtime, host)`. New `sas_pairing_host_t` (`uint64_t`) and `SAS_PAIRING_HOST_INVALID` (`0`). ABI version `1`; no status value or earlier signature changed, and no status code was added.

### Implementation

| Part | Where | What |
|---|---|---|
| Hierarchy | `runtime.rs` | `Runtime.hosts: BTreeMap<NonZeroU64, HostContext>` beside `authorities`; `HostContext { authority: NonZeroU64, router: Box<Router> }` (`hosting.rs`) |
| Create | `hosting.rs` `AbiState::create_host` | `with_runtime(Normal)` (fatal, slot, runtime), the authority lookup, `allocate_handle` (shared counter), then `enter_core(construct_router(parent.executor()))`, then install. `router_creation_status`: `Ceremony(Owner(OwnershipUncertain))` → `OWNERSHIP_UNCERTAIN`; any other `RouteError` → mark fatal, `FATAL` |
| Destroy | `hosting.rs` `AbiState::destroy_host` | `with_runtime(Cleanup)`, remove, then drop |
| Release cascade | `authority.rs` `release_authority` | Check the authority, `Runtime::destroy_hosts_of` (remove every child, then drop), remove the authority, `TrustedAuthority::release` |
| Destroy order | `runtime.rs` `Runtime::destroy` | Destructures the runtime and drops `hosts`, then `authorities`, explicitly |
| Test seams | `hosting.rs`, `#[cfg(test)]` only | A per-thread `ROUTER_CONSTRUCTIONS` counter, and a per-thread `ROUTER_FAULT` that, after the real `Router::new` has run, substitutes an error or panics while the new router is still alive. Not in the artifact; `Router` itself is unchanged |

### Tests (`abi::tests::host`, feature `native-abi`)

| Area | Tests | What they show |
|---|---|---|
| Constants, header, coverage (extended) | `abi_constants_are_frozen`, `export_signatures_are_pinned`, `header_matches_the_rust_abi`, `every_export_runs_inside_the_central_panic_boundary` | `sas_pairing_host_t` is 8 bytes; the header's typedef set, `SAS_PAIRING_HOST_INVALID`, and the eight exact declarations equal the Rust ABI and the `no_mangle` set; exactly eight exports, each starting with `dispatch(` |
| Error boundary | `router_constructor_errors_map_narrowly` | The documented failure → 104; `UnknownSession`, `UnknownRoute`, `SessionProtocolFailure`, `InvalidState`, and other owner errors → 900 |
| Validation, fatal (all platforms) | `host_operations_reject_unknown_and_foreign_handles`, `a_fatal_state_refuses_host_creation_before_any_handle_check`, `a_poisoned_runtime_slot_refuses_host_creation_but_admits_host_destroy`, `host_create_rejects_bad_output_pointers_before_anything_else` | Bad runtime or authority handles → `INVALID_HANDLE`, no router built, no handle reserved; fatal precedes handle checks for create, destroy stays admitted; a poisoned slot makes create fatal; null and misaligned `out_host` → `INVALID_ARGUMENT`, nothing written |
| Handles (Windows) | `hosts_share_the_handle_counter_and_never_alias_another_kind`, `host_handle_exhaustion_builds_no_router`, `a_router_constructor_failure_burns_the_handle_and_installs_nothing` | Runtime 1, authority 2, hosts 3 and 4, destroy 3, next host 5; nine wrong-kind combinations → `INVALID_HANDLE` with nothing changed; release cascades; re-registration 6, host 7, next runtime 8. At exhaustion: `HANDLES_EXHAUSTED`, construction count unchanged, status still `READY`/10. An injected documented failure after the real constructor → `OWNERSHIP_UNCERTAIN`, value burned (the next host skips it), nothing installed, not fatal; an injected `UnknownSession` → `FATAL`, process fatal, later creates build nothing, cleanup works |
| Router lifetime (Windows) | `every_router_keeps_one_heap_address_while_the_maps_change` | One router's address stays the same across 64 inserts over two authorities, 32 removals, and a move of the whole host map through a `Box` and a `Vec` and back; every host has a distinct router; each router's executor shares exactly its parent's authority state (`Arc::ptr_eq`), and no other authority's |
| Export lifecycle (child) | `host_lifecycle_through_the_exports` | Raw and handle rejections enter no core; two hosts of one authority (two routers), status `READY`/10 and the same accounting allocation; seven wrong-kind combinations; destroying one host leaves the sibling and the authority; a new host never reuses a value; **release with two live hosts → `OK`, not `BUSY`**, both host handles invalid, registration `Inactive`; re-registration gives newer handles and the same session; runtime destroy with hosts on two authorities invalidates all of them and leaves both registrations `Inactive`; in a new runtime none of the eleven old values names anything |
| P6-D-002 (child) | `host_churn_never_changes_process_session_accounting` | After one spent opportunity, four rounds of create/create/destroy/destroy keep `READY`/9; with an exposed ceremony the churn keeps `BUSY`/0, then `READY`/8; release with a live host, re-register → `READY`/8; runtime destroy with a live host, new runtime, register → `READY`/8, same session allocation; an exhausted authority stays `EXHAUSTED` through churn, a host creation (not an opportunity), release, and re-registration; no host value repeats |
| Fatal (children) | `host_create_is_fatal_gated_and_host_destroy_is_cleanup`, `a_panic_around_router_construction_is_contained`, `a_drop_panicking_payload_around_router_construction_is_never_dropped` | After an injected panic, create → `FATAL`/0 for nine runtime/authority combinations with no core entry and no construction; host destroy `OK` then `INVALID_HANDLE`; the sibling stays until release cascades it; cleanup never clears fatal; create and host create stay `FATAL`. A panic right after the real `Router::new` (ordinary, and `panic_any(PanicOnDrop)`), reached through `sas_pairing_host_create`: `FATAL`/0, constructions +1, fatal set, payload destructor never run (the child would abort otherwise), nothing installed, status `FATAL` with no core entry, accounting `Active`/10 unchanged, cleanup works, then `Inactive`/10 |
| Races (children) | `host_create_racing_sibling_destroy_both_succeed`, `host_create_racing_authority_release_never_outlives_it`, `host_destroy_racing_authority_release_drops_once`, `host_create_racing_runtime_destroy_never_outlives_it`, `host_destroy_racing_runtime_destroy_drops_once` | 24 rounds each, barrier roles swapped every other round. Create vs sibling destroy: both `OK`. Release always `OK` (never `BUSY`); a host created first is gone afterwards. Exactly one path removes each host; afterwards every handle is invalid, no host remains, the registration is `Inactive`. Locally both admission orders occurred: 13/11, 12/12, 12/12, 12/12. A 120 s child deadline turns a deadlock into a failure |
| P7.1 fatal children and unsupported platform (extended) | `an_ordinary_panic_makes_the_process_permanently_fatal`, `a_drop_panicking_payload_is_contained_at_an_export`, `authority_registration_fails_closed_on_unsupported_platforms` | After fatal, host create → `FATAL` for valid, zero, and unknown runtimes with no core entry or construction; host destroy admitted. On Linux no authority exists, so host create and destroy give `INVALID_HANDLE` |

Counts: `cargo test --features native-abi --lib abi::tests` gives 58 passed and 28 ignored (the child bodies) on Windows; `abi::tests::host` alone 19 passed and 10 ignored. The full suite with the feature gives 473 unit tests passed (31 ignored: 3 P5 deep runs and 28 children), 2 + 9 integration, and 1 doc test, 0 failed. Without the feature: unchanged at 415 unit (3 ignored), 2 + 9 integration, and 1 doc test, 0 failed. On Linux the five platform-neutral host tests run; the rest need a registered authority, which fails closed there, and no authority is faked.

### Mutation checks (temporary, not committed)

Run with `cargo test --features native-abi --lib abi::tests --no-fail-fast`; every source restored byte for byte (SHA-256 checked).

| Mutation | Result |
|---|---|
| A: authority release no longer destroys the authority's hosts | Fails: 6 tests; release with live hosts returned `BUSY` ("live ABI hosts never make release BUSY"), stale hosts survived (lifecycle, accounting, fatal, both release races, counter test) |
| B: runtime destroy leaks its hosts instead of dropping them (`mem::forget`) | Fails: 5 tests; registrations stayed `Active` after runtime destroy (lifecycle, accounting, both runtime-destroy races, router-address test) |
| C: host handles derived from the authority and host count instead of the counter (reuse) | Fails: 5 tests ("a destroyed host's value is never reissued", "a value was reused", `third > second`, the burned-value test, and an overflow at exhaustion) |
| D: host create admitted like cleanup (no fatal gate, poison tolerated) | Fails: 9 tests: both P7.1 fatal children and the clean-state test, the host fatal child, both router-panic children, the local fatal, poisoned-slot, and constructor-failure tests |
| E: host destroy also destroys its siblings and releases the parent authority | Fails: 10 tests (lifecycle, accounting, fatal, sibling-destroy and release races, counter, address, constructor-failure, both router-panic children) |

### Artifact, header, and C smoke

`cargo build --manifest-path core/Cargo.toml --release --features native-abi`: `llvm-readobj --coff-exports` lists exactly the eight exports (no router symbol, test seam, or Rust-mangled name); a release build without the feature exports none. A throwaway C program (clang 19.1.5, `-std=c11 -Wall -Wextra -Werror -pedantic`, linked against the import library, not committed) ran: version 1; runtime 1; authority 2; `NULL` `out_host` → `INVALID_ARGUMENT`; the runtime handle as authority → `INVALID_HANDLE`, output 0 (no value consumed); hosts 3 and 4; destroy 3, again `INVALID_HANDLE`; status `READY`/10; release `OK` (host 4 cascaded: destroy → `INVALID_HANDLE`); host create on the released authority → `INVALID_HANDLE`; runtime destroy. The header parses as strict C11 and C++17 (`-Werror -pedantic`).

### Unsafe audit (new in P7.3)

| Site | Why | Precondition, prior validation, lifetime |
|---|---|---|
| `mod.rs`, `sas_pairing_host_create`: `out_host.write(value)` (one block, used for the entry `0` and the handle) | Fill the caller's output slot | After the null and alignment checks. The caller guarantees one writable, caller-owned, unaliased `uint64_t` for the call. Plain `u64` write; nothing retained |
| `pub unsafe extern "C" fn sas_pairing_host_create` | Marks the raw-pointer precondition | Not a block; the `# Safety` section matches the header. `sas_pairing_host_destroy` takes no pointer and is a safe `extern "C" fn` |
| `#[unsafe(no_mangle)]` × 2 | Symbol export (edition 2024) | `sas_pairing_` prefix; the header test pins the exact set |
| Tests | Exercise the export | A live, aligned, exclusive `u64`; or null and misaligned pointers rejected before any write |

No lifetime-related `unsafe`: no raw `Router` pointer, `Box::leak`, `transmute`, `'static` borrow, `ManuallyDrop`, or self-referential helper. The router address in the tests is read with `ptr::from_ref(..).addr()`, which is safe and never dereferenced.

### Frozen-core check

`git diff 508d0cd -- core/src ':!core/src/abi'` is empty: no change to `router.rs`, `host.rs`, `transport.rs`, `windows_tcp.rs`, `windows_owner_loop.rs`, `lib.rs`, `test_hook.rs`, the ceremony, cryptography, protocol codec, deadlines, START limiter, or process-session accounting; `Cargo.toml` and `Cargo.lock` unchanged. Everything else is `core/src/abi/*`, the header, and documents; CI is unchanged (the existing `abi::tests` steps run the new tests).

### Verification

| Check | Result |
|---|---|
| `cargo fmt --manifest-path core/Cargo.toml -- --check` | Pass |
| `cargo clippy --manifest-path core/Cargo.toml --all-targets -- -D warnings`, and with `--all-features` | Pass (Windows; also `--target x86_64-unknown-linux-gnu`) |
| `cargo test --manifest-path core/Cargo.toml`, with and without `--features native-abi` | Pass (counts above) |
| `cargo build --manifest-path core/Cargo.toml --release --features native-abi` | Pass |
| Repository consistency script, `git diff --check`, Markdown links and anchors | Pass |
| GitHub Actions on `94e3834` | Pass: Repository consistency; Rust security core `windows-core` and `unsupported-platform-fails-closed` |

## P7.4 evidence

Verified on Windows 11 (`rustc 1.99.0`) at `96af6af` and its test corrections up to `613a00b`; Linux is covered by CI. Decisions: [P7-D-006](decisions.md#p7-d-006--windows-listener-ownership-and-responder-configuration) (listener ownership and Responder configuration) and [P7-D-007](decisions.md#p7-d-007--owner-loop--router-lifetime-bridge) (owner-loop / Router lifetime bridge); contract [§17](abi-contract.md#17-windows-listener-ownership).

### Why P7.4 was narrowed

The earlier P7.4 combined the listener, the owner loop, and a bounded drive/event ABI. `WindowsOwnerLoop::drive_once` returns an `OwnerStep` whose `OwnerEvent`s carry `ConnectionRef`s (`Accepted`, `Step`, `Closed`), and a `Step` carries a `TcpStep` with at most one `TcpEvent` (an `Inbound` event names its run by `RunRef`) and at most one `PairingResult`, the one-shot local verified completion (P6-D-005). None of that is disposable: a drive export that could drop a `PairingResult` would lose a completed ceremony, and later local actions need stable references for `ConnectionRef` and `RunRef`. So P7.4 does not expose driving; P7.5 designs the connection, run, event, result, and error representation first. Because no drive is exposed, P7.4 cannot produce, and so cannot lose, a `PairingResult`.

### Source recheck (before implementing)

| Fact | Where | Consequence |
|---|---|---|
| `WindowsOwnerLoop<'r, L = TcpListener>` holds `router: &'r Router` and `connections: Vec<Live<'r, ..>>` | `windows_owner_loop.rs` | The loop borrows the host's router for its whole life |
| An accepted `WindowsTcpConnection<'r>` holds `Option<HostConnection<'r>>`, which holds `TransportConnection<'r>`, which holds `router: &'r Router`; `AcceptPermit<'r>` borrows it during admission | `windows_tcp.rs`, `host.rs`, `transport.rs` | The deepest borrow chain is loop → connection → host connection → transport connection → router; connections are owned by the loop and die with it |
| `from_bound_listener(listener, router, local, expected)` only calls `set_nonblocking(true)`; its only error is `ListenerIo(kind)`, with the listener dropped | `windows_owner_loop.rs` | One documented setup failure (`LISTENER_SETUP_FAILED`); no setup is duplicated in the ABI |
| `close()` drops the listener and attempts every connection's teardown; it reports only `Closed` or `OwnershipUncertain`; the loop has no `Drop` of its own, and each connection's `Drop` runs its teardown | `windows_owner_loop.rs`, `windows_tcp.rs` | Detach maps `OK`/`Closed` → `OK`, `OwnershipUncertain` → `OWNERSHIP_UNCERTAIN` |
| `TcpStep { event, result: Option<PairingResult>, write_pending }`; the adapter retains one `PendingWrite` and writes it in `on_writable`; neither step type carries outbound bytes | `windows_tcp.rs` | No outbound buffer or send API is needed or invented |
| `Bootstrap::new` validates the four fields and builds the canonical frame (`MAX_BOOTSTRAP_FRAME` = 16384); `Bootstrap::decode` stays private | `protocol.rs` | The ABI copies views into `Bootstrap::new`; no duplicate validation, no fake frame |
| A loop's `drive_once` is the only path to accept, poll, or event production; `from_bound_listener` opens no session and accepts nothing | `windows_owner_loop.rs` | Attach is inert and accounting neutral |

### Surface

Ten exports, all entering through `dispatch`: the eight of P7.3 plus `sas_pairing_host_attach_windows_listener(runtime, host, sas_pairing_socket_t *inout_listener, const sas_pairing_bootstrap_view_t *local, const sas_pairing_bootstrap_view_t *expected)` and `sas_pairing_host_detach_listener(runtime, host)`. New types `sas_pairing_socket_t` (`uintptr_t`), `SAS_PAIRING_SOCKET_INVALID` (`UINTPTR_MAX`, Windows `INVALID_SOCKET`), `sas_pairing_bytes_view_t`, and `sas_pairing_bootstrap_view_t`; new status values `SAS_PAIRING_INVALID_BOOTSTRAP = 203`, `SAS_PAIRING_LISTENER_ALREADY_ATTACHED = 400`, `SAS_PAIRING_LISTENER_SETUP_FAILED = 401` (range 400–499 reserved for host, listener, and transport-boundary lifecycle). ABI version `1`; no earlier value or signature changed. Host destroy can now also return `SAS_PAIRING_OWNERSHIP_UNCERTAIN` (a connection's cleanup could not be established); no connection can exist yet, because nothing is driven.

### Implementation

```text
Runtime
  ├── authorities: BTreeMap<handle, TrustedAuthority>
  └── hosts:       BTreeMap<handle, Box<HostContext>>
                     HostContext {
                       authority: NonZeroU64,
                       network:   Option<WindowsNetworkContext>   // private; declared first
                                    └── owner_loop: WindowsOwnerLoop<'static>
                       router:    Box<Router>                      // private; never reassigned
                     }
```

| Part | Where | What |
|---|---|---|
| Views | `mod.rs` | `#[repr(C)] BytesView { data, len }`, `BootstrapView { application_identity, key_algorithm, public_key, shared_context }`; `byte_range` (structural check, now shared with authority registration) and the one `caller_bytes` slice helper; `BootstrapInput::to_bootstrap` copies each field (a field over `MAX_BOOTSTRAP_FRAME` is refused uncopied) into `Bootstrap::new` |
| Attach export | `mod.rs` | Null/misaligned slot, `local`, or `expected`; malformed views; a slot holding `INVALID` → `INVALID_ARGUMENT` with nothing written; then the views and slot are wrapped and handed to the state |
| Adoption | `listener.rs` `ListenerSlot::adopt` | `TcpListener::from_raw_socket`, then `INVALID` written to the slot: the linearization point, with nothing fallible between |
| Attach | `listener.rs` `AbiState::attach_listener` | Bootstrap → `with_runtime(Normal)` (fatal, runtime) → host → `has_network` → `adopt` → (test-only fault) → `HostContext::attach_network` → map the constructor error (`ListenerIo` → 401, else fatal). Off Windows it returns `UNSUPPORTED_PLATFORM` untouched |
| Lifetime bridge | `hosting.rs` `router_for_owner_loop` | The one lifetime extension (raw-pointer re-borrow, no `transmute`), called only by `attach_network`, whose result goes only into the same host's `network` |
| Teardown | `hosting.rs` `HostContext::detach_network`, `Drop for HostContext`; `runtime.rs` `Runtime::destroy`; `hosting.rs` `destroy_hosts_of`, `destroy_host` | Network out of the host first, then the loop's `close`, then drop, with the router untouched; every parent path calls it before any router drops; `Drop` is the backstop |
| Detach | `listener.rs` `AbiState::detach_listener` | `with_runtime(Cleanup)`, host lookup, `detach_network`, narrow close mapping |
| Boxed hosts | `runtime.rs`, `hosting.rs` | `hosts: BTreeMap<_, Box<HostContext>>`, so neither a host context nor its router box is ever moved by value once created |
| Test seams | `hosting.rs`, `listener.rs`, `#[cfg(test)]` only | Per-thread `OWNER_LOOP_CONSTRUCTIONS`, `OWNER_LOOP_FAULT` (substitutes a constructor error after the real constructor ran), `ADOPTION_FAULT` (runs right after adoption, before the loop), and `NETWORK_DROPS` fed by a `DropProbe` field declared after the owner loop (a weak reference to the authority state, recording the live-connection count and the holders of the authority state when it drops). Not in the artifact; no core file changed |

### Tests (`abi::tests::listener`, feature `native-abi`)

| Area | Tests | What they show |
|---|---|---|
| Constants, header, coverage (extended) | `abi_constants_are_frozen`, `input_view_layouts_are_pinned`, `export_signatures_are_pinned`, `header_matches_the_rust_abi`, `every_export_runs_inside_the_central_panic_boundary` | 20 status values (203, 400, 401 added, none renumbered); socket width = pointer width, `INVALID` = `usize::MAX` (and `INVALID_SOCKET` at compile time on Windows); both views' sizes, alignment, and field offsets; the header's typedefs, both struct bodies field for field, `SAS_PAIRING_SOCKET_INVALID`, and the ten exact declarations equal the Rust ABI and the `no_mangle` set; exactly ten exports, each starting with `dispatch(` |
| Arguments (all platforms) | `attach_rejects_bad_arguments_before_anything_else` | Null and misaligned slot, null and misaligned `local`, misaligned `expected`, a slot holding `INVALID`, and three malformed byte views in each of the eight view fields → `INVALID_ARGUMENT`, slot untouched; a structurally valid call with runtime 0 → `INVALID_HANDLE` (Windows) or `UNSUPPORTED_PLATFORM`, slot untouched |
| Bootstrap | `the_bootstrap_copy_bound_never_changes_the_outcome`, `bootstrap_views_are_copied_into_bootstrap_new` | `Bootstrap::new` itself refuses a field of `MAX_BOOTSTRAP_FRAME + 1` in every position, so the copy bound changes no outcome; a view yields exactly the `Bootstrap::new` value; a null zero-length context is empty; invalid, empty-identity, and oversized views → none |
| Error boundaries | `owner_loop_errors_map_narrowly` | `ListenerIo(any)` → 401; every other `OwnerLoopError` from the constructor → 900; close `Ok`/`Closed` → 0, `OwnershipUncertain` → 104, anything else → 900 |
| Pre-adoption ownership (local) | `every_failure_before_adoption_leaves_the_socket_with_the_caller` | Invalid `local` or `expected` Bootstrap wins over bad handles; eight bad runtime/host combinations → `INVALID_HANDLE`; slot unchanged and no loop built; attach with an expected peer Bootstrap → `OK`, slot `INVALID`; a second listener → `LISTENER_ALREADY_ATTACHED`, slot unchanged, and the caller's socket still accepts a connection; detach twice `OK`; replacement attach `OK`; status `READY`/10 throughout; after fatal, attach → `FATAL` for three combinations with the slot unchanged, no loop built, and the caller's socket still accepting; detach still `OK` |
| Deepest borrow chain (local) | `the_owner_loop_and_its_connections_drop_before_the_router` | A real loopback client connects; the stored owner loop is driven internally (no ABI export) until `Accepted`; then loop 1 connection, router 1 session, authority 1 live connection. For detach, host destroy, authority release, and runtime destroy over two authorities, the probe recorded `(holders, 0)`: no live connection was left and the router was still among the holders when the loop had dropped; afterwards the holder count fell by one per router (host destroy) or the core release returned `OK` (impossible with a router left); the client saw its connection end; registrations ended `Inactive` |
| Lifecycle (child) | `listener_lifecycle_through_the_exports` | Eight invalid host/runtime combinations and three invalid Bootstraps: slot unchanged, socket still listening (`getsockopt(SO_ACCEPTCONN)`), no core entry, no loop built. Attach → slot `INVALID`, socket still listening (adopted, not closed); a second socket → `LISTENER_ALREADY_ATTACHED`, still the caller's; detach closes the first (`getsockopt` → `WSAENOTSOCK`), again `OK`; replacement adopts the second; host destroy closes it; attach and detach on the stale host → `INVALID_HANDLE`, slot unchanged; a new host on the same authority attaches, release closes its socket; same accounting allocation, `Inactive`/10 |
| Cascades (child) | `parent_destruction_closes_listeners_before_routers` | Three hosts with listeners over two authorities. Host destroy: probe `(alone + 2, 0)`, then one fewer holder; only its socket closed. Authority release: probe `(alone + 1, 0)`, release `OK`, its socket closed, the other host's still listening. Runtime destroy with listeners on hosts of two authorities: two probe records (one per authority, router counted), both sockets closed, every handle invalid, both registrations `Inactive`, and no old value names anything in a new runtime |
| Fatal (child) | `attach_is_fatal_gated_and_detach_is_cleanup` | After an injected panic: attach → `FATAL` for four combinations, slot unchanged, no core entry, no loop built (an invalid Bootstrap still gives `INVALID_BOOTSTRAP`, the stateless value check that precedes fatal); detach closes the adopted socket, is idempotent, keeps fatal; attach stays `FATAL`; cleanup works; create stays `FATAL`; the caller closes its socket itself |
| Panic after adoption (children) | `a_panic_after_socket_adoption_leaves_one_owner`, `a_drop_panicking_payload_after_socket_adoption_is_never_dropped` | `ADOPTION_FAULT` panics right after adoption and before the loop (ordinary, and `panic_any(PanicOnDrop)`): `FATAL`, slot `INVALID`, socket closed by the unwinding Rust owner, no loop built, no network installed, payload destructor never run (the child would abort otherwise), process fatal; later attach → `FATAL` with its slot unchanged; host create and status `FATAL`; accounting `Active`/10; detach, host destroy, release, destroy all work; create `FATAL` |
| Setup failure (child) | `an_owner_loop_setup_failure_closes_the_adopted_socket` | `OWNER_LOOP_FAULT` after the real constructor: `ListenerIo` → `LISTENER_SETUP_FAILED`, slot `INVALID`, socket closed, constructor ran once, no network, not fatal, and the host then attaches normally; `Poll` → `FATAL`, slot `INVALID`, socket closed, process fatal, cleanup works |
| P6-D-002 (child) | `listener_churn_never_changes_process_session_accounting` | After one spent opportunity, `READY`/9 through attach, detach, attach, detach, attach, host destroy, new host, attach; START limiter snapshot unchanged; same session allocation. With an exposed ceremony, the same churn keeps `BUSY`/0, then `READY`/8. An exhausted authority stays `EXHAUSTED` through the churn, release, re-registration, and churn again |
| Races (children) | `attach_racing_detach_never_leaves_two_owners`, `attach_racing_host_destroy_has_one_owner`, `attach_racing_authority_release_has_one_owner`, `attach_racing_runtime_destroy_has_one_owner`, `detach_racing_host_destroy_closes_once`, `detach_racing_authority_release_closes_once`, `detach_racing_runtime_destroy_closes_once` | 24 rounds each. Rounds 0 and 1 run the two calls in each forced order, so both outcomes are checked whatever the scheduler does; rounds 2–23 race them through a barrier, with roles swapped every other round and one side delayed by 0–1 ms (attach validates its Bootstrap before taking the slot, so unstaggered races were one-sided). Attach first: `OK`, slot `INVALID`, and the parent then closes the socket; parent first: `INVALID_HANDLE`, slot unchanged, socket still listening, the test closes it. Detach first: `OK`; parent first: `INVALID_HANDLE`; the socket is closed afterwards either way. Locally (all rounds) 11/13 for each attach race and 12/12 for each detach race, so the raced rounds saw both orders too. A 120 s child deadline turns a deadlock into a failure |
| Unsupported platform (child, Linux) | `attach_fails_closed_on_unsupported_platforms` | Runtime `OK`; structurally valid attaches (valid or invalid Bootstraps, three handle combinations) → `UNSUPPORTED_PLATFORM` with the slot unchanged; detach → `INVALID_HANDLE`; destroy `OK`. Also its own CI step requiring exactly one passed test |

Counts: `cargo test --features native-abi --lib abi::tests` gives 79 passed and 42 ignored (the child bodies) on Windows; `abi::tests::listener` alone 20 passed and 14 ignored. The full suite with the feature gives 494 unit tests passed (45 ignored: 3 P5 deep runs and 42 children), 2 + 9 integration, and 1 doc test, 0 failed. Without the feature: unchanged at 415 unit (3 ignored), 2 + 9 integration, and 1 doc test, 0 failed. On Linux the platform-neutral listener tests run (argument order, the Bootstrap copy bound) and the unsupported-platform child; the rest needs a registered authority and a Windows owner loop, and nothing is faked.

### Mutation checks (temporary, not committed)

Run with `cargo test --features native-abi --lib abi::tests --no-fail-fast` on the production sources of the final head (the same results on `96af6af` and `465f3ef`; later commits change only test scopes and CI); every source restored byte for byte (SHA-256 checked) after each.

| Mutation | Result |
|---|---|
| A: the router drops before the owner loop (router declared before the network, no explicit network teardown in `Drop`, host destroy, authority release, or runtime destroy) | Fails: 2 tests, the local drop-order test and the cascades child: the probe saw one holder fewer (`[Some((2, 0))]` instead of `[Some((3, 0))]`), so the router was already gone when the loop dropped |
| B: the slot is not set to `INVALID` after adoption | Fails: 9 tests (lifecycle, pre-adoption ownership, setup failure, both adoption-panic children, all four attach races) |
| C: a second attach is allowed (no `has_network` check, no debug assertion) | Fails: 2 tests (lifecycle child and the local ownership test: the second socket was adopted) |
| D: authority release skips hosts that have a network context | Fails: 6 tests (cascades, lifecycle, accounting, drop order, attach/release and detach/release races: release became `BUSY` and sockets stayed open) |
| E: attach admitted like cleanup (no fatal gate) | Fails: 4 tests (the fatal child, both adoption-panic children, the local ownership test: attach after fatal adopted the socket) |
| F: detach keeps the owner loop | Fails: 7 tests (lifecycle, fatal, setup failure, accounting, attach/detach race, local ownership, drop order) |

### Artifact, header, and C smoke

`cargo build --manifest-path core/Cargo.toml --release --features native-abi`: `llvm-readobj --coff-exports` lists exactly the ten exports (no router, owner-loop, test-seam, drive, event, or Rust-mangled symbol); a release build without the feature exports none. A throwaway C host (clang 19.1.5, `-std=c11 -Wall -Wextra -Werror -pedantic`, linked against the import library and `ws2_32`, not committed) with `_Static_assert`s on the socket width, `SAS_PAIRING_SOCKET_INVALID == INVALID_SOCKET`, both view layouts, and 203/400/401 ran: `WSAStartup`; it bound and listened on a loopback socket itself; runtime 1, authority 2, host 3; null slot → `INVALID_ARGUMENT`, invalid Bootstrap → `INVALID_BOOTSTRAP`, the authority handle as host → `INVALID_HANDLE`, the socket still listening; attach → `OK`, the socket variable now `SAS_PAIRING_SOCKET_INVALID`; a second socket → `LISTENER_ALREADY_ATTACHED`, still its own; detach → `OK`, the first socket closed (`WSAENOTSOCK`), again `OK`; attach the second → `OK`; status `READY`/10; host destroy closed it; detach on the destroyed host → `INVALID_HANDLE`; release; runtime destroy; `WSACleanup`. The header also parses as strict C11 and C++17 (`-Werror -pedantic`).

### Unsafe audit (new in P7.4)

| Site | Why | Precondition, prior validation, lifetime |
|---|---|---|
| `mod.rs`, `sas_pairing_host_attach_windows_listener`: one block reading `*inout_listener`, `*local`, and `*expected` (when non-null) | Copy the caller's slot value and views | After the null and alignment checks. The caller guarantees each addresses one readable value of its type for the call. `usize` and the view structs (integers and raw pointers) have no invalid bit patterns and no destructor; values are copied, no reference formed |
| `mod.rs`, `BootstrapInput::new` (an `unsafe fn`) and its two calls | Record that the views' bytes are readable for the call | Called only after every view is well formed (`byte_range`); the caller guarantees the bytes, unmutated for the call; `PhantomData<&'a [u8]>` ties the input to the call |
| `mod.rs`, `caller_bytes` (an `unsafe fn` with one `slice::from_raw_parts` block), called by `to_bootstrap` per field and by authority registration (this replaces P7.2's inline block) | Read caller bytes | Precondition `byte_range(data, len)`: non-null for `len > 0`, `len <= isize::MAX`, no wrap; `u8` needs no alignment; `len == 0` never dereferences. `to_bootstrap` copies with `to_vec` at once and keeps nothing; registration's slice lives only until the core copied the scope |
| `mod.rs`, `ListenerSlot::new` (an `unsafe fn`) and its call | Record the slot and the caller's socket precondition | Called after the slot's null and alignment checks and with a value other than `INVALID`; the caller guarantees a writable, unaliased slot and one valid, already-bound listening socket it owns exclusively |
| `listener.rs`, `ListenerSlot::adopt`: `TcpListener::from_raw_socket(raw)` | Raw-socket adoption | The caller owned one valid listening socket at entry; ownership moves into this one listener (no duplicate handle, no second Rust owner); the slot write that follows tells the caller it no longer owns it; the listener (or the loop it moves into) closes it exactly once; nothing keeps the value afterwards |
| `listener.rs`, `ListenerSlot::adopt`: `slot.write(SAS_PAIRING_SOCKET_INVALID)` | Publish the transfer to the caller | The slot is non-null, aligned, writable, and unaliased for the call; `usize` write; the only write of the call, after every input was copied |
| `hosting.rs`, `router_for_owner_loop` (an `unsafe fn` with one `&*router` block) and its one call in `HostContext::attach_network` | The one lifetime extension (P7-D-007) | The pointer comes from a live `&Router` (non-null, aligned, initialized); the router lives in its own box, never replaced, moved out of, written through, or borrowed mutably; host contexts are boxed, so nothing is moved by value; the result is stored only in the same host's network context, which never leaves it and always ends before the router on every path, with `Drop` as the backstop; nothing returns it or crosses the ABI with it |
| `pub unsafe extern "C" fn sas_pairing_host_attach_windows_listener` | Marks the raw-pointer and socket preconditions | Not a block; the `# Safety` section matches the header. Detach takes no pointer and is a safe `extern "C" fn` |
| `#[unsafe(no_mangle)]` × 2 | Symbol export (edition 2024) | `sas_pairing_` prefix; the header test pins the exact set |
| Tests | Exercise the exports and seams | Live, aligned, exclusive slots and views; pointers the export rejects before access (null, misaligned, `ptr::without_provenance` near the top of the address space, over-long lengths); `TcpListener::from_raw_socket` only for sockets the test bound and the ABI did not adopt; `getsockopt` with live locals |

No other lifetime-related `unsafe`: no stored raw router pointer, `Box::leak`, `transmute`, `ManuallyDrop`, or self-referential crate. The aliasing argument for the bridge is reasoned, not machine-checked (Miri cannot run the WinSock path).

### Frozen-core check

`git diff fa079c6 -- core/src ':!core/src/abi'` is empty: no change to `router.rs`, `transport.rs`, `host.rs`, `windows_tcp.rs`, `windows_owner_loop.rs`, `protocol.rs`, `ceremony.rs`, `lib.rs`, `test_hook.rs`, the cryptography, deadlines, or process-session accounting; `Cargo.toml` and `Cargo.lock` unchanged. Everything else is `core/src/abi/*`, the header, CI (one Linux step), and documents.

### CI corrections

`windows-core` failed in the native ABI test step on `96af6af`; the other two jobs passed. Job logs need a signed-in viewer, which this environment does not have, so the step was made to report failures publicly: `465f3ef` also forced both admission orders in the listener races (the most scheduler-dependent new check), `0d420ed` and `b2e205b` published failing lines as annotations and in the run summary, and `8827498` fixed that reporting (GitHub runs `shell: bash` with `-e`, which ended the step before the report). `8827498` passed and three other runs failed with no code change, so the failure was intermittent; `98a75e9` added a temporary step repeating the native ABI tests six times, which captured it: `child_adoption_panic_ordinary` panicked at `session(scope).unwrap()`. Its sibling `child_adoption_panic_on_drop` used the same scope and runs in parallel in another process, and the OS ownership lease excludes a scope across processes, so the second to register got `OWNERSHIP_UNAVAILABLE`: a test-isolation defect, not an ABI one. `613a00b` gives each payload kind its own scope, and fixes the same latent hazard in the P7.2 real-core panic pair and the P7.3 router panic pair (they had passed CI by timing). No scope literal is now shared by two tests. The closure commit removes the temporary repetition step and keeps the failure reporting.

### Verification

| Check | Result |
|---|---|
| `cargo fmt --manifest-path core/Cargo.toml -- --check` | Pass |
| `cargo clippy --manifest-path core/Cargo.toml --all-targets -- -D warnings`, and with `--all-features` | Pass (Windows; also `--target x86_64-unknown-linux-gnu`) |
| `cargo test --manifest-path core/Cargo.toml`, with and without `--features native-abi` | Pass (counts above) |
| `cargo build --manifest-path core/Cargo.toml --release --features native-abi` | Pass |
| Repository consistency script, `git diff --check`, Markdown links and anchors | Pass |
| GitHub Actions on `96af6af` | Pass on `613a00b`: Repository consistency; Rust security core `windows-core` (fmt, both clippy runs, core tests, native-ABI tests including every listener child, release build, artifact check) and `unsupported-platform-fails-closed` (the same, plus the steps that require the unsupported-platform authority and listener tests to run and pass exactly once, and the negative `panic = "abort"` check). The closure commit changes only documents and removes the temporary CI repetition step |

## P7.5 evidence

Verified on Windows 11 (`rustc 1.99.0`) at `7e87e2d`; Linux is covered by CI. Decisions: [P7-D-008](decisions.md#p7-d-008--bounded-drive-and-foreign-event-model) (bounded drive and event model), [P7-D-009](decisions.md#p7-d-009--connection--run-reference-semantics) (connection and run references), [P7-D-010](decisions.md#p7-d-010--pairingresult-ownership-and-foreign-access) (result ownership and access); contract [§18](abi-contract.md#18-network-drive-connections-runs-and-events) and [§19](abi-contract.md#19-results). Started from `59d2baa` (20 commits ahead of `main`, 0 behind, no pull request, all three CI jobs green there).

### Source recheck (before implementing)

| Fact | Where | Consequence |
|---|---|---|
| `drive_once` is synchronous and threadless: a deadline sweep, at most one `WSAPoll` over at most `MAX_POLL_SOCKETS` (17) sockets waiting at most `OWNER_LOOP_MAX_WAIT` (250 ms), a second sweep, at most one socket operation per existing connection, at most one accept. `MAX_STEP_EVENTS = MAX_POLL_SOCKETS = 1 + MAX_LIVE_UNAUTHENTICATED_CONNECTIONS = 17`: the listener adds at most one event, each connection at most one | `windows_owner_loop.rs` | A fixed array of 17 records always suffices; `SAS_PAIRING_MAX_DRIVE_EVENTS` is pinned to `MAX_STEP_EVENTS` |
| `OwnerEvent`: `Accepted(ConnectionRef)`, `AcceptRefused(TcpError)`, `ListenerDisabled(ListenerFailure { Io, Readiness })`, `Step(ConnectionRef, TcpStep)`, `Closed(ConnectionRef, ConnectionEnd { Adapter(TcpError), Readiness })`; `OwnerStep.failure` is set only by `fail` (with `Poll` or `OwnershipUncertain`), which closes every connection without `Closed` events and keeps earlier events; `drive_once`/`recheck_after_resume` return `Err` only with `Closed` | `windows_owner_loop.rs` | `OK` + `out_failure` with every earlier event; all references of a failed loop end; `Err(Closed)` → `OWNER_LOOP_CLOSED`; any other value is a broken invariant (fatal) |
| An accepted connection is marked served: no I/O on it in the drive that accepted it | `windows_owner_loop.rs` `listen` | The connection handle exists before any step can name it |
| `TcpStep { event: Option<TcpEvent>, result: Option<PairingResult>, write_pending }`; `TcpEvent`: `Inbound { request_id, run, event }`, `Refused(RouteError)`, `Deadline { request_id: Option, kind, cancel }`, `Written`, `Confirmed`, `Unconfirmed(RouteError)`, `Discarded`; `TimeoutCancel`: `NotBuilt`, `Pending`, `Dropped` | `windows_tcp.rs` | One fixed record covers every outcome; each variant is matched explicitly |
| `HostEvent`: `StartAccepted`, `StartDuplicate`, `Accept`, `InitiatorKey`, `ResponderKey`, `BootstrapMac(Authenticated / AlreadyAuthenticated)`, `InitiatorFinish`, `InitiatorFinishDuplicate`, `ResponderFinishAck`, `InitiatorFinishAck`, `Cancel(PeerCancellation)`; `CeremonyDeadline`: `TimedOut(Absolute / Inactivity)`, `PendingExpired`, `ClockUnavailable` | `host.rs`, `deadline.rs` | Twelve protocol events, five deadline kinds; timeout, pending expiry, and clock failure stay distinct |
| The adapter keeps one `PendingWrite` and writes it in `on_writable`; the final ACK is confirmed only after its last byte; no step type carries outbound bytes | `windows_tcp.rs` | No outbound buffer, send API, or second transport |
| `ConnectionRef(SessionHandle)`: the Router session, never reissued; `RunRef { session, request_id, instance }`: exact, rechecked under the run's lock (`UnknownRoute` for a stale one, also when the request ID is reused); one route per (session, request ID); `Routed.run` is `Some` only while the run is live and `result` only when it finished, so a step never has both | `windows_owner_loop.rs`, `router.rs` | Exact references, same-key retirement, at most one handle per step event |
| Some run endings carry no request ID: `Refused` (a frame failed its run terminally through `fail`), `Deadline` from an inbound frame or confirmation without a known owner, `Unconfirmed`, `Discarded`; the ABI cannot read a `RunRef`'s session or query liveness without a core change | `windows_tcp.rs`, `ceremony.rs` | Stale references are possible; a remote peer can grow them on a connection kept alive by overlapping runs (P6-D-001), so the owner selected a per-connection bound (P7-D-009 item 6) |
| `PairingResult { request_id, ceremony_identity: [u8; 32], peer_role: Role, authenticated_peer_bootstrap, authenticated_shared_context, profile_identifier: &'static [u8], profile_version: u16 }`, emitted once, in the step that completed the run | `ceremony.rs` | Info record + four copyable fields; moved, not cloned, into runtime storage |
| Every handle allocation (`create`, `register_authority`, `create_host`) already runs under the runtime slot mutex | `runtime.rs`, `authority.rs`, `hosting.rs` | The drive's preflight, drive, and conversion under the same slot make the preflight atomic with the drive (the condition of P7.5 item 44 holds) |
| Request IDs are 1–64 bytes in every frame (`bounded(request_id, 1, 64)`) | `protocol.rs` | A 64-byte array; a longer ID in a step would be a broken invariant |

### Surface

Sixteen exports, all entering through `dispatch`: the ten of P7.4 plus `sas_pairing_host_drive`, `sas_pairing_host_recheck_after_resume`, `sas_pairing_connection_close`, `sas_pairing_result_info`, `sas_pairing_result_copy`, and `sas_pairing_result_destroy`. New types: `sas_pairing_connection_t`, `sas_pairing_run_t`, `sas_pairing_result_t` (`uint64_t`, invalid `0`); `sas_pairing_event_kind_t`, `sas_pairing_step_kind_t`, `sas_pairing_protocol_event_t`, `sas_pairing_event_reason_t`, `sas_pairing_deadline_kind_t`, `sas_pairing_cancel_state_t`, `sas_pairing_cancel_reason_t`, `sas_pairing_event_flags_t`, `sas_pairing_role_t`, `sas_pairing_result_field_t` (`uint32_t`); the records `sas_pairing_event_t` (128 bytes) and `sas_pairing_result_info_t` (56 bytes); `SAS_PAIRING_MAX_DRIVE_EVENTS` (17), `SAS_PAIRING_MAX_REQUEST_ID_LEN` (64), `SAS_PAIRING_MAX_RUNS_PER_CONNECTION` (32). New statuses: `SAS_PAIRING_BUFFER_TOO_SMALL = 300`, `SAS_PAIRING_LISTENER_NOT_ATTACHED = 402`, `SAS_PAIRING_OWNER_LOOP_CLOSED = 403`, `SAS_PAIRING_NETWORK_POLL_FAILED = 404`; no other status was needed. ABI version `1`; no earlier value, declaration, or signature changed.

### Implementation

```text
Runtime
  ├── authorities: BTreeMap<handle, TrustedAuthority>
  ├── hosts:       BTreeMap<handle, Box<HostContext>>
  │                  HostContext {
  │                    authority, network: Option<WindowsNetworkContext>,
  │                    bindings:  Bindings            // connection handle ↔ ConnectionRef,
  │                                                   //   each with ≤ 32 run handle ↔ exact RunRef
  │                    router:    Box<Router>
  │                  }
  └── results:     BTreeMap<handle, PairingResult>   // runtime-owned, outlives every host
```

| Part | Where | What |
|---|---|---|
| Exports | `mod.rs` | `host_drive` and `host_recheck_after_resume` forward to `network::drive_through`; `connection_close` to `AbiState::close_connection`; the three result exports validate their memory and field, then use `result.rs` |
| Caller memory | `network.rs` `drive_through`, `element_range`, `overlaps` | Outputs non-null, aligned, disjoint; the event array null only with capacity `0`, aligned, `capacity × 128` within `isize::MAX` and not wrapping, disjoint from both outputs; all before any write. Only produced records are written, each whole |
| Preflight and drive | `network.rs` `AbiState::drive_host` | Capacity (`BUFFER_TOO_SMALL` before the slot), then `with_runtime(Normal)` (fatal, runtime), host, `has_network` (`LISTENER_NOT_ATTACHED`), `can_allocate_handles(17)` (`HANDLES_EXHAUSTED`), then `HostContext::step_network`, then `convert`, all under the slot |
| Owner-loop access | `hosting.rs` `step_network`, `close_network_connection`, `bindings_mut` | The loop's `drive_once`/`recheck_after_resume`/`close_connection` run in place through `enter_core`; only owned values (`OwnerStep`, results) leave the module. `detach_network` clears the bindings before the network context ends, on every path (detach, host destroy, release and runtime cascades, `Drop`) |
| Conversion | `network.rs` `convert`, `convert_event`, `convert_step`, `well_formed` | Validation pass first (≤ 17 events, each connection once, bound/unbound state, request IDs ≤ 64), then one record per event from `Event::ZERO`; `Accepted` binds, `Closed` unbinds (with runs) after writing the handle; inbound runs reuse or issue exact run handles; visible endings retire; a result is moved into `Runtime.results` under a new handle; an owner failure clears every binding and maps `Poll` → 404, `OwnershipUncertain` → 104, anything else → fatal |
| Translations | `network.rs` | `protocol_event`, `cancel_reason`, `deadline_kind`, `cancel_state`, `tcp_reason`, `host_reason`, `transport_reason`, `route_reason`, `ceremony_reason`, `listener_reason`, `end_reason`, `owner_failure_status`: wildcard-free matches |
| Bindings | `network.rs` `Bindings`, `ConnectionBinding::run_handle`, `retire` | `Vec`s reserved once (16 connections, 32 runs each); exact `RunRef` equality; same-key retirement before a new handle; beyond 32, `RUN_UNTRACKED` and no handle |
| Close | `network.rs` `AbiState::close_connection` | `with_runtime(Cleanup)`, host, listener, `unbind_handle` (removes the connection and its runs first), the loop's `close_connection`; `OwnershipUncertain` → 104 and every binding cleared; any other error breaks the invariant → fatal |
| Results | `result.rs`, `runtime.rs` | `ResultInfo::of` copies the fields; `with_result_field` and `destroy_result` run under `Admission::Data` (fatal and poison tolerated, never the core); `Runtime::destroy` drops the results last |
| Preflight primitive | `runtime.rs` `HandleCounter::can_allocate`, `AbiState::can_allocate_handles` | Non-consuming: whether the next `count` values exist |
| Test seams | `hosting.rs`, `#[cfg(test)]` only | Per-thread `NETWORK_STEPS` (owner-loop calls made) and `DRIVE_FAULT` (rewrites a real step with the loop in hand: close the loop and set a failure, or panic); not in the artifact; no core file changed |

### Tests (`abi::tests::network` and the extended consistency tests, feature `native-abi`)

| Area | Tests | What they show |
|---|---|---|
| Consistency (extended) | `abi_constants_are_frozen`, `export_signatures_are_pinned`, `header_matches_the_rust_abi`, `every_export_runs_inside_the_central_panic_boundary`, `event_and_result_info_layouts_are_pinned`, `abi_sources_keep_one_lifetime_extension_and_no_thread_or_send_path` | 24 statuses (300, 402–404 added, none renumbered); three new 8-byte handle types; every typed event and result constant in the header equals Rust, each enumeration dense and frozen; both records field for field in the header; 16 exact declarations equal the `no_mangle` set, each starting with `dispatch(`; sizes 128/56, alignments 8/4, every offset contiguous, no trailing padding, zero records all zero bytes; the ABI sources contain exactly one `unsafe fn router_for_owner_loop`, one call of it, two `&'static Router` (its signature and the loop constructor), and no `transmute`, `Box::leak`, `ManuallyDrop`, `thread::spawn`, `std::thread`, `Arc<Router>`, or send/outbound path |
| Arguments (all platforms) | `drive_arguments_are_checked_before_anything_else`, `result_access_arguments_are_checked_before_anything_else` | For both drive exports: null and misaligned outputs, overlapping outputs, a null array with capacity, a misaligned array, size overflow, address wrap, and either output inside the array → `INVALID_ARGUMENT` with nothing written; the size query and capacities 0, 1, 16 → `BUFFER_TOO_SMALL` with `*out_count = 17` (Windows) or `UNSUPPORTED_PLATFORM`; untouched records. Result info/copy: null and misaligned outputs, a null buffer with capacity, a wrapping or oversized buffer, `out_required` inside the buffer, fields 0, 5, `UINT32_MAX` → `INVALID_ARGUMENT`, nothing written, buffer unread; well-formed calls zero their outputs and give `INVALID_HANDLE` |
| Preflight primitive, request-ID bound | `the_handle_preflight_is_non_consuming_and_exact`, `the_request_id_array_is_the_codec_bound` | `can_allocate` is non-consuming and exact at the top of the counter; the bound is 17; a 64-byte request ID encodes and decodes, 65 is refused |
| Translations (Windows) | `every_core_outcome_maps_to_one_frozen_event_value` | Every constructible `HostEvent`, `CancelReason`, `CeremonyDeadline`, `TimeoutCancel`, all 12 `TransportError`, every `TcpError`, `HostError`, `RouteError`, all 11 core `Error`s under `CeremonyError::Owner`, 20 further `CeremonyError` variants, `ListenerFailure`, `ConnectionEnd`, and every `OwnerLoopError` as a step failure, with its frozen value (`PeerCancellation` and `Timeout` cannot be built outside the core: the peer-CANCEL flow covers the first; the second is matched explicitly) |
| Conversion over real core references (Windows) | `a_connection_keeps_one_handle_until_its_closed_event`, `an_exact_run_keeps_one_handle_and_a_reused_request_id_gets_a_new_one`, `a_full_connection_reports_new_runs_untracked_and_evicts_nothing`, `an_owner_failure_never_discards_the_events_before_it`, `every_event_issues_at_most_one_handle` | Real `ConnectionRef`s (a real loop's accepts) and real `RunRef`s (router Initiator runs, two instances under one request ID) in synthetic steps: one handle per connection across steps, CLOSED names it then it is gone, a new connection gets a larger handle; refusals and listener failures name no connection; write-pending and 64-byte request IDs copied exactly; one handle per exact run, a replacement under the reused ID gets a new handle and retires the old, a duplicate START without a run, a deadline without an ID, and a refusal retire nothing, a deadline with the ID and a run-less inbound ending retire at once, a retired run never regains its handle, CLOSED removes every run; the 33rd run is untracked with no handle issued and the first 32 keep theirs; `Poll` → 404 and `OwnershipUncertain` → 104 keep both earlier events and clear every reference, an impossible failure is fatal, `Err(Closed)` → 403, other refusals fatal, 18 events / a repeated connection / a 65-byte ID → fatal with no handle issued; each event issued at most one handle and known runs none |
| Refused calls do no network work (Windows) | `a_refused_drive_makes_no_network_progress`, `the_handle_preflight_precedes_every_network_step` | With a pending accept, and then with unread input on a connection, too-small arrays (both modes) return `BUFFER_TOO_SMALL` and the owner loop is never called (`NETWORK_STEPS` unchanged, no connection), and the next full drive finds the pending work. With 16 handle values left, drive and recheck return `HANDLES_EXHAUSTED` without calling the loop, the connection is still pending (the loop itself then accepts it), and no handle exists for it; with exactly 17 left the drive runs |
| Connections (Windows) | `connection_handles_are_stable_until_closed_and_never_reused`, `an_accept_refusal_names_no_connection` | One handle through ACCEPTED, the START step, and WRITTEN; a graceful peer close gives CLOSED/`PEER_CLOSED` naming it, then it and its run are invalid and close gives `INVALID_HANDLE`; explicit close with a live run → `OK`, references gone first, the peer sees the end, a second close and eight wrong-kind or stale values → `INVALID_HANDLE`; detach → `LISTENER_NOT_ATTACHED` for close, drive, and recheck; after re-attach the old handle names nothing and a new connection gets a new handle. The 17th connection → `ACCEPT_REFUSED`/`RESOURCE_LIMITED` with connection 0 while 16 keep their handles |
| Exact runs (Windows) | `a_reused_request_id_never_reaches_the_replacement_run` | A changed START for a live request ID ends that run (`REFUSED`, no request ID): its handle stays (honest stale contract) and the core refuses the old exact run (`UnknownRoute`); the next START under the same ID on the same connection gets a new handle, a new exact run, the stale reference is retired, and the old run still reaches nothing while the new one answers |
| Results (Windows) | `a_responder_result_is_delivered_once_and_outlives_its_frontend`, `an_initiator_result_is_local_completion_only_and_dies_with_its_runtime`, `a_peer_cancel_retires_its_run_at_once` | Complete real ceremonies over loopback against a peer adapter of another authority (local actions on the ABI side are test-side owner-loop calls; no ceremony export exists). Responder: every event checked (one run handle from START_ACCEPTED to INITIATOR_FINISH, WRITTEN after each local action), then INITIATOR_FINISH_ACK with a result handle, `run = 0`, the request ID, and the run reference retired; every field equals the stored core result byte for byte and the expected ceremony identity, peer role, peer Bootstrap frame, shared context, profile identifier and version; copies are exact with and without spare capacity, one byte short or zero → `BUFFER_TOO_SMALL`; one opportunity consumed, never refunded; nothing more is reported later; the result survives connection close, detach, host destroy, and authority release unchanged; destroy then `INVALID_HANDLE`. Initiator: the result arrives in the CONFIRMED step (request ID from the result) while the peer has not read the final ACK (its run still routed: no peer result), the peer then leaves without reading it, and the local result is unaffected; runtime destroy invalidates it (also for a new runtime). Peer CANCEL after SAS: `PEER_CANCEL`/`USER_REJECTION`, no run, no result, the request ID, the run reference retired at once |
| Owner failure, resume (Windows) | `a_drive_that_fails_closed_still_delivers_its_events`, `the_resume_recheck_accepts_reads_and_writes_nothing`, `the_resume_recheck_surfaces_deadline_endings` | `DRIVE_FAULT` closes the real loop right after it produced a real ACCEPTED event and sets `Poll`: `OK`, one event, `NETWORK_POLL_FAILED`, every reference gone; later drive and recheck → `OK`, 0, `OWNER_LOOP_CLOSED`; detach cleans up; not fatal. Three rechecks with a pending accept and unread START input: no event, one owner-loop call each, no accept; the next drive reports both; a recheck does not write the retained ACCEPT, the next drive does. After the 10 s first-frame deadline a recheck closes a silent connection and one whose START bytes it never read, both `TRANSPORT_DEADLINE` |
| Fatal (Windows) | `after_fatal_only_cleanup_and_result_data_remain` | After a real result and an injected panic: drive and recheck `FATAL` with no owner-loop call; info and copies unchanged; connection close `OK`; result destroy `OK` then `INVALID_HANDLE`; fatal stays |
| Exports end to end (child) | `the_drive_and_result_exports_work_end_to_end` | Through the real exports and process state: the size query; a Responder and an Initiator ceremony on two connections, two distinct result handles, accounting 8; then an injected panic: drive and recheck `FATAL` without loop calls (the capacity check still first), every result export works, connection close works, the result survives detach, host destroy, and release, accounting 8, and runtime destroy invalidates it; fatal stays |
| Panic mid-drive (child) | `a_panic_during_a_drive_is_contained_without_false_success` | `DRIVE_FAULT` panics right after a real drive produced an ACCEPTED event: the export returns `FATAL` with `*out_count = 0`, the process is fatal, later drives never call the loop, detach, host destroy, release, and destroy work, the authority's budget and accounting allocation are unchanged, create stays `FATAL` |
| Races (child) | `drive_serializes_with_every_teardown` | 8 rounds × 4 teardowns (detach, host destroy, authority release, runtime destroy) raced against a drive with a pending accept, roles swapped every other round: the teardown is always `OK`, the drive `OK` or the refusal of a teardown admitted first (`LISTENER_NOT_ATTACHED` or `INVALID_HANDLE`), and a later drive always refuses; no event of the old loop, no deadlock (120 s child deadline), never fatal |
| Unsupported platform (child, Linux) | `driving_fails_closed_on_unsupported_platforms` | With a live runtime: both drive exports → `UNSUPPORTED_PLATFORM` with `0`/`OK` and untouched records; connection close → `UNSUPPORTED_PLATFORM`; result info and destroy → `INVALID_HANDLE` (data access works; no result can exist). Also its own CI step requiring exactly one passed test |

Counts: `cargo test --features native-abi --lib abi::tests` gives 106 passed and 45 ignored (the child bodies) on Windows; `abi::tests::network` alone 25 passed and 3 ignored. The full suite with the feature gives 521 unit tests passed (48 ignored: 3 P5 deep runs and 45 children), 2 + 9 integration, and 1 doc test, 0 failed. Without the feature: unchanged at 415 unit (3 ignored), 2 + 9 integration, and 1 doc test, 0 failed. Every test and child uses its own authority scopes (the P7.4 lesson). On Linux the platform-neutral tests and the unsupported-platform child run; the rest needs a Windows owner loop and nothing is faked.

### Mutation checks (temporary, not committed)

Each applied to `core/src/abi/network.rs` alone and run against its targeted tests; the file was restored byte for byte after each (compared with a saved copy) and the suite re-run green.

| Mutation | Result |
|---|---|
| A: the drive runs with an undersized event array | Killed: `a_refused_drive_makes_no_network_progress` (the too-small call returned `OK` and drove) |
| B: the `PairingResult` is dropped instead of stored | Killed: both result tests (no result handle in the completing event) |
| C: a new connection handle on every step | Killed: `a_connection_keeps_one_handle_until_its_closed_event`, `connection_handles_are_stable_until_closed_and_never_reused` |
| D: the old run handle is reused for a replacement run under the same request ID | Killed: `a_reused_request_id_never_reaches_the_replacement_run`, `an_exact_run_keeps_one_handle_and_a_reused_request_id_gets_a_new_one` |
| E: earlier events are discarded when the step has a failure | Killed: `an_owner_failure_never_discards_the_events_before_it`, `a_drive_that_fails_closed_still_delivers_its_events` |
| F: connection and run references are kept after a CLOSED event | Killed: both connection tests (the closed handle stayed resolvable) |
| G: no handle-capacity preflight | Killed: `the_handle_preflight_precedes_every_network_step` (the drive ran with 16 values left) |

### Artifact, header, and C smoke

`cargo build --manifest-path core/Cargo.toml --release --features native-abi`: `llvm-readobj --coff-exports core/target/release/sas_pairing_core.dll` lists exactly the 16 exports: `sas_pairing_abi_version`, `sas_pairing_authority_register`, `sas_pairing_authority_release`, `sas_pairing_authority_status`, `sas_pairing_connection_close`, `sas_pairing_host_attach_windows_listener`, `sas_pairing_host_create`, `sas_pairing_host_destroy`, `sas_pairing_host_detach_listener`, `sas_pairing_host_drive`, `sas_pairing_host_recheck_after_resume`, `sas_pairing_result_copy`, `sas_pairing_result_destroy`, `sas_pairing_result_info`, `sas_pairing_runtime_create`, `sas_pairing_runtime_destroy` (no local ceremony action, debug, panic, router, owner-loop, or Rust-mangled symbol). The header compiles as strict C11 and C++17 (`-Wall -Wextra -Werror -pedantic`) with static assertions on both record sizes, alignments, and offsets and on `SAS_PAIRING_MAX_DRIVE_EVENTS == 17`. A throwaway C host (clang 19.1.5, linked against the import library and `ws2_32`, built as C11 and as C++17, not committed) ran: `WSAStartup`; it bound and listened on loopback itself; runtime, authority, host, attach (slot `INVALID`); connect a client; the size query and a 4-record array → `BUFFER_TOO_SMALL` with 17 and no accept; a full drive → `CONNECTION_ACCEPTED` with handle 4, no run, no result, zero reserved and request ID; the canonical START test vector from the client → `CONNECTION_STEP`/`INBOUND`/`START_ACCEPTED` naming connection 4, run 5, `WRITE_PENDING`, the 16-byte request ID; then `WRITTEN` on connection 4; connection close `OK`, again `INVALID_HANDLE`; detach; drive → `LISTENER_NOT_ATTACHED`; host destroy; release; runtime destroy; `WSACleanup`. Both builds printed `P7.5 C smoke OK`.

### Unsafe audit (new in P7.5)

| Site | Why | Precondition, prior validation, lifetime |
|---|---|---|
| `mod.rs`, `sas_pairing_host_drive` and `sas_pairing_host_recheck_after_resume`: one block each calling `network::drive_through` | Forward the raw-pointer contract | The exports' `# Safety` contract is exactly `drive_through`'s; nothing is checked or dereferenced in between |
| `network.rs`, `drive_through` (an `unsafe fn`): `out_count.write`, `out_failure.write` | Fill the caller's two output slots | After the null, alignment, and pairwise-overlap checks against each other and the event array. Caller-owned, writable, unaliased for the call; `usize` and `i32` writes; nothing retained |
| `network.rs`, `drive_through`: `events.add(index).write(*event)` | Write one produced event record | `index < count <= 17 <= capacity` (a smaller capacity returns before the drive); the array is non-null, aligned, `capacity × 128` bytes without overflow or wrap, disjoint from both outputs; `Event` is a padding-free `repr(C)` record of integers written whole, so no uninitialized byte reaches the caller; only produced records are written |
| `mod.rs`, `sas_pairing_result_info`: `out_info.write` (zeroing and the result) | Fill the caller's info record | After the null and alignment checks; `ResultInfo` is a padding-free `repr(C)` record of integers and bytes |
| `mod.rs`, `sas_pairing_result_copy`: `out_required.write`; `ptr::copy_nonoverlapping(bytes, buffer, len)` | Report the length; copy the field | After the null and alignment check of `out_required`, the buffer range check (null only with capacity 0, within `isize::MAX`, no wrap), and their non-overlap. The copy runs only when `len <= capacity` and `len > 0`, so the buffer is non-null and holds it; the source is runtime-owned storage no caller memory overlaps, borrowed only under the runtime slot |
| `pub unsafe extern "C" fn` × 4 (drive, recheck, info, copy) | Mark the raw-pointer preconditions | Not blocks; `# Safety` sections match the header. `connection_close` and `result_destroy` take no pointer and are safe `extern "C" fn`s |
| `#[unsafe(no_mangle)]` × 6 | Symbol export (edition 2024) | `sas_pairing_` prefix; the header test pins the exact set |
| Tests | Exercise the exports and seams | Live, aligned, exclusive outputs, arrays, and buffers; or pointers the exports reject before access (null, misaligned, `ptr::without_provenance` near the top of the address space, overlapping ranges, oversized capacities) |

No new lifetime-related `unsafe`: the P7-D-007 check below holds.

### P7-D-007 check

`router_for_owner_loop` is still the ABI's only lifetime extension: one `unsafe fn` definition and one call (`HostContext::attach_network`), both in `hosting.rs`, and `&'static Router` appears exactly twice (its signature and the owner-loop constructor it feeds), now enforced by `abi_sources_keep_one_lifetime_extension_and_no_thread_or_send_path`. P7.5 adds no raw router pointer, `Box::leak`, `transmute`, `ManuallyDrop`, `Arc<Router>`, or second extension; the drive runs the loop in place inside `hosting.rs`, and no reference to the router, the loop, or the network context leaves that module (the bindings hold only `ConnectionRef`/`RunRef` values, which borrow nothing).

### P6 handoffs in P7.5

- **P6-D-004.** Every new export runs inside the central boundary (16 of 16), no new `catch_unwind`, no thread. A panic in the middle of a real drive is contained without false success, fatal, cleanup allowed, and accounting unchanged. **Consumed-accounting panic evidence is still open:** no P7.5 export consumes an opportunity (the ceremonies above consumed theirs through test-side owner-loop calls), so the proof that a panic during an ABI operation that consumed an opportunity leaves it consumed waits for the P7.6 authorization and exposure exports.
- **P6-D-002.** Drive, recheck, connection close, and result access consume or refund nothing, reset no budget or START limiter, and start no process session; the ceremonies consumed exactly one opportunity each, kept after close, detach, host destroy, release, fatal, and runtime destroy.
- **P6-D-005.** A result handle is presented as local verified completion only; the Initiator test shows a local result while the peer has none and never gets one.

### Frozen-core check

`git diff 59d2baa..7e87e2d -- core/src ':!core/src/abi'` is empty: no change to `router.rs`, `host.rs`, `transport.rs`, `windows_tcp.rs`, `windows_owner_loop.rs`, `ceremony.rs`, `protocol.rs`, the cryptography, deadlines, `lib.rs`, `test_hook.rs`, or process-session accounting; `Cargo.toml` and `Cargo.lock` unchanged. Everything else is `core/src/abi/*`, the header, one Linux CI step, and documents.

### Verification

| Check | Result |
|---|---|
| `cargo fmt --manifest-path core/Cargo.toml -- --check` | Pass |
| `cargo clippy --manifest-path core/Cargo.toml --all-targets -- -D warnings`, and with `--all-features` | Pass (Windows; also `--target x86_64-unknown-linux-gnu`) |
| `cargo test --manifest-path core/Cargo.toml`, with and without `--features native-abi` | Pass (counts above) |
| `cargo build --manifest-path core/Cargo.toml --release --features native-abi` | Pass |
| Repository consistency script, `git diff --check`, Markdown links and anchors | Pass |
| GitHub Actions on `7e87e2d` | Pass: Repository consistency; Rust security core `windows-core` (fmt, both clippy runs, core tests, native-ABI tests including every network child, release build, artifact check) and `unsupported-platform-fails-closed` (the same, plus the steps that require the unsupported-platform authority, listener, and new network-drive tests to run and pass exactly once, and the negative `panic = "abort"` check). The closure commit changes only documents |

## P7.6 evidence

Verified on Windows 11 (`rustc 1.99.0`) at `fd5e030`; Linux is covered by CI. Decisions: [P7-D-011](decisions.md#p7-d-011--trusted-local-ceremony-action-abi) (trusted local ceremony action ABI) and [P7-D-012](decisions.md#p7-d-012--sas-presentation-identity-binding-and-local-action-statuses) (SAS presentation, identity binding, local action statuses); contract [§20](abi-contract.md#20-trusted-local-ceremony-control) and [§3](abi-contract.md#3-status-codes). Started from `8790b68` (23 commits ahead of `main`, 0 behind, no pull request, all three CI jobs green there). Commits: `00bbf3c` (decisions and contract), `8b9ae06` (implementation, header, tests, CI), `fd5e030` (consumed-accounting panic evidence), and the closure commit.

### Source recheck (before implementing)

| Fact | Where | Consequence |
|---|---|---|
| The owner loop's nine local methods each find exactly one connection by `ConnectionRef` and forward to its adapter; an adapter error removes that connection (`OwnerLoopError::Connection`), an uncertain one shuts the whole loop (`OwnershipUncertain`) | `windows_owner_loop.rs` `on` | `CONNECTION_ENDED` (only that connection's handles end) vs. `OWNERSHIP_UNCERTAIN` (every handle of the host ends); `UnknownConnection`, `Poll`, `ListenerIo` cannot follow a valid binding (fatal) |
| `WindowsTcpConnection::act` refuses every mutating action with `Refused::WritePending` before the host while a frame is retained, otherwise makes one host call and retains its one frame; `presentation` bypasses `act` and runs while a write is pending | `windows_tcp.rs` | `WRITE_PENDING` (205) with nothing done; presentation never returns it |
| `HostConnection` local actions: one `RemoteCeremony` call through `Router::with_exact_run`; `TimedOut`/`PendingExpired`/`ClockUnavailable` become `LocalEvent::Deadline` with the action not performed; `UnknownSession`, `SessionProtocolFailure`, and `OwnershipUncertain` end the connection (`ends_session`); `initiate` first polls the transport's connection deadlines | `host.rs` | `DEADLINE` is a successful action; session-ending route errors never arrive as `Refused::Run` (fatal if they do); a start on an expired connection ends it |
| `with_exact_run` rechecks the run instance under the run's lock; a stale or foreign reference is `UnknownRoute` with nothing changed; a refusal can finish the run (`fail` → terminal), and then `Routed.run` is lost with the error | `router.rs` | `RUN_ENDED` (204) removes a stale mapping; refusals keep the mapping (honestly stale) |
| `authorize` exposes nothing (a second one fails `InvalidState` and ends the run); `expose_key` takes the permit, `reserve` (guard + one opportunity), then the hook `Point::InitiatorReserved`, then the ephemeral and INITIATOR_KEY; without authorization it is `MissingAuthorization` and ends the run; `approve_sas` never emits; `emit_bootstrap_mac` and `emit_initiator_finish` are once-only and idempotent | `ceremony.rs` | Separate exports; the existing test hook is the consumed-opportunity panic point; no core change needed |
| The decimal SAS is `format!("{first:04} {second:04} {third:04}")` of three values 1000–9191 | `crypto.rs` `Established::sas` | `SAS_PAIRING_SAS_DECIMAL_LEN = 14`, shape-checked |
| Every handle allocation already runs under the runtime slot | `runtime.rs`, `authority.rs`, `hosting.rs`, `network.rs` | The local start's run-cap and one-handle preflight stay true until the handle is bound (the condition of P7.6 item 93 holds; not blocked) |

### Surface

25 exports, all entering through `dispatch`: the 16 of P7.5 plus `sas_pairing_connection_start_initiator`, `sas_pairing_run_authorize_exposure`, `sas_pairing_run_expose_key`, `sas_pairing_run_presentation`, `sas_pairing_run_approve_sas`, `sas_pairing_run_emit_bootstrap_mac`, `sas_pairing_run_reject_sas`, `sas_pairing_run_cancel_sas`, `sas_pairing_run_emit_initiator_finish`. New types: `sas_pairing_local_event_t`, `sas_pairing_action_flags_t` (`uint32_t`), `sas_pairing_action_t` (24 bytes, align 8), `sas_pairing_sas_presentation_t` (56 bytes, align 4); `SAS_PAIRING_SAS_DECIMAL_LEN` (14); local events 0–12; `SAS_PAIRING_ACTION_FLAG_WRITE_PENDING` (0x1). New statuses 204–226 and 405; nothing renumbered. ABI version `1`. No `run_release`, raw frame, send, final-ACK confirmation, debug, or panic export.

### Implementation

| Part | Where | What |
|---|---|---|
| Exports | `mod.rs` | Nine thin exports forwarding to `control::{start_through, act_through, decide_through, present_through}` |
| Caller memory | `control.rs` | `out_action`/`out_presentation` non-null and aligned; the identity a non-wrapping 32-byte range disjoint from the record; the start's view records and every byte string disjoint from the record; all before any write; then the record is zeroed, then inputs copied |
| State operations | `control.rs` `AbiState::{start_initiator, act, presentation}` | Under `with_runtime(Normal)`: host, listener, connection, run as a run of exactly that connection; for a start the run cap (32) and `can_allocate_handles(1)`; then one owner-loop call; `settle` maps the loop's refusals; `action_record` converts `Acted`; `run_refusal` maps `Refused::Run` |
| Owner-loop access | `hosting.rs` `HostContext::{start_initiator, act_on_run, presentation}` | One reviewed owner-loop call per request, through `enter_core`; exposure authorization borrows the host's parent `TrustedAuthority` from the runtime for that call only |
| Bindings | `network.rs` | `connection`, `run` (exact parent), `run_count`, `remove_run`, `bind_local_run` (retires the same key first) |
| Mappings | `status.rs` `map_ceremony_error`, `map_run_refusal`; `control.rs` `local_event` | Wildcard-free; `Owner` reuses `map_core_error` |
| Test seams | `hosting.rs`, `#[cfg(test)]` only | `LOCAL_ACTIONS` (owner-loop calls), `ACTION_FAULT`/`PRESENTATION_FAULT` (rewrite a real outcome with the loop in hand), `START_CLOCK` (a test ceremony clock for the next local start through the owner loop's existing test entry point) |

### Tests (`abi::tests::control`, `abi::tests::consumed_panic`, and the extended consistency tests)

| Area | Tests | What they show |
|---|---|---|
| Consistency (extended) | `abi_constants_are_frozen`, `export_signatures_are_pinned`, `header_matches_the_rust_abi`, `every_export_runs_inside_the_central_panic_boundary`, `action_and_presentation_layouts_are_pinned`, `abi_sources_keep_one_lifetime_extension_and_no_thread_or_send_path` | 48 statuses (204–226, 405 added, none renumbered); local events dense 0–12, one action flag; both records field for field in the header; 25 exact declarations equal the `no_mangle` set, each starting with `dispatch(`; sizes 24/56, alignments 8/4, contiguous offsets, zero records all zero bytes, the 14-byte display shape; still exactly one `router_for_owner_loop` and no thread or send path |
| Mapping (all platforms) | `every_ceremony_error_maps_to_one_frozen_status`, `a_real_ceremony_timeout_maps_to_its_frozen_status`, `every_local_event_maps_to_one_frozen_action_value` | Every `CeremonyError` (a real core-built `TimedOut` on Windows) → its value; `Owner` keeps 100–107/200–202; `UnknownRoute` → 204; `UnknownSession`/`SessionProtocolFailure` → invariant failure; every `LocalEvent` (four deadline kinds) → its value; wildcard-free test matches stop compiling on a new variant |
| Arguments (all platforms) | `local_action_arguments_are_checked_before_anything_else` | Null/misaligned records, null/wrapping/overlapping identities, null/misaligned/malformed views, view records and byte strings overlapping the record → `INVALID_ARGUMENT`, nothing written; well-formed calls zero the record, then `INVALID_BOOTSTRAP` (before handles) or `INVALID_HANDLE` (Windows) / `UNSUPPORTED_PLATFORM` (Linux) |
| Local start, backpressure | `a_local_start_issues_one_exact_run_and_backpressures_every_mutation`, `a_full_connection_refuses_a_local_start_before_the_core`, `a_local_start_checks_its_handle_before_the_core` | `INITIATOR_STARTED`, a new handle naming an exact run with a 16-byte core request ID, `WRITE_PENDING`, START limiter untouched, nothing spent; before START is written all seven mutating actions and a second start → `WRITE_PENDING` with zero records while the presentation answers, and afterwards exactly one START reaches the peer and the run continues on the same handle. With 32 run handles a start → `RESOURCE_LIMITED` with no owner-loop call, handle, route, or request-ID reservation and never an untracked run; a run ended by a refusal still counts until an action reports `RUN_ENDED`, then a start fits. With exactly one handle value left the start takes it (`u64::MAX`); with none → `HANDLES_EXHAUSTED` before the owner loop, nothing sent |
| Authorization and exposure | `authorization_spends_nothing_and_exposure_spends_exactly_one`, `exposure_needs_a_fresh_authorization_of_exactly_that_run`, `a_second_exposure_while_the_guard_is_held_is_busy`, `an_exhausted_budget_refuses_exposure_without_output`, `every_host_authorizes_with_its_own_authority_and_parents_are_exact` | Authorize → 10 remaining, nothing written; expose → 9, `BUSY` status, the key reaches the peer; a second exposure → `MISSING_AUTHORIZATION` (core-terminal). Without authorization → `MISSING_AUTHORIZATION`, nothing spent, then `RUN_ENDED`, then `INVALID_HANDLE`; one run's authorization never authorizes another; a second authorization → `CEREMONY_INVALID_STATE`; a foreign authority (test-side owner-loop call; the ABI has no such parameter) maps to `STALE_AUTHORIZATION`. Guard held → `BUSY`. Spent budget → `EXHAUSTED`, no frame, 0 after every teardown. Two authorities in one runtime spend independently; 12 wrong-parent and wrong-kind combinations and a detached loop's handles → `INVALID_HANDLE` (or `LISTENER_NOT_ATTACHED` while detached) |
| Presentation and decisions | `presentation_is_exact_and_read_only_also_while_a_write_is_pending`, `a_decision_must_name_the_exact_ceremony_identity`, `reject_and_cancel_end_the_run_without_a_refund`, `a_responder_cannot_emit_the_initiator_finish` | The Responder's SAS is presented while its key is retained: identity and decimal equal the core's and the peer's byte for byte, repeated reads equal, MATCH then → `WRITE_PENDING`. Five wrong identities (one bit off, the request ID, a run handle, a connection handle, zeros) × three decisions → `CEREMONY_IDENTITY_MISMATCH` with nothing changed. Reject/cancel → `SAS_REJECTED`/`SAS_CANCELLED`, run 0, `WRITE_PENDING`, the handle invalid, the peer receives the authenticated CANCEL (`UserRejection`/`UserCancellation`), no result, 9 remaining through close, detach, host destroy, release, runtime destroy, and re-registration (same process session). A Responder finish → `NOT_INITIATOR`, the run continues |
| Deadlines | `a_deadline_found_by_an_action_is_a_deadline_event` | With a test ceremony clock: inactivity → `DEADLINE`/`INACTIVITY_TIMEOUT`, run 0, no flag, nothing authorized; a failed clock → `CLOCK_UNAVAILABLE`; the absolute deadline during the comparison → `ABSOLUTE_TIMEOUT` with `WRITE_PENDING`, and the peer receives the timeout CANCEL |
| Stale runs | `a_stale_run_reports_run_ended_and_never_reaches_a_replacement` | A run ended by a changed START keeps its handle until an action returns `RUN_ENDED` and removes it; then `INVALID_HANDLE`. A stale handle whose mapping still exists while a replacement under the same request ID is live (admitted by a test-side drive the ABI did not convert) → `RUN_ENDED`, and the replacement is live and untouched |
| Endings and invariants | `a_local_action_that_ends_its_connection_invalidates_its_handles`, `owner_loop_endings_and_broken_invariants_are_reported_exactly` | A start on a connection past its first-frame deadline → `CONNECTION_ENDED` (real), its handle gone, the sibling and its run untouched. Seams after real actions: a connection ending removes exactly that connection and both its runs; `OwnershipUncertain` / `Closed` clear every reference (later drive `OWNER_LOOP_CLOSED`); a decision whose CANCEL was not built gives `SAS_REJECTED` with no flag and run 0; an impossible loop refusal (three kinds), a different live run, a start event from a non-start action, a start without a run, `UnknownSession` reported as run-local (start and action), and an unusable presentation → `FATAL` |
| Fatal | `after_fatal_no_local_action_enters_the_core` | All nine refuse with `FATAL` for valid, zero, and unknown handles with no owner-loop call; close, detach, destroy still work |
| Public ABI flows (children) | `the_initiator_ceremony_runs_on_the_public_abi`, `the_responder_ceremony_runs_on_the_public_abi` | §20 end to end through the real exports (below) |
| Races (child) | `local_actions_serialize_with_drives_and_teardowns` | 6 rounds × 6 teardowns (drive, detach, connection close, host destroy, authority release, runtime destroy) raced against a local start, roles swapped every other round: the teardown always `OK`, the start `OK` or the teardown's refusal, later actions see the teardown; two concurrent starts on one connection → exactly one `INITIATOR_STARTED` and one `WRITE_PENDING`, one run handle; two concurrent authorizations of one run → exactly one `EXPOSURE_AUTHORIZED` and one `CEREMONY_INVALID_STATE`, nothing spent; never fatal, no deadlock (120 s child deadline) |
| Consumed-opportunity panic (children) | `a_consumed_opportunity_panic_is_contained`, `a_consumed_opportunity_panic_on_drop_is_contained` | See below |
| Unsupported platform (child, Linux) | `local_actions_fail_closed_on_unsupported_platforms` | All nine → `UNSUPPORTED_PLATFORM` with zeroed records, for two handle sets; no handle issued or burned (the next runtime takes the next value). Also its own CI step requiring exactly one passed test |

Counts: `cargo test --features native-abi --lib abi::tests` gives 133 passed and 50 ignored (the child bodies) on Windows; `abi::tests::control` alone 24 passed and 3 ignored, `abi::tests::consumed_panic` 2 and 2. The full suite with the feature gives 548 unit tests passed (53 ignored: 3 P5 deep runs and 50 children), 2 + 9 integration, and 1 doc test, 0 failed. Without the feature: unchanged at 415 unit (3 ignored), 2 + 9 integration, and 1 doc test. One no-feature run hit an intermittent failure in the frozen P5 router race test `p5_router_race_002_close_versus_start_admission` (an admission outcome outside its expected set under full-suite load); it passed in 8 isolated and 4 further full runs, and no file it compiles changed (the no-feature build contains no ABI code, and `core/src` outside `abi` is unchanged).

### Full ceremonies on the public ABI

**Initiator** (`child_initiator_flow`, real exports, process state): connection accepted by a drive; `start_initiator` → `INITIATOR_STARTED`, run R, `WRITE_PENDING`; WRITTEN; the peer's ACCEPT arrives on R; authorize → R, no flag (10 left); expose → R, `WRITE_PENDING` (9 left); the peer's key arrives on R; presentation: available, identity and 14-byte decimal equal to the core's and the peer's; MATCH → `SAS_APPROVED`, no flag, then no drive event and nothing at the peer (no MAC); MATCH again → `SAS_ALREADY_APPROVED`; presentation then zero (withdrawn by the approval); emit MAC → `BOOTSTRAP_MAC_EMITTED` + `WRITE_PENDING`; again while pending → `WRITE_PENDING`; WRITTEN; again → `BOOTSTRAP_MAC_ALREADY_EMITTED`, no new frame; the peer authenticates our MAC, approves, emits its MAC; `BOOTSTRAP_MAC_AUTHENTICATED` on R; then no drive event and nothing at the peer (no automatic finish); emit finish → `INITIATOR_FINISH_EMITTED` + `WRITE_PENDING`; WRITTEN; again → `INITIATOR_FINISH_ALREADY_EMITTED`; the peer's `RESPONDER_FINISH_ACK` on R with `WRITE_PENDING` and no result; an action then → `WRITE_PENDING` (the final ACK is retained); the next drive: `STEP_CONFIRMED` with the result (byte-for-byte equal to the core's), run 0, R invalid. The peer has no result yet (its run still routed). One opportunity spent, kept after runtime destroy.

**Responder** (`child_responder_flow`): the peer's START → run R; ACCEPT written; the peer's key on R; authorize → R; expose → `WRITE_PENDING` (9 left) and the presentation is available while RESPONDER_KEY is retained; WRITTEN; identity and decimal equal to the core's and the peer's; the peer's MAC authenticated; MATCH → `SAS_APPROVED`; finish → `NOT_INITIATOR`; MAC → `BOOTSTRAP_MAC_EMITTED`; WRITTEN; the peer's INITIATOR_FINISH → `INITIATOR_FINISH` on R with `WRITE_PENDING` (RESPONDER_FINISH_ACK retained by the drive itself), no result; WRITTEN; the peer's final ACK → `INITIATOR_FINISH_ACK` with the result, run 0, R invalid. No local finish export was needed.

### Consumed-opportunity panic (P6-D-004)

**Hook point.** The existing test-only `Point::InitiatorReserved` in `RemoteCeremony::expose_key` (`ceremony.rs`), after `executor.reserve` (guard taken, `remaining -= 1`) and before the ephemeral, INITIATOR_KEY, or any state transition. No production hook or core change was added.

**Sequence** (each payload in its own child process, own scopes): runtime, authority, host, listener, accepted connection; `sas_pairing_connection_start_initiator`; the peer's ACCEPT through drives; `sas_pairing_run_authorize_exposure` (status `READY`/10; registry 10); install a hook that counts and panics (`panic!`, or `panic_any(PanicOnDrop)`); `sas_pairing_run_expose_key`.

| Check | Ordinary | `PanicOnDrop` |
|---|---|---|
| Hook fired after the reserve (a real core panic) | 1 | 1 |
| Return, record | `FATAL`, zero (written on entry; never a success record) | same |
| Process fatal; host process survived | set; yes | set; yes (it would abort with `0xc0000409` if the payload's destructor ran) |
| Payload destructor runs | — | 0 |
| Remaining opportunities (test-only registry read) | 9, the same process-session allocation: consumed, never restored to 10 | same |
| Next normal operations (expose, authorize, MATCH, MAC, finish, presentation, start, for the live and zero handles; drive; authority status; register; host create; runtime create) | all `FATAL`; core entries and owner-loop calls unchanged; hook count still 1 | same |
| Version query | 1 | 1 |
| Cleanup | connection close `OWNERSHIP_UNCERTAIN` (the panic poisoned the run's lock, so its session teardown is uncertain and keeps its capacity held), detach `OK`, host destroy `OK`, release `OK`, runtime destroy `OK`; fatal stays | same |
| After cleanup | registration `Inactive`, 9 remaining, same allocation; runtime create `FATAL`; test-side same-process `TrustedAuthority::register` → `OwnershipUncertain` (fails closed while the uncertain capacity is held), still 9 | same |

**P6-D-004 ABI PANIC CONTAINMENT EVIDENCE COMPLETE.** A real core panic, raised after an ABI operation consumed an opportunity, is contained in Rust, makes the process fatal, never runs the payload destructor, leaves no normal path that re-enters the core, keeps cleanup available, and leaves the consumed opportunity consumed. The frozen P6-D-004 decision itself is unchanged.

### Mutation checks (temporary, not committed)

Each applied alone, then `abi::tests::control` (including `consumed_panic` in its filter only for H; the children run inside it) re-run; every file restored byte for byte (SHA-256 checked) and touched.

| Mutation | Result |
|---|---|
| A: exposure authorization also exposes the key | Killed: 20 tests (both flows, accounting, busy, exhausted, identity, deadline, parents, races, both panic children) |
| B: the adapter's write-pending check removed (core, temporary) | Killed: backpressure (adapter assertion), presentation-while-pending, the Initiator flow and races children |
| C: `with_exact_run` without the instance check (request-ID targeting; core, temporary) | Killed: `a_stale_run_reports_run_ended_and_never_reaches_a_replacement` (`CEREMONY_INVALID_STATE` instead of `RUN_ENDED`: the stale handle reached the replacement) |
| D: MATCH uses the live identity instead of the caller's | Killed: `a_decision_must_name_the_exact_ceremony_identity` |
| E: MATCH also emits BOOTSTRAP_MAC | Killed: both flows, identity, deadline |
| F: a drive emits INITIATOR_FINISH after a peer MAC | Killed: the Initiator flow child ("no automatic finish") |
| G: reject/cancel refund the opportunity | Killed: `reject_and_cancel_end_the_run_without_a_refund` (10 instead of 9) |
| H: `mem::forget(payload)` replaced by `drop(payload)` | Killed: the `PanicOnDrop` child aborted (`0xc0000409`) |
| I: no run-cap refusal; an untracked local start reported instead | Killed: `a_full_connection_refuses_a_local_start_before_the_core` (`OK`, run 0, flags 3 instead of `RESOURCE_LIMITED`) |

### Artifact, header, and C smoke

`cargo build --manifest-path core/Cargo.toml --release --features native-abi`: `llvm-readobj --coff-exports` lists exactly the 25 exports (the 16 of P7.5 and the nine above; no test hook, seam, debug, panic, router, `RemoteCeremony`, `RunRef`, authorization, final-ACK, or Rust-mangled symbol); a release build without the feature exports none. The header parses as strict C11 and C++17 (`-Wall -Wextra -Werror -pedantic`). A throwaway C host (clang 19.1.5, linked against the import library and `ws2_32`, built as C11 and as C++17, not committed) with static assertions on both record sizes, alignments, and offsets and on 14, 204, 205, 226, and 405 ran: `WSAStartup`; it bound and listened on loopback; runtime, authority, host, attach; a client connected; a drive → `CONNECTION_ACCEPTED` (4); start with a null view → `INVALID_ARGUMENT` (record untouched), an invalid Bootstrap → `INVALID_BOOTSTRAP` (zeroed), the authority handle as connection → `INVALID_HANDLE`; start → `OK`, `INITIATOR_STARTED`, run 5, `WRITE_PENDING`; authorize, a second start, and MATCH → `WRITE_PENDING` with zero records; presentation → `OK`, `available = 0`; the run handle used as a run of itself → `INVALID_HANDLE`; a drive → `WRITTEN`, and the client received 152 START bytes written by the library; connection close, presentation → `INVALID_HANDLE`; detach, host destroy, release, runtime destroy, `WSACleanup`. Both builds printed `P7.6 C smoke OK`.

### Unsafe audit (new in P7.6)

| Site | Why | Precondition, prior validation, lifetime |
|---|---|---|
| `mod.rs`: nine `pub unsafe extern "C" fn` exports, each with one block forwarding to its `control` body | Mark and forward the raw-pointer contract | Not checks themselves: each export's `# Safety` contract is exactly its body function's |
| `control.rs` `act_through`, `decide_through`, `start_through`: `out_action.write(Action::ZERO)` | Zero the caller's record | After the null and alignment checks (and, for decisions and starts, the non-overlap checks against every input); `Action` is a padding-free `repr(C)` record of integers, written whole |
| `control.rs` `deliver` (an `unsafe fn`): `out_action.write(action)` | Fill the record on `OK` | Same record, already validated and zeroed; nothing retained |
| `control.rs` `decide_through`: `caller_bytes(ceremony_identity, 32)` | Copy the 32 identity bytes | After `byte_range` (non-null, no wrap) and the non-overlap check; copied at once into a `[u8; 32]`; the borrow ends there; no pointer kept |
| `control.rs` `start_through`: `local.read()`, `expected.read()` | Copy the view records | After the null and alignment checks; views are integers and raw pointers (every bit pattern valid, nothing dropped) |
| `control.rs` `start_through`: two `BootstrapInput::new` calls | Record that the views' bytes are readable for the call | After every view is well formed; the existing audited P7.4 machinery (`to_bootstrap` → `caller_bytes` → `to_vec`) copies the bytes |
| `control.rs` `present_through`: `out_presentation.write` (zeroing and the result) | Fill the presentation record | After the null and alignment check; a padding-free `repr(C)` record of integers and bytes |
| `#[unsafe(no_mangle)]` × 9 | Symbol export (edition 2024) | `sas_pairing_` prefix; the header test pins the exact set |
| Tests | Exercise the exports and seams | Live, aligned, exclusive records, identities, and views; or pointers the exports reject before access (null, misaligned, `ptr::without_provenance` near the top of the address space, overlapping ranges) |

No unsafe `RunRef` or `ConnectionRef` lifetime, raw core object pointer, or `transmute`.

### P7-D-007 check

`router_for_owner_loop` is still the ABI's only lifetime extension: one definition and one call in `hosting.rs`, and `&'static Router` exactly twice, enforced by `abi_sources_keep_one_lifetime_extension_and_no_thread_or_send_path` (which now also scans `control.rs`). The local actions run the loop in place inside `hosting.rs`; only owned values (`Acted`, `Refused`, `Option<SasPresentation>`, `OwnerLoopError`) leave it, and the bindings hold `ConnectionRef`/`RunRef` values, which borrow nothing.

### P6 handoffs in P7.6

- **P6-D-004.** All 25 exports run inside the central boundary; no new `catch_unwind`, `C-unwind`, thread, or panic hook. The consumed-accounting evidence is complete (above).
- **P6-D-002.** Authorization spends nothing; exposure spends exactly one; reject, cancel, a deadline, connection close, detach, host destroy, release, runtime destroy, fatal, and re-registration never refund it or start a new process session; an exhausted budget stays exhausted; the Responder START limiter is untouched by local starts.
- **P6-D-005.** No bilateral-success concept: the Initiator's result appears only in `STEP_CONFIRMED` after the adapter's complete local write of the final ACK, while the peer has none yet; the Responder's only after the verified final ACK.

### Frozen-core check

`git diff 8790b68..fd5e030 -- core/src ':!core/src/abi' core/Cargo.toml core/Cargo.lock` is empty: no change to `lib.rs`, `ceremony.rs`, `router.rs`, `host.rs`, `windows_tcp.rs`, `windows_owner_loop.rs`, `protocol.rs`, `crypto.rs`, `transport.rs`, `deadline.rs`, `start_limiter.rs`, or `test_hook.rs`. Everything else is `core/src/abi/*`, the header, one Linux CI step, and documents.

### Verification

| Check | Result |
|---|---|
| `cargo fmt --manifest-path core/Cargo.toml -- --check` | Pass |
| `cargo clippy --manifest-path core/Cargo.toml --all-targets -- -D warnings`, and with `--all-features` | Pass (Windows; also `--target x86_64-unknown-linux-gnu`) |
| `cargo test --manifest-path core/Cargo.toml`, with and without `--features native-abi` | Pass (counts above) |
| `cargo build --manifest-path core/Cargo.toml --release --features native-abi` | Pass |
| `git diff --check`, workflow YAML parse, Markdown links and anchors of the changed documents | Pass |
| GitHub Actions on `fd5e030` | Pass: Repository consistency; Rust security core `windows-core` (fmt, both clippy runs, core tests, native-ABI tests including every control and consumed-panic child, release build, artifact check) and `unsupported-platform-fails-closed` (the same, plus the steps that require the unsupported-platform authority, listener, network-drive, and new ceremony-control tests to run and pass exactly once, and the negative `panic = "abort"` check). The closure commit changes only documents |
