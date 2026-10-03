# P7 Native ABI

> **Pre-alpha. Not production approval.** P7 exposes the frozen experimental protocol candidate through a language-neutral native boundary for the future Dart and .NET wrappers. Nothing here is a professional audit, formal verification, certification, or production-security or release approval.

## Status

**P7 IN PROGRESS — P7.3 COMPLETE.** P7.1 established the ABI version, type conventions, status namespace, opaque runtime handle, runtime lifecycle, and the central panic containment ([evidence](#p71-evidence)). The P7.1.1 correction fixed the loader boundary those process-lifetime guarantees depend on: one native library image per process, resident until process exit, never unloaded or reloaded as recovery ([P7-D-002](decisions.md#p7-d-002--native-library-residency-and-loader-lifetime), [evidence](#p711-evidence)). P7.2 brought real core state across the ABI: opaque authority handles owned by the runtime, register, release, and status around `TrustedAuthority`, a cascading runtime destroy, and one explicit mapping of every core error ([P7-D-003](decisions.md#p7-d-003--authority-handles-ownership-and-lifecycle), [P7-D-004](decisions.md#p7-d-004--stable-core-error-mapping), [evidence](#p72-evidence)). The P6-D-004 handoff is now **REAL CORE PANIC CONTAINMENT COMPLETE; CONSUMED-ACCOUNTING PRESERVATION EVIDENCE REMAINS FOR A LATER CEREMONY INCREMENT**: a real panic inside `TrustedAuthority::register`, reached through `sas_pairing_authority_register`, is contained with both payload kinds, but no ABI operation consumes an opportunity yet. P7.3 fixed the hosting hierarchy before any networking: opaque host handles, each a runtime-owned hosting context that records its parent authority and owns one real core `Router` in a `Box<Router>`, several hosts per authority sharing its accounting, host create and destroy, and cascades on authority release and runtime destroy ([P7-D-005](decisions.md#p7-d-005--hosting-context-ownership-and-router-lifetime), [evidence](#p73-evidence)). Now: P7.4 — Windows Listener Ownership + Owner-Loop Lifetime Bridge ([P7-D-006](decisions.md#p7-d-006--windows-listener-ownership-and-responder-configuration), [P7-D-007](decisions.md#p7-d-007--owner-loop--router-lifetime-bridge), contract [§17](abi-contract.md#17-windows-listener-ownership)), narrowed from the earlier "listener + owner loop + bounded drive/event" scope; then P7.5 — Bounded Network Drive + Connection/Run/Event/Result ABI. P7 must not be marked complete before every [completion gate](#completion-gates) holds.

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
| P7.4 | Windows listener ownership + owner-loop lifetime bridge: ownership transfer of a caller-bound listening socket through an in/out slot, the Responder Bootstrap views, the one contained `WindowsOwnerLoop<'static>` → boxed Router lifetime extension, attach/detach/replacement, cleanup order on every path, panic and ownership-transfer safety; [P7-D-006](decisions.md#p7-d-006--windows-listener-ownership-and-responder-configuration), [P7-D-007](decisions.md#p7-d-007--owner-loop--router-lifetime-bridge). Narrowed: `drive_once` events carry `ConnectionRef`s, `RunRef`s, `TcpEvent`s, and one-shot `PairingResult`s that no ABI call may drop, so driving waits for their representation (P7.5) | In progress: decisions and contract defined |
| P7.5 | Bounded network drive + connection/run/event/result ABI: the `drive_once` export, a bounded event array, opaque connection and run handles and their invalidation, lossless `PairingResult` delivery, `TcpEvent`/`OwnerEvent` representation, the `OwnerLoopError`/`TcpError`/`HostError`/`RouteError` translation, `recheck_after_resume`, and confirmation that outbound bytes stay adapter-owned | Planned |
| Later | Ceremony start (Initiator/Responder), SAS presentation, local authorization, MATCH/REJECT, results (P6-D-005), the consumed-accounting part of the P6-D-004 exit test, final header, P7 closure | Planned |

## Mandatory P6 handoff

| Obligation | Source | State |
|---|---|---|
| Every export runs inside a Rust `catch_unwind` boundary; no panic crosses `extern "C"`; no `C-unwind` | P6-D-004 items 3–4 | P7.1: one central dispatcher; P7.2: all six exports use it; P7.3: all eight (source-scan test) |
| Caught panic → permanent fatal state; later operations return the fatal error without entering the core | P6-D-004 item 5 | P7.1: process-wide fatal unit (P7-D-001); create refuses after fatal. P7.2: register and status refuse after fatal before any handle check, with a test-only core-entry counter showing no re-entry. P7.3: host create refuses after fatal without cloning an executor or building a router (test-only per-thread construction counter); a panic right after the real `Router::new` is contained with both payload kinds |
| Payload destructor never runs; mark fatal → suppress destruction → return the fatal error; no payload inspection | P6-D-004 item 14 (P6.4.1) | P7.1: implemented and tested with a Drop-panicking payload |
| Fatal handle stays destroyable; destroy never reactivates or resets | P6-D-004 item 7 | P7.1: runtime handle. P7.2: authority release and the cascading runtime destroy stay allowed as cleanup after fatal and never clear it. P7.3: host destroy is cleanup too |
| Stable fatal error distinct from ordinary errors, carrying no payload data | P6-D-004 items 8–9 | P7.1: `SAS_PAIRING_FATAL = 900` |
| Unwind-compatible supported artifact, pinned and checked in CI | P6-D-004 item 12 | P7.1: `[profile.release] panic = "unwind"`, `compile_error!` guard, negative CI check |
| Rust-owned thread roots contained | P6-D-004 item 11 | Not applicable yet: P7.1 starts no thread |
| Real core panic → ABI fatal → host survives → next operation fatal without core re-entry → no fresh accounting → destroy works (ordinary and Drop-panicking payloads) | P6-D-004 item 13; P7 exit criteria | **REAL CORE PANIC CONTAINMENT COMPLETE (P7.2); CONSUMED-ACCOUNTING PRESERVATION EVIDENCE REMAINS FOR A LATER CEREMONY INCREMENT.** A panic inside `TrustedAuthority::register`, reached through `sas_pairing_authority_register`, is caught in Rust with an ordinary and a `PanicOnDrop` payload: fatal, `FATAL`, host alive, payload destructor never run, no core re-entry, cleanup allowed, no fresh accounting through the ABI. Not yet shown: a panic during an ABI operation that itself consumed an opportunity, because no ceremony export exists ([details](#p72-evidence)) |
| No same-process accounting reset through any ABI path | P6-D-002 | P7.2: release, re-registration, runtime destroy, and a new runtime keep the same process session, budget, and exhaustion (opportunities spent through the core's own reserve path in tests); a fatal process cannot register again. P7.3: host creation and destruction, and release or runtime destroy with live hosts, change no budget, guard, or session |
| Loader lifetime invariant established before authority lifecycle: one native image per process, resident until process exit, no unload/reload or copied image as reset or recovery | P6-D-002, P6-D-004 via [P7-D-002](decisions.md#p7-d-002--native-library-residency-and-loader-lifetime) | P7.1.1: normative in the contract and header; a host obligation, not enforced by the library. P8 and P9 must carry it into their loaders. P7.2: authority process-session accounting now crosses the ABI and depends on it (contract §15.6); still no self-pinning or shared-memory accounting. P7.3: host handles and routers are module state under the same invariant (contract §16.8) |
| Results presented as local verified completion, never a bilateral commit | P6-D-005 | Later increment (result access) |

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
