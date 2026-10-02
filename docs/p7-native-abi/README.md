# P7 Native ABI

> **Pre-alpha. Not production approval.** P7 exposes the frozen experimental protocol candidate through a language-neutral native boundary for the future Dart and .NET wrappers. Nothing here is a professional audit, formal verification, certification, or production-security or release approval.

## Status

**P7 IN PROGRESS — P7.1 ABI FOUNDATION COMPLETE.** P7.1 established the ABI version, type conventions, status namespace, opaque runtime handle, runtime lifecycle, and the central panic containment ([evidence](#p71-evidence)). The P6-D-004 handoff is **PARTIAL / FOUNDATION COMPLETE**: its end-to-end exit test still needs an export that enters the core. Next: P7.2 — Authority Lifecycle + Core Error Mapping. P7 must not be marked complete before every [completion gate](#completion-gates) holds.

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
| Real core panic → ABI fatal → host survives → next operation fatal without core re-entry → no fresh accounting → destroy works (ordinary and Drop-panicking payloads) | P6-D-004 item 13; P7 exit criteria | **Open (PARTIAL / FOUNDATION COMPLETE):** P7.1 proves the primitive, the fatal runtime lifecycle, and payload-destructor suppression at an `extern "C"` seam; the end-to-end test needs an export that enters the core (later increment) |
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
