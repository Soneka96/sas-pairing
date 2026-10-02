# sas-pairing Native ABI Contract — Version 1

> **Pre-alpha, experimental.** This is the language-neutral boundary that the future Dart (P8) and .NET (P9) wrappers call. It wraps the frozen experimental candidate `sas-pairing-vodozemac-profile-draft-01`, version 1, and is not production-security approved.

This document is normative for the native ABI. The C declarations are in [`core/include/sas_pairing.h`](../../core/include/sas_pairing.h), and the Rust implementation is in [`core/src/abi`](../../core/src/abi/mod.rs). The decision behind the runtime and fatal model is [P7-D-001](decisions.md#p7-d-001--native-runtime-handle-and-fatal-containment-unit). The current contents are the P7.1 foundation: a version query and the runtime lifecycle. No pairing operation is exposed yet.

## 1. ABI version

| Item | Value |
|---|---|
| Export | `uint32_t sas_pairing_abi_version(void)` |
| Current ABI version | `1` (`SAS_PAIRING_ABI_VERSION`) |
| Reserved invalid value | `0` (`SAS_PAIRING_ABI_VERSION_INVALID`): returned only if the query itself caught a panic, and never a successful version |

The ABI version, the protocol profile version, and the crate version are separate concepts. The protocol is still `sas-pairing-vodozemac-profile-draft-01` with profile version `1`, and the crate is `sas-pairing-core 0.1.0`. That the ABI version is also `1` is a coincidence and does not tie them together. Within ABI version 1, later P7 increments add exports, status codes, and handle kinds; existing values and signatures are never changed or reused.

## 2. Type rules

Only stable, language-neutral representations cross the ABI:

- `uint8_t`, `uint32_t`, `uint64_t`, and `int32_t` for contract values; `size_t` only where a host-memory length needs it;
- raw pointers to caller-owned memory, with explicit lengths where the size is variable.

Never exposed: Rust `bool`, Rust enum layout, `String`, `Vec`, slices, `Result`, `Option`, references, `Box`, `Arc`, trait objects, or any Rust object pointer. Truth values, when needed later, use fixed-width integers with documented values.

## 3. Status codes

ABI operations that can fail return `sas_pairing_status_t` (`int32_t`). The values below are frozen and never renumbered or reused:

| Name | Value | Meaning |
|---|---:|---|
| `SAS_PAIRING_OK` | 0 | Success |
| `SAS_PAIRING_INVALID_ARGUMENT` | 1 | A required pointer was null or misaligned; nothing was written through it |
| `SAS_PAIRING_INVALID_HANDLE` | 2 | The handle is `0`, unknown, or already destroyed |
| `SAS_PAIRING_ALREADY_INITIALIZED` | 3 | A runtime is already active in this process; it was not replaced |
| `SAS_PAIRING_HANDLES_EXHAUSTED` | 4 | The process has issued every handle value; no handle is ever reused (§4) |
| `SAS_PAIRING_FATAL` | 900 | A Rust panic was contained; the native ABI state of this process is permanently fatal (§6) |

Reserved ranges for later increments:

| Range | Use |
|---|---|
| 1–99 | ABI, lifecycle, and argument errors |
| 100–199 | Authority, resource, and core errors |
| 200–299 | Ceremony and protocol errors |
| 300–399 | Buffer and data-result errors |
| 900–999 | Fatal and internal errors |

The core's Rust `Error` discriminants are never exposed directly; later increments map each core error to an explicit ABI value. Wrappers must treat every non-zero value as failure, including values they do not recognize. `SAS_PAIRING_FATAL` is distinct from every ordinary error (P6-D-004 item 8).

## 4. Handles

- `typedef uint64_t sas_pairing_runtime_t;` `0` (`SAS_PAIRING_RUNTIME_INVALID`) is never a valid handle.
- Handles are opaque and process-local. They are not pointers, network identities, security secrets, authority identities, or reusable protocol identifiers, and must not be persisted, sent to peers, or used as trust material.
- Handles come from one process-lifetime counter that starts at `1` and only increases. A value is issued at most once per OS process, so a destroyed (stale) handle never aliases a later runtime, and using one returns `SAS_PAIRING_INVALID_HANDLE` forever.
- After `UINT64_MAX` has been issued, creation returns `SAS_PAIRING_HANDLES_EXHAUSTED` for the rest of the process. The counter never wraps or resets.
- Later handle kinds (authorities, ceremonies) follow the same rules; whether they share this counter is decided when they are added.

## 5. Runtime lifecycle

At most one runtime is active per OS process ([P7-D-001](decisions.md#p7-d-001--native-runtime-handle-and-fatal-containment-unit)).

**`sas_pairing_status_t sas_pairing_runtime_create(sas_pairing_runtime_t *out_runtime)`**

| Condition | Result | `*out_runtime` |
|---|---|---|
| `out_runtime` null or misaligned | `SAS_PAIRING_INVALID_ARGUMENT` | not written |
| Process fatal | `SAS_PAIRING_FATAL` | `0` |
| A runtime is already active | `SAS_PAIRING_ALREADY_INITIALIZED`; the active runtime is untouched | `0` |
| Handle space exhausted | `SAS_PAIRING_HANDLES_EXHAUSTED` | `0` |
| Otherwise | `SAS_PAIRING_OK` | the new non-zero handle |
| A panic is caught | `SAS_PAIRING_FATAL`; the process becomes fatal | `0` |

The output slot is set to `0` on entry and receives a handle only once creation has fully succeeded. Creation is native infrastructure only: it registers no authority, takes no OS lock, consumes no opportunity, starts no listener, creates no ceremony, and generates no protocol randomness. Concurrent creates from many threads admit exactly one runtime; the others return `SAS_PAIRING_ALREADY_INITIALIZED`.

**`sas_pairing_status_t sas_pairing_runtime_destroy(sas_pairing_runtime_t runtime)`**

| Condition | Result |
|---|---|
| Valid live handle | The handle is invalidated first, then the runtime is destroyed best-effort; `SAS_PAIRING_OK` |
| `0`, unknown, random, or already destroyed handle | `SAS_PAIRING_INVALID_HANDLE` |
| Valid handle while the process is fatal | Allowed: `SAS_PAIRING_OK` (fatal state stays set) |
| A panic is caught | `SAS_PAIRING_FATAL`; the process becomes fatal |

After a successful destroy the handle is invalid forever, and a later create (outside the fatal state) returns a different handle. Concurrent destroys of one live handle succeed exactly once.

## 6. Fatal semantics

A caught Rust panic in any export makes the native ABI state of the process permanently fatal (P6-D-004, P7-D-001):

- every later `sas_pairing_runtime_create` returns `SAS_PAIRING_FATAL`, and every later normal operation added by later increments returns it without entering the core;
- an existing runtime stays destroyable, and destroy never clears the fatal state;
- nothing resets it: there is no clear, reset, or re-initialize API, and destroying and re-creating gives no fresh state or accounting (P6-D-002);
- the only recovery is a new OS process.

`sas_pairing_abi_version` keeps returning `1` in the fatal state: it reads a constant and enters neither a runtime nor the core, so a wrapper can always identify the library. Fatal state is reported by every status-returning operation.

## 7. Panic containment

Every export runs its Rust work inside one central containment boundary (`abi::dispatch` → `panic_boundary::contain`). No Rust panic or unwind crosses `extern "C"`; foreign callers are never expected to catch one, and `extern "C-unwind"` is not used. On a caught panic, in this order:

1. the process fatal marker is set: a single atomic store that does not allocate, lock, or panic, and does not depend on a mutex the panic may have poisoned;
2. the panic payload's destructor is suppressed (`std::mem::forget`): it is never dropped, downcast, formatted, inspected, or returned (P6.4.1), because dropping it could panic again outside the boundary and abort the host;
3. the stable fallback is returned: `SAS_PAIRING_FATAL` for status-returning exports, `0` for `sas_pairing_abi_version`.

The leaked payload is bounded by the number of fatal events and reclaimed at process exit. The library installs no panic hook. This covers unwinding panics that reach the boundary; aborting failures, memory corruption, and arbitrary process corruption are outside what containment claims. P7.1 has no Rust-owned threads; when later increments add one, its thread root needs the same containment (P6-D-004 item 11).

## 8. Pointer and trust boundary

The library guarantees that:

- required pointers that are null (or misaligned for their type) are rejected with `SAS_PAIRING_INVALID_ARGUMENT` and never written through;
- handles are checked, and zero, stale, unknown, and random handles fail with `SAS_PAIRING_INVALID_HANDLE`;
- no Rust panic crosses the boundary;
- no Rust-owned state or object pointer becomes a foreign pointer.

The caller must guarantee that:

- every non-null pointer it passes really refers to the documented amount of accessible caller-owned memory (writable for outputs) for the whole call;
- no other thread reads or mutates that memory against the documented contract during the call.

Rust cannot validate an arbitrary non-null address, so an invalid one is undefined behavior, as in any C ABI. Wrappers are trusted local callers of this boundary; it is not a sandbox against hostile in-process code.

## 9. Memory ownership

The ABI never transfers ownership of a Rust heap allocation to the caller. Frozen for every later increment:

- variable input is passed as a pointer plus an explicit length;
- variable output goes into a caller-owned buffer with an explicit capacity and an explicit required or written length;
- no API makes foreign code free a `Vec` or `String`, drop a `Box`, or know anything about Rust's allocator.

## 10. Strings and bytes

Protocol and application data (identities, scopes, contexts, bootstrap values) are bytes, not implicit C strings. They cross the ABI as bytes plus length, never as NUL-terminated `char *`, and are compared exactly as bytes.

## 11. Threading

The P7.1 exports are safe to call concurrently from any threads: concurrent creates admit exactly one runtime, and concurrent valid, stale, or random destroys never race into undefined behavior. The library starts no thread. What happens when the only runtime is destroyed while a protocol operation is still in progress will be fixed precisely by the increment that adds protocol operations.

## 12. Supported build

```text
cargo build --manifest-path core/Cargo.toml --release --features native-abi
```

| Platform | Artifact |
|---|---|
| Windows (MSVC) | `core/target/release/sas_pairing_core.dll`, import library `sas_pairing_core.dll.lib` |
| Linux | `core/target/release/libsas_pairing_core.so` (compiles; this does not claim platform support, and pairing operations added later still fail closed on unsupported platforms) |

The crate builds both `rlib` (the Rust library used by the tests and tools) and `cdylib`. Exports exist only with the `native-abi` feature; an ordinary build exports no ABI symbols. The supported artifact uses `panic = "unwind"` (`[profile.release]`), and the `native-abi` module refuses to compile under `panic = "abort"` (a `compile_error!` on `not(panic = "unwind")`), so a profile or `RUSTFLAGS` override cannot silently produce an artifact that claims containment it cannot provide.

## 13. Extension rules

- New exports, status codes, and handle kinds may be added within ABI version 1; existing names, values, and signatures never change, and retired values are never reused.
- Every new export goes through `abi::dispatch`, is declared in the header, and is covered by the header consistency test.
- A new export that enters the core first checks the fatal state and returns `SAS_PAIRING_FATAL` without entering the core.
- Core errors are mapped explicitly into the reserved ranges, never by exposing Rust discriminants.
- Data follows §9 and §10. No callbacks or Rust-owned threads are added without the P6-D-004 thread-root containment.
- An incompatible change requires a new ABI version, an owner decision, and an updated header.
