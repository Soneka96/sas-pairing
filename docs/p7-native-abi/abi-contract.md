# sas-pairing Native ABI Contract — Version 1

> **Pre-alpha, experimental.** This is the language-neutral boundary that the future Dart (P8) and .NET (P9) wrappers call. It wraps the frozen experimental candidate `sas-pairing-vodozemac-profile-draft-01`, version 1, and is not production-security approved.

This document is normative for the native ABI. The C declarations are in [`core/include/sas_pairing.h`](../../core/include/sas_pairing.h), and the Rust implementation is in [`core/src/abi`](../../core/src/abi/mod.rs). The decision behind the runtime and fatal model is [P7-D-001](decisions.md#p7-d-001--native-runtime-handle-and-fatal-containment-unit); the loader invariant it depends on is [P7-D-002](decisions.md#p7-d-002--native-library-residency-and-loader-lifetime) (§14); the authority lifecycle is [P7-D-003](decisions.md#p7-d-003--authority-handles-ownership-and-lifecycle) (§15), and the core error mapping is [P7-D-004](decisions.md#p7-d-004--stable-core-error-mapping) (§3). Wherever this contract says "per OS process" or "for the rest of the process", it means under that invariant. The current contents are the P7.1 foundation (a version query and the runtime lifecycle) and the P7.2 authority lifecycle (register, release, status). No ceremony operation is exposed yet.

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
| `SAS_PAIRING_INVALID_SCOPE` | 100 | Core `InvalidScope`: the scope is empty or longer than the core accepts (`u32::MAX` bytes) |
| `SAS_PAIRING_ALREADY_REGISTERED` | 101 | Core `AlreadyRegistered`: this authority already has an active registration in this process; it is untouched |
| `SAS_PAIRING_OWNERSHIP_UNAVAILABLE` | 102 | Core `OwnershipUnavailable`: the authority's OS ownership could not be acquired (for example another process holds it, or the account's lock location is unusable). Not an authentication result |
| `SAS_PAIRING_UNSUPPORTED_PLATFORM` | 103 | Core `UnsupportedPlatform`: this platform has no supported OS ownership mechanism; nothing was registered |
| `SAS_PAIRING_OWNERSHIP_UNCERTAIN` | 104 | Core `OwnershipUncertain`: ownership or accounting state is uncertain (an uncertain release, poisoned or held state); the core fails closed for that authority until process restart |
| `SAS_PAIRING_BUSY` | 105 | Core `Busy`: the authority is in use (for release: another holder still shares the registration) |
| `SAS_PAIRING_EXHAUSTED` | 106 | Core `Exhausted`: the authority's opportunity budget for this process session is spent. Not a protocol rejection |
| `SAS_PAIRING_RESOURCE_LIMITED` | 107 | Core `ResourceLimited`: a generic pre-exposure resource or admission refusal; says nothing about authentication, SAS, compromise, or the budget, and spends or refunds no opportunity |
| `SAS_PAIRING_MISSING_AUTHORIZATION` | 200 | Core `MissingAuthorization`: a reservation was attempted without local authorization |
| `SAS_PAIRING_STALE_AUTHORIZATION` | 201 | Core `StaleAuthorization`: the authorization or ceremony does not belong to this exact ceremony and authority |
| `SAS_PAIRING_TERMINATED` | 202 | Core `Terminated`: the ceremony is already terminal |
| `SAS_PAIRING_FATAL` | 900 | A Rust panic was contained; the native ABI state of this process is permanently fatal (§6) |

**Core error mapping (P7-D-004).** Every core `Error` variant has exactly one ABI value above (100–107, 200–202), assigned by one exhaustive, wildcard-free mapping (`abi::status::map_core_error`); a new core variant does not compile until P7 assigns it a value. The ABI translates and never reinterprets: each meaning is the reviewed core's. The 200-range values are frozen now for exhaustiveness; no P7.2 export returns them.

Reserved ranges for later increments:

| Range | Use |
|---|---|
| 1–99 | ABI, lifecycle, and argument errors |
| 100–199 | Authority, resource, and core errors |
| 200–299 | Ceremony and protocol errors |
| 300–399 | Buffer and data-result errors |
| 900–999 | Fatal and internal errors |

The core's Rust `Error` discriminants are never exposed directly. Wrappers must treat every non-zero value as failure, including values they do not recognize. `SAS_PAIRING_FATAL` is distinct from every ordinary error (P6-D-004 item 8).

## 4. Handles

- `typedef uint64_t sas_pairing_runtime_t;` and `typedef uint64_t sas_pairing_authority_t;`. `0` (`SAS_PAIRING_RUNTIME_INVALID`, `SAS_PAIRING_AUTHORITY_INVALID`) is never a valid handle.
- Handles are opaque and process-local. They are not pointers, network identities, security secrets, authority identities, or reusable protocol identifiers, and must not be persisted, sent to peers, or used as trust material.
- Every handle kind (runtimes, authorities, and later ceremonies) comes from one shared counter that starts at `1` and only increases (P7-D-003). Each value is issued once, to one kind, so a handle of one kind presented as another names nothing (`SAS_PAIRING_INVALID_HANDLE`). Under the loader invariant (§14) the counter lives as long as the OS process, so a value is issued at most once per OS process, a destroyed or released (stale) handle never aliases a later object, and using one returns `SAS_PAIRING_INVALID_HANDLE` forever: create H1, destroy H1, create H2 gives H2 ≠ H1. The counter is module state; a host that unloads the library or loads another image of it gets a new counter, and no uniqueness is promised across images.
- After `UINT64_MAX` has been issued, creation and registration return `SAS_PAIRING_HANDLES_EXHAUSTED` for the rest of the process. The counter never wraps or resets.
- A value reserved for an operation that then fails (§15.2) is burned: it is never issued.

## 5. Runtime lifecycle

At most one runtime is active per OS process ([P7-D-001](decisions.md#p7-d-001--native-runtime-handle-and-fatal-containment-unit)), under the loader invariant (§14). The single-runtime slot is module state: a second, independently loaded image of the library would have its own, which is why loading one is unsupported.

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
| Valid live handle | The handle is invalidated first (and with it every authority handle the runtime owns), then the runtime is destroyed best-effort, releasing its authorities (§15.5); `SAS_PAIRING_OK` |
| `0`, unknown, random, or already destroyed handle | `SAS_PAIRING_INVALID_HANDLE` |
| Valid handle while the process is fatal | Allowed: `SAS_PAIRING_OK` (fatal state stays set) |
| A panic is caught | `SAS_PAIRING_FATAL`; the process becomes fatal |

After a successful destroy the handle is invalid forever, and a later create (outside the fatal state) returns a different handle. Concurrent destroys of one live handle succeed exactly once.

## 6. Fatal semantics

A caught Rust panic in any export makes the native ABI state of the process permanently fatal (P6-D-004, P7-D-001):

- every later `sas_pairing_runtime_create`, `sas_pairing_authority_register`, and `sas_pairing_authority_status` returns `SAS_PAIRING_FATAL` without entering the core, as will every normal operation added later;
- an existing runtime stays destroyable and its authorities releasable (cleanup), and cleanup never clears the fatal state;
- nothing resets it: there is no clear, reset, or re-initialize API, and destroying and re-creating gives no fresh state or accounting (P6-D-002);
- the only recovery is a new OS process. Unloading and reloading the library, or loading another copy of it, is not recovery: it leaves the supported contract (§14) and is not process replacement (P6-D-004).

Fatal is permanent for the OS process under the loader invariant (§14). The marker is module state like the rest of the ABI state, so the library does not claim that it survives an unsupported unload; it claims that a supported host never unloads it.

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
- byte inputs (pointer plus length) are checked before any slice is formed: a null pointer with a non-zero length, a length above `PTRDIFF_MAX` (`isize::MAX`), a range that wraps the address space, or a range overlapping an output slot of the same call gives `SAS_PAIRING_INVALID_ARGUMENT`; a zero length never dereferences the pointer, which may then be null; input bytes are copied or consumed during the call and never retained;
- handles are checked, and zero, stale, unknown, and random handles fail with `SAS_PAIRING_INVALID_HANDLE`;
- no Rust panic crosses the boundary;
- no Rust-owned state or object pointer becomes a foreign pointer.

The caller must guarantee that:

- every non-null pointer it passes really refers to the documented amount of accessible caller-owned memory (writable for outputs) for the whole call;
- no other thread reads or mutates that memory against the documented contract during the call.

Rust cannot validate an arbitrary non-null address, so an invalid one is undefined behavior, as in any C ABI. Wrappers are trusted local callers of this boundary; it is not a sandbox against hostile in-process code. The caller also keeps the loader invariant of §14.

## 9. Memory ownership

The ABI never transfers ownership of a Rust heap allocation to the caller. Frozen for every later increment:

- variable input is passed as a pointer plus an explicit length;
- variable output goes into a caller-owned buffer with an explicit capacity and an explicit required or written length;
- no API makes foreign code free a `Vec` or `String`, drop a `Box`, or know anything about Rust's allocator.

## 10. Strings and bytes

Protocol and application data (identities, scopes, contexts, bootstrap values) are bytes, not implicit C strings. They cross the ABI as bytes plus length, never as NUL-terminated `char *`, and are compared exactly as bytes.

## 11. Threading

Every export is safe to call concurrently from any threads: concurrent creates admit exactly one runtime, concurrent valid, stale, or random destroys never race into undefined behavior, and authority operations serialize with runtime destruction as §15.7 defines. The library starts no thread. Host requirement: the library stays loaded for the rest of the process once stateful use begins (§14), so no thread may unload it, including after `SAS_PAIRING_FATAL`. Ceremony and network operations, when added, define their own interaction with destroy while keeping §15.7.

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
- State that must last for the OS process (handles, fatal state, and from P7.2 authority accounting) relies on the loader invariant (§14). No export may unload, reload, reset, or re-initialize the library or its state, and none may offer a way around §14.
- An incompatible change requires a new ABI version, an owner decision, and an updated header.

## 14. Native-library loading and residency

Normative ([P7-D-002](decisions.md#p7-d-002--native-library-residency-and-loader-lifetime)). The ABI state (handle counter, runtime slot, fatal marker) and, since P7.2, the core's authority registry and process-session accounting it reaches (`REGISTRY`, the opportunity budget, the START limiter and its clock) are module state of the loaded library image: it begins when the image is loaded and ends when it is unloaded. It has OS-process lifetime only because a supported host follows these rules:

1. **One image.** Exactly one sas-pairing native library image is loaded per OS process. The host does not load an independent copy (another path, filename, copy, or rename).
2. **Resident until process exit.** Stateful use begins no later than the first `sas_pairing_runtime_create`. From then on the image stays loaded until the OS process terminates, and the host keeps its load of the library (module handle or library object) for the whole process.
3. **No unload or reload.** The host does not unload the image after stateful use (`FreeLibrary`, `dlclose`, `NativeLibrary.Free`, or a wrapper close or reset), and does not reload it or load an alternate image to obtain fresh state.
4. **Recovery is process restart.** After `SAS_PAIRING_FATAL`, the only supported recovery is a new OS process (P6-D-004). A library reload is not process replacement.

Guarantees and their scope:

| Guarantee | Under the invariant | If a host breaks it |
|---|---|---|
| Handle values never reused (§4) | For the OS-process lifetime | Not promised across images: a reload restarts the counter, and each copy has its own |
| At most one active runtime (§5) | Per OS process | Each image has its own runtime slot |
| Fatal is permanent (§6) | For the OS-process lifetime | A new image starts without the fatal marker; that is unsupported, not recovery |
| No fresh authority accounting in the same process (P6-D-002; authorities cross the ABI since P7.2) | Holds: no supported path (release, re-registration, runtime destroy, a new runtime) re-creates the opportunity budget, START limiter, limiter clock, or process session (§15.6) | A new image has new module state; this is outside the supported security contract |

**Trusted host.** The library does not detect, prevent, or report a duplicate image or an unload; there is no status code for it, and it does not pin itself. Code with arbitrary control over the process's loader is outside what the ABI protects against, as is any other hostile in-process code (§8). A host that breaks these rules is outside the supported security contract; what it gets is not a supported reset.

**Wrappers.** The Dart wrapper (P8) and the .NET wrapper (P9) load the library once, keep it loaded for the process lifetime, expose no close, unload, reload, or reset operation, load no alternate copy, and tell their consumers that process restart is the recovery from `SAS_PAIRING_FATAL`.

## 15. Authorities

Normative ([P7-D-003](decisions.md#p7-d-003--authority-handles-ownership-and-lifecycle)). An authority is one canonical pairing scope registered with the reviewed core (`TrustedAuthority`) through a runtime. The ABI wraps the core's semantics and does not redefine them.

**The critical distinction.** An *authority handle* names one ABI object lifetime: one active registration, holding the authority's OS lease, owned by one runtime. The authority's *process session* (its opportunity budget, START limiter and limiter clock, and registration state, in the core's process-wide registry, P6-D-002) is a different and longer lifetime: it begins with the first successful OS ownership of that canonical authority in this OS process and ends only when the process ends. Release, re-registration, runtime destroy, and a new runtime end or begin handles and registrations; none of them ends or refreshes a process session. A new handle never means a new security session.

### 15.1 Types

| Item | Value |
|---|---|
| Handle | `typedef uint64_t sas_pairing_authority_t;` `SAS_PAIRING_AUTHORITY_INVALID = 0` is never valid. Same rules as §4, from the same counter |
| State | `typedef uint32_t sas_pairing_authority_state_t;` `SAS_PAIRING_AUTHORITY_STATE_INVALID = 0`, `SAS_PAIRING_AUTHORITY_READY = 1`, `SAS_PAIRING_AUTHORITY_BUSY = 2`, `SAS_PAIRING_AUTHORITY_EXHAUSTED = 3`. Fixed values; the Rust `Status` layout is never exposed. Wrappers treat an unknown value as not ready |

### 15.2 Registration

**`sas_pairing_status_t sas_pairing_authority_register(sas_pairing_runtime_t runtime, const uint8_t *scope, size_t scope_len, sas_pairing_authority_t *out_authority)`**

`scope` is bytes plus length, never a C string (§10). The core copies it into the canonical identity; the ABI retains neither the pointer nor the bytes after return.

| Order | Condition | Result | `*out_authority` |
|---:|---|---|---|
| 1 | `out_authority` null or misaligned; `scope` null with `scope_len > 0`; `scope_len > PTRDIFF_MAX`; the scope range wraps the address space or overlaps `*out_authority` | `SAS_PAIRING_INVALID_ARGUMENT` | not written |
| 2 | Otherwise the output is set to `0` | | `0` |
| 3 | Process fatal | `SAS_PAIRING_FATAL`, the core is not entered | `0` |
| 4 | `runtime` is `0`, unknown, or destroyed (or any other kind of handle) | `SAS_PAIRING_INVALID_HANDLE` | `0` |
| 5 | Handle space exhausted | `SAS_PAIRING_HANDLES_EXHAUSTED`, the core is not entered | `0` |
| 6 | The core rejects the registration | its mapped error (§3): `INVALID_SCOPE` (also for `scope_len == 0`, where `scope` is never read and may be null), `ALREADY_REGISTERED`, `OWNERSHIP_UNAVAILABLE`, `OWNERSHIP_UNCERTAIN`, `UNSUPPORTED_PLATFORM` | `0` |
| 7 | Registered | `SAS_PAIRING_OK` | the new non-zero handle |
| — | A panic is caught | `SAS_PAIRING_FATAL`; the process becomes fatal | `0` |

The handle value is reserved at step 5, before the core is entered, so a successful core registration always receives a handle. When step 6 fails, the reserved value is burned (never issued); that consumes no opportunity, resets no accounting, and creates no handle, and the core's own error is returned. Platform edge: lengths above `PTRDIFF_MAX` are rejected by the ABI because no slice can describe them; on 64-bit platforms, lengths between `UINT32_MAX + 1` and `PTRDIFF_MAX` reach the core, which returns `INVALID_SCOPE` without reading the bytes (the caller must still describe readable memory, §8). On 32-bit platforms every length the core could reject as too long is above `PTRDIFF_MAX` and gives `INVALID_ARGUMENT`.

The core decides ownership: one active registration per canonical authority per process (`ALREADY_REGISTERED` otherwise, including under concurrent registrations, where exactly one wins), OS ownership excluding other processes (`OWNERSHIP_UNAVAILABLE`), and fail-closed after an uncertain release (`OWNERSHIP_UNCERTAIN`). On a platform without supported ownership, a valid scope reaches the core and gives `UNSUPPORTED_PLATFORM`; nothing is faked. Registering an authority whose process session already exists (after a release in this process) reacquires the OS lease and continues that session's budget and START limiter under a new handle.

### 15.3 Release

**`sas_pairing_status_t sas_pairing_authority_release(sas_pairing_runtime_t runtime, sas_pairing_authority_t authority)`**

| Condition | Result |
|---|---|
| `runtime` invalid, or `authority` `0`, unknown, released, of another kind, or owned by no live runtime | `SAS_PAIRING_INVALID_HANDLE` |
| Valid | The handle is removed from the runtime **first**, then the core's explicit release runs: `SAS_PAIRING_OK`, or its mapped error (`BUSY` while another holder shares the registration, which then ends when that holder goes; `OWNERSHIP_UNCERTAIN` when the lease release is uncertain, after which this authority's registration fails closed until process restart) |
| Process fatal | Allowed, as cleanup (like runtime destroy); same results |
| A panic is caught | `SAS_PAIRING_FATAL`; the process becomes fatal |

After the call returns, the handle is invalid forever, whatever the result. A failed release never restores it and never creates a replacement handle. Release ends only the registration and its OS lease; it does not end process-session accounting, reset the START limiter or the budget, permit a library unload or reload, or reset the ABI.

### 15.4 Status

**`sas_pairing_status_t sas_pairing_authority_status(sas_pairing_runtime_t runtime, sas_pairing_authority_t authority, sas_pairing_authority_state_t *out_state, uint32_t *out_remaining)`**

Both outputs must be distinct, aligned, writable slots. If either is null or misaligned, or both are the same slot: `SAS_PAIRING_INVALID_ARGUMENT`, nothing written. Otherwise both are set to `INVALID` and `0` first. Then: fatal → `SAS_PAIRING_FATAL`; invalid runtime or authority handle → `SAS_PAIRING_INVALID_HANDLE`; a core error (for example `OWNERSHIP_UNCERTAIN` on poisoned accounting) → its mapped value. Every failure leaves `INVALID` and `0`. On `SAS_PAIRING_OK` the core's own status is translated:

| Core status | `*out_state` | `*out_remaining` |
|---|---|---|
| `Ready { remaining }` | `READY` | `remaining` (1–10) |
| `Busy` (an exposed ceremony holds the guard) | `BUSY` | `0` |
| `Exhausted` | `EXHAUSTED` | `0` |

### 15.5 Ownership and runtime destroy

The runtime is the owning root: it owns its authorities as real core objects (no pointers cross the boundary), and one runtime may own several authorities for different canonical scopes. `sas_pairing_runtime_destroy` cascades: it invalidates the runtime handle and, with it, every authority handle the runtime owns, then releases those authorities through the core's own drop path, best-effort (an uncertain lease release is recorded by the core and fails that authority closed, as for an explicit release), and returns as in §5. Callers need not release authorities first. After destroy returns, no authority handle of that runtime is valid, and none aliases anything in a later runtime. Destroy is cleanup only: it never resets fatal state, creates accounting, or does ceremony work. A panic during destroy is contained (fatal, `SAS_PAIRING_FATAL`) and the runtime is never reinserted.

### 15.6 Process-session persistence

Register S → H1, release H1, register S → H2 gives H2 ≠ H1 and **the same process session**: the same opportunity budget (a spent opportunity stays spent, `EXHAUSTED` stays exhausted), the same START limiter and clock. The same holds across runtime destroy and a new runtime. Only a new OS process that safely acquires ownership starts a fresh process session (P6-D-002). This depends on the loader invariant (§14): under supported use one native image stays resident for the process, so the registry, budget, and limiter history cannot be recreated through any supported loader operation. The library does not claim to stop hostile in-process code from violating §14.

### 15.7 Fatal state and concurrency

Register and status are normal operations: after fatal they return `SAS_PAIRING_FATAL` without entering the core. Release and runtime destroy are cleanup and stay allowed; cleanup never clears fatal, creates an authority, or refreshes accounting.

Validation precedence for normal authority calls is fixed: (1) raw-memory and structural argument checks, (2) output slots set to their invalid values, (3) the process fatal state, (4) the runtime handle, (5) the authority handle where applicable, (6) the core, (7) the mapped core result. Raw-memory errors are never overridden by core errors. Release skips (3).

Runtime destruction serializes with authority operations. A call admitted against a live runtime finishes before destroy proceeds; once destroy has begun, no new authority operation is admitted (`SAS_PAIRING_INVALID_HANDLE`). Allowed outcomes of races:

| Race | Outcomes |
|---|---|
| register vs runtime destroy | register first: `OK`, then destroy invalidates and releases the new authority; destroy first: `INVALID_HANDLE` with output `0` |
| release vs runtime destroy | exactly one of them ends the authority: release `OK` then destroy `OK`, or destroy `OK` then release `INVALID_HANDLE` |
| status vs release | status `OK` with the live state, then release `OK`; or release `OK`, then status `INVALID_HANDLE` |
| register vs register, same scope | exactly one `OK`; the others `ALREADY_REGISTERED` with output `0` |
| register vs register, different scopes | each `OK` with distinct handles, where platform ownership permits |

No interleaving gives a use-after-free, an authority surviving its runtime, two live handles for one canonical authority, or a deadlock.
