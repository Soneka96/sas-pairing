# sas-pairing Native ABI Contract — Version 1

> **Pre-alpha, experimental.** This is the language-neutral boundary that the future Dart (P8) and .NET (P9) wrappers call. It wraps the frozen experimental candidate `sas-pairing-vodozemac-profile-draft-01`, version 1, and is not production-security approved.

This document is normative for the native ABI. The C declarations are in [`core/include/sas_pairing.h`](../../core/include/sas_pairing.h), and the Rust implementation is in [`core/src/abi`](../../core/src/abi/mod.rs). The decision behind the runtime and fatal model is [P7-D-001](decisions.md#p7-d-001--native-runtime-handle-and-fatal-containment-unit); the loader invariant it depends on is [P7-D-002](decisions.md#p7-d-002--native-library-residency-and-loader-lifetime) (§14); the authority lifecycle is [P7-D-003](decisions.md#p7-d-003--authority-handles-ownership-and-lifecycle) (§15), the core error mapping is [P7-D-004](decisions.md#p7-d-004--stable-core-error-mapping) (§3), hosting contexts are [P7-D-005](decisions.md#p7-d-005--hosting-context-ownership-and-router-lifetime) (§16), and Windows listener ownership and the owner-loop lifetime bridge are [P7-D-006](decisions.md#p7-d-006--windows-listener-ownership-and-responder-configuration) and [P7-D-007](decisions.md#p7-d-007--owner-loop--router-lifetime-bridge) (§17). Wherever this contract says "per OS process" or "for the rest of the process", it means under that invariant. The current contents are the P7.1 foundation (a version query and the runtime lifecycle), the P7.2 authority lifecycle (register, release, status), the P7.3 hosting-context foundation (host create and destroy), and P7.4 Windows listener ownership (attach and detach of a caller-bound listener). No network driving, connection, run, event, result, or ceremony operation is exposed yet.

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
| `SAS_PAIRING_INVALID_BOOTSTRAP` | 203 | The supplied trusted-local Bootstrap configuration failed the core's own Bootstrap validation (`Bootstrap::new`); nothing was created (§17.2) |
| `SAS_PAIRING_LISTENER_ALREADY_ATTACHED` | 400 | The host already has a listener; the offered socket was not adopted and stays the caller's (§17.5) |
| `SAS_PAIRING_LISTENER_SETUP_FAILED` | 401 | The adopted listener could not be configured for the owner loop; the library closed it (§17.5) |
| `SAS_PAIRING_FATAL` | 900 | A Rust panic was contained; the native ABI state of this process is permanently fatal (§6) |

**Core error mapping (P7-D-004).** Every core `Error` variant has exactly one ABI value above (100–107, 200–202), assigned by one exhaustive, wildcard-free mapping (`abi::status::map_core_error`); a new core variant does not compile until P7 assigns it a value. The ABI translates and never reinterprets: each meaning is the reviewed core's. The 200–202 values are frozen for exhaustiveness; no export returns them yet. 203 and 400–401 are ABI-level results of listener attach (P7-D-006), not core `Error` translations; P7.5 defines the translation of the owner-loop, TCP, host, and routing errors that driving needs.

Reserved ranges for later increments:

| Range | Use |
|---|---|
| 1–99 | ABI, lifecycle, and argument errors |
| 100–199 | Authority, resource, and core errors |
| 200–299 | Ceremony and protocol errors |
| 300–399 | Buffer and data-result errors |
| 400–499 | Host, listener, and transport-boundary lifecycle |
| 900–999 | Fatal and internal errors |

The core's Rust `Error` discriminants are never exposed directly. Wrappers must treat every non-zero value as failure, including values they do not recognize. `SAS_PAIRING_FATAL` is distinct from every ordinary error (P6-D-004 item 8).

## 4. Handles

- `typedef uint64_t sas_pairing_runtime_t;`, `typedef uint64_t sas_pairing_authority_t;`, and `typedef uint64_t sas_pairing_host_t;`. `0` (`SAS_PAIRING_RUNTIME_INVALID`, `SAS_PAIRING_AUTHORITY_INVALID`, `SAS_PAIRING_HOST_INVALID`) is never a valid handle.
- Handles are opaque and process-local. They are not pointers, network identities, security secrets, authority identities, or reusable protocol identifiers, and must not be persisted, sent to peers, or used as trust material.
- Every handle kind (runtimes, authorities, hosts, and later connections and runs) comes from one shared counter that starts at `1` and only increases (P7-D-003, P7-D-005). Each value is issued once, to one kind, so a handle of one kind presented as another names nothing (`SAS_PAIRING_INVALID_HANDLE`). Under the loader invariant (§14) the counter lives as long as the OS process, so a value is issued at most once per OS process, a destroyed or released (stale) handle never aliases a later object, and using one returns `SAS_PAIRING_INVALID_HANDLE` forever: create H1, destroy H1, create H2 gives H2 ≠ H1. The counter is module state; a host that unloads the library or loads another image of it gets a new counter, and no uniqueness is promised across images.
- After `UINT64_MAX` has been issued, creation and registration (runtime, authority, host) return `SAS_PAIRING_HANDLES_EXHAUSTED` for the rest of the process. The counter never wraps or resets.
- A value reserved for an operation that then fails (§15.2, §16.2) is burned: it is never issued.
- A Windows socket handed to listener attach (`sas_pairing_socket_t`, §17) is an OS resource, not a handle: it never comes from this counter, and no handle is ever derived from a socket value, request ID, router session, or address.

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
| Valid live handle | The handle is invalidated first (and with it every authority and host handle the runtime owns), then the runtime is destroyed best-effort: every host's listener and owner loop first, then its hosts and their routers, then its authorities (§15.5, §16.5, §17.7); `SAS_PAIRING_OK` |
| `0`, unknown, random, or already destroyed handle | `SAS_PAIRING_INVALID_HANDLE` |
| Valid handle while the process is fatal | Allowed: `SAS_PAIRING_OK` (fatal state stays set) |
| A panic is caught | `SAS_PAIRING_FATAL`; the process becomes fatal |

After a successful destroy the handle is invalid forever, and a later create (outside the fatal state) returns a different handle. Concurrent destroys of one live handle succeed exactly once.

## 6. Fatal semantics

A caught Rust panic in any export makes the native ABI state of the process permanently fatal (P6-D-004, P7-D-001):

- every later `sas_pairing_runtime_create`, `sas_pairing_authority_register`, `sas_pairing_authority_status`, `sas_pairing_host_create`, and `sas_pairing_host_attach_windows_listener` returns `SAS_PAIRING_FATAL` without entering the core (attach first runs only its structural, platform, and Bootstrap value checks, §17.8, and never adopts the socket), as will every normal operation added later;
- an existing runtime stays destroyable, its authorities releasable, its hosts destroyable, and their listeners detachable (cleanup), and cleanup never clears the fatal state;
- nothing resets it: there is no clear, reset, or re-initialize API, and destroying and re-creating gives no fresh state or accounting (P6-D-002);
- the only recovery is a new OS process. Unloading and reloading the library, or loading another copy of it, is not recovery: it leaves the supported contract (§14) and is not process replacement (P6-D-004).

Fatal is permanent for the OS process under the loader invariant (§14). The marker is module state like the rest of the ABI state, so the library does not claim that it survives an unsupported unload; it claims that a supported host never unloads it.

`sas_pairing_abi_version` keeps returning `1` in the fatal state: it reads a constant and enters neither a runtime nor the core, so a wrapper can always identify the library. Fatal state is reported by every status-returning operation.

## 7. Panic containment

Every export runs its Rust work inside one central containment boundary (`abi::dispatch` → `panic_boundary::contain`). No Rust panic or unwind crosses `extern "C"`; foreign callers are never expected to catch one, and `extern "C-unwind"` is not used. On a caught panic, in this order:

1. the process fatal marker is set: a single atomic store that does not allocate, lock, or panic, and does not depend on a mutex the panic may have poisoned;
2. the panic payload's destructor is suppressed (`std::mem::forget`): it is never dropped, downcast, formatted, inspected, or returned (P6.4.1), because dropping it could panic again outside the boundary and abort the host;
3. the stable fallback is returned: `SAS_PAIRING_FATAL` for status-returning exports, `0` for `sas_pairing_abi_version`.

The leaked payload is bounded by the number of fatal events and reclaimed at process exit. The library installs no panic hook. This covers unwinding panics that reach the boundary; aborting failures, memory corruption, and arbitrary process corruption are outside what containment claims. The library has no Rust-owned threads (an attached owner loop is cooperative and is not driven yet); when a later increment adds one, its thread root needs the same containment (P6-D-004 item 11).

## 8. Pointer and trust boundary

The library guarantees that:

- required pointers that are null (or misaligned for their type) are rejected with `SAS_PAIRING_INVALID_ARGUMENT` and never written through;
- byte inputs (pointer plus length, including the `sas_pairing_bytes_view_t` fields of §17.2) are checked before any slice is formed: a null pointer with a non-zero length, a length above `PTRDIFF_MAX` (`isize::MAX`), a range that wraps the address space, or a range overlapping an output slot of the same call gives `SAS_PAIRING_INVALID_ARGUMENT`; a zero length never dereferences the pointer, which may then be null; input bytes are copied or consumed during the call and never retained (listener attach copies every input before its only write, §17.4);
- handles are checked, and zero, stale, unknown, and random handles fail with `SAS_PAIRING_INVALID_HANDLE`;
- no Rust panic crosses the boundary;
- no Rust-owned state or object pointer becomes a foreign pointer.

The caller must guarantee that:

- every non-null pointer it passes really refers to the documented amount of accessible caller-owned memory (writable for outputs) for the whole call;
- no other thread reads or mutates that memory against the documented contract during the call.

Rust cannot validate an arbitrary non-null address, so an invalid one is undefined behavior, as in any C ABI. The same holds for a socket value handed to listener attach: it must be one valid, already-bound listening socket the caller owns (§17.3). Wrappers are trusted local callers of this boundary; it is not a sandbox against hostile in-process code. The caller also keeps the loader invariant of §14.

## 9. Memory ownership

The ABI never transfers ownership of a Rust heap allocation to the caller. Frozen for every later increment:

- variable input is passed as a pointer plus an explicit length;
- variable output goes into a caller-owned buffer with an explicit capacity and an explicit required or written length;
- no API makes foreign code free a `Vec` or `String`, drop a `Box`, or know anything about Rust's allocator.

## 10. Strings and bytes

Protocol and application data (identities, scopes, contexts, bootstrap values) are bytes, not implicit C strings. They cross the ABI as bytes plus length, never as NUL-terminated `char *`, and are compared exactly as bytes.

## 11. Threading

Every export is safe to call concurrently from any threads: concurrent creates admit exactly one runtime, concurrent valid, stale, or random destroys never race into undefined behavior, and authority, host, and listener operations serialize with authority release and runtime destruction as §15.7, §16.7, and §17.9 define. The library starts no thread, worker, timer, or callback. Host requirement: the library stays loaded for the rest of the process once stateful use begins (§14), so no thread may unload it, including after `SAS_PAIRING_FATAL`. Ceremony and network operations, when added, define their own interaction with destroy while keeping §15.7.

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
| Valid | Every host of this authority is removed and destroyed (§16.4), the handle is removed from the runtime, and only then does the core's explicit release run: `SAS_PAIRING_OK`, or its mapped error (`BUSY` while another holder shares the registration, which then ends when that holder goes, never because of an ABI-owned host; `OWNERSHIP_UNCERTAIN` when the lease release is uncertain, after which this authority's registration fails closed until process restart) |
| Process fatal | Allowed, as cleanup (like runtime destroy); same results |
| A panic is caught | `SAS_PAIRING_FATAL`; the process becomes fatal |

After the call returns, the handle and every host handle of the authority are invalid forever, whatever the result. A failed release never restores them and never creates a replacement handle. Release ends only the registration and its OS lease; it does not end process-session accounting, reset the START limiter or the budget, permit a library unload or reload, or reset the ABI.

### 15.4 Status

**`sas_pairing_status_t sas_pairing_authority_status(sas_pairing_runtime_t runtime, sas_pairing_authority_t authority, sas_pairing_authority_state_t *out_state, uint32_t *out_remaining)`**

Both outputs must be distinct, aligned, writable slots. If either is null or misaligned, or both are the same slot: `SAS_PAIRING_INVALID_ARGUMENT`, nothing written. Otherwise both are set to `INVALID` and `0` first. Then: fatal → `SAS_PAIRING_FATAL`; invalid runtime or authority handle → `SAS_PAIRING_INVALID_HANDLE`; a core error (for example `OWNERSHIP_UNCERTAIN` on poisoned accounting) → its mapped value. Every failure leaves `INVALID` and `0`. On `SAS_PAIRING_OK` the core's own status is translated:

| Core status | `*out_state` | `*out_remaining` |
|---|---|---|
| `Ready { remaining }` | `READY` | `remaining` (1–10) |
| `Busy` (an exposed ceremony holds the guard) | `BUSY` | `0` |
| `Exhausted` | `EXHAUSTED` | `0` |

### 15.5 Ownership and runtime destroy

The runtime is the owning root: it owns its authorities as real core objects (no pointers cross the boundary), and one runtime may own several authorities for different canonical scopes. `sas_pairing_runtime_destroy` cascades: it invalidates the runtime handle and, with it, every authority and host handle the runtime owns, then destroys every host (§16.5), then releases those authorities through the core's own drop path, best-effort (an uncertain lease release is recorded by the core and fails that authority closed, as for an explicit release), and returns as in §5. Callers need not release authorities first. After destroy returns, no authority handle of that runtime is valid, and none aliases anything in a later runtime. Destroy is cleanup only: it never resets fatal state, creates accounting, or does ceremony work. A panic during destroy is contained (fatal, `SAS_PAIRING_FATAL`) and the runtime is never reinserted.

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

## 16. Hosting contexts

Normative ([P7-D-005](decisions.md#p7-d-005--hosting-context-ownership-and-router-lifetime)). A host is one local routing and hosting context for one registered authority: it owns one real core `Router` built over that authority's executor. The ABI wraps the core's router semantics and does not redefine them.

**Three lifetimes.** They are distinct and must not be confused:

| Lifetime | What it is | Begins | Ends |
|---|---|---|---|
| Authority *process session* | Long-lived security accounting: opportunity budget, START limiter and its clock, registration state (P6-D-002) | First successful OS ownership of the canonical authority in this OS process | Only with the OS process |
| Authority *handle* | One ABI registration, holding the OS lease (§15) | `sas_pairing_authority_register` | Release, or runtime destroy |
| Host *handle* | One router and hosting-object lifetime | `sas_pairing_host_create` | Host destroy, its authority's release, or runtime destroy |

A new host handle is never a new security session, and no host operation ends or refreshes a process session.

### 16.1 Types and object hierarchy

| Item | Value |
|---|---|
| Handle | `typedef uint64_t sas_pairing_host_t;` `SAS_PAIRING_HOST_INVALID = 0` is never valid. Same rules as §4, from the same counter: a runtime or authority handle presented as a host handle, or a host handle presented as either, gives `SAS_PAIRING_INVALID_HANDLE` |

```text
Runtime (owning root)
  ├── authorities: handle → TrustedAuthority
  └── hosts:       handle → host context
                     ├── parent authority handle
                     └── Box<Router>   (Router::new(authority.executor()))
```

Each host has exactly one parent authority, owned by the same runtime. One authority may have several hosts, each with its own router; they share the authority's one opportunity budget, START limiter, guard, and process-session accounting through the authority's core state (the core's own multi-router rule). The router is owned in a heap allocation, so its address stays stable for the host's lifetime while the runtime's maps change; that address is an implementation property for later increments, never ABI semantics, and no pointer to it or to any other Rust object crosses or is stored in the ABI.

### 16.2 Creation

**`sas_pairing_status_t sas_pairing_host_create(sas_pairing_runtime_t runtime, sas_pairing_authority_t authority, sas_pairing_host_t *out_host)`**

| Order | Condition | Result | `*out_host` |
|---:|---|---|---|
| 1 | `out_host` null or misaligned | `SAS_PAIRING_INVALID_ARGUMENT` | not written |
| 2 | Otherwise the output is set to `0` | | `0` |
| 3 | Process fatal | `SAS_PAIRING_FATAL`; the core is not entered (no executor clone, no router) | `0` |
| 4 | `runtime` is `0`, unknown, destroyed, or another kind | `SAS_PAIRING_INVALID_HANDLE` | `0` |
| 5 | `authority` is `0`, unknown, released, another kind, or not owned by `runtime` | `SAS_PAIRING_INVALID_HANDLE` | `0` |
| 6 | Handle space exhausted | `SAS_PAIRING_HANDLES_EXHAUSTED`; no router is built | `0` |
| 7 | The router constructor reports its documented failure (router-ID exhaustion) | `SAS_PAIRING_OWNERSHIP_UNCERTAIN`; the reserved value is burned, nothing installed | `0` |
| 7′ | The router constructor returns any other error (a broken constructor invariant) | `SAS_PAIRING_FATAL`; the process becomes fatal | `0` |
| 8 | Created | `SAS_PAIRING_OK` | the new non-zero handle |
| — | A panic is caught | `SAS_PAIRING_FATAL`; the process becomes fatal; nothing installed | `0` |

Creation builds the router with the reviewed `Router::new(authority.executor())` and nothing else. It consumes no opportunity, refreshes no budget, resets no START limiter, takes no OS lease, registers nothing, creates no ceremony, opens no router session, generates no protocol randomness, and opens no listener or socket. The authority's status (§15.4) is the same before and after.

### 16.3 Destruction

**`sas_pairing_status_t sas_pairing_host_destroy(sas_pairing_runtime_t runtime, sas_pairing_host_t host)`**

| Condition | Result |
|---|---|
| `runtime` invalid, or `host` `0`, unknown, destroyed, of another kind, or owned by no live runtime | `SAS_PAIRING_INVALID_HANDLE` |
| Valid | The host is removed from the runtime **first** (its handle is invalid forever), then its listener and owner loop, if any, are closed while the router is alive (§17.7), then its router is dropped through its own drop path; `SAS_PAIRING_OK`, or `SAS_PAIRING_OWNERSHIP_UNCERTAIN` when a connection's cleanup could not be established (the handle stays invalid; the host is never restored) |
| Process fatal | Allowed, as cleanup; same results; fatal stays set |
| A panic is caught | `SAS_PAIRING_FATAL`; the process becomes fatal |

Destroying a host never releases or invalidates its authority, never touches its sibling hosts, and changes no accounting: the authority stays registered and usable. As cleanup it never clears fatal, builds a router, recreates an authority, or resets anything.

### 16.4 Cascade on authority release

`sas_pairing_authority_release` (§15.3) checks the authority handle, then removes and destroys every host of that authority (first each host's listener and owner loop, then their routers and the executor clones they hold, §17.7), then removes the authority handle, then runs the core's release. After it returns, the authority handle and all of its host handles are invalid forever, whatever the core result; no host is ever restored. Because the ABI's own routers are gone before the core release, an authority with live hosts releases normally: `BUSY` from release never means "this authority still had ABI hosts".

### 16.5 Cascade on runtime destruction

`sas_pairing_runtime_destroy` (§5) invalidates the runtime handle and with it every authority and host handle it owns, then closes every host's listener and owner loop, then destroys every host (all routers), and only then the authorities. The order is explicit in the cleanup, because routers hold executor clones and must be gone before authority ownership ends. No host survives its runtime, and no host handle aliases anything in a later runtime.

### 16.6 Fatal state

`sas_pairing_host_create` is a normal operation: after fatal it returns `SAS_PAIRING_FATAL` before any handle check and enters neither `executor()` nor `Router::new`. `sas_pairing_host_destroy` is cleanup and stays allowed; like authority release and runtime destroy, it never clears fatal or refreshes anything.

### 16.7 Concurrency

Host create and destroy run under the runtime slot, as authority operations do (§15.7), so they serialize with authority release and runtime destruction. Allowed outcomes of races:

| Race | Outcomes |
|---|---|
| host create vs host destroy (of a sibling) | both `OK`; the sibling is gone and the new host is live |
| host create vs authority release | create first: `OK`, then release removes the new host; release first: `INVALID_HANDLE` with output `0` |
| host destroy vs authority release | exactly one of them removes the host: destroy `OK` then release `OK`, or release `OK` then destroy `INVALID_HANDLE` |
| host create vs runtime destroy | create first: `OK`, then destroy removes the new host; destroy first: `INVALID_HANDLE` with output `0` |
| host destroy vs runtime destroy | exactly one of them removes the host: destroy `OK` then runtime destroy `OK`, or runtime destroy `OK` then host destroy `INVALID_HANDLE` |

No interleaving gives a use-after-free, a router dropped twice, a host surviving its authority or runtime, a reachable stale handle, or a deadlock.

### 16.8 Residency and scope

Hosts and their routers are module state of the loaded image, so the loader invariant (§14) applies unchanged: one image, resident until process exit, no reload or reset. Since P7.4 a host may own one caller-bound Windows listener and its owner loop (§17), but nothing drives it: there is no connection, network event, or run, and the ABI exposes no host drive or status operation yet. P7.5 adds bounded driving and the connection, run, event, result, and error representation on top of this hierarchy.

## 17. Windows listener ownership

Normative ([P7-D-006](decisions.md#p7-d-006--windows-listener-ownership-and-responder-configuration), [P7-D-007](decisions.md#p7-d-007--owner-loop--router-lifetime-bridge)). A host may own one Windows network context: the reviewed `WindowsOwnerLoop` over one listening socket that the caller bound, built over the host's router with the host's Responder Bootstrap configuration. **No drive API exists yet:** nothing accepts, reads, writes, polls, or reports an event until a later increment (P7.5) adds bounded driving with its connection, run, event, and result representation. An attached listener is inert; it cannot produce, and so cannot lose, a `PairingResult`.

The ABI never binds a socket and never chooses an address, interface, loopback or LAN exposure, or port, or configures discovery or a firewall: the caller does all of that. TCP is the experimental P4 carrier only. The socket handle, its address, and its port are not protocol identity, authenticated identity, or security identity, and enter no transcript, MAC, authorization, routing, limiter, or accounting decision.

### 17.1 Types

| Item | Value |
|---|---|
| Socket | `typedef uintptr_t sas_pairing_socket_t;` a Windows `SOCKET` handed to the library. An OS resource, not a handle of the §4 counter, and never a peer, connection, authority, or protocol identity |
| Invalid socket | `SAS_PAIRING_SOCKET_INVALID` = `((sas_pairing_socket_t)UINTPTR_MAX)`, Windows `INVALID_SOCKET`. Never adopted |
| Bytes view | `typedef struct sas_pairing_bytes_view { const uint8_t *data; size_t len; } sas_pairing_bytes_view_t;` |
| Bootstrap view | `typedef struct sas_pairing_bootstrap_view { sas_pairing_bytes_view_t application_identity; sas_pairing_bytes_view_t key_algorithm; sas_pairing_bytes_view_t public_key; sas_pairing_bytes_view_t shared_context; } sas_pairing_bootstrap_view_t;` |

Both views are input only, with C layout: a bytes view is two pointer-sized words; a Bootstrap view is four bytes views in the order above, eight words, aligned like a pointer.

### 17.2 Bootstrap input views

For every bytes view: `len == 0` never dereferences `data`, which may be null; `len > 0` requires non-null `data`, `len <= PTRDIFF_MAX`, and a range that does not wrap the address space, else `SAS_PAIRING_INVALID_ARGUMENT`; the caller guarantees `len` readable bytes, unmutated for the call. `local` is required: non-null, aligned, and readable for one view. `expected` is either null (no exact expected peer Bootstrap) or meets the same rules. The library copies every byte during the call and retains no pointer to a view or to its bytes.

The copied bytes are built into the core's Bootstrap with the reviewed `Bootstrap::new`, which alone decides validity (field bounds, the key-algorithm alphabet, the canonical frame bound). A configuration it refuses gives `SAS_PAIRING_INVALID_BOOTSTRAP`; no `CodecError` layout, diagnostic string, or field name is part of the ABI. A field longer than `MAX_BOOTSTRAP_FRAME` (16384 bytes) is refused without being copied, which is the outcome `Bootstrap::new` would give.

### 17.3 Socket ownership and caller precondition

`*inout_listener` is an in/out ownership slot. Before the transfer it holds the caller's socket; after the transfer it holds `SAS_PAIRING_SOCKET_INVALID` and the library owns the socket and closes it exactly once. Whenever the slot reads `SAS_PAIRING_SOCKET_INVALID` after a call, the caller must not close, use, mutate, or hand on that socket. Whenever it still holds the socket, the caller still owns it and closes it when done.

Trusted local caller precondition: a slot value other than `SAS_PAIRING_SOCKET_INVALID` is one valid, already-bound Windows listening `SOCKET`, owned exclusively by the caller at entry, and not closed, used, or given to another owner by anyone during the call. The library cannot prove that an integer is such a socket; a value that is not one is a caller error like an invalid pointer (§8), not something the library claims to reject safely.

### 17.4 Ownership-transfer linearization

Once every check of §17.5 steps 1–7 has passed, the library, with no fallible or panicking operation in between: converts the raw value, builds one Rust-owned listener from it (the only owner; no duplicate handle is created), and writes `SAS_PAIRING_SOCKET_INVALID` to the slot. That write is the linearization point. Every failure before it leaves the slot unchanged and the socket with the caller. Every outcome after it (success, `SAS_PAIRING_LISTENER_SETUP_FAILED`, `SAS_PAIRING_FATAL`, or a caught panic) leaves the slot `INVALID`, and the library closes the socket: through the owner loop on detach or teardown, or by dropping the listener when a later step fails or unwinds. At no instant are there two owners or none.

### 17.5 Attach

**`sas_pairing_status_t sas_pairing_host_attach_windows_listener(sas_pairing_runtime_t runtime, sas_pairing_host_t host, sas_pairing_socket_t *inout_listener, const sas_pairing_bootstrap_view_t *local, const sas_pairing_bootstrap_view_t *expected)`**

| Order | Condition | Result | `*inout_listener` |
|---:|---|---|---|
| 1 | `inout_listener` null or misaligned; `local` null or misaligned; `expected` misaligned; a malformed bytes view (§17.2); the slot holds `SAS_PAIRING_SOCKET_INVALID` | `SAS_PAIRING_INVALID_ARGUMENT` | unchanged |
| 2 | Not Windows | `SAS_PAIRING_UNSUPPORTED_PLATFORM`; nothing read beyond the views, copied, or created | unchanged |
| 3 | `local`, or a non-null `expected`, fails `Bootstrap::new` | `SAS_PAIRING_INVALID_BOOTSTRAP` | unchanged |
| 4 | Process fatal | `SAS_PAIRING_FATAL`; no core, router, or owner-loop work | unchanged |
| 5 | `runtime` is `0`, unknown, destroyed, or another kind | `SAS_PAIRING_INVALID_HANDLE` | unchanged |
| 6 | `host` is `0`, unknown, destroyed, another kind, or not owned by `runtime` | `SAS_PAIRING_INVALID_HANDLE` | unchanged |
| 7 | The host already has a listener | `SAS_PAIRING_LISTENER_ALREADY_ATTACHED`; the existing one is untouched | unchanged |
| 8 | Adoption (§17.4) | | `SAS_PAIRING_SOCKET_INVALID` |
| 9 | The owner-loop constructor reports its documented failure (the listener cannot be made nonblocking) | `SAS_PAIRING_LISTENER_SETUP_FAILED`; the library closed the socket; nothing installed; not fatal | `SAS_PAIRING_SOCKET_INVALID` |
| 9′ | The constructor returns any other error (a broken constructor invariant) | `SAS_PAIRING_FATAL`; the process becomes fatal; the library closed the socket; nothing installed | `SAS_PAIRING_SOCKET_INVALID` |
| 10 | Attached | `SAS_PAIRING_OK` | `SAS_PAIRING_SOCKET_INVALID` |
| — | A panic is caught before step 8 | `SAS_PAIRING_FATAL`; the process becomes fatal | unchanged |
| — | A panic is caught after step 8 | `SAS_PAIRING_FATAL`; the process becomes fatal; the unwinding listener closed the socket; nothing installed | `SAS_PAIRING_SOCKET_INVALID` |

Step 3 precedes step 4 because it is a pure value check of copied bytes: it touches no authority, router, registry, accounting, randomness, or socket. Every stateful step follows the fatal check.

The owner loop is built with exactly the reviewed `WindowsOwnerLoop::from_bound_listener(listener, router, local, expected)`. A successful attach leaves one owner loop, a listening socket, and zero connections; it calls no drive, recheck, accept, session, or accept-permit operation, creates no thread, timer, or callback, and changes no accounting: no opportunity is consumed or refunded, and no budget, START limiter, guard, session, connection, or ceremony is touched. `local` is the Responder configuration the loop gives accepted connections for new STARTs, and `expected` the exact expected peer Bootstrap; both are configuration, not identity checks performed by attach.

One host holds at most one listener. There is no replace-in-place operation; replacement is detach, then attach.

### 17.6 Detach and replacement

**`sas_pairing_status_t sas_pairing_host_detach_listener(sas_pairing_runtime_t runtime, sas_pairing_host_t host)`**

| Condition | Result |
|---|---|
| `runtime` invalid, or `host` `0`, unknown, destroyed, another kind, or owned by no live runtime | `SAS_PAIRING_INVALID_HANDLE` |
| Valid host with a listener | The network context leaves the host first; then the owner loop closes its listener and every connection it owns while the router is alive; then it is dropped. `SAS_PAIRING_OK`, or `SAS_PAIRING_OWNERSHIP_UNCERTAIN` when a connection's cleanup could not be established (the core keeps that capacity held, as for any uncertain teardown); the listener is gone either way |
| Valid host without a listener | `SAS_PAIRING_OK` (idempotent) |
| Process fatal | Allowed, as cleanup; same results; fatal stays set |
| A panic is caught | `SAS_PAIRING_FATAL`; the process becomes fatal |

After detach the host, its router, its authority, and all accounting remain; a new listener may be attached while the process is not fatal. Replacement (attach L1, detach, attach L2) creates no new process session, opportunity budget, START limiter, or authority ownership. Destroying the host and creating a new one on the same authority, then attaching, keeps the same process-session accounting.

### 17.7 Owner-loop lifetime bridge

```text
Runtime
  ├── authorities: handle → TrustedAuthority
  └── hosts:       handle → Box<host context>
                     ├── parent authority handle
                     ├── optional Windows network context
                     │     └── WindowsOwnerLoop          (borrows the router below)
                     │           ├── listener
                     │           └── accepted connections (each borrows the router)
                     └── Box<Router>
```

The owner loop, and every connection it will own, borrows the host's router. The library keeps that borrow valid by these invariants (P7-D-007): the router lives in its own box, which is never replaced, moved out of, written through, or borrowed mutably; host contexts are boxed, so neither moves after construction; the network context never leaves its host context; no reference to the router, the loop, or the network context crosses the ABI; and the network context always ends before the router:

| Path | Order |
|---|---|
| Listener detach | network context out of the host → loop closes listener and connections → dropped; router stays |
| Host destroy | host removed (handle invalid) → network context ended → router dropped |
| Authority release | every child host removed → each network context ended → routers dropped → core release |
| Runtime destroy | runtime removed (every handle invalid) → every network context ended → every router dropped → every authority dropped |
| Any other drop of a host context | its `Drop` ends the network context before any field drops |

No use of a router can follow its destruction, and no router can be dropped while a loop or connection borrowing it exists.

### 17.8 Fatal state

Attach is a normal operation: after the structural checks, the platform, and the Bootstrap check, a fatal process returns `SAS_PAIRING_FATAL` without core, router, or owner-loop work and without adopting the socket. Detach is cleanup: allowed after fatal, it closes an attached listener and never clears fatal. After a fatal detach, attach still returns `SAS_PAIRING_FATAL`. Host destroy, authority release, and runtime destroy close attached listeners as part of their cleanup.

### 17.9 Concurrency

Attach and detach run under the runtime slot, like every host operation (§16.7), so they serialize with host destroy, authority release, and runtime destroy. Allowed outcomes:

| Race | Outcomes |
|---|---|
| attach vs detach (same host) | both `OK`: attach first, then detach closes the new listener; or detach first (nothing to detach), then attach installs it |
| attach vs host destroy | attach first: `OK`, slot `INVALID`, then destroy closes the socket; destroy first: attach `INVALID_HANDLE`, slot unchanged, the caller still owns the socket |
| attach vs authority release | the same, with release (always `OK`, never `BUSY` because of a host or its loop) |
| attach vs runtime destroy | the same, with runtime destroy |
| detach vs host destroy | detach first: `OK`, then destroy finds no listener; destroy first: detach `INVALID_HANDLE` |
| detach vs authority release | the same, with release |
| detach vs runtime destroy | the same, with runtime destroy |

Exactly one owner closes each socket. No interleaving gives a double close, a use-after-free, two owner loops in one host, an owner loop outliving its router, or a deadlock.

### 17.10 Platform behavior and scope

Both exports exist on every platform. Off Windows, attach returns `SAS_PAIRING_UNSUPPORTED_PLATFORM` after the structural checks and leaves the slot unchanged: no listener, owner loop, or networking exists or is faked. Detach then names no host (no authority can register there, so no host exists) and returns `SAS_PAIRING_INVALID_HANDLE`.

Listeners and owner loops are module state of the one resident image (§14): no self-pinning, duplicate-image handling, or reload recovery. This increment exposes no drive, poll, or recheck operation, no connection or run handle, no event array, no result access, and no outbound-byte buffer or send operation: the TCP adapter keeps and writes its own outbound frame. Those belong to P7.5.
