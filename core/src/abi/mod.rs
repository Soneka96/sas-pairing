//! Language-neutral native ABI, version 1 (P7). Compiled only with the `native-abi` feature;
//! the C contract is `core/include/sas_pairing.h` and `docs/p7-native-abi/abi-contract.md`.
//!
//! The ABI lives inside the core crate so later increments can call the reviewed crate-private
//! core directly; nothing here widens the public Rust API. Only fixed-width integers and raw
//! pointers to caller-owned memory cross the boundary; no Rust allocation, reference, `bool`,
//! enum, `Result`, or object pointer does. Every export enters Rust work through [`dispatch`],
//! the one panic-containment boundary (P6-D-004).
//!
//! Argument precedence for every export (contract §15.7, §16.2, §17.5, §18): raw-memory
//! validation, then output slots set to their invalid values, then the fatal state (normal
//! operations only), then the runtime handle, then the authority, host, connection, or result
//! handle, then the core. Listener attach validates its Bootstrap configuration (a stateless
//! value check) before the fatal state, and adopts the caller's socket only after every other
//! check passed. The drive exports check the platform and their event capacity before the fatal
//! state, and every remaining refusal (handles, listener, handle space) before the owner loop
//! runs. Result access is ABI-owned data access and is admitted in the fatal state.

// A caught panic is the containment model, so the supported artifact must unwind (P6-D-004
// item 12). Profile settings can be overridden, so the build itself refuses `panic = "abort"`.
#[cfg(not(panic = "unwind"))]
compile_error!(
    "the `native-abi` feature requires panic = \"unwind\": P6-D-004 panic containment cannot \
     work under panic = \"abort\""
);

mod authority;
mod hosting;
mod listener;
mod network;
mod panic_boundary;
mod result;
mod runtime;
mod status;
#[cfg(test)]
mod tests;

use std::{marker::PhantomData, ptr, slice};

#[cfg(windows)]
use crate::protocol::{Bootstrap, MAX_BOOTSTRAP_FRAME};
use authority::{AuthorityHandle, SAS_PAIRING_AUTHORITY_STATE_INVALID};
use hosting::HostHandle;
use listener::{ListenerSlot, SAS_PAIRING_SOCKET_INVALID, SocketHandle};
use network::{ConnectionHandle, DriveMode, Event, drive_through, element_range, overlaps};
use result::{ResultField, ResultHandle, ResultInfo};
use runtime::AbiState;
use status::{
    SAS_PAIRING_BUFFER_TOO_SMALL, SAS_PAIRING_FATAL, SAS_PAIRING_INVALID_ARGUMENT, SAS_PAIRING_OK,
};

/// The native ABI version. Not the protocol profile version and not the crate version.
const ABI_VERSION: u32 = 1;
/// Never a successful ABI version; returned only if the version query itself panicked.
const INVALID_ABI_VERSION: u32 = 0;

/// `sas_pairing_runtime_t`: an opaque process-local handle; `0` is never valid.
type RuntimeHandle = u64;

/// The one native ABI state of this OS process. It is never reset.
static PROCESS: AbiState = AbiState::new();

/// `sas_pairing_bytes_view_t`: borrowed caller bytes, an input view only. `data` may be null
/// only when `len` is `0`. The ABI copies the bytes during the call and keeps no pointer.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct BytesView {
    data: *const u8,
    len: usize,
}

/// `sas_pairing_bootstrap_view_t`: one Bootstrap configuration as four borrowed byte strings, an
/// input view only. Copied during the call into `Bootstrap::new`; no pointer is kept.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct BootstrapView {
    application_identity: BytesView,
    key_algorithm: BytesView,
    public_key: BytesView,
    shared_context: BytesView,
}

impl BytesView {
    /// Whether a Rust slice can describe these bytes (nothing is dereferenced).
    fn is_well_formed(self) -> bool {
        byte_range(self.data, self.len).is_some()
    }
}

impl BootstrapView {
    fn fields(self) -> [BytesView; 4] {
        [
            self.application_identity,
            self.key_algorithm,
            self.public_key,
            self.shared_context,
        ]
    }

    /// Whether every byte view is well formed (nothing is dereferenced).
    fn is_well_formed(self) -> bool {
        self.fields().into_iter().all(BytesView::is_well_formed)
    }
}

/// A caller's Bootstrap view that passed structural validation and whose bytes are readable for
/// the call `'a`. Its bytes are read only by [`BootstrapInput::to_bootstrap`], which copies them.
#[cfg_attr(
    not(windows),
    expect(dead_code, reason = "no Bootstrap is built off Windows")
)]
pub(super) struct BootstrapInput<'a> {
    view: BootstrapView,
    _call: PhantomData<&'a [u8]>,
}

impl BootstrapInput<'_> {
    /// # Safety
    ///
    /// `view` is well formed, and each of its non-empty byte views addresses `len` readable
    /// bytes that the caller owns and does not mutate for the call `'a`.
    unsafe fn new(view: BootstrapView) -> Self {
        debug_assert!(view.is_well_formed());
        Self {
            view,
            _call: PhantomData,
        }
    }

    /// Copies the four byte strings and builds the core `Bootstrap` with the reviewed
    /// `Bootstrap::new`, which alone decides validity; `None` if it refuses. A field longer
    /// than `MAX_BOOTSTRAP_FRAME` can never fit the canonical bootstrap frame, so it is refused
    /// without being copied: an allocation bound, with the same outcome `Bootstrap::new` gives.
    #[cfg(windows)]
    pub(super) fn to_bootstrap(&self) -> Option<Bootstrap> {
        let fields = self.view.fields();
        if fields.iter().any(|field| field.len > MAX_BOOTSTRAP_FRAME) {
            return None;
        }
        // SAFETY: each view is well formed and readable for the call (constructor contract).
        // `caller_bytes` borrows them only until `to_vec` has copied them; nothing is kept.
        let [
            application_identity,
            key_algorithm,
            public_key,
            shared_context,
        ] = fields.map(|field| unsafe { caller_bytes(field.data, field.len) }.to_vec());
        Bootstrap::new(
            application_identity,
            key_algorithm,
            public_key,
            shared_context,
        )
        .ok()
    }
}

/// The address range `[start, end)` of `len` caller bytes at `data`, when a Rust slice can
/// describe it: `data` is non-null unless `len` is `0`, `len` fits `isize`, and the range does
/// not wrap the address space. Addresses are compared as integers; nothing is dereferenced.
fn byte_range(data: *const u8, len: usize) -> Option<(usize, usize)> {
    if len == 0 {
        return Some((data.addr(), data.addr()));
    }
    if data.is_null() || isize::try_from(len).is_err() {
        return None;
    }
    Some((data.addr(), data.addr().checked_add(len)?))
}

/// Borrows `len` caller bytes at `data` for the current call. A zero length never dereferences
/// `data`, which may then be null.
///
/// # Safety
///
/// `byte_range(data, len)` is `Some`, and when `len > 0` the caller guarantees `len` readable
/// bytes at `data`, not mutated while the returned slice is used. The slice must not outlive
/// the call that received `data`.
unsafe fn caller_bytes<'a>(data: *const u8, len: usize) -> &'a [u8] {
    debug_assert!(byte_range(data, len).is_some());
    if len == 0 {
        return &[];
    }
    // SAFETY: `data` is non-null, `len` fits `isize`, and the range does not wrap (the
    // precondition); `u8` needs no alignment; the caller guarantees `len` readable, unmutated
    // bytes for as long as the slice is used.
    unsafe { slice::from_raw_parts(data, len) }
}

/// The central export dispatcher: runs `op` on the process state inside the containment
/// boundary. A caught panic marks the process fatal and returns `fallback`.
fn dispatch<T: Copy>(fallback: T, op: impl FnOnce(&'static AbiState) -> T) -> T {
    panic_boundary::contain(&PROCESS.fatal, fallback, || op(&PROCESS))
}

/// Returns the native ABI version, `1`. Callable in any state, including after a fatal panic,
/// because it reads a constant and never enters a runtime or the core.
#[unsafe(no_mangle)]
pub extern "C" fn sas_pairing_abi_version() -> u32 {
    dispatch(INVALID_ABI_VERSION, |_| ABI_VERSION)
}

/// Creates the process's one native runtime and writes its handle to `out_runtime`.
///
/// Null or misaligned `out_runtime` → `INVALID_ARGUMENT`, nothing written. Otherwise the slot is
/// set to `0` on entry and receives the new non-zero handle only on `OK`. A fatal process returns
/// `FATAL`; an active runtime gives `ALREADY_INITIALIZED` and is not replaced.
///
/// # Safety
///
/// A non-null, aligned `out_runtime` must point to one caller-owned `uint64_t` that is writable
/// and not accessed concurrently for the duration of the call. Rust cannot validate other
/// invalid addresses.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sas_pairing_runtime_create(out_runtime: *mut RuntimeHandle) -> i32 {
    dispatch(SAS_PAIRING_FATAL, |state| {
        if out_runtime.is_null() || !out_runtime.is_aligned() {
            return SAS_PAIRING_INVALID_ARGUMENT;
        }
        // SAFETY: the pointer is non-null and aligned (checked above), and the caller guarantees
        // it addresses one writable `u64` it owns, unaliased, for this whole call. `u64` has no
        // invalid bit patterns and no destructor, so plain writes are sound.
        let write_out = |value: RuntimeHandle| unsafe { out_runtime.write(value) };
        write_out(0);
        match state.create() {
            Ok(handle) => {
                write_out(handle.get());
                SAS_PAIRING_OK
            }
            Err(status) => status,
        }
    })
}

/// Destroys the runtime named by `runtime`; the handle is invalid forever afterwards.
///
/// Zero, unknown, and already destroyed handles give `INVALID_HANDLE`. Destroy is the cleanup
/// path: it still works after a fatal panic and never clears the fatal state.
#[unsafe(no_mangle)]
pub extern "C" fn sas_pairing_runtime_destroy(runtime: RuntimeHandle) -> i32 {
    dispatch(SAS_PAIRING_FATAL, |state| state.destroy(runtime))
}

/// Registers the authority `scope` (bytes, not a C string) under `runtime` and writes its new
/// opaque handle to `out_authority`.
///
/// Null or misaligned `out_authority`, a null `scope` with a non-zero length, a length no Rust
/// slice can have, or a `scope` range that overlaps `out_authority` → `INVALID_ARGUMENT`,
/// nothing written. Otherwise the slot is set to `0` on entry and receives the non-zero handle
/// only on `OK`. A zero length enters the core as an empty scope (`INVALID_SCOPE`) without
/// reading `scope`. The scope is copied by the core; no pointer is retained.
///
/// # Safety
///
/// A non-null, aligned `out_authority` must point to one caller-owned `uint64_t` that is
/// writable and not accessed concurrently for the duration of the call. When `scope_len` is
/// non-zero, `scope` must point to `scope_len` readable bytes that are not mutated during the
/// call. Rust cannot validate other invalid addresses.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sas_pairing_authority_register(
    runtime: RuntimeHandle,
    scope: *const u8,
    scope_len: usize,
    out_authority: *mut AuthorityHandle,
) -> i32 {
    dispatch(SAS_PAIRING_FATAL, |state| {
        if out_authority.is_null()
            || !out_authority.is_aligned()
            || (scope.is_null() && scope_len != 0)
            || !scope_range_is_valid(scope, scope_len, out_authority)
        {
            return SAS_PAIRING_INVALID_ARGUMENT;
        }
        // SAFETY: the pointer is non-null and aligned (checked above), and the caller guarantees
        // it addresses one writable `u64` it owns, unaliased, for this whole call. It does not
        // overlap the scope bytes (checked above). `u64` has no invalid bit patterns and no
        // destructor, so plain writes are sound.
        let write_out = |value: AuthorityHandle| unsafe { out_authority.write(value) };
        write_out(0);
        // SAFETY: the scope range is well formed (checked above) and the caller guarantees
        // `scope_len` readable bytes left unmutated for this call. The slice is borrowed only
        // until `register_authority` returns; the core copies the bytes into its own identity
        // and keeps no reference.
        let scope = unsafe { caller_bytes(scope, scope_len) };
        match state.register_authority(runtime, scope) {
            Ok(handle) => {
                write_out(handle.get());
                SAS_PAIRING_OK
            }
            Err(status) => status,
        }
    })
}

/// Whether `scope`/`scope_len` can form a Rust slice and stays clear of the output slot: the
/// length fits `isize`, the byte range does not wrap the address space, and it does not overlap
/// the `uint64_t` at `out`. Addresses are compared as integers; nothing is dereferenced.
fn scope_range_is_valid(scope: *const u8, scope_len: usize, out: *mut AuthorityHandle) -> bool {
    let Some((scope_start, scope_end)) = byte_range(scope, scope_len) else {
        return false;
    };
    if scope_len == 0 {
        return true;
    }
    let out_start = out.addr();
    let Some(out_end) = out_start.checked_add(size_of::<AuthorityHandle>()) else {
        return false;
    };
    scope_end <= out_start || out_end <= scope_start
}

/// Releases `authority`. Its handle is invalid forever once this returns, whatever the result:
/// the handle leaves the runtime before the core's release runs, and a core error (mapped) never
/// restores it. Allowed in the fatal state as cleanup; it never clears fatal state, and ends
/// only this registration, never the authority's process-session accounting.
#[unsafe(no_mangle)]
pub extern "C" fn sas_pairing_authority_release(
    runtime: RuntimeHandle,
    authority: AuthorityHandle,
) -> i32 {
    dispatch(SAS_PAIRING_FATAL, |state| {
        state.release_authority(runtime, authority)
    })
}

/// Writes `authority`'s state and remaining opportunities to `out_state` and `out_remaining`.
///
/// Either pointer null or misaligned, or both naming the same slot → `INVALID_ARGUMENT`, nothing
/// written. Otherwise both are set to `0` (`INVALID`, no opportunities) on entry and receive the
/// core status only on `OK`: `READY` with the remaining count, or `BUSY`/`EXHAUSTED` with `0`.
///
/// # Safety
///
/// Non-null, aligned `out_state` and `out_remaining` must each point to one distinct
/// caller-owned `uint32_t` that is writable and not accessed concurrently for the duration of
/// the call. Rust cannot validate other invalid addresses.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sas_pairing_authority_status(
    runtime: RuntimeHandle,
    authority: AuthorityHandle,
    out_state: *mut u32,
    out_remaining: *mut u32,
) -> i32 {
    dispatch(SAS_PAIRING_FATAL, |state| {
        if out_state.is_null()
            || !out_state.is_aligned()
            || out_remaining.is_null()
            || !out_remaining.is_aligned()
            || out_state == out_remaining
        {
            return SAS_PAIRING_INVALID_ARGUMENT;
        }
        // SAFETY: both pointers are non-null, aligned, and distinct (checked above); two aligned
        // `u32` slots at different addresses cannot overlap. The caller guarantees each
        // addresses one writable `u32` it owns, unaliased, for this whole call. `u32` has no
        // invalid bit patterns and no destructor.
        let write_out = |(value, remaining): (u32, u32)| unsafe {
            out_state.write(value);
            out_remaining.write(remaining);
        };
        write_out((SAS_PAIRING_AUTHORITY_STATE_INVALID, 0));
        match state.authority_status(runtime, authority) {
            Ok(status) => {
                write_out(status);
                SAS_PAIRING_OK
            }
            Err(status) => status,
        }
    })
}

/// Creates a hosting context (one core router) for `authority` under `runtime` and writes its
/// new opaque handle to `out_host`.
///
/// Null or misaligned `out_host` → `INVALID_ARGUMENT`, nothing written. Otherwise the slot is
/// set to `0` on entry and receives the non-zero handle only on `OK`. A fatal process returns
/// `FATAL` without building a router. Creation is accounting neutral and does no networking.
///
/// # Safety
///
/// A non-null, aligned `out_host` must point to one caller-owned `uint64_t` that is writable
/// and not accessed concurrently for the duration of the call. Rust cannot validate other
/// invalid addresses.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sas_pairing_host_create(
    runtime: RuntimeHandle,
    authority: AuthorityHandle,
    out_host: *mut HostHandle,
) -> i32 {
    dispatch(SAS_PAIRING_FATAL, |state| {
        if out_host.is_null() || !out_host.is_aligned() {
            return SAS_PAIRING_INVALID_ARGUMENT;
        }
        // SAFETY: the pointer is non-null and aligned (checked above), and the caller guarantees
        // it addresses one writable `u64` it owns, unaliased, for this whole call. `u64` has no
        // invalid bit patterns and no destructor, so plain writes are sound.
        let write_out = |value: HostHandle| unsafe { out_host.write(value) };
        write_out(0);
        match state.create_host(runtime, authority) {
            Ok(handle) => {
                write_out(handle.get());
                SAS_PAIRING_OK
            }
            Err(status) => status,
        }
    })
}

/// Destroys `host`; its handle is invalid forever once this returns, and its router is dropped.
/// Its authority stays registered and its sibling hosts stay live. Allowed in the fatal state as
/// cleanup; it never clears fatal state or changes accounting.
#[unsafe(no_mangle)]
pub extern "C" fn sas_pairing_host_destroy(runtime: RuntimeHandle, host: HostHandle) -> i32 {
    dispatch(SAS_PAIRING_FATAL, |state| state.destroy_host(runtime, host))
}

/// Attaches the caller's ALREADY-BOUND Windows listening socket to `host`: the host's owner loop
/// is built over it, with `local` as the Responder Bootstrap for accepted connections and
/// `expected` (or none, when null) as the exact expected peer Bootstrap. Nothing is driven.
///
/// Ownership transfer (contract §17.4): on entry `*inout_listener` is the caller's socket. Every
/// failure before adoption (bad arguments, an unsupported platform, an invalid Bootstrap, fatal,
/// bad handles, a listener already attached) leaves the slot unchanged and the socket with the
/// caller. At adoption `*inout_listener` becomes `SAS_PAIRING_SOCKET_INVALID` and Rust owns and
/// closes the socket, also if a later step fails (`LISTENER_SETUP_FAILED`, `FATAL`).
///
/// # Safety
///
/// Non-null, aligned `inout_listener` must address one caller-owned, writable
/// `sas_pairing_socket_t`, and non-null, aligned `local` and `expected` one readable
/// `sas_pairing_bootstrap_view_t` each, none accessed concurrently, for the duration of the call.
/// Every non-empty byte view must address `len` readable bytes not mutated during the call. A
/// socket value other than `SAS_PAIRING_SOCKET_INVALID` must be one valid, already-bound Windows
/// listening `SOCKET` that the caller owns exclusively and nobody closes or uses during the
/// call. Rust cannot validate other invalid addresses or socket values.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sas_pairing_host_attach_windows_listener(
    runtime: RuntimeHandle,
    host: HostHandle,
    inout_listener: *mut SocketHandle,
    local: *const BootstrapView,
    expected: *const BootstrapView,
) -> i32 {
    dispatch(SAS_PAIRING_FATAL, |state| {
        if inout_listener.is_null()
            || !inout_listener.is_aligned()
            || local.is_null()
            || !local.is_aligned()
            || !expected.is_aligned()
        {
            return SAS_PAIRING_INVALID_ARGUMENT;
        }
        // SAFETY: `inout_listener`, `local`, and a non-null `expected` are non-null and aligned
        // (checked above), and the caller guarantees each addresses one readable value of its
        // type for this call. Each type is plain integers and raw pointers, so every bit pattern
        // is valid and nothing is dropped; the values are copied out and no reference is formed.
        let (socket, local, expected) = unsafe {
            (
                inout_listener.read(),
                local.read(),
                (!expected.is_null()).then(|| expected.read()),
            )
        };
        if socket == SAS_PAIRING_SOCKET_INVALID
            || !local.is_well_formed()
            || !expected.is_none_or(BootstrapView::is_well_formed)
        {
            return SAS_PAIRING_INVALID_ARGUMENT;
        }
        // SAFETY: every byte view is well formed (checked above), and the caller guarantees
        // their bytes readable and unmutated for this call; the inputs do not outlive it.
        let local = unsafe { BootstrapInput::new(local) };
        // SAFETY: as for `local`.
        let expected = expected.map(|view| unsafe { BootstrapInput::new(view) });
        // SAFETY: `inout_listener` is non-null and aligned (checked above) and the caller's
        // writable, unaliased slot for this call; `socket` is its entry value and not INVALID
        // (checked above); the caller guarantees it is one valid, already-bound listening SOCKET
        // it owns exclusively.
        let slot = unsafe { ListenerSlot::new(inout_listener, socket) };
        state.attach_listener(runtime, host, slot, &local, expected.as_ref())
    })
}

/// Detaches `host`'s listener: the owner loop closes the listener and every connection it owns
/// while the host's router is alive. The host, its router, its authority, and all accounting
/// stay; a new listener may be attached later. Idempotent (`OK` when none is attached). Allowed
/// in the fatal state as cleanup; it never clears fatal state.
#[unsafe(no_mangle)]
pub extern "C" fn sas_pairing_host_detach_listener(
    runtime: RuntimeHandle,
    host: HostHandle,
) -> i32 {
    dispatch(SAS_PAIRING_FATAL, |state| {
        state.detach_listener(runtime, host)
    })
}

/// Drives `host`'s owner loop once: one bounded `drive_once` (deadline sweeps, at most one
/// readiness wait of at most 250 ms, at most one socket operation per connection, at most one
/// accept), translated into at most `SAS_PAIRING_MAX_DRIVE_EVENTS` records written to `events`.
///
/// The return value says whether the call itself ran; `*out_failure` says whether the owner loop
/// failed during it. On `OK`, `*out_count` events were written and must all be consumed, also
/// when `*out_failure` is not `OK` (events produced before the loop failed closed are kept). A
/// capacity below `SAS_PAIRING_MAX_DRIVE_EVENTS` gives `BUFFER_TOO_SMALL` with `*out_count` set
/// to the required capacity and drives nothing (`events` may then be null with capacity `0`).
/// Every refusal (arguments, platform, capacity, fatal, handles, no listener, handle space) is
/// decided before any network progress. No outbound byte is returned: the adapter writes it.
///
/// # Safety
///
/// Non-null, aligned `out_count` and `out_failure` must each address one caller-owned writable
/// value of their type, and a non-null `events` must address `event_capacity` caller-owned
/// writable `sas_pairing_event_t` records, none accessed concurrently, for the duration of the
/// call. Rust cannot validate other invalid addresses.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sas_pairing_host_drive(
    runtime: RuntimeHandle,
    host: HostHandle,
    events: *mut Event,
    event_capacity: usize,
    out_count: *mut usize,
    out_failure: *mut i32,
) -> i32 {
    dispatch(SAS_PAIRING_FATAL, |state| {
        // SAFETY: forwarded unchanged under this export's own contract, which is
        // `drive_through`'s.
        unsafe {
            drive_through(
                state,
                runtime,
                host,
                DriveMode::Drive,
                events,
                event_capacity,
                out_count,
                out_failure,
            )
        }
    })
}

/// For trusted outer code after an OS resume notification: one `recheck_after_resume` of
/// `host`'s owner loop, a deadline sweep and nothing else (no readiness wait, socket read or
/// write, or accept), with exactly the event, capacity, handle-space, and `out_failure` contract
/// of `sas_pairing_host_drive`.
///
/// # Safety
///
/// As for `sas_pairing_host_drive`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sas_pairing_host_recheck_after_resume(
    runtime: RuntimeHandle,
    host: HostHandle,
    events: *mut Event,
    event_capacity: usize,
    out_count: *mut usize,
    out_failure: *mut i32,
) -> i32 {
    dispatch(SAS_PAIRING_FATAL, |state| {
        // SAFETY: forwarded unchanged under this export's own contract, which is
        // `drive_through`'s.
        unsafe {
            drive_through(
                state,
                runtime,
                host,
                DriveMode::Resume,
                events,
                event_capacity,
                out_count,
                out_failure,
            )
        }
    })
}

/// Closes one connection of `host`'s owner loop (cleanup): its connection handle and every run
/// handle of that connection are invalidated first, then the loop's own close of that
/// connection runs (no CANCEL, nothing retried). Allowed in the fatal state; never clears it.
#[unsafe(no_mangle)]
pub extern "C" fn sas_pairing_connection_close(
    runtime: RuntimeHandle,
    host: HostHandle,
    connection: ConnectionHandle,
) -> i32 {
    dispatch(SAS_PAIRING_FATAL, |state| {
        state.close_connection(runtime, host, connection)
    })
}

/// Writes the fixed fields of `result` (its ceremony identity, the peer's role, the profile
/// version, and the lengths of the variable fields) to `out_info`.
///
/// Null or misaligned `out_info` → `INVALID_ARGUMENT`, nothing written. Otherwise `*out_info` is
/// zeroed on entry and filled only on `OK`. ABI-owned data access: allowed in the fatal state,
/// never entering the core.
///
/// # Safety
///
/// A non-null, aligned `out_info` must address one caller-owned writable
/// `sas_pairing_result_info_t`, not accessed concurrently for the duration of the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sas_pairing_result_info(
    runtime: RuntimeHandle,
    result: ResultHandle,
    out_info: *mut ResultInfo,
) -> i32 {
    dispatch(SAS_PAIRING_FATAL, |state| {
        if out_info.is_null() || !out_info.is_aligned() {
            return SAS_PAIRING_INVALID_ARGUMENT;
        }
        // SAFETY: the pointer is non-null and aligned (checked above), and the caller guarantees
        // one writable record it owns, unaliased, for this call. `ResultInfo` is a padding-free
        // `repr(C)` record of integers and bytes with no destructor, written whole.
        let write_out = |value: ResultInfo| unsafe { out_info.write(value) };
        write_out(ResultInfo::ZERO);
        match state.result_info(runtime, result) {
            Ok(info) => {
                write_out(info);
                SAS_PAIRING_OK
            }
            Err(status) => status,
        }
    })
}

/// Copies the bytes of one variable-length `field` of `result` into `buffer`.
///
/// `out_required` must be non-null and aligned; `buffer` may be null only when `capacity` is
/// `0`; the buffer range must be describable and must not overlap `*out_required`; `field` must
/// be a known `sas_pairing_result_field_t`. Otherwise `INVALID_ARGUMENT`, nothing written.
/// Then `*out_required` is set to `0`, and once the result is found to the field's exact length.
/// A capacity below it gives `BUFFER_TOO_SMALL` and copies nothing; otherwise exactly that many
/// bytes are copied (never truncated, never NUL-terminated) and `OK` is returned. ABI-owned data
/// access: allowed in the fatal state, never entering the core.
///
/// # Safety
///
/// A non-null, aligned `out_required` must address one caller-owned writable `size_t`, and a
/// non-null `buffer` `capacity` caller-owned writable bytes, neither accessed concurrently for
/// the duration of the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sas_pairing_result_copy(
    runtime: RuntimeHandle,
    result: ResultHandle,
    field: u32,
    buffer: *mut u8,
    capacity: usize,
    out_required: *mut usize,
) -> i32 {
    dispatch(SAS_PAIRING_FATAL, |state| {
        if out_required.is_null() || !out_required.is_aligned() {
            return SAS_PAIRING_INVALID_ARGUMENT;
        }
        let (Some(required_range), Some(buffer_range)) = (
            element_range(out_required.cast_const(), 1),
            element_range(buffer.cast_const(), capacity),
        ) else {
            return SAS_PAIRING_INVALID_ARGUMENT;
        };
        if overlaps(buffer_range, required_range) {
            return SAS_PAIRING_INVALID_ARGUMENT;
        }
        let Some(field) = ResultField::from_raw(field) else {
            return SAS_PAIRING_INVALID_ARGUMENT;
        };
        // SAFETY: the pointer is non-null and aligned and does not overlap the buffer (checked
        // above); the caller guarantees one writable `size_t` it owns, unaliased, for this call.
        let write_required = |value: usize| unsafe { out_required.write(value) };
        write_required(0);
        let copied = state.with_result_field(runtime, result, field, |bytes| {
            write_required(bytes.len());
            if bytes.len() > capacity {
                return SAS_PAIRING_BUFFER_TOO_SMALL;
            }
            if !bytes.is_empty() {
                // SAFETY: `bytes.len() <= capacity`, so `buffer` is non-null (a null buffer has
                // capacity 0) and its validated range holds the copy; the caller guarantees the
                // bytes writable and unaliased for this call. The source is the runtime's own
                // result storage, which no caller memory overlaps.
                unsafe { ptr::copy_nonoverlapping(bytes.as_ptr(), buffer, bytes.len()) };
            }
            SAS_PAIRING_OK
        });
        copied.unwrap_or_else(|status| status)
    })
}

/// Destroys `result`: its handle is invalid forever once this returns and the immutable result
/// is dropped. ABI-owned data cleanup: allowed in the fatal state, never entering the core.
#[unsafe(no_mangle)]
pub extern "C" fn sas_pairing_result_destroy(runtime: RuntimeHandle, result: ResultHandle) -> i32 {
    dispatch(SAS_PAIRING_FATAL, |state| {
        state.destroy_result(runtime, result)
    })
}
