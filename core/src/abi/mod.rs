//! Language-neutral native ABI, version 1 (P7). Compiled only with the `native-abi` feature;
//! the C contract is `core/include/sas_pairing.h` and `docs/p7-native-abi/abi-contract.md`.
//!
//! The ABI lives inside the core crate so later increments can call the reviewed crate-private
//! core directly; nothing here widens the public Rust API. Only fixed-width integers and raw
//! pointers to caller-owned memory cross the boundary; no Rust allocation, reference, `bool`,
//! enum, `Result`, or object pointer does. Every export enters Rust work through [`dispatch`],
//! the one panic-containment boundary (P6-D-004).
//!
//! Argument precedence for every export (contract §15.7): raw-memory validation, then output slots
//! set to their invalid values, then the fatal state (normal operations only), then the runtime
//! handle, then the authority handle, then the core.

// A caught panic is the containment model, so the supported artifact must unwind (P6-D-004
// item 12). Profile settings can be overridden, so the build itself refuses `panic = "abort"`.
#[cfg(not(panic = "unwind"))]
compile_error!(
    "the `native-abi` feature requires panic = \"unwind\": P6-D-004 panic containment cannot \
     work under panic = \"abort\""
);

mod authority;
mod panic_boundary;
mod runtime;
mod status;
#[cfg(test)]
mod tests;

use std::slice;

use authority::{AuthorityHandle, SAS_PAIRING_AUTHORITY_STATE_INVALID};
use runtime::AbiState;
use status::{SAS_PAIRING_FATAL, SAS_PAIRING_INVALID_ARGUMENT, SAS_PAIRING_OK};

/// The native ABI version. Not the protocol profile version and not the crate version.
const ABI_VERSION: u32 = 1;
/// Never a successful ABI version; returned only if the version query itself panicked.
const INVALID_ABI_VERSION: u32 = 0;

/// `sas_pairing_runtime_t`: an opaque process-local handle; `0` is never valid.
type RuntimeHandle = u64;

/// The one native ABI state of this OS process. It is never reset.
static PROCESS: AbiState = AbiState::new();

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
        let scope: &[u8] = if scope_len == 0 {
            &[]
        } else {
            // SAFETY: `scope` is non-null (checked above), `u8` needs no alignment, the length
            // fits `isize` and the range does not wrap the address space (checked above), and
            // the caller guarantees `scope_len` readable bytes left unmutated for this call.
            // The slice is borrowed only until `register_authority` returns; the core copies
            // the bytes into its own identity and keeps no reference.
            unsafe { slice::from_raw_parts(scope, scope_len) }
        };
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
    if scope_len == 0 {
        return true;
    }
    if isize::try_from(scope_len).is_err() {
        return false;
    }
    let Some(scope_end) = scope.addr().checked_add(scope_len) else {
        return false;
    };
    let out_start = out.addr();
    let Some(out_end) = out_start.checked_add(size_of::<AuthorityHandle>()) else {
        return false;
    };
    scope_end <= out_start || out_end <= scope.addr()
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
