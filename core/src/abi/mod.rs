//! Language-neutral native ABI, version 1 (P7). Compiled only with the `native-abi` feature;
//! the C contract is `core/include/sas_pairing.h` and `docs/p7-native-abi/abi-contract.md`.
//!
//! The ABI lives inside the core crate so later increments can call the reviewed crate-private
//! core directly; nothing here widens the public Rust API. Only fixed-width integers and raw
//! pointers to caller-owned memory cross the boundary; no Rust allocation, reference, `bool`,
//! enum, `Result`, or object pointer does. Every export enters Rust work through [`dispatch`],
//! the one panic-containment boundary (P6-D-004).

// A caught panic is the containment model, so the supported artifact must unwind (P6-D-004
// item 12). Profile settings can be overridden, so the build itself refuses `panic = "abort"`.
#[cfg(not(panic = "unwind"))]
compile_error!(
    "the `native-abi` feature requires panic = \"unwind\": P6-D-004 panic containment cannot \
     work under panic = \"abort\""
);

mod panic_boundary;
mod runtime;
mod status;
#[cfg(test)]
mod tests;

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
