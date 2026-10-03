//! Windows listener ownership through the native ABI (P7-D-006, P7-D-007).
//!
//! Trusted outer code binds a listener (address, interface, port, exposure, firewall, and
//! discovery are all its decisions) and hands the already-bound Windows `SOCKET` to a host
//! through an in/out slot. The ABI adopts it at one linearization point ([`ListenerSlot::adopt`]):
//! before it, every failure leaves the socket with the caller and the slot unchanged; from it on,
//! Rust owns and closes the socket and the slot holds `SAS_PAIRING_SOCKET_INVALID`. The socket is
//! an OS resource handed in, not a handle of the ABI's counter, and it enters no protocol,
//! authorization, routing, limiter, or accounting decision.
//!
//! Attach builds the reviewed `WindowsOwnerLoop` over the host's router and stores it; it drives
//! nothing (no accept, poll, session, or event). Detach ends it. No thread, timer, or callback is
//! created.

use std::{marker::PhantomData, num::NonZeroU64};

#[cfg(all(test, windows))]
use std::cell::Cell;
#[cfg(windows)]
use std::{
    net::TcpListener,
    os::windows::io::{FromRawSocket, RawSocket},
};

#[cfg(not(windows))]
use super::status::SAS_PAIRING_UNSUPPORTED_PLATFORM;
#[cfg(windows)]
use super::status::{
    SAS_PAIRING_INVALID_BOOTSTRAP, SAS_PAIRING_LISTENER_ALREADY_ATTACHED,
    SAS_PAIRING_LISTENER_SETUP_FAILED, SAS_PAIRING_OWNERSHIP_UNCERTAIN,
};
use super::{
    BootstrapInput,
    hosting::CloseError,
    runtime::{AbiState, Admission},
    status::{SAS_PAIRING_FATAL, SAS_PAIRING_INVALID_HANDLE, SAS_PAIRING_OK},
};
#[cfg(windows)]
use crate::windows_owner_loop::OwnerLoopError;

/// `sas_pairing_socket_t`: a Windows `SOCKET` value (`uintptr_t`). An OS resource handed to the
/// ABI, never a handle of the ABI's counter.
pub(super) type SocketHandle = usize;

/// `SAS_PAIRING_SOCKET_INVALID`: `UINTPTR_MAX`, Windows `INVALID_SOCKET`. Never adopted; written
/// to the caller's slot at the moment ownership transfers.
pub(super) const SAS_PAIRING_SOCKET_INVALID: SocketHandle = SocketHandle::MAX;

#[cfg(windows)]
const _: () =
    assert!(SAS_PAIRING_SOCKET_INVALID == windows_sys::Win32::Networking::WinSock::INVALID_SOCKET);

/// The caller's in/out listener slot and the socket it held at entry, structurally validated
/// and not yet adopted. Until [`ListenerSlot::adopt`] runs, the socket is the caller's.
#[cfg_attr(
    not(windows),
    expect(dead_code, reason = "nothing is adopted off Windows")
)]
pub(super) struct ListenerSlot<'a> {
    slot: *mut SocketHandle,
    socket: SocketHandle,
    _call: PhantomData<&'a mut SocketHandle>,
}

impl ListenerSlot<'_> {
    /// # Safety
    ///
    /// `slot` is non-null, aligned, and addresses the caller's writable `sas_pairing_socket_t`,
    /// not accessed by anyone else for the duration of the call. `socket` is the value it held at
    /// entry and is not `SAS_PAIRING_SOCKET_INVALID`. Trusted caller precondition (contract
    /// §17.3): `socket` is one valid, already-bound Windows listening `SOCKET`, owned exclusively
    /// by the caller at entry, and not closed or used by anyone else during the call. The ABI
    /// cannot verify that an integer is such a socket.
    pub(super) unsafe fn new(slot: *mut SocketHandle, socket: SocketHandle) -> Self {
        Self {
            slot,
            socket,
            _call: PhantomData,
        }
    }

    /// THE ownership linearization point (contract §17.4): the socket becomes one Rust-owned
    /// `TcpListener`, and the caller's slot becomes `SAS_PAIRING_SOCKET_INVALID`, with nothing
    /// that can fail or panic between the two: an integer conversion, then a constructor that
    /// only wraps the value, then one plain write. From here on Rust closes the socket exactly
    /// once, when that listener (or the owner loop it moves into) drops; the caller never
    /// closes or uses it again.
    #[cfg(windows)]
    pub(super) fn adopt(self) -> TcpListener {
        // A Windows SOCKET is pointer-sized; `RawSocket` (`u64`) holds every value.
        let raw = self.socket as RawSocket;
        // SAFETY: by the constructor's contract, `raw` is one valid listening SOCKET that the
        // caller owned exclusively at entry and that nobody closes or uses during the call. Its
        // ownership moves into this one `TcpListener` (no duplicate handle is created, and no
        // other Rust owner exists); the write below then tells the caller it no longer owns
        // it. The listener closes it exactly once when dropped, and nothing keeps the value
        // after that.
        let listener = unsafe { TcpListener::from_raw_socket(raw) };
        // SAFETY: `slot` is non-null, aligned, and the caller's writable, unaliased slot for this
        // call (constructor contract). `usize` has no invalid bit pattern and no destructor.
        unsafe { self.slot.write(SAS_PAIRING_SOCKET_INVALID) };
        listener
    }
}

#[cfg(all(test, windows))]
thread_local! {
    /// Runs right after adoption and before the owner loop is built, on this thread (tests
    /// only): an injected panic there must leave exactly one owner of the socket.
    pub(super) static ADOPTION_FAULT: Cell<Option<fn()>> = const { Cell::new(None) };
}

/// The narrow translation of a `WindowsOwnerLoop::from_bound_listener` failure. Its one
/// documented failure, the listener cannot be made nonblocking, is `LISTENER_SETUP_FAILED`;
/// anything else breaks the constructor's invariant and is fatal.
#[cfg(windows)]
pub(super) fn owner_loop_creation_status(error: &OwnerLoopError) -> i32 {
    match error {
        OwnerLoopError::ListenerIo(_) => SAS_PAIRING_LISTENER_SETUP_FAILED,
        OwnerLoopError::Closed
        | OwnerLoopError::UnknownConnection
        | OwnerLoopError::Poll(_)
        | OwnerLoopError::OwnershipUncertain
        | OwnerLoopError::Connection(_) => SAS_PAIRING_FATAL,
    }
}

/// The narrow translation of a network context's close report. `close` reports only
/// `OwnershipUncertain` (a connection's cleanup could not be established; the core keeps that
/// capacity held) or `Closed` (it had already failed closed, so nothing was left to close);
/// anything else breaks its invariant and is fatal.
pub(super) fn network_close_status(closed: &Result<(), CloseError>) -> i32 {
    #[cfg(windows)]
    match closed {
        Ok(()) | Err(OwnerLoopError::Closed) => SAS_PAIRING_OK,
        Err(OwnerLoopError::OwnershipUncertain) => SAS_PAIRING_OWNERSHIP_UNCERTAIN,
        Err(
            OwnerLoopError::UnknownConnection
            | OwnerLoopError::ListenerIo(_)
            | OwnerLoopError::Poll(_)
            | OwnerLoopError::Connection(_),
        ) => SAS_PAIRING_FATAL,
    }
    #[cfg(not(windows))]
    match closed {
        Ok(()) => SAS_PAIRING_OK,
        Err(never) => match *never {},
    }
}

impl AbiState {
    /// Maps a network close report, marking the process fatal for a broken invariant.
    pub(super) fn network_close_status(&self, closed: Result<(), CloseError>) -> i32 {
        let status = network_close_status(&closed);
        if status == SAS_PAIRING_FATAL {
            self.fatal.mark();
        }
        status
    }

    /// Attaches the caller's already-bound listener to `host` (contract §17.5).
    ///
    /// Order: the Bootstrap configuration (copied, then `Bootstrap::new`), the fatal state and
    /// runtime (through `with_runtime`), the host, an existing network context; every one of
    /// these leaves the socket with the caller. Then adoption, then the owner loop, then
    /// installation. Nothing is driven.
    #[cfg(windows)]
    pub(super) fn attach_listener(
        &self,
        runtime: u64,
        host: u64,
        slot: ListenerSlot<'_>,
        local: &BootstrapInput<'_>,
        expected: Option<&BootstrapInput<'_>>,
    ) -> i32 {
        let Some(local) = local.to_bootstrap() else {
            return SAS_PAIRING_INVALID_BOOTSTRAP;
        };
        let expected = match expected.map(BootstrapInput::to_bootstrap) {
            None => None,
            Some(Some(expected)) => Some(expected),
            Some(None) => return SAS_PAIRING_INVALID_BOOTSTRAP,
        };
        let attached = self.with_runtime(runtime, Admission::Normal, |live| {
            let handle = NonZeroU64::new(host).ok_or(SAS_PAIRING_INVALID_HANDLE)?;
            let context = live
                .hosts
                .get_mut(&handle)
                .ok_or(SAS_PAIRING_INVALID_HANDLE)?;
            if context.has_network() {
                return Err(SAS_PAIRING_LISTENER_ALREADY_ATTACHED);
            }
            // Ownership transfers here. Every failure after this line leaves the slot INVALID,
            // and the Rust listener (or the owner loop it moved into) closes the socket.
            let listener = slot.adopt();
            #[cfg(test)]
            if let Some(fault) = ADOPTION_FAULT.take() {
                fault();
            }
            context
                .attach_network(listener, local, expected)
                .map_err(|error| {
                    let status = owner_loop_creation_status(&error);
                    if status == SAS_PAIRING_FATAL {
                        self.fatal.mark();
                    }
                    status
                })
        });
        match attached {
            Ok(()) => SAS_PAIRING_OK,
            Err(status) => status,
        }
    }

    /// Off Windows no listener can be attached: nothing is read, copied, adopted, or created,
    /// and the caller's slot is left unchanged.
    #[cfg(not(windows))]
    pub(super) fn attach_listener(
        &self,
        runtime: u64,
        host: u64,
        slot: ListenerSlot<'_>,
        local: &BootstrapInput<'_>,
        expected: Option<&BootstrapInput<'_>>,
    ) -> i32 {
        let _ = (self, runtime, host, slot, local, expected);
        SAS_PAIRING_UNSUPPORTED_PLATFORM
    }

    /// Detaches `host`'s listener, if any: its network context leaves the host first, then the
    /// owner loop closes the listener and every connection while the router is alive. The host,
    /// router, authority, and accounting stay. Cleanup: admitted after fatal, idempotent (`OK`
    /// without a network context), and it never clears fatal.
    pub(super) fn detach_listener(&self, runtime: u64, host: u64) -> i32 {
        let detached = self.with_runtime(runtime, Admission::Cleanup, |live| {
            let handle = NonZeroU64::new(host).ok_or(SAS_PAIRING_INVALID_HANDLE)?;
            let context = live
                .hosts
                .get_mut(&handle)
                .ok_or(SAS_PAIRING_INVALID_HANDLE)?;
            Ok(context.detach_network())
        });
        match detached {
            Ok(closed) => self.network_close_status(closed),
            Err(status) => status,
        }
    }
}
