use std::{
    collections::{HashMap, HashSet},
    fmt,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

#[cfg(feature = "native-abi")]
mod abi;
mod ceremony;
mod crypto;
mod deadline;
mod host;
pub mod protocol;
mod request_id;
mod router;
mod start_limiter;
#[cfg(test)]
mod test_hook;
mod transport;
#[cfg(windows)]
mod windows_owner_loop;
#[cfg(windows)]
mod windows_tcp;

use deadline::{Clock, system_clock};
use start_limiter::{StartAdmission, StartLimiter};

const DOMAIN: &[u8] = b"sas-pairing-authority-v1";
const MAX_OPPORTUNITIES: u8 = 10;
/// P3 §11.1.1: accepted but unexposed Responder runs per authority.
const MAX_PENDING_RESPONDERS: usize = 4;
/// P3 §11.1.1: concurrent expensive preliminary operations per authority.
const MAX_PRELIMINARY_OPERATIONS: usize = 2;
/// The process-wide authority registry (P3 §11.1.2(3)), keyed only by canonical identity. An
/// entry is created by the first successful OS ownership of that identity and is never removed:
/// its accounting lives until the OS process terminates (P6-D-002).
static REGISTRY: OnceLock<Mutex<HashMap<Vec<u8>, ProcessSession>>> = OnceLock::new();
static NEXT_CEREMONY: AtomicU64 = AtomicU64::new(1);
static NEXT_AUTHORIZATION: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    InvalidScope,
    AlreadyRegistered,
    OwnershipUnavailable,
    UnsupportedPlatform,
    OwnershipUncertain,
    Busy,
    MissingAuthorization,
    StaleAuthorization,
    Exhausted,
    Terminated,
    /// Generic pre-exposure resource/admission refusal. It says nothing about authentication,
    /// SAS mismatch, compromise, or the opportunity budget, and never spends or refunds one.
    ResourceLimited,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for Error {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Initiator,
    Responder,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Ready { remaining: u8 },
    Busy,
    Exhausted,
}

/// Trusted local configuration owns this type and is the only authorization issuer.
/// Its scope is never accepted from a network message.
pub struct TrustedAuthority(Arc<State>);

/// Give this restricted handle to ceremony execution, never the trusted handle.
///
/// ```compile_fail
/// use sas_pairing_core::{Role, TrustedAuthority};
/// let trusted = TrustedAuthority::register(b"scope").unwrap();
/// let executor = trusted.executor();
/// let mut ceremony = executor.begin(Role::Initiator).unwrap();
/// executor.authorize(&mut ceremony).unwrap();
/// ```
#[derive(Clone)]
pub struct CeremonyExecutor(Arc<State>);

impl fmt::Debug for TrustedAuthority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TrustedAuthority").finish_non_exhaustive()
    }
}

impl fmt::Debug for CeremonyExecutor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CeremonyExecutor").finish_non_exhaustive()
    }
}

/// One active registration: this process currently holds the authority's OS lease. Registrations
/// come and go inside one process; the accounting they use belongs to the process session.
struct State {
    identity: Vec<u8>,
    /// The process session's one accounting state, shared with the registry entry.
    shared: Arc<Mutex<Shared>>,
    ownership: Mutex<Option<os_lock::Lease>>,
    /// The authority's one monotonic START-limiter clock for its whole process session, so all
    /// limiter instants share one origin across registrations. Never a ceremony's clock; never
    /// wall-clock time. Read only while `shared` is held; it must never take `shared` itself.
    limiter_clock: Clock,
    /// Whether this registration has yet to end (release its lease, settle the registry entry).
    live: bool,
}

/// Whether a process session's authority is currently registered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Registration {
    /// No registration and no lease; the accounting waits for the next registration.
    Inactive,
    /// One registration holds the OS lease.
    Active,
    /// Releasing the lease was uncertain: registration fails closed until process replacement.
    Uncertain,
}

/// The process-session state of one canonical authority this process has owned (P6-D-002). The
/// registry holds it strongly, so no release, drop, idle time, or failed reacquisition ends it;
/// only process termination does. It is never persisted.
struct ProcessSession {
    /// Opportunity budget, START limiter, and the active registration's runtime resources, in
    /// the one mutex that keeps guard and opportunity reservation atomic.
    shared: Arc<Mutex<Shared>>,
    /// Selected when the session is created and reused by every later registration.
    limiter_clock: Clock,
    registration: Registration,
}

struct Shared {
    remaining: u8,
    active: Option<u64>,
    /// Honestly generated request IDs of live local Initiator ceremonies of this authority.
    /// Volatile pre-exposure routing state: never persisted, never peer IDs, never authority.
    initiator_request_ids: HashSet<[u8; 16]>,
    /// Accepted but unexposed Responder runs; each slot is owned by exactly one `Ceremony`.
    /// Separate from `active`, which remains exclusively the exposed-ceremony guard.
    pending_responders: usize,
    /// Expensive preliminary operations in progress, each held by one `PreliminaryPermit`.
    preliminary_operations: usize,
    /// The authority-wide START admission limiter. Volatile, never persisted, never reset by
    /// any ceremony, connection, refusal, release, or re-registration event; only a new process
    /// session (a new OS process that safely acquires ownership) starts it fresh.
    start_limiter: StartLimiter,
    /// P3 §11.1.1 transport admission, shared by every router and listener of this authority
    /// (see `transport`): adapter accept-work tasks not yet turned into live connections, each
    /// held by one `AcceptPermit`.
    pending_accepts: usize,
    /// Live unauthenticated transport connections, each counted from activation until its
    /// Router session teardown is certain. An uncertain teardown keeps its count for good.
    live_connections: usize,
    /// Retained incomplete transport frames, each owned by one connection's assembler.
    incomplete_frames: usize,
}

impl Shared {
    /// A new process session: ten opportunities, a fresh START limiter, no runtime resources.
    fn new() -> Self {
        Self {
            remaining: MAX_OPPORTUNITIES,
            active: None,
            initiator_request_ids: HashSet::new(),
            pending_responders: 0,
            preliminary_operations: 0,
            start_limiter: StartLimiter::new(),
            pending_accepts: 0,
            live_connections: 0,
            incomplete_frames: 0,
        }
    }

    /// Whether every runtime resource of past registrations was released. The budget and the
    /// limiter are not runtime resources and carry over unchanged.
    fn quiescent(&self) -> bool {
        self.active.is_none()
            && self.initiator_request_ids.is_empty()
            && self.pending_responders == 0
            && self.preliminary_operations == 0
            && self.pending_accepts == 0
            && self.live_connections == 0
            && self.incomplete_frames == 0
    }

    /// Releases a ceremony's request-ID reservation, if any, exactly once.
    fn release_request_id(&mut self, owned: &mut Option<[u8; 16]>) {
        if let Some(request_id) = owned.take() {
            self.initiator_request_ids.remove(&request_id);
        }
    }

    /// Releases a ceremony's pending Responder slot, if any, exactly once.
    fn release_pending_responder(&mut self, owned: &mut Option<Duration>) {
        if owned.take().is_some() {
            self.pending_responders -= 1;
        }
    }
}

/// Outcome of one atomic check-and-reserve of a generated Initiator request ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RequestIdReservation {
    Reserved,
    /// Another live local Initiator of this authority holds it; nothing changed.
    Collision,
    /// Only an Initiator ceremony without a reservation may reserve; nothing changed.
    NotEligible,
}

/// Outcome of one atomic check-and-acquire of a pending Responder slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PendingAdmission {
    Admitted,
    /// Only a Responder ceremony without a slot may acquire one; nothing changed.
    NotEligible,
}

/// Outcome of one atomic authority START limiter decision for a new Responder candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StartLimit {
    /// Both components permitted and both are charged; the charge is never refunded.
    Admitted,
    /// Generic refusal by either component; nothing was charged.
    Refused,
    /// The limiter clock was unusable: refused with the limiter state unchanged.
    UnsafeClock,
    /// Only a Responder ceremony without a pending slot may present a candidate; no change.
    NotEligible,
}

/// One of the authority's bounded expensive preliminary operations (P3 §11.1.1). Hold it only
/// around the operation itself; dropping it releases the count exactly once. With poisoned
/// shared state the count stays conservatively held.
pub(crate) struct PreliminaryPermit(Arc<State>);

impl Drop for PreliminaryPermit {
    fn drop(&mut self) {
        if let Ok(mut shared) = self.0.shared.lock() {
            shared.preliminary_operations -= 1;
        }
    }
}

fn registry() -> &'static Mutex<HashMap<Vec<u8>, ProcessSession>> {
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

impl State {
    /// Ends this registration once: releases the OS lease, then marks its process session
    /// inactive, or uncertain if the release was. The session's accounting is kept either way.
    /// Takes the registry lock with no other lock held; it never takes `shared`.
    fn end(&mut self) -> Result<(), Error> {
        if !std::mem::replace(&mut self.live, false) {
            return Ok(());
        }
        let released = match self.ownership.get_mut() {
            Ok(lease) => lease.take().map_or(Ok(()), os_lock::Lease::release),
            Err(_) => Err(Error::OwnershipUncertain),
        };
        // A poisoned registry fails every later registration closed, so nothing is lost.
        if let Ok(mut sessions) = registry().lock()
            && let Some(session) = sessions.get_mut(&self.identity)
        {
            session.registration = match released {
                Ok(()) => Registration::Inactive,
                Err(_) => Registration::Uncertain,
            };
        }
        released
    }
}

impl Drop for State {
    fn drop(&mut self) {
        let _ = self.end();
    }
}

pub struct Ceremony {
    authority: CeremonyExecutor,
    id: u64,
    role: Role,
    authorization: Option<u64>,
    terminal: bool,
    /// At most one generated request ID, owned by this ceremony until terminal cleanup or drop.
    request_id: Option<[u8; 16]>,
    /// At most one pending Responder slot, holding its monotonic admission instant. Owned by
    /// this ceremony until it crosses exposure, terminal cleanup, or drop; never transferred.
    pending_responder: Option<Duration>,
}

pub struct Authorization {
    ceremony: u64,
    seal: u64,
}

impl fmt::Debug for Authorization {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Authorization").finish_non_exhaustive()
    }
}

impl TrustedAuthority {
    /// Registers one canonical scope. The trusted registry must issue one stable scope per capability.
    ///
    /// The opportunity budget and START limiter belong to this process's session for the
    /// authority, not to the registration (P3 §11.1, P6-D-002): registering again after a
    /// release or the final drop reacquires the OS lease and continues the same accounting.
    /// Only a new OS process that safely acquires ownership starts fresh.
    pub fn register(scope: &[u8]) -> Result<Self, Error> {
        Self::register_with(scope, system_clock)
    }

    /// `register` with one injected authority START-limiter clock (tests only; registration
    /// succeeds only where an ownership lease exists). The clock takes effect only when this
    /// call creates the process session; a later registration of the same authority keeps the
    /// session's original clock and ignores `clock`, so no registration rewrites the timeline.
    #[cfg(all(test, windows))]
    pub(crate) fn register_with_limiter_clock(scope: &[u8], clock: Clock) -> Result<Self, Error> {
        Self::register_with(scope, move || clock)
    }

    fn register_with(scope: &[u8], limiter_clock: impl FnOnce() -> Clock) -> Result<Self, Error> {
        if scope.is_empty() || scope.len() > u32::MAX as usize {
            return Err(Error::InvalidScope);
        }
        let mut identity = DOMAIN.to_vec();
        identity.extend_from_slice(&(scope.len() as u32).to_be_bytes());
        identity.extend_from_slice(scope);
        // ponytail: one registry mutex serializes authority registration; shard only if contention is measured.
        // Lock order: registry, then a session's `shared`; nothing takes the registry while
        // holding `shared`.
        let mut sessions = registry().lock().map_err(|_| Error::OwnershipUncertain)?;
        let (shared, limiter_clock, lease) = match sessions.get_mut(&identity) {
            Some(session) => {
                match session.registration {
                    Registration::Active => return Err(Error::AlreadyRegistered),
                    Registration::Uncertain => return Err(Error::OwnershipUncertain),
                    Registration::Inactive => {}
                }
                // Reactivation never resets or repairs: runtime resources an earlier
                // registration left held (only after poisoning or an uncertain teardown) or
                // poisoned accounting fail closed until process replacement.
                if !matches!(
                    session.shared.lock().map(|shared| shared.quiescent()),
                    Ok(true)
                ) {
                    return Err(Error::OwnershipUncertain);
                }
                // Same accounting, but OS ownership is acquired anew; a failure leaves the
                // session inactive with its accounting unchanged.
                let lease = os_lock::Lease::acquire(&identity)?;
                session.registration = Registration::Active;
                (session.shared.clone(), session.limiter_clock.clone(), lease)
            }
            None => {
                // A failed first acquisition establishes no ownership and creates no session.
                let lease = os_lock::Lease::acquire(&identity)?;
                let session = ProcessSession {
                    shared: Arc::new(Mutex::new(Shared::new())),
                    limiter_clock: limiter_clock(),
                    registration: Registration::Active,
                };
                let parts = (session.shared.clone(), session.limiter_clock.clone(), lease);
                sessions.insert(identity.clone(), session);
                parts
            }
        };
        Ok(Self(Arc::new(State {
            identity,
            shared,
            ownership: Mutex::new(Some(lease)),
            limiter_clock,
            live: true,
        })))
    }

    pub fn canonical_identity(&self) -> &[u8] {
        &self.0.identity
    }

    /// Create the limited interface intended for untrusted protocol execution.
    pub fn executor(&self) -> CeremonyExecutor {
        CeremonyExecutor(self.0.clone())
    }

    /// Local application boundary: issue ceremony-specific consent after user approval.
    pub fn authorize(&self, ceremony: &mut Ceremony) -> Result<Authorization, Error> {
        if ceremony.terminal {
            return Err(Error::Terminated);
        }
        if !Arc::ptr_eq(&self.0, &ceremony.authority.0) {
            return Err(Error::StaleAuthorization);
        }
        let seal = NEXT_AUTHORIZATION
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
            .map_err(|_| Error::OwnershipUncertain)?;
        ceremony.authorization = Some(seal);
        Ok(Authorization {
            ceremony: ceremony.id,
            seal,
        })
    }

    /// Explicit release is preferred; dropping the final handle releases the OS lease the same
    /// way. Either ends only this registration: the process session's budget and START limiter
    /// stay, and an uncertain release disables registration until process replacement.
    pub fn release(self) -> Result<(), Error> {
        let mut state = Arc::try_unwrap(self.0).map_err(|_| Error::Busy)?;
        state.end()
    }
}

impl CeremonyExecutor {
    pub fn begin(&self, role: Role) -> Result<Ceremony, Error> {
        let id = NEXT_CEREMONY
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
            .map_err(|_| Error::OwnershipUncertain)?;
        Ok(Ceremony {
            authority: self.clone(),
            id,
            role,
            authorization: None,
            terminal: false,
            request_id: None,
            pending_responder: None,
        })
    }

    /// Atomically checks and reserves `candidate` in this authority's active local Initiator
    /// request-ID namespace for `ceremony`, in one critical section. It touches neither the
    /// exposed-ceremony guard nor the opportunity budget, and authorizes nothing.
    pub(crate) fn reserve_request_id(
        &self,
        ceremony: &mut Ceremony,
        candidate: [u8; 16],
    ) -> Result<RequestIdReservation, Error> {
        if ceremony.terminal {
            return Err(Error::Terminated);
        }
        if !Arc::ptr_eq(&self.0, &ceremony.authority.0) {
            return Err(Error::StaleAuthorization);
        }
        if ceremony.role != Role::Initiator || ceremony.request_id.is_some() {
            return Ok(RequestIdReservation::NotEligible);
        }
        let mut shared = self
            .0
            .shared
            .lock()
            .map_err(|_| Error::OwnershipUncertain)?;
        if !shared.initiator_request_ids.insert(candidate) {
            return Ok(RequestIdReservation::Collision);
        }
        ceremony.request_id = Some(candidate);
        Ok(RequestIdReservation::Reserved)
    }

    /// Atomically acquires one of this authority's pending Responder slots for `ceremony`,
    /// recording `admitted` (an already-read monotonic instant) as its admission time. It
    /// touches neither the exposed-ceremony guard nor the opportunity budget.
    pub(crate) fn admit_pending_responder(
        &self,
        ceremony: &mut Ceremony,
        admitted: Duration,
    ) -> Result<PendingAdmission, Error> {
        if ceremony.terminal {
            return Err(Error::Terminated);
        }
        if !Arc::ptr_eq(&self.0, &ceremony.authority.0) {
            return Err(Error::StaleAuthorization);
        }
        if ceremony.role != Role::Responder || ceremony.pending_responder.is_some() {
            return Ok(PendingAdmission::NotEligible);
        }
        let mut shared = self
            .0
            .shared
            .lock()
            .map_err(|_| Error::OwnershipUncertain)?;
        if shared.pending_responders >= MAX_PENDING_RESPONDERS {
            return Err(Error::ResourceLimited);
        }
        shared.pending_responders += 1;
        ceremony.pending_responder = Some(admitted);
        Ok(PendingAdmission::Admitted)
    }

    /// The Responder crossed its exposure boundary: it is no longer pending pre-exposure state.
    pub(crate) fn release_pending_responder(&self, ceremony: &mut Ceremony) -> Result<(), Error> {
        if !Arc::ptr_eq(&self.0, &ceremony.authority.0) {
            return Err(Error::StaleAuthorization);
        }
        let mut shared = self
            .0
            .shared
            .lock()
            .map_err(|_| Error::OwnershipUncertain)?;
        shared.release_pending_responder(&mut ceremony.pending_responder);
        Ok(())
    }

    /// One atomic authority-wide START limiter decision for a new Responder candidate that
    /// `ceremony` is about to process (P3 §11.1.1). Under the shared lock it reads the
    /// authority's limiter clock, applies elapsed-time bookkeeping, and admits only if both the
    /// burst and rolling components permit, charging both; otherwise it charges neither. An
    /// admission is final: no later outcome refunds it. It never waits or queues and touches
    /// neither the guard, the opportunity budget, the pending slots, nor the permits.
    pub(crate) fn admit_start(&self, ceremony: &Ceremony) -> Result<StartLimit, Error> {
        if ceremony.terminal {
            return Err(Error::Terminated);
        }
        if !Arc::ptr_eq(&self.0, &ceremony.authority.0) {
            return Err(Error::StaleAuthorization);
        }
        if ceremony.role != Role::Responder || ceremony.pending_responder.is_some() {
            return Ok(StartLimit::NotEligible);
        }
        let mut shared = self
            .0
            .shared
            .lock()
            .map_err(|_| Error::OwnershipUncertain)?;
        // `now` is read inside the decision, so readings are ordered with the state they change.
        let now = self.0.limiter_clock.now();
        Ok(match shared.start_limiter.admit(now) {
            StartAdmission::Admitted => StartLimit::Admitted,
            StartAdmission::Refused => StartLimit::Refused,
            StartAdmission::UnsafeClock => StartLimit::UnsafeClock,
        })
    }

    /// Read-only view of this authority's START limiter (tests only).
    #[cfg(all(test, windows))]
    pub(crate) fn start_limiter_snapshot(&self) -> start_limiter::StartLimiterSnapshot {
        self.0.shared.lock().unwrap().start_limiter.snapshot()
    }

    /// Immediately takes one of this authority's expensive-operation permits, or refuses with
    /// `ResourceLimited`; it never waits or queues. The lock covers only the accounting.
    pub(crate) fn preliminary_permit(&self) -> Result<PreliminaryPermit, Error> {
        let mut shared = self
            .0
            .shared
            .lock()
            .map_err(|_| Error::OwnershipUncertain)?;
        if shared.preliminary_operations >= MAX_PRELIMINARY_OPERATIONS {
            return Err(Error::ResourceLimited);
        }
        shared.preliminary_operations += 1;
        Ok(PreliminaryPermit(self.0.clone()))
    }

    /// Acquires the shared guard and burns one opportunity in one critical section.
    pub fn reserve(
        &self,
        ceremony: &mut Ceremony,
        authorization: Option<Authorization>,
    ) -> Result<u8, Error> {
        if ceremony.terminal {
            return Err(Error::Terminated);
        }
        let authorization = authorization.ok_or(Error::MissingAuthorization)?;
        if !Arc::ptr_eq(&self.0, &ceremony.authority.0)
            || authorization.ceremony != ceremony.id
            || ceremony.authorization != Some(authorization.seal)
        {
            return Err(Error::StaleAuthorization);
        }
        ceremony.authorization = None;
        let mut shared = self
            .0
            .shared
            .lock()
            .map_err(|_| Error::OwnershipUncertain)?;
        if shared.active.is_some() {
            return Err(Error::Busy);
        }
        if shared.remaining == 0 {
            return Err(Error::Exhausted);
        }
        shared.remaining -= 1;
        shared.active = Some(ceremony.id);
        Ok(shared.remaining)
    }

    pub fn terminate(&self, ceremony: &mut Ceremony) -> Result<(), Error> {
        if ceremony.terminal {
            return Err(Error::Terminated);
        }
        if !Arc::ptr_eq(&self.0, &ceremony.authority.0) {
            return Err(Error::StaleAuthorization);
        }
        let mut shared = self
            .0
            .shared
            .lock()
            .map_err(|_| Error::OwnershipUncertain)?;
        // Make terminal state irreversible before the authority-wide slot can be reused.
        ceremony.authorization = None;
        ceremony.terminal = true;
        shared.release_request_id(&mut ceremony.request_id);
        shared.release_pending_responder(&mut ceremony.pending_responder);
        if shared.active == Some(ceremony.id) {
            shared.active = None;
        }
        Ok(())
    }

    pub fn status(&self) -> Result<Status, Error> {
        let shared = self
            .0
            .shared
            .lock()
            .map_err(|_| Error::OwnershipUncertain)?;
        Ok(if shared.active.is_some() {
            Status::Busy
        } else if shared.remaining == 0 {
            Status::Exhausted
        } else {
            Status::Ready {
                remaining: shared.remaining,
            }
        })
    }
}

impl Ceremony {
    pub fn role(&self) -> Role {
        self.role
    }
}

impl Drop for Ceremony {
    fn drop(&mut self) {
        self.authorization = None;
        self.terminal = true;
        // A poisoned lock leaves the guard, any request-ID reservation, and any pending
        // Responder slot conservatively held.
        if let Ok(mut shared) = self.authority.0.shared.lock() {
            shared.release_request_id(&mut self.request_id);
            shared.release_pending_responder(&mut self.pending_responder);
            if shared.active == Some(self.id) {
                shared.active = None;
            }
        }
    }
}

#[cfg(windows)]
mod os_lock {
    use super::Error;
    use sha2::{Digest, Sha256};
    use std::{
        fs::{self, File, OpenOptions},
        os::windows::fs::{MetadataExt, OpenOptionsExt},
        path::{Component, Path, PathBuf, Prefix},
    };
    use windows_sys::Win32::{
        Foundation::{CloseHandle, ERROR_LOCK_VIOLATION, HANDLE},
        Security::{
            GetLengthSid, GetTokenInformation, IsValidSid, TOKEN_QUERY, TOKEN_USER, TokenUser,
        },
        Storage::FileSystem::{
            FILE_FLAG_OPEN_REPARSE_POINT, LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY,
            LockFileEx, UnlockFileEx,
        },
        System::IO::OVERLAPPED,
        System::Threading::{GetCurrentProcess, OpenProcessToken},
        UI::Shell::GetUserProfileDirectoryW,
    };

    pub struct Lease {
        file: File,
        overlapped: OVERLAPPED,
    }

    // LockFileEx is synchronous here (the file handle is not opened for overlapped I/O).
    // The operation has completed before the lease moves between threads.
    unsafe impl Send for Lease {}

    #[cfg(test)]
    thread_local! {
        /// Test-only fault: the calling thread's next `release` reports an uncertain unlock
        /// without unlocking (closing the handle still frees the lock). Per thread, so parallel
        /// tests never see it.
        pub(crate) static FAIL_NEXT_RELEASE: std::cell::Cell<bool> =
            const { std::cell::Cell::new(false) };
    }

    impl Lease {
        pub fn acquire(identity: &[u8]) -> Result<Self, Error> {
            let (sid, profile) = authenticated_account()?;
            let dir = profile
                .join("AppData")
                .join("Local")
                .join("sas-pairing")
                .join("authority-locks");
            ensure_plain_directories(&dir)?;
            let mut account_identity = (sid.len() as u32).to_be_bytes().to_vec();
            account_identity.extend_from_slice(&sid);
            account_identity.extend_from_slice(identity);
            let name = format!("{}.lock", hex(&Sha256::digest(account_identity)));
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                // Without FILE_SHARE_DELETE, another process cannot unlink and replace this locked inode.
                .share_mode(0x0000_0003)
                .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
                .open(dir.join(name))
                .map_err(|_| Error::OwnershipUnavailable)?;
            ensure_regular_lock_file(&file)?;
            let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
            let acquired = unsafe {
                LockFileEx(
                    file.as_raw_handle() as HANDLE,
                    LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
                    0,
                    1,
                    0,
                    &mut overlapped,
                )
            };
            if acquired == 0 {
                let code = std::io::Error::last_os_error().raw_os_error();
                return Err(if code == Some(ERROR_LOCK_VIOLATION as i32) {
                    Error::OwnershipUnavailable
                } else {
                    Error::OwnershipUncertain
                });
            }
            Ok(Self { file, overlapped })
        }
        pub fn release(mut self) -> Result<(), Error> {
            #[cfg(test)]
            if FAIL_NEXT_RELEASE.take() {
                return Err(Error::OwnershipUncertain);
            }
            let ok = unsafe {
                UnlockFileEx(
                    self.file.as_raw_handle() as HANDLE,
                    0,
                    1,
                    0,
                    &mut self.overlapped,
                )
            };
            if ok == 0 {
                return Err(Error::OwnershipUncertain);
            }
            Ok(())
        }
    }
    use std::os::windows::io::AsRawHandle;

    pub(super) fn authenticated_account() -> Result<(Vec<u8>, PathBuf), Error> {
        let mut token: HANDLE = std::ptr::null_mut();
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
            return Err(Error::OwnershipUnavailable);
        }
        struct Token(HANDLE);
        impl Drop for Token {
            fn drop(&mut self) {
                unsafe { CloseHandle(self.0) };
            }
        }
        let token = Token(token);
        let mut size = 0;
        unsafe {
            GetTokenInformation(token.0, TokenUser, std::ptr::null_mut(), 0, &mut size);
        }
        if size == 0 {
            return Err(Error::OwnershipUnavailable);
        }
        let mut info = vec![0u8; size as usize];
        if unsafe {
            GetTokenInformation(
                token.0,
                TokenUser,
                info.as_mut_ptr().cast(),
                size,
                &mut size,
            )
        } == 0
        {
            return Err(Error::OwnershipUnavailable);
        }
        // The second call's returned size is the number of bytes written.
        if size as usize > info.len() {
            return Err(Error::OwnershipUnavailable);
        }
        info.truncate(size as usize);
        let sid = token_user_sid(&info)?;

        let mut chars = 0;
        unsafe { GetUserProfileDirectoryW(token.0, std::ptr::null_mut(), &mut chars) };
        if chars == 0 {
            return Err(Error::OwnershipUnavailable);
        }
        let mut profile = vec![0u16; chars as usize];
        if unsafe { GetUserProfileDirectoryW(token.0, profile.as_mut_ptr(), &mut chars) } == 0 {
            return Err(Error::OwnershipUnavailable);
        }
        profile.truncate(chars.saturating_sub(1) as usize);
        let profile = String::from_utf16(&profile).map_err(|_| Error::OwnershipUnavailable)?;
        Ok((sid, PathBuf::from(profile)))
    }

    /// Copies the SID out of `TokenUser` bytes written by `GetTokenInformation`.
    /// `info` is byte storage with no alignment guarantee for `TOKEN_USER`.
    pub(super) fn token_user_sid(info: &[u8]) -> Result<Vec<u8>, Error> {
        if info.len() < std::mem::size_of::<TOKEN_USER>() {
            return Err(Error::OwnershipUnavailable);
        }
        // SAFETY: `info` holds at least `size_of::<TOKEN_USER>()` initialized bytes, and
        // `read_unaligned` copies the header out without requiring `TOKEN_USER` alignment,
        // so no reference to `TOKEN_USER` is formed over the byte buffer. The copied header
        // is plain data whose `User.Sid` points into `info`, which stays borrowed (alive)
        // until the SID bytes below have been copied.
        let user = unsafe { std::ptr::read_unaligned(info.as_ptr().cast::<TOKEN_USER>()) };
        let sid = user.User.Sid;
        // SAFETY: `sid` is non-null and points into the still-borrowed `info`, as written by
        // Windows; `IsValidSid` validates the structure before its length is trusted.
        if sid.is_null() || unsafe { IsValidSid(sid) } == 0 {
            return Err(Error::OwnershipUnavailable);
        }
        // SAFETY: `sid` passed `IsValidSid` above.
        let sid_len = unsafe { GetLengthSid(sid) } as usize;
        if !(8..=68).contains(&sid_len) {
            return Err(Error::OwnershipUnavailable);
        }
        // SAFETY: a valid SID of `sid_len` bytes at `sid`, inside `info`, which outlives this
        // owned copy. `u8` has alignment 1.
        Ok(unsafe { std::slice::from_raw_parts(sid.cast::<u8>(), sid_len) }.to_vec())
    }

    pub(super) fn ensure_plain_directories(path: &Path) -> Result<(), Error> {
        if !path.is_absolute() {
            return Err(Error::OwnershipUnavailable);
        }
        if !matches!(path.components().next(), Some(Component::Prefix(prefix)) if matches!(prefix.kind(), Prefix::Disk(_)))
        {
            return Err(Error::OwnershipUnavailable);
        }
        let mut current = PathBuf::new();
        for component in path.components() {
            current.push(component);
            if matches!(component, Component::Prefix(_)) {
                continue;
            }
            match fs::symlink_metadata(&current) {
                Ok(metadata) => {
                    let attributes = metadata.file_attributes();
                    if attributes & 0x400 != 0 || attributes & 0x10 == 0 {
                        return Err(Error::OwnershipUnavailable);
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    fs::create_dir(&current).map_err(|_| Error::OwnershipUnavailable)?;
                    let metadata =
                        fs::symlink_metadata(&current).map_err(|_| Error::OwnershipUncertain)?;
                    let attributes = metadata.file_attributes();
                    if attributes & 0x400 != 0 || attributes & 0x10 == 0 {
                        return Err(Error::OwnershipUnavailable);
                    }
                }
                Err(_) => return Err(Error::OwnershipUncertain),
            }
        }
        Ok(())
    }

    pub(super) fn ensure_regular_lock_file(file: &File) -> Result<(), Error> {
        let attributes = file
            .metadata()
            .map_err(|_| Error::OwnershipUncertain)?
            .file_attributes();
        if attributes & 0x400 != 0 || attributes & 0x10 != 0 {
            return Err(Error::OwnershipUnavailable);
        }
        Ok(())
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}

#[cfg(not(windows))]
mod os_lock {
    use super::Error;
    pub struct Lease;
    impl Lease {
        pub fn acquire(_: &[u8]) -> Result<Self, Error> {
            Err(Error::UnsupportedPlatform)
        }
        pub fn release(self) -> Result<(), Error> {
            Err(Error::UnsupportedPlatform)
        }
    }
}

#[cfg(all(test, windows))]
mod windows_tests {
    use super::{Error, Role, TrustedAuthority, os_lock};
    use std::{
        fs::{self, OpenOptions},
        os::windows::fs::{OpenOptionsExt, symlink_dir, symlink_file},
        path::PathBuf,
    };

    fn temp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("sas-pairing-{name}-{}", std::process::id()))
    }

    #[test]
    fn lock_paths_reject_file_parents_and_reparse_points() {
        let base = temp_path("path-check");
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).unwrap();

        let regular_file = base.join("not-a-directory");
        fs::write(&regular_file, b"").unwrap();
        assert_eq!(
            os_lock::ensure_plain_directories(&regular_file.join("child")),
            Err(Error::OwnershipUnavailable)
        );

        let target_dir = base.join("target");
        let linked_dir = base.join("junction-like-link");
        fs::create_dir(&target_dir).unwrap();
        if let Err(error) = symlink_dir(&target_dir, &linked_dir) {
            eprintln!("UNVERIFIED: directory reparse-point check unavailable: {error}");
        } else {
            assert_eq!(
                os_lock::ensure_plain_directories(&linked_dir.join("child")),
                Err(Error::OwnershipUnavailable)
            );
        }

        let target_file = base.join("target.lock");
        let linked_file = base.join("linked.lock");
        fs::write(&target_file, b"").unwrap();
        match symlink_file(&target_file, &linked_file) {
            Ok(()) => match OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(0x0020_0000) // FILE_FLAG_OPEN_REPARSE_POINT
                .open(&linked_file)
            {
                Ok(file) => assert_eq!(
                    os_lock::ensure_regular_lock_file(&file),
                    Err(Error::OwnershipUnavailable)
                ),
                Err(error) => {
                    eprintln!("UNVERIFIED: lock-file reparse-point check unavailable: {error}")
                }
            },
            Err(error) => eprintln!("UNVERIFIED: lock-file symlink setup unavailable: {error}"),
        }
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn account_identity_comes_from_windows_and_is_stable() {
        let first = os_lock::authenticated_account().unwrap();
        let second = os_lock::authenticated_account().unwrap();
        assert_eq!(first, second);
        assert!(!first.0.is_empty());
        assert!(first.1.is_absolute());
    }

    #[test]
    fn token_user_parsing_does_not_assume_buffer_alignment() {
        use std::mem::{align_of, size_of};
        use windows_sys::Win32::Security::{SID_AND_ATTRIBUTES, TOKEN_USER};

        // S-1-5-32-544: revision 1, two subauthorities, NT authority, 32, 544.
        let sid = [1u8, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 0x20, 0x02, 0, 0];
        let header = size_of::<TOKEN_USER>();
        let total = header + sid.len();
        let mut storage = vec![0u8; total + align_of::<TOKEN_USER>()];
        let mut misaligned = 0;
        for offset in 0..align_of::<TOKEN_USER>() {
            let buffer = &mut storage[offset..offset + total];
            buffer.fill(0);
            buffer[header..].copy_from_slice(&sid);
            let base = buffer.as_mut_ptr();
            if base.align_offset(align_of::<TOKEN_USER>()) != 0 {
                misaligned += 1;
            }
            // Same layout as Windows: the header's SID pointer refers to bytes after it.
            let info = unsafe {
                std::ptr::write_unaligned(
                    base.cast::<TOKEN_USER>(),
                    TOKEN_USER {
                        User: SID_AND_ATTRIBUTES {
                            Sid: base.add(header).cast(),
                            Attributes: 0,
                        },
                    },
                );
                std::slice::from_raw_parts(base, total)
            };
            assert_eq!(os_lock::token_user_sid(info).as_deref(), Ok(&sid[..]));
            assert_eq!(
                os_lock::token_user_sid(&info[..header - 1]),
                Err(Error::OwnershipUnavailable)
            );
        }
        assert_eq!(misaligned, align_of::<TOKEN_USER>() - 1);

        let mut storage = vec![0u8; header + 1];
        assert_eq!(
            os_lock::token_user_sid(&storage[1..]),
            Err(Error::OwnershipUnavailable)
        );
        storage.truncate(header);
        assert_eq!(
            os_lock::token_user_sid(&storage),
            Err(Error::OwnershipUnavailable)
        );
    }

    #[test]
    fn poisoned_shared_state_fails_closed() {
        let authority = TrustedAuthority::register(b"poisoned-state-test").unwrap();
        let executor = authority.executor();
        let poisoned = executor.clone();
        let _ = std::thread::spawn(move || {
            let _state = poisoned.0.shared.lock().unwrap();
            panic!("simulate ambiguous in-process state");
        })
        .join();
        assert_eq!(executor.status().unwrap_err(), Error::OwnershipUncertain);
        let mut ceremony = executor.begin(Role::Initiator).unwrap();
        let authorization = authority.authorize(&mut ceremony).unwrap();
        assert_eq!(
            executor.reserve(&mut ceremony, Some(authorization)),
            Err(Error::OwnershipUncertain)
        );
        drop(ceremony);
        drop(executor);
        authority.release().unwrap();
        // Poisoned accounting is never discarded or rebuilt: re-registering this authority
        // fails closed for the rest of the process (P6.3).
        for _ in 0..2 {
            assert_eq!(
                TrustedAuthority::register(b"poisoned-state-test").unwrap_err(),
                Error::OwnershipUncertain
            );
        }
    }

    /// P6.3 process-session regressions (P5-F-003, P6-D-002).
    mod process_session;
}

#[cfg(all(test, not(windows)))]
mod unsupported_platform_tests {
    use super::{Error, TrustedAuthority};

    #[test]
    fn ownership_is_never_faked_on_unsupported_platforms() {
        assert_eq!(
            TrustedAuthority::register(b"unsupported-test").unwrap_err(),
            Error::UnsupportedPlatform
        );
    }
}
