use std::{
    collections::HashSet,
    fmt,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicU64, Ordering},
    },
};

const DOMAIN: &[u8] = b"sas-pairing-authority-v1";
const MAX_OPPORTUNITIES: u8 = 10;
static REGISTRY: OnceLock<Mutex<HashSet<Vec<u8>>>> = OnceLock::new();
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

/// A registration is an opaque handle issued from trusted local configuration.
/// Its scope is never accepted from a network message.
#[derive(Clone)]
pub struct Authority(Arc<State>);

impl fmt::Debug for Authority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Authority").finish_non_exhaustive()
    }
}

struct State {
    identity: Vec<u8>,
    shared: Mutex<Shared>,
    ownership: Mutex<Option<os_lock::Lease>>,
}

struct Shared {
    remaining: u8,
    active: Option<u64>,
}

impl Drop for State {
    fn drop(&mut self) {
        if let Ok(mut known) = REGISTRY.get_or_init(|| Mutex::new(HashSet::new())).lock() {
            known.remove(&self.identity);
        }
    }
}

pub struct Ceremony {
    authority: Authority,
    id: u64,
    role: Role,
    authorization: Option<u64>,
    terminal: bool,
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

impl Authority {
    /// Registers one canonical scope. The trusted registry must issue one stable scope per capability.
    pub fn register(scope: &[u8]) -> Result<Self, Error> {
        if scope.is_empty() || scope.len() > u32::MAX as usize {
            return Err(Error::InvalidScope);
        }
        let mut identity = DOMAIN.to_vec();
        identity.extend_from_slice(&(scope.len() as u32).to_be_bytes());
        identity.extend_from_slice(scope);
        // ponytail: one registry mutex serializes authority registration; shard only if contention is measured.
        let registry = REGISTRY.get_or_init(|| Mutex::new(HashSet::new()));
        let mut known = registry.lock().map_err(|_| Error::OwnershipUncertain)?;
        if !known.insert(identity.clone()) {
            return Err(Error::AlreadyRegistered);
        }
        let lease = match os_lock::Lease::acquire(&identity) {
            Ok(lease) => lease,
            Err(error) => {
                known.remove(&identity);
                return Err(error);
            }
        };
        Ok(Self(Arc::new(State {
            identity,
            shared: Mutex::new(Shared {
                remaining: MAX_OPPORTUNITIES,
                active: None,
            }),
            ownership: Mutex::new(Some(lease)),
        })))
    }

    pub fn canonical_identity(&self) -> &[u8] {
        &self.0.identity
    }

    pub fn begin(&self, role: Role) -> Result<Ceremony, Error> {
        let id = NEXT_CEREMONY
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
            .map_err(|_| Error::OwnershipUncertain)?;
        Ok(Ceremony {
            authority: self.clone(),
            id,
            role,
            authorization: None,
            terminal: false,
        })
    }

    /// Trusted local boundary: issue an exact-ceremony authorization capability.
    pub fn authorize(&self, ceremony: &mut Ceremony) -> Result<Authorization, Error> {
        if ceremony.terminal {
            return Err(Error::Terminated);
        }
        if !Arc::ptr_eq(&self.0, &ceremony.authority.0) {
            return Err(Error::StaleAuthorization);
        }
        let seal = NEXT_AUTHORIZATION
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
            .map_err(|_| Error::OwnershipUncertain)?;
        ceremony.authorization = Some(seal);
        Ok(Authorization {
            ceremony: ceremony.id,
            seal,
        })
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
        if shared.active == Some(ceremony.id) {
            shared.active = None;
        }
        ceremony.authorization = None;
        ceremony.terminal = true;
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

    /// Explicit release is preferred; dropping the final handle also closes the OS lease.
    pub fn release(self) -> Result<(), Error> {
        let mut state = Arc::try_unwrap(self.0).map_err(|_| Error::Busy)?;
        let lease = state
            .ownership
            .get_mut()
            .map_err(|_| Error::OwnershipUncertain)?
            .take();
        if let Some(lease) = lease {
            lease.release()?;
        }
        Ok(())
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
        if let Ok(mut shared) = self.authority.0.shared.lock()
            && shared.active == Some(self.id)
        {
            shared.active = None;
        }
    }
}

#[cfg(windows)]
mod os_lock {
    use super::Error;
    use sha2::{Digest, Sha256};
    use std::{
        fs::{self, File, OpenOptions},
        os::windows::fs::OpenOptionsExt,
        path::PathBuf,
    };
    use windows_sys::Win32::{
        Foundation::{ERROR_LOCK_VIOLATION, HANDLE},
        Storage::FileSystem::{
            FILE_FLAG_OPEN_REPARSE_POINT, LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY,
            LockFileEx, UnlockFileEx,
        },
        System::IO::OVERLAPPED,
    };

    pub struct Lease {
        file: File,
        overlapped: OVERLAPPED,
    }

    // LockFileEx is synchronous here (the file handle is not opened for overlapped I/O).
    // The operation has completed before the lease moves between threads.
    unsafe impl Send for Lease {}

    impl Lease {
        pub fn acquire(identity: &[u8]) -> Result<Self, Error> {
            let root = std::env::var_os("LOCALAPPDATA").ok_or(Error::OwnershipUnavailable)?;
            let dir = PathBuf::from(root)
                .join("sas-pairing")
                .join("authority-locks");
            fs::create_dir_all(&dir).map_err(|_| Error::OwnershipUnavailable)?;
            let name = format!("{}.lock", hex(&Sha256::digest(identity)));
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
    use super::{Authority, Error, Role};

    #[test]
    fn poisoned_shared_state_fails_closed() {
        let authority = Authority::register(b"poisoned-state-test").unwrap();
        let poisoned = authority.clone();
        let _ = std::thread::spawn(move || {
            let _state = poisoned.0.shared.lock().unwrap();
            panic!("simulate ambiguous in-process state");
        })
        .join();
        assert_eq!(authority.status().unwrap_err(), Error::OwnershipUncertain);
        let mut ceremony = authority.begin(Role::Initiator).unwrap();
        let authorization = authority.authorize(&mut ceremony).unwrap();
        assert_eq!(
            authority.reserve(&mut ceremony, Some(authorization)),
            Err(Error::OwnershipUncertain)
        );
        drop(ceremony);
        authority.release().unwrap();
    }
}

#[cfg(all(test, not(windows)))]
mod unsupported_platform_tests {
    use super::{Authority, Error};

    #[test]
    fn ownership_is_never_faked_on_unsupported_platforms() {
        assert_eq!(
            Authority::register(b"unsupported-test").unwrap_err(),
            Error::UnsupportedPlatform
        );
    }
}
