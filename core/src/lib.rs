use std::{
    collections::HashSet,
    fmt,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicU64, Ordering},
    },
};

mod ceremony;
mod crypto;
mod deadline;
pub mod protocol;

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
    authority: CeremonyExecutor,
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

impl TrustedAuthority {
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
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
            .map_err(|_| Error::OwnershipUncertain)?;
        ceremony.authorization = Some(seal);
        Ok(Authorization {
            ceremony: ceremony.id,
            seal,
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

impl CeremonyExecutor {
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
        let user = unsafe { &*info.as_ptr().cast::<TOKEN_USER>() };
        let sid = user.User.Sid;
        if sid.is_null() || unsafe { IsValidSid(sid) } == 0 {
            return Err(Error::OwnershipUnavailable);
        }
        let sid_len = unsafe { GetLengthSid(sid) } as usize;
        if !(8..=68).contains(&sid_len) {
            return Err(Error::OwnershipUnavailable);
        }
        let sid = unsafe { std::slice::from_raw_parts(sid.cast::<u8>(), sid_len) }.to_vec();

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
    }
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
