use std::{
    io::{self, Read, Write},
    path::PathBuf,
    thread,
    time::{Duration, Instant},
};

use sas_pairing_core::{Role, TrustedAuthority};

fn main() {
    let args: Vec<_> = std::env::args().collect();
    let scope = args.get(1).expect("scope argument");
    if let Some(index) = args.iter().position(|arg| arg == "--file-control") {
        file_control(scope, PathBuf::from(&args[index + 1]));
        return;
    }
    if args.iter().any(|arg| arg == "--session") {
        process_session(scope);
        return;
    }
    if args.iter().any(|arg| arg == "--race") {
        println!("ARMED");
        let _ = io::stdout().flush();
        let mut command = String::new();
        if io::stdin().read_line(&mut command).is_err() || command.trim() != "GO" {
            std::process::exit(2);
        }
        match TrustedAuthority::register(scope.as_bytes()) {
            Ok(authority) => {
                println!("WON");
                let _ = io::stdout().flush();
                command.clear();
                let _ = io::stdin().read_line(&mut command);
                drop(authority);
                println!("RELEASED");
            }
            Err(_) => {
                println!("LOST");
                let _ = io::stdout().flush();
                std::process::exit(1);
            }
        }
        let _ = io::stdout().flush();
        return;
    }
    let authority = TrustedAuthority::register(scope.as_bytes()).expect("authority ownership");
    println!("READY");
    let _ = io::stdout().flush();
    let mut input = String::new();
    let _ = io::stdin().read_to_string(&mut input);
    drop(authority);
}

/// One process session: reports the status at its first registration, spends one opportunity,
/// releases, registers again in the same process, and reports again, then exits.
fn process_session(scope: &str) {
    let authority = TrustedAuthority::register(scope.as_bytes()).expect("authority ownership");
    let executor = authority.executor();
    println!("FIRST {:?}", executor.status().expect("status"));
    let mut ceremony = executor.begin(Role::Initiator).expect("ceremony");
    let token = authority.authorize(&mut ceremony).expect("authorization");
    executor
        .reserve(&mut ceremony, Some(token))
        .expect("reservation");
    executor.terminate(&mut ceremony).expect("termination");
    drop((ceremony, executor));
    authority.release().expect("release ownership");
    let again = TrustedAuthority::register(scope.as_bytes()).expect("authority ownership");
    println!("AGAIN {:?}", again.executor().status().expect("status"));
    again.release().expect("release ownership");
    let _ = io::stdout().flush();
}

fn file_control(scope: &str, dir: PathBuf) {
    std::fs::create_dir_all(&dir).expect("control directory");
    let log = dir.join(format!("{}.log", std::process::id()));
    let record = |message: &str| {
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log)
            .expect("diagnostic log");
        writeln!(file, "{message}").expect("write diagnostic");
        file.flush().expect("flush diagnostic");
    };
    let (sid, session_id) = windows_identity();
    record(&format!(
        "pid={} sid={sid} session_id={session_id} scope={scope} canonical_identity_hex={}",
        std::process::id(),
        hex(&canonical_identity(scope.as_bytes()))
    ));
    let authority = match TrustedAuthority::register(scope.as_bytes()) {
        Ok(authority) => authority,
        Err(error) => {
            record(&format!(
                "ownership=DENIED error={error:?} reservation=BLOCKED_BEFORE_EXECUTOR"
            ));
            std::process::exit(1);
        }
    };
    record("ownership=ACQUIRED");
    std::fs::write(dir.join(format!("{}.ready", std::process::id())), "ready").expect("readiness");
    let deadline = Instant::now() + Duration::from_secs(300);
    let mut timed_out = false;
    loop {
        if dir.join("release").exists() {
            break;
        }
        if Instant::now() >= deadline {
            record("failure=control_timeout");
            timed_out = true;
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }
    authority.release().expect("release ownership");
    record("ownership=RELEASED");
    let _ = std::fs::remove_file(dir.join(format!("{}.ready", std::process::id())));
    if timed_out {
        std::process::exit(2);
    }
}

#[cfg(windows)]
fn windows_identity() -> (String, u32) {
    use std::ptr;
    use windows_sys::Win32::{
        Foundation::{CloseHandle, HANDLE},
        Security::{GetLengthSid, GetTokenInformation, TOKEN_QUERY, TOKEN_USER, TokenUser},
        System::{
            RemoteDesktop::ProcessIdToSessionId,
            Threading::{GetCurrentProcess, OpenProcessToken},
        },
    };

    unsafe {
        let mut token: HANDLE = ptr::null_mut();
        assert_ne!(
            OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token),
            0
        );
        let mut size = 0;
        GetTokenInformation(token, TokenUser, ptr::null_mut(), 0, &mut size);
        let mut info = vec![0u8; size as usize];
        assert_ne!(
            GetTokenInformation(token, TokenUser, info.as_mut_ptr().cast(), size, &mut size),
            0
        );
        // The byte buffer has no TOKEN_USER alignment guarantee; copy the header out unaligned.
        assert!(size as usize >= std::mem::size_of::<TOKEN_USER>() && size as usize <= info.len());
        let sid = ptr::read_unaligned(info.as_ptr().cast::<TOKEN_USER>())
            .User
            .Sid;
        let bytes = std::slice::from_raw_parts(sid.cast::<u8>(), GetLengthSid(sid) as usize);
        let authority = bytes[2..8]
            .iter()
            .fold(0u64, |n, b| (n << 8) | u64::from(*b));
        let mut sid_text = format!("S-{}-{authority}", bytes[0]);
        for sub in 0..bytes[1] as usize {
            let offset = 8 + sub * 4;
            sid_text.push_str(&format!(
                "-{}",
                u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
            ));
        }
        let mut session_id = 0;
        assert_ne!(ProcessIdToSessionId(std::process::id(), &mut session_id), 0);
        CloseHandle(token);
        (sid_text, session_id)
    }
}

#[cfg(not(windows))]
fn windows_identity() -> (String, u32) {
    ("unsupported".into(), 0)
}

fn canonical_identity(scope: &[u8]) -> Vec<u8> {
    let mut identity = b"sas-pairing-authority-v1".to_vec();
    identity.extend_from_slice(&(scope.len() as u32).to_be_bytes());
    identity.extend_from_slice(scope);
    identity
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
