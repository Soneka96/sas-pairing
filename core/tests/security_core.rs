#![cfg(windows)]

use std::{
    io::{BufRead, BufReader, Write},
    process::{Child, ChildStdin, Command, Stdio},
    sync::{Arc, Barrier, mpsc},
    thread,
    time::Duration,
};

use sas_pairing_core::{Error, Role, Status, TrustedAuthority};

fn owner(scope: &str) -> (Child, ChildStdin) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_ownership_probe"))
        .arg(scope)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let (send, line) = mpsc::channel();
    thread::spawn(move || {
        let mut line = String::new();
        let _ = BufReader::new(stdout).read_line(&mut line);
        let _ = send.send(line);
    });
    let line = match line.recv_timeout(Duration::from_secs(10)) {
        Ok(line) => line,
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            panic!("ownership probe timed out: {error}");
        }
    };
    if line.trim() != "READY" {
        let _ = child.kill();
        let _ = child.wait();
        panic!("unexpected ownership probe output: {}", line.trim());
    }
    let input = child.stdin.take().unwrap();
    (child, input)
}

#[test]
fn process_ownership_and_full_reservation_lifecycle() {
    assert_eq!(
        TrustedAuthority::register(b"").unwrap_err(),
        Error::InvalidScope
    );
    let (mut child, child_input) = owner("integration-owner");
    assert_eq!(
        TrustedAuthority::register(b"integration-owner").unwrap_err(),
        Error::OwnershipUnavailable
    );
    let contender = Command::new(env!("CARGO_BIN_EXE_ownership_probe"))
        .arg("integration-owner")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .unwrap();
    assert!(!contender.status.success());
    let separate = TrustedAuthority::register(b"independent-owner").unwrap();
    separate.release().unwrap();

    child.kill().unwrap();
    child.wait().unwrap();
    drop(child_input);

    let authority = TrustedAuthority::register(b"integration-owner").unwrap();
    let executor = authority.executor();
    let mut expected_identity = b"sas-pairing-authority-v1".to_vec();
    expected_identity.extend_from_slice(&17u32.to_be_bytes());
    expected_identity.extend_from_slice(b"integration-owner");
    assert_eq!(authority.canonical_identity(), expected_identity);
    assert_eq!(
        TrustedAuthority::register(b"integration-owner").unwrap_err(),
        Error::AlreadyRegistered
    );
    assert_eq!(executor.status().unwrap(), Status::Ready { remaining: 10 });
    let mut unauthorized = executor.begin(Role::Initiator).unwrap();
    assert_eq!(
        executor.reserve(&mut unauthorized, None),
        Err(Error::MissingAuthorization)
    );
    executor.terminate(&mut unauthorized).unwrap();
    drop(unauthorized);
    let initiator = executor.begin(Role::Initiator).unwrap();
    let mut responder = executor.begin(Role::Responder).unwrap();
    let mut other = executor.begin(Role::Initiator).unwrap();
    let stale = authority.authorize(&mut other).unwrap();
    assert_eq!(
        executor.reserve(&mut responder, Some(stale)),
        Err(Error::StaleAuthorization)
    );
    assert_eq!(executor.status().unwrap(), Status::Ready { remaining: 10 });
    let mut terminated = executor.begin(Role::Initiator).unwrap();
    let pending = authority.authorize(&mut terminated).unwrap();
    executor.terminate(&mut terminated).unwrap();
    assert_eq!(
        executor.reserve(&mut terminated, Some(pending)),
        Err(Error::Terminated)
    );
    drop(terminated);
    let authorization = authority.authorize(&mut responder).unwrap();
    assert_eq!(
        executor
            .reserve(&mut responder, Some(authorization))
            .unwrap(),
        9
    );
    assert_eq!(executor.status().unwrap(), Status::Busy);

    let mut blocked = executor.begin(Role::Initiator).unwrap();
    let authorization = authority.authorize(&mut blocked).unwrap();
    assert_eq!(
        executor.reserve(&mut blocked, Some(authorization)),
        Err(Error::Busy)
    );
    assert_eq!(executor.status().unwrap(), Status::Busy);

    executor.terminate(&mut responder).unwrap();
    assert_eq!(
        authority.authorize(&mut responder).unwrap_err(),
        Error::Terminated
    );
    assert_eq!(executor.status().unwrap(), Status::Ready { remaining: 9 });

    executor.terminate(&mut blocked).unwrap();
    executor.terminate(&mut other).unwrap();
    let auth = authority.authorize(&mut blocked).unwrap_err();
    assert_eq!(auth, Error::Terminated);
    drop(initiator);
    drop(blocked);
    drop(responder);
    drop(other);

    let mut abandoned = executor.begin(Role::Initiator).unwrap();
    let authorization = authority.authorize(&mut abandoned).unwrap();
    assert_eq!(
        executor
            .reserve(&mut abandoned, Some(authorization))
            .unwrap(),
        8
    );
    drop(abandoned);
    assert_eq!(executor.status().unwrap(), Status::Ready { remaining: 8 });

    // Post-reservation failures are represented by termination; the spent opportunity stays spent.
    for remaining in (0..8).rev() {
        let mut ceremony = executor.begin(Role::Initiator).unwrap();
        let token = authority.authorize(&mut ceremony).unwrap();
        assert_eq!(
            executor.reserve(&mut ceremony, Some(token)).unwrap(),
            remaining
        );
        executor.terminate(&mut ceremony).unwrap();
    }
    assert_eq!(executor.status().unwrap(), Status::Exhausted);
    let mut eleventh = executor.begin(Role::Responder).unwrap();
    let token = authority.authorize(&mut eleventh).unwrap();
    assert_eq!(
        executor.reserve(&mut eleventh, Some(token)),
        Err(Error::Exhausted)
    );
    executor.terminate(&mut eleventh).unwrap();
    drop(eleventh);
    drop(executor);
    authority.release().unwrap();
    let replacement = TrustedAuthority::register(b"integration-owner").unwrap();
    assert_eq!(
        replacement.executor().status().unwrap(),
        Status::Ready { remaining: 10 }
    );
    replacement.release().unwrap();
}

#[test]
fn file_control_probe_reports_identity_and_releases_ownership() {
    let dir = std::env::temp_dir().join(format!("sas-p4-probe-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let scope = format!("file-control-{}", std::process::id());
    let mut child = Command::new(env!("CARGO_BIN_EXE_ownership_probe"))
        .args([&scope, "--file-control", dir.to_str().unwrap()])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let ready = dir.join(format!("{}.ready", child.id()));
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while !ready.exists() && std::time::Instant::now() < deadline {
        thread::sleep(Duration::from_millis(20));
    }
    assert!(ready.exists(), "probe did not become ready");
    let contender = Command::new(env!("CARGO_BIN_EXE_ownership_probe"))
        .args([&scope, "--file-control", dir.to_str().unwrap()])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let contender_pid = contender.id();
    assert_eq!(contender.wait_with_output().unwrap().status.code(), Some(1));
    let owner_log = std::fs::read_to_string(dir.join(format!("{}.log", child.id()))).unwrap();
    let contender_log = std::fs::read_to_string(dir.join(format!("{contender_pid}.log"))).unwrap();
    assert!(contender_log.contains("ownership=DENIED"));
    assert!(contender_log.contains("reservation=BLOCKED_BEFORE_EXECUTOR"));
    assert_eq!(
        owner_log
            .lines()
            .next()
            .unwrap()
            .split("canonical_identity_hex=")
            .nth(1),
        contender_log
            .lines()
            .next()
            .unwrap()
            .split("canonical_identity_hex=")
            .nth(1)
    );
    std::fs::write(dir.join("release"), "release").unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while child.try_wait().unwrap().is_none() && std::time::Instant::now() < deadline {
        thread::sleep(Duration::from_millis(20));
    }
    if child.try_wait().unwrap().is_none() {
        child.kill().unwrap();
    }
    assert!(child.wait().unwrap().success());
    let log = std::fs::read_to_string(dir.join(format!("{}.log", child.id()))).unwrap();
    assert!(log.contains("ownership=ACQUIRED"));
    assert!(log.contains("ownership=RELEASED"));
    assert!(log.contains("canonical_identity_hex="));
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn shared_guard_race_has_one_winner() {
    let authority = TrustedAuthority::register(b"thread-race").unwrap();
    let executor = authority.executor();
    let barrier = Arc::new(Barrier::new(3));
    let workers: Vec<_> = [Role::Initiator, Role::Responder]
        .into_iter()
        .map(|role| {
            let mut ceremony = executor.begin(role).unwrap();
            let token = authority.authorize(&mut ceremony).unwrap();
            (ceremony, token)
        })
        .map(|(mut ceremony, token)| {
            let authority = executor.clone();
            let barrier = barrier.clone();
            thread::spawn(move || {
                barrier.wait();
                let result = authority.reserve(&mut ceremony, Some(token));
                (authority, ceremony, result)
            })
        })
        .collect();
    barrier.wait();
    let results: Vec<_> = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect();
    assert_eq!(
        results
            .iter()
            .filter(|(_, _, result)| result.is_ok())
            .count(),
        1
    );
    assert_eq!(
        results
            .iter()
            .filter(|(_, _, result)| matches!(result, Err(Error::Busy)))
            .count(),
        1
    );
    for (authority, mut ceremony, _) in results {
        authority.terminate(&mut ceremony).unwrap();
    }
    drop(executor);
    authority.release().unwrap();
}

#[test]
fn graceful_shutdown_allows_replacement_with_fresh_volatile_budget() {
    let (mut child, mut input) = owner("normal-release");
    writeln!(input).unwrap();
    drop(input);
    assert!(child.wait().unwrap().success());
    let authority = TrustedAuthority::register(b"normal-release").unwrap();
    assert_eq!(
        authority.executor().status().unwrap(),
        Status::Ready { remaining: 10 }
    );
    authority.release().unwrap();
}

struct RaceProbe {
    child: Child,
    input: ChildStdin,
    lines: mpsc::Receiver<String>,
}

impl RaceProbe {
    fn start(scope: &str) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_ownership_probe"))
            .arg(scope)
            .arg("--race")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let (send, lines) = mpsc::channel();
        thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                if send.send(line.unwrap_or_default()).is_err() {
                    break;
                }
            }
        });
        Self {
            input: child.stdin.take().unwrap(),
            child,
            lines,
        }
    }

    fn line(&self) -> String {
        self.lines
            .recv_timeout(Duration::from_secs(10))
            .expect("ownership probe timed out")
    }

    fn send(&mut self, command: &str) {
        writeln!(self.input, "{command}").unwrap();
        self.input.flush().unwrap();
    }
}

impl Drop for RaceProbe {
    fn drop(&mut self) {
        if self.child.try_wait().unwrap().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

#[test]
fn simultaneous_independent_processes_have_one_owner_and_safe_replacement() {
    let scope = format!("race-{}", std::process::id());
    let mut first = RaceProbe::start(&scope);
    let mut second = RaceProbe::start(&scope);
    assert_eq!(first.line(), "ARMED");
    assert_eq!(second.line(), "ARMED");

    // Both children are independently waiting at the gate before either acquisition begins.
    first.send("GO");
    second.send("GO");
    let first_result = first.line();
    let second_result = second.line();
    let outcomes = [first_result.as_str(), second_result.as_str()];
    assert_eq!(outcomes.iter().filter(|&&s| s == "WON").count(), 1);
    assert_eq!(outcomes.iter().filter(|&&s| s == "LOST").count(), 1);

    let (winner, loser) = if first_result == "WON" {
        (&mut first, &mut second)
    } else {
        (&mut second, &mut first)
    };
    assert_eq!(loser.child.wait().unwrap().code(), Some(1));
    assert_eq!(
        TrustedAuthority::register(scope.as_bytes()).unwrap_err(),
        Error::OwnershipUnavailable
    );
    winner.send("RELEASE");
    assert_eq!(winner.line(), "RELEASED");
    assert!(winner.child.wait().unwrap().success());

    let replacement = TrustedAuthority::register(scope.as_bytes()).unwrap();
    replacement.release().unwrap();
}
