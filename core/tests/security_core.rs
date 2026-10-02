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
    // P6.3 (P6-D-002) intentionally corrected the P4 registration-lifetime interpretation, under
    // which this re-registration started a fresh `Ready { remaining: 10 }`. Re-registering in
    // the same live process is not a replacement owner: the session stays exhausted.
    let again = TrustedAuthority::register(b"integration-owner").unwrap();
    let executor = again.executor();
    assert_eq!(executor.status().unwrap(), Status::Exhausted);
    let mut twelfth = executor.begin(Role::Initiator).unwrap();
    let token = again.authorize(&mut twelfth).unwrap();
    assert_eq!(
        executor.reserve(&mut twelfth, Some(token)),
        Err(Error::Exhausted)
    );
    drop(twelfth);
    drop(executor);
    again.release().unwrap();
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

// R-OWNER-031: clean release first requires that no ceremony state of the authority remains.
// While any exists the explicit release is refused, the OS lease stays held (another process
// and an in-process re-registration are both denied), and the exposed ceremony keeps its guard.
// Only once that state has ended is the lease released. A re-registration in this same process
// then continues the same process session (P6.3, P6-D-002; P4 expected a fresh 10 here).
#[test]
fn ownership_is_never_released_while_ceremony_state_remains() {
    let scope = format!("release-live-{}", std::process::id());
    let authority = TrustedAuthority::register(scope.as_bytes()).unwrap();
    let executor = authority.executor();
    let mut ceremony = executor.begin(Role::Responder).unwrap();
    let token = authority.authorize(&mut ceremony).unwrap();
    assert_eq!(executor.reserve(&mut ceremony, Some(token)).unwrap(), 9);
    assert_eq!(authority.release().unwrap_err(), Error::Busy);
    assert_eq!(executor.status().unwrap(), Status::Busy);
    let contender = Command::new(env!("CARGO_BIN_EXE_ownership_probe"))
        .arg(&scope)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .unwrap();
    assert!(!contender.status.success(), "the lease is still held");
    assert_eq!(
        TrustedAuthority::register(scope.as_bytes()).unwrap_err(),
        Error::AlreadyRegistered
    );
    executor.terminate(&mut ceremony).unwrap();
    assert_eq!(executor.status().unwrap(), Status::Ready { remaining: 9 });
    drop(ceremony);
    drop(executor);
    let again = TrustedAuthority::register(scope.as_bytes()).unwrap();
    assert_eq!(
        again.executor().status().unwrap(),
        Status::Ready { remaining: 9 }
    );
    again.release().unwrap();
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

/// One locally authorized exposure reservation, terminated at once; the opportunity stays spent.
fn spend(authority: &TrustedAuthority) -> Result<u8, Error> {
    let executor = authority.executor();
    let mut ceremony = executor.begin(Role::Initiator).unwrap();
    let token = authority.authorize(&mut ceremony).unwrap();
    let result = executor.reserve(&mut ceremony, Some(token));
    executor.terminate(&mut ceremony).unwrap();
    result
}

// P6.3 (P6-D-002, R-OWNER-017, R-OWNER-021): while another process holds the authority between
// two registrations of this process, reactivation fails on the OS lease and this process's
// session keeps its spent budget; once the other process is gone the same session continues.
#[test]
fn a_foreign_owner_in_between_never_resets_this_process_session() {
    let scope = format!("foreign-between-{}", std::process::id());
    let authority = TrustedAuthority::register(scope.as_bytes()).unwrap();
    assert_eq!(spend(&authority), Ok(9));
    assert_eq!(spend(&authority), Ok(8));
    authority.release().unwrap();

    let (mut child, mut input) = owner(&scope);
    for _ in 0..2 {
        assert_eq!(
            TrustedAuthority::register(scope.as_bytes()).unwrap_err(),
            Error::OwnershipUnavailable
        );
    }
    writeln!(input).unwrap();
    drop(input);
    assert!(child.wait().unwrap().success());

    let again = TrustedAuthority::register(scope.as_bytes()).unwrap();
    assert_eq!(
        again.executor().status().unwrap(),
        Status::Ready { remaining: 8 }
    );
    // This process holds the lease again: another process is excluded.
    let contender = Command::new(env!("CARGO_BIN_EXE_ownership_probe"))
        .arg(&scope)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .unwrap();
    assert!(!contender.status.success(), "the lease is held again");
    again.release().unwrap();
}

// P6.3 (P6-D-002, I1): threads racing to re-register an inactive process session produce one
// registration per round, all over one budget, so the session never exposes more than ten.
#[test]
fn same_process_re_registration_race_has_one_winner_and_one_budget() {
    const THREADS: usize = 8;
    let scope = format!("reregister-race-{}", std::process::id());
    TrustedAuthority::register(scope.as_bytes())
        .unwrap()
        .release()
        .unwrap();
    let mut granted = 0u8;
    for round in 0..14 {
        let barrier = Arc::new(Barrier::new(THREADS));
        let contenders: Vec<_> = (0..THREADS)
            .map(|_| {
                let (barrier, scope) = (barrier.clone(), scope.clone());
                thread::spawn(move || {
                    barrier.wait();
                    TrustedAuthority::register(scope.as_bytes())
                })
            })
            .collect();
        let (mut winners, losers): (Vec<_>, Vec<_>) = contenders
            .into_iter()
            .map(|contender| contender.join().unwrap())
            .partition(Result::is_ok);
        assert_eq!(winners.len(), 1, "round {round}");
        assert!(
            losers
                .iter()
                .all(|loser| loser.as_ref().err() == Some(&Error::AlreadyRegistered)),
            "round {round}: {losers:?}"
        );
        let winner = winners.pop().unwrap().unwrap();
        let expected = if granted == 10 {
            Status::Exhausted
        } else {
            Status::Ready {
                remaining: 10 - granted,
            }
        };
        assert_eq!(
            winner.executor().status().unwrap(),
            expected,
            "round {round}"
        );
        if spend(&winner).is_ok() {
            granted += 1;
        }
        winner.release().unwrap();
    }
    assert_eq!(granted, 10);
}

// P6.3 (P6-D-002, R-OWNER-006, R-OWNER-038(c)): each genuinely new OS process starts a fresh
// volatile session after safely acquiring ownership, while its own same-process release and
// re-registration continues that session.
#[test]
fn every_new_process_starts_fresh_but_its_re_registration_does_not() {
    let scope = format!("process-session-{}", std::process::id());
    for process in 0..2 {
        let output = Command::new(env!("CARGO_BIN_EXE_ownership_probe"))
            .args([&scope, "--session"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .output()
            .unwrap();
        assert!(output.status.success(), "process {process}");
        assert_eq!(
            String::from_utf8(output.stdout)
                .unwrap()
                .lines()
                .collect::<Vec<_>>(),
            [
                "FIRST Ready { remaining: 10 }",
                "AGAIN Ready { remaining: 9 }"
            ],
            "process {process}"
        );
    }
    // This test process never owned the scope, so its first registration is fresh as well.
    let authority = TrustedAuthority::register(scope.as_bytes()).unwrap();
    assert_eq!(
        authority.executor().status().unwrap(),
        Status::Ready { remaining: 10 }
    );
    authority.release().unwrap();
}
