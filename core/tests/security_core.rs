#![cfg(windows)]

use std::{
    io::{BufRead, BufReader, Write},
    process::{Child, ChildStdin, Command, Stdio},
    sync::{Arc, Barrier},
    thread,
};

use sas_pairing_core::{Authority, Error, Role, Status};

fn owner(scope: &str) -> (Child, ChildStdin) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_ownership_probe"))
        .arg(scope)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let mut line = String::new();
    BufReader::new(stdout).read_line(&mut line).unwrap();
    assert_eq!(line.trim(), "READY");
    let input = child.stdin.take().unwrap();
    (child, input)
}

#[test]
fn process_ownership_and_full_reservation_lifecycle() {
    assert_eq!(Authority::register(b"").unwrap_err(), Error::InvalidScope);
    let (mut child, child_input) = owner("integration-owner");
    assert_eq!(
        Authority::register(b"integration-owner").unwrap_err(),
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
    let separate = Authority::register(b"independent-owner").unwrap();
    separate.release().unwrap();

    child.kill().unwrap();
    child.wait().unwrap();
    drop(child_input);

    let authority = Authority::register(b"integration-owner").unwrap();
    let mut expected_identity = b"sas-pairing-authority-v1".to_vec();
    expected_identity.extend_from_slice(&17u32.to_be_bytes());
    expected_identity.extend_from_slice(b"integration-owner");
    assert_eq!(authority.canonical_identity(), expected_identity);
    assert_eq!(
        Authority::register(b"integration-owner").unwrap_err(),
        Error::AlreadyRegistered
    );
    assert_eq!(authority.status().unwrap(), Status::Ready { remaining: 10 });
    let mut unauthorized = authority.begin(Role::Initiator).unwrap();
    assert_eq!(
        authority.reserve(&mut unauthorized, None),
        Err(Error::MissingAuthorization)
    );
    authority.terminate(&mut unauthorized).unwrap();
    drop(unauthorized);
    let initiator = authority.begin(Role::Initiator).unwrap();
    let mut responder = authority.begin(Role::Responder).unwrap();
    let mut other = authority.begin(Role::Initiator).unwrap();
    let stale = authority.authorize(&mut other).unwrap();
    assert_eq!(
        authority.reserve(&mut responder, Some(stale)),
        Err(Error::StaleAuthorization)
    );
    assert_eq!(authority.status().unwrap(), Status::Ready { remaining: 10 });
    let mut terminated = authority.begin(Role::Initiator).unwrap();
    let pending = authority.authorize(&mut terminated).unwrap();
    authority.terminate(&mut terminated).unwrap();
    assert_eq!(
        authority.reserve(&mut terminated, Some(pending)),
        Err(Error::Terminated)
    );
    drop(terminated);
    let authorization = authority.authorize(&mut responder).unwrap();
    assert_eq!(
        authority
            .reserve(&mut responder, Some(authorization))
            .unwrap(),
        9
    );
    assert_eq!(authority.status().unwrap(), Status::Busy);

    let mut blocked = authority.begin(Role::Initiator).unwrap();
    let authorization = authority.authorize(&mut blocked).unwrap();
    assert_eq!(
        authority.reserve(&mut blocked, Some(authorization)),
        Err(Error::Busy)
    );
    assert_eq!(authority.status().unwrap(), Status::Busy);

    authority.terminate(&mut responder).unwrap();
    assert_eq!(
        authority.authorize(&mut responder).unwrap_err(),
        Error::Terminated
    );
    assert_eq!(authority.status().unwrap(), Status::Ready { remaining: 9 });

    authority.terminate(&mut blocked).unwrap();
    authority.terminate(&mut other).unwrap();
    let auth = authority.authorize(&mut blocked).unwrap_err();
    assert_eq!(auth, Error::Terminated);
    drop(initiator);
    drop(blocked);
    drop(responder);
    drop(other);

    let mut abandoned = authority.begin(Role::Initiator).unwrap();
    let authorization = authority.authorize(&mut abandoned).unwrap();
    assert_eq!(
        authority
            .reserve(&mut abandoned, Some(authorization))
            .unwrap(),
        8
    );
    drop(abandoned);
    assert_eq!(authority.status().unwrap(), Status::Ready { remaining: 8 });

    // Post-reservation failures are represented by termination; the spent opportunity stays spent.
    for remaining in (0..8).rev() {
        let mut ceremony = authority.begin(Role::Initiator).unwrap();
        let token = authority.authorize(&mut ceremony).unwrap();
        assert_eq!(
            authority.reserve(&mut ceremony, Some(token)).unwrap(),
            remaining
        );
        authority.terminate(&mut ceremony).unwrap();
    }
    assert_eq!(authority.status().unwrap(), Status::Exhausted);
    let mut eleventh = authority.begin(Role::Responder).unwrap();
    let token = authority.authorize(&mut eleventh).unwrap();
    assert_eq!(
        authority.reserve(&mut eleventh, Some(token)),
        Err(Error::Exhausted)
    );
    authority.terminate(&mut eleventh).unwrap();
    drop(eleventh);
    authority.release().unwrap();
    let replacement = Authority::register(b"integration-owner").unwrap();
    assert_eq!(
        replacement.status().unwrap(),
        Status::Ready { remaining: 10 }
    );
    replacement.release().unwrap();
}

#[test]
fn shared_guard_race_has_one_winner() {
    let authority = Authority::register(b"thread-race").unwrap();
    let barrier = Arc::new(Barrier::new(3));
    let workers: Vec<_> = [Role::Initiator, Role::Responder]
        .into_iter()
        .map(|role| {
            let authority = authority.clone();
            let barrier = barrier.clone();
            thread::spawn(move || {
                let mut ceremony = authority.begin(role).unwrap();
                let token = authority.authorize(&mut ceremony).unwrap();
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
    authority.release().unwrap();
}

#[test]
fn graceful_shutdown_allows_replacement_with_fresh_volatile_budget() {
    let (mut child, mut input) = owner("normal-release");
    writeln!(input).unwrap();
    drop(input);
    assert!(child.wait().unwrap().success());
    let authority = Authority::register(b"normal-release").unwrap();
    assert_eq!(authority.status().unwrap(), Status::Ready { remaining: 10 });
    authority.release().unwrap();
}
