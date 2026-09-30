# Native Rust security core

This increment implements canonical scope registration, Windows process ownership, a trusted authorization issuer, a shared ceremony guard, a volatile ten-opportunity budget, terminal cleanup, and a standalone canonical P3 remote frame codec. The codec handles bootstrap records and all nine wire message types, bounds and validates syntax, and preserves accepted canonical bytes. It does not authenticate messages or implement cryptography, ceremony state, key generation, SAS, or network transport. Parsing alone cannot acquire an authority, authorize a ceremony, or reserve an exposure opportunity.

The codec uses the selected experimental profile at `docs/p3-vodozemac-ceremony-profile-draft.md` §§3, 4, and 6. It validates framing, ordered field counts, profile/version, field lengths, bootstrap grammar, role codes, and cancellation reason codes. The codec itself performs no cryptographic validation. The private module supplies the P4 cryptographic primitives below; ceremony sequencing, semantic peer/context checks, duplicate handling, and authority/exposure policy remain for later increments.

## Internal P3 cryptographic foundation

The private `crypto` module pins `vodozemac` to 0.11.0 with default features disabled. It owns single-use ephemeral SAS state, contributory DH validation, the exact responder commitment, transcript identity, and SAS context/info encoding. It exposes none of these operations to applications; public-key release remains unimplemented until a state machine can enforce the existing authority authorization, shared guard, and ten-opportunity admission boundary. It implements no ceremony dispatch, MACs, approval, transport, or completion.

The 2026-09-30 Cargo.lock resolves `rand 0.10.3`, `rand_core 0.10.1`, `getrandom 0.4.3`, `x25519-dalek 3.0.0`, `curve25519-dalek 5.0.0`, `hkdf 0.13.0`, `hmac 0.13.0`, `sha2 0.11.0` (vodozemac; the core also uses `sha2 0.10.9`), and `zeroize 1.9.0`. The pinned vodozemac manifest disables default features but explicitly enables `x25519-dalek/zeroize`. The resolved X25519 source zeroizes `EphemeralSecret` and `SharedSecret` on drop. This does not establish zeroization of Rand's internal ThreadRng state, derived SAS bytes, HKDF/HMAC temporaries, encoded context or digest buffers, compiler/runtime copies, swap, or crash dumps.

For Windows 10 and later, resolved `getrandom 0.4.3` uses the system `ProcessPrng` API from `bcryptprimitives.dll`. Rand's `ThreadRng` seeds and periodically reseeds from `SysRng`; an entropy failure can panic through `Sas::new()` because that constructor is infallible. This module has no path to successful protocol completion, so such a panic cannot become pairing success. Rand documents no automatic reseed after `fork`; forked processes, VM snapshots, and restored RNG state are unsupported for claiming fresh ephemeral keys unless an independently verified fresh-entropy mechanism is established. No such mechanism is implemented here.

The deterministic vector test compares the complete commitment input/digest, transcript bytes/identity, SAS context frame, and exact info string directly against the checked-in JSON. vodozemac 0.11.0 has no public fixed-private-key SAS constructor, so that fixture's six fixed-secret SAS bytes and decimal rendering cannot be reproduced through the API; a separate live test verifies fresh vodozemac DH and equal SAS outputs.

## Ownership guarantees

Windows obtains the current process token's authenticated `TokenUser` SID and profile root from Windows security APIs. The lock file lives under that profile's `AppData\Local\sas-pairing\authority-locks`; `%LOCALAPPDATA%` and caller-provided identity values are not used. Its name is SHA-256 of a length-prefixed SID followed by the existing canonical identity bytes, `sas-pairing-authority-v1 || u32be(scope_length) || scope`. The canonical identity encoding and the value returned by `canonical_identity()` are unchanged. Each path component is checked as a real directory (not a reparse point), and the opened lock handle is checked for a regular, non-reparse file. `FILE_FLAG_OPEN_REPARSE_POINT` protects the final path component. Sharing allows read/write but denies delete/rename while open. Access, path, token, and unexpected OS errors fail closed.

The resulting scope is:

- Multiple processes and logon sessions for one Windows account: the process-token SID and Windows profile API produce the same ownership key and lock location. Manual verification on 2026-09-30 exercised exclusive ownership across two different Windows process session IDs for the same account and canonical authority identity (details below). This verifies the tested Windows configuration, not cross-machine coordination, same-profile attacker resistance, or a formal security property.
- Different Windows accounts: the SID produces independent lock namespaces. This is supported only for genuinely independent pairing capabilities and state; shared cross-account capabilities are unsupported.
- Separate machines: no coordination. Copied identities and restored state across machines remain outside the approved policy guarantee.

Do not reinterpret a Windows logon session as a Windows user account. The trusted local registry identifies the underlying pairing capability, supplies a stable logical scope across restarts, and must reject aliases and conflicting mappings. The core cannot determine whether two app-level scopes name the same capability. Do not pass a scope from network-controlled input. See [decision 0003](../docs/decisions/0003-windows-account-scoped-ownership.md).

`LockFileEx` locks the opened file object, conflicts with exclusive byte-range locks from other processes, and is released when the handle closes or the process terminates. `FILE_FLAG_OPEN_REPARSE_POINT` alone would not secure parent directories; the explicit path-component checks address existing parent junctions and reparse points. They do not defend against an attacker controlling the same user profile while the path is being checked. No protection against that attacker or an administrator/SYSTEM boundary is claimed. Lock files remain empty; no counters are persisted. See Microsoft's [LockFileEx](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-lockfileex) and [CreateFile sharing and reparse-point flags](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew) documentation.

## Authorization boundary

The trusted application/configuration boundary keeps `TrustedAuthority`. Only it can issue exact-ceremony, one-shot authorization after obtaining genuine local consent; the Rust core cannot prove human interaction. Give network/protocol execution only `CeremonyExecutor`, which can begin, reserve and terminate a ceremony but has no authorization method. A compile-fail doctest checks this API boundary. The application integration must not expose `TrustedAuthority` to protocol handlers or derive authorization from network input.

Authorization is ceremony-specific and consumed by every valid reservation attempt. Stale, missing, cross-ceremony and terminal authorization cannot reserve. The executor atomically acquires the single shared guard and consumes the opportunity. Reservation is never refunded after failure or termination. Initiator and Responder use the same guard and budget.

## Checks

On Windows, run from the repository root:

```powershell
cargo fmt --manifest-path core/Cargo.toml -- --check
cargo clippy --manifest-path core/Cargo.toml --all-targets -- -D warnings
cargo test --manifest-path core/Cargo.toml
```

The Windows suite uses the real file lock. It covers contention, a synchronized simultaneous two-process acquisition, forced termination, normal release and replacement, roles sharing the guard and budget, authorization lifecycle, and ten successful reservations followed by rejection of the eleventh. The simultaneous test uses two child processes held at an explicit stdin barrier and bounded output waits. Codec unit tests use the authoritative remote frame vectors for bootstrap, START, ACCEPT, key exchange, approval MAC, and finish messages; CANCEL has no deterministic wire vector and is covered by typed encode/decode checks. Malformed frame tests cover bad headers, unsupported versions, unknown types, missing/extra fields, truncation, invalid profile, and oversize declarations. Non-Windows builds return `UnsupportedPlatform`; no in-process fallback is provided.

### Cross-session verification (manual; completed 2026-09-30)

The owner accepted account-scoped Windows authority in [decision 0003](../docs/decisions/0003-windows-account-scoped-ownership.md). The owner manually ran the test-only `--file-control <directory>` probe on Windows 11 Pro build 26200 under one authenticated account using Task Scheduler with the same account and passwordless S4U configuration. Two different actual process session IDs, `0` and `1`, were observed. In every comparison, account identity (SID) and canonical authority identity matched.

- Session 0 acquired ownership; the session 1 contender was denied with `OwnershipUnavailable`, recorded `BLOCKED_BEFORE_EXECUTOR`, and exited 1. The owner then reported release.
- After release, a session 1 process acquired ownership. While it owned the authority, a session 0 contender was denied with `OwnershipUnavailable` before executor/reservation exposure.
- The session 1 owner then reported final release. The owner also confirmed that the scheduled process could acquire ownership with no competing owner, distinguishing contention from a Task Scheduler access/configuration failure.

These are owner-supplied manual observations, not automated CI results, and were not executed by Codex. They verify the tested same-account, same-authority contention and replacement behavior across distinct Windows process sessions. They do not establish cross-machine coordination, resistance to an attacker controlling the same profile, administrator/SYSTEM isolation, cryptographic security, or a formal proof/audit. No cryptographic ceremony is implemented in this increment. The probe writes a PID-named log and readiness marker, retains ownership until a `release` file appears, and self-releases after five minutes. Its log includes the process token SID, actual Windows session ID, scope, canonical identity bytes, and ownership outcome. A denied contender records that it was blocked before an executor (and therefore could not reserve an exposure).

Task Scheduler's S4U logon type avoids storing a password and uses the named account. A reproduction must still verify the actual session IDs and local profile-lock access on its target Windows host. Microsoft documents S4U as not having network or encrypted-file access; the probe uses a local profile path. See [Task Scheduler logon types](https://learn.microsoft.com/en-us/windows/win32/taskschd/taskschedulerschema-logontype-principaltype-element). Do not use SYSTEM or another account.

On the owner’s Windows host:

1. Build `ownership_probe.exe` with `cargo build --manifest-path core/Cargo.toml --bin ownership_probe`. In PowerShell, set `$dir = Join-Path $env:TEMP 'sas-p4-cross-session'` and `$probe = (Resolve-Path 'core\target\debug\ownership_probe.exe').Path`; remove old files from `$dir`.
2. In the normal interactive session, run `& $probe sas-p4-cross-session-check --file-control $dir` in a dedicated PowerShell window and leave it running. Its `<PID>.ready` file marks acquisition; the process PID is in the matching `<PID>.log` filename.
3. In Task Scheduler, create a task whose principal is the same account SID shown by `whoami /user`, select **Run whether user is logged on or not**, and enable **Do not store password** (S4U). Configure its action to run the same executable with arguments `sas-p4-cross-session-check --file-control <directory>`. Set the task execution limit to six minutes (the probe self-releases after five). If Windows requests a credential, enter it locally; do not send it to anyone. Start the task.
4. Read the task process’s `<PID>.log`, then verify the two reported SIDs match and the processes have different actual session IDs; session `0` is not mandatory. The scheduled contender must report `ownership=DENIED` and `reservation=BLOCKED_BEFORE_EXECUTOR`, and exit with code 1; compare `canonical_identity_hex` byte-for-byte. Record Task Scheduler's result and ensure no second process was launched under another principal.
5. Create the directory's `release` file. Confirm the interactive owner reports `ownership=RELEASED`; remove the `release` file, rerun the same task, and require `ownership=ACQUIRED`. Then create `release` again. For the reverse direction, remove `release`, run the task first, and start the identical probe interactively; require its denial before releasing the task-owned process.

For each run, record `Get-ComputerInfo | Select-Object WindowsProductName, WindowsVersion, OsBuildNumber`, task name/logon mode/result, both PIDs/SIDs/session IDs, canonical identity, both ownership outcomes, the reservation denial, and release/replacement behavior. Repeat with the scheduled task as initial owner where practical. If Task Scheduler does not produce a different session ID for the same SID, use Windows Server with Remote Desktop Services configured for two same-account sessions and rerun this procedure. No SAS ceremony or protocol behavior is included in this increment.
