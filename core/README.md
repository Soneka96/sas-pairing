# Native Rust security core

This increment implements canonical scope registration, Windows process ownership, a trusted authorization issuer, a shared ceremony guard, a volatile ten-opportunity budget and terminal cleanup. It does not implement pairing messages, key generation, SAS or network transport.

## Ownership guarantees

Windows obtains the current process token's authenticated `TokenUser` SID and profile root from Windows security APIs. The lock file lives under that profile's `AppData\Local\sas-pairing\authority-locks`; `%LOCALAPPDATA%` and caller-provided identity values are not used. Its name is SHA-256 of a length-prefixed SID followed by the existing canonical identity bytes, `sas-pairing-authority-v1 || u32be(scope_length) || scope`. The canonical identity encoding and the value returned by `canonical_identity()` are unchanged. Each path component is checked as a real directory (not a reparse point), and the opened lock handle is checked for a regular, non-reparse file. `FILE_FLAG_OPEN_REPARSE_POINT` protects the final path component. Sharing allows read/write but denies delete/rename while open. Access, path, token, and unexpected OS errors fail closed.

The resulting scope is:

- Multiple processes and logon sessions for one Windows account: the process-token SID and Windows profile API produce the same ownership key and lock location. Cross-session execution has **not been verified** in this environment.
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

The Windows suite uses the real file lock. It covers contention, a synchronized simultaneous two-process acquisition, forced termination, normal release and replacement, roles sharing the guard and budget, authorization lifecycle, and ten successful reservations followed by rejection of the eleventh. The simultaneous test uses two child processes held at an explicit stdin barrier and bounded output waits. Non-Windows builds return `UnsupportedPlatform`; no in-process fallback is provided.

### Cross-session verification (open gate)

The owner accepted account-scoped Windows authority in [decision 0003](../docs/decisions/0003-windows-account-scoped-ownership.md). Only the same-account cross-session execution evidence remains open. The test-only `--file-control <directory>` probe writes a PID-named log and readiness marker, retains ownership until a `release` file appears, and self-releases after five minutes. Its log includes the process token SID, actual Windows session ID, scope, canonical identity bytes, and ownership outcome. A denied contender records that it was blocked before an executor (and therefore could not reserve an exposure).

Task Scheduler's S4U logon type avoids storing a password and uses the named account, but its actual process session ID and access to the profile lock must be verified on the target Windows host. Microsoft documents S4U as not having network or encrypted-file access; the probe uses a local profile path. See [Task Scheduler logon types](https://learn.microsoft.com/en-us/windows/win32/taskschd/taskschedulerschema-logontype-principaltype-element). Do not use SYSTEM or another account.

On the owner’s Windows host:

1. Build `ownership_probe.exe` with `cargo build --manifest-path core/Cargo.toml --bin ownership_probe`. In PowerShell, set `$dir = Join-Path $env:TEMP 'sas-p4-cross-session'` and `$probe = (Resolve-Path 'core\target\debug\ownership_probe.exe').Path`; remove old files from `$dir`.
2. In the normal interactive session, run `& $probe sas-p4-cross-session-check --file-control $dir` in a dedicated PowerShell window and leave it running. Its `<PID>.ready` file marks acquisition; the process PID is in the matching `<PID>.log` filename.
3. In Task Scheduler, create a task whose principal is the same account SID shown by `whoami /user`, select **Run whether user is logged on or not**, and enable **Do not store password** (S4U). Configure its action to run the same executable with arguments `sas-p4-cross-session-check --file-control <directory>`. Set the task execution limit to six minutes (the probe self-releases after five). If Windows requests a credential, enter it locally; do not send it to anyone. Start the task.
4. Read the task process’s `<PID>.log`, then verify the two reported SIDs match, the interactive process has its normal session ID, and the scheduled process has session ID `0`. The scheduled contender must report `ownership=DENIED` and `reservation=BLOCKED_BEFORE_EXECUTOR`, and exit with code 1; compare `canonical_identity_hex` byte-for-byte. Record Task Scheduler's result and ensure no second process was launched under another principal.
5. Create the directory's `release` file. Confirm the interactive owner reports `ownership=RELEASED`; remove the `release` file, rerun the same task, and require `ownership=ACQUIRED`. Then create `release` again. For the reverse direction, remove `release`, run the task first, and start the identical probe interactively; require its denial before releasing the task-owned process.

For each run, record `Get-ComputerInfo | Select-Object WindowsProductName, WindowsVersion, OsBuildNumber`, task name/logon mode/result, both PIDs/SIDs/session IDs, canonical identity, both ownership outcomes, the reservation denial, and release/replacement behavior. Repeat with the scheduled task as initial owner where practical. The owner has not yet completed this procedure: the current Codex execution policy rejected launching the long-lived probe process, so no Task Scheduler session-0 claim or cross-session result is recorded. If Task Scheduler does not produce a different session ID for the same SID, use Windows Server with Remote Desktop Services configured for two same-account sessions and rerun this exact procedure. No SAS ceremony or protocol behavior is included in this increment.
