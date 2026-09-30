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

### Manual cross-session procedure (not yet run)

Use two interactive Windows logon sessions for the **same account** and confirm they have different session IDs. In session A, run `cargo run --manifest-path core/Cargo.toml --bin ownership_probe -- sas-p4-cross-session-check` and leave it at `READY`. Record `whoami /user`, then find the probe PID and session ID with `Get-CimInstance Win32_Process -Filter "Name='ownership_probe.exe'" | Select-Object ProcessId,SessionId`. In session B, verify the same user SID and a different session ID, then run the identical command and scope. Session B must fail before `READY`. End the session A probe and confirm it exits; retry in B and it must print `READY`. Do not treat two terminals in the same logon session as a cross-session test. Record the Windows edition/build, both session IDs, user SID, and each outcome. Cross-session exclusivity remains an open gate until this is executed.

Cross-account authority scope also remains an owner decision gate before any broader Windows ownership guarantee is enabled. No SAS ceremony or protocol behavior is included in this increment.
