# Native Rust security core

This increment implements trusted-scope registration, Windows process ownership, ceremony-specific local authorization, one authority-wide exposed-ceremony guard, the volatile ten-opportunity budget, terminal cleanup, and local status. It does not implement pairing messages, key generation, SAS, or network transport.

## Windows ownership

The core opens a deterministic lock file under the current user's `%LOCALAPPDATA%\sas-pairing\authority-locks` and holds an exclusive `LockFileEx` byte-range lock for the lifetime of the owning authority. The filename is SHA-256 of the exact canonical authority identity; file contents are unused. The profile's identity bytes are `sas-pairing-authority-v1 || u32be(scope_length) || scope`. Opening the lock file itself does not follow a reparse point, and sharing denies delete/rename while the handle is open.

`LockFileEx` is handle/process scoped rather than thread-owned. A thread ending cannot abandon ownership while the shared core still holds its file handle. The Windows kernel releases the range lock when the owning file handle closes, including process termination. Lock files remain as empty names; they contain no counters or ceremony state. File sharing denies delete/rename while the handle is open, so another process cannot replace the locked file to acquire a second range lock through the same path.

An abandoned named mutex was rejected: mutex ownership belongs to a thread, so thread exit can release it while another thread in that process may still expose a ceremony. A `Global\\` mutex would also require explicit namespace and DACL policy, and an ACL mistake or session-local name could undermine the intended scope. The file lock uses the user's profile ACL and is shared across that user's Windows logon sessions. It does not coordinate different Windows user profiles or machines. An attacker controlling the trusted local configuration or that user's security boundary is outside this mechanism's guarantee.

The trusted application registry must supply the same canonical scope for every frontend instance of one authority and must reject its own aliases/conflicting mappings. The core rejects duplicate exact scopes in its process-wide registry and uses the canonical bytes for OS ownership. It cannot discover that two unrelated scope byte strings were intended to name the same capability; that mapping is owned by the trusted registry, as the normative profile requires. `register` returns `OwnershipUnavailable` when the lock cannot be opened/acquired and `OwnershipUncertain` on unexpected OS or poisoned-state results. Local status reports ready, busy, and exhausted states after registration succeeds.

Reservation consumes authorization on every valid attempt. Only the exact active ceremony can release the guard. Explicit termination or dropping a live ceremony irreversibly cancels it; neither path refunds its reserved opportunity.

The mechanism follows Microsoft's documented `LockFileEx` behavior: exclusive byte-range locks conflict across processes and Windows releases them when the locking process terminates or its handle closes. It is deliberately not a named mutex. Windows named objects default to per-session namespaces unless explicitly put in `Global\\`; named mutex ownership is thread-affine and an abandoned mutex means the owning thread terminated, not necessarily the process. See [LockFileEx](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-lockfileex), [kernel object namespaces](https://learn.microsoft.com/en-us/windows/win32/termserv/kernel-object-namespaces), and [Windows mutex ownership](https://learn.microsoft.com/en-us/dotnet/standard/threading/mutexes).

## Checks

On Windows, run from the repository root:

```powershell
cargo fmt --manifest-path core/Cargo.toml -- --check
cargo clippy --manifest-path core/Cargo.toml --all-targets -- -D warnings
cargo test --manifest-path core/Cargo.toml
```

`cargo test` uses a child process and the real Windows byte-range lock to check contention, distinct authorities, forced termination and replacement, the shared role/thread guard, authorization binding, the tenth and eleventh reservations, and non-refund after termination. It is not a pairing-protocol test.

### Cross-session check

The automated process test runs in one Windows logon session. To check session namespace behavior manually, use two interactive sessions for the same Windows user. In session A run `cargo run --manifest-path core/Cargo.toml --bin ownership_probe -- sas-p4-cross-session-check` and leave it waiting at stdin. In session B run the same command and scope: it must fail ownership acquisition. End session A's process, then retry in session B: it must acquire ownership. Different Windows user profiles are not supported by the selected `%LOCALAPPDATA%` scope and are not covered by this procedure.

Non-Windows builds compile the API but ownership acquisition returns `UnsupportedPlatform`; they do not provide a fallback lock.
