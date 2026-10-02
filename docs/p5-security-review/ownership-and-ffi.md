# P5 Analysis — Ownership, Accounting, Unsafe, and Win32 FFI

Reviewed source: `core/src/lib.rs` (production part) and `core/src/bin/ownership_probe.rs`, at `e21ff0b`. Findings referenced here are defined in [findings](findings.md).

## 1. Account identity and lock derivation

| Step | Code | Review result |
|---|---|---|
| Token | `OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY)`, closed by the RAII `Token` | Process token of the caller. No impersonation or thread token is used, so a thread impersonating another user still resolves the **process** account. Failure → `OwnershipUnavailable`. |
| SID | Two-call `GetTokenInformation(TokenUser)`, buffer truncated to the returned size, then `token_user_sid` | Increment 20.1 re-audited (§4). The length bound is 8–68 bytes. The SID bytes are copied before the buffer is released. |
| Profile root | Two-call `GetUserProfileDirectoryW(token)`, NUL trimmed, strict UTF-16 decode | Not from `%USERPROFILE%`, `%LOCALAPPDATA%`, or caller input. Invalid UTF-16 → `OwnershipUnavailable`. |
| Directory | `profile\AppData\Local\sas-pairing\authority-locks` | Each component checked with `symlink_metadata` (no follow) as a real directory with no `FILE_ATTRIBUTE_REPARSE_POINT`. Missing components are created and re-checked. Only `Prefix::Disk` paths are accepted, so UNC and verbatim paths fail closed. |
| Name | `hex(SHA-256(u32be(len(SID)) ‖ SID ‖ canonical_identity))` + `.lock` | Length-prefixed binary SID, so it is injective. A collision needs a SHA-256 collision. Canonical identity is `sas-pairing-authority-v1 ‖ u32be(len) ‖ scope`, unchanged from P3. |
| Open | `read+write+create`, no truncate, share mode `READ \| WRITE` (no `DELETE`), `FILE_FLAG_OPEN_REPARSE_POINT` | The final component cannot be a followed reparse point. `ensure_regular_lock_file` rejects a directory or reparse attribute on the opened handle. The file cannot be deleted or renamed while open. |
| Lease | `LockFileEx(EXCLUSIVE \| FAIL_IMMEDIATELY, byte 0, length 1)` with a zeroed `OVERLAPPED` on a synchronous handle | `ERROR_LOCK_VIOLATION` → `OwnershipUnavailable`. Any other failure → `OwnershipUncertain`. The lock belongs to the handle (file object), not the thread. |

**Session independence.** No step uses a logon-session or Windows session ID. Cross-session exclusivity therefore reduces to (a) the same token SID and (b) the same resolved profile directory. (a) holds by definition for one account. (b) is the environmental assumption recorded in [assumptions](assumptions-and-boundaries.md#environmental-assumptions-the-core-relies-on).

**Path aliasing.** Two textual profile paths for one directory (8.3 names, case) reach the same file. The lock name does not depend on the path. Harmless.

**Squatting and replacement.** Another account cannot write inside the profile. A same-account process can pre-create the path as a reparse point or directory, or open the lock file with an exclusive share mode. Every such case is refused (`OwnershipUnavailable`), which is fail-closed. A same-account process can also race the component checks against a junction swap before the open. That is the documented limitation [P5-F-008](findings.md#p5-f-008).

**Concurrent first creation.** Two first-ever acquisitions racing on `fs::create_dir` can make the loser fail with `AlreadyExists`, mapped to `OwnershipUnavailable`. This is a spurious, transient, fail-closed refusal. It is an observation only, with no security effect.

## 2. Lease lifecycle

| Event | Behavior | Review result |
|---|---|---|
| Explicit `release()` | `Arc::try_unwrap` (fails `Busy` if any executor, ceremony, permit, or router still exists), `UnlockFileEx`, then the handle closes | A failed unlock → `OwnershipUncertain`. The handle still closes at the end of `release` (so the OS releases the lock). Uncertain is reported while the lock is in fact released: conservative. |
| `release()` refused (`Busy`) | The consumed `TrustedAuthority` is gone, but the `State` lives on in other handles | The lease stays held until the last `Arc<State>` drops. Nobody can authorize after that, because no `TrustedAuthority` remains. |
| Last handle dropped | `State::drop` removes the registry entry, then fields drop (the `File` closes and the OS releases the lock) | A concurrent in-process `register` in that window gets `ERROR_LOCK_VIOLATION` (the old handle still holds the lock) → `OwnershipUnavailable`. Transient and fail-closed. No overlap of two live owners is possible. |
| Process crash | The OS closes the handle and releases the lock (`LockFileEx` semantics; release timing is OS-dependent) | A replacement acquires only once the OS reports the range free. Nothing is persisted, so nothing resumes. |
| In-process replacement | After the old `State` is gone, `register` of the same scope succeeds with a **fresh 10-opportunity budget and START limiter** | Behavior as designed and tested in P4. Whether this matches P3's "process/session" budget is [P5-F-003](findings.md#p5-f-003). |

## 3. Authority scope (attack on aliasing)

Two textual scopes that name one real capability are **two authorities** in the core: two leases, two guards, two budgets, two limiters. That would double the exposure ceiling for that capability. The core's documented guarantee is exclusivity per canonical identity. P3 §11.1.2(2) and decision 0003 assign alias and conflicting-mapping rejection to the trusted registry. The core documentation (`TrustedAuthority` docs, core README "Ownership guarantees", decision 0003) says so and forbids network-derived scopes. **No violation of the core's own boundary**, so this is recorded as the false positive [P5-F-018](findings.md#p5-f-018). The P7 binding must not expose `register(&[u8])` to untrusted or peer-derived input ([assumptions](assumptions-and-boundaries.md)).

## 4. Increment 20.1 `TOKEN_USER` re-audit

`token_user_sid(info)`:

1. `info.len() >= size_of::<TOKEN_USER>()` (16 on x64), else refusal.
2. `ptr::read_unaligned::<TOKEN_USER>` copies the header. `TOKEN_USER` is plain data (a pointer and a `u32`), so every bit pattern is valid. **Alignment: correct.** No reference to `TOKEN_USER` is formed over the byte buffer.
3. `sid = header.User.Sid`. Null → refusal.
4. `IsValidSid(sid)`, then `GetLengthSid(sid)` within 8..=68, then `slice::from_raw_parts(sid, len).to_vec()` while `info` is still borrowed.

**Lifetime:** `info` is not moved or reallocated between `GetTokenInformation` writing the absolute SID pointer and the copy (`truncate` keeps the allocation), so the pointer stays valid. **Range:** nothing checks that `sid` lies inside `info`, or that `sid + len` ends inside `info`. Correctness relies on Windows writing the SID inside the supplied buffer. A malformed OS result would make `IsValidSid` and the slice read out of range. This is [P5-F-004](findings.md#p5-f-004) (INFO). The synthetic unaligned test constructs a well-formed buffer, so it cannot catch this.

The test-only `ownership_probe` copies the header the same way but calls `GetLengthSid` without `IsValidSid`, and indexes SID bytes for display. It is evidence tooling, not production. No finding.

## 5. Attempt bound, re-derived from code

Claim: under one registration (`State`), at most 10 public contributions are released, across both roles, all threads, routers, sessions, and connections.

- The only decrement of `Shared::remaining` is in `CeremonyExecutor::reserve`. It happens under the `shared` mutex, after the `active.is_none()` and `remaining > 0` checks, and sets `active` in the same critical section.
- `reserve` requires an `Authorization` whose `ceremony` field and `seal` match the ceremony. It clears the seal before taking the lock, so one authorization reserves at most once. While a ceremony is `active` a second `reserve` returns `Busy`, and the guard is released only by `terminate` or `Drop`, both of which set `terminal`. `authorize` refuses a terminal ceremony, so **one `Ceremony` reserves at most once**.
- **Initiator:** `I_pub` is generated only after `reserve` returns, inside `expose_key`. The state is already `Terminal` (`mem::replace`) before generation, so a panic or failure exposes nothing and refunds nothing.
- **Responder:** `R_pub` exists from admission but is bound only in the commitment. Its bytes leave the core only in the `RESPONDER_KEY` encoded after `reserve`. No `Debug` or accessor exposes `rpub` or the ephemeral state. Busy or exhaustion ends the run without the key.
- **Duplicates and replays** of `INITIATOR_KEY`, `ACCEPT`, `START`, or `RESPONDER_KEY` are ignored or terminal and never re-emit a contribution. `expose_key` twice → the second call is `MissingAuthorization` and the run fails.
- **Panic or unwind:** the opportunity is consumed before generation. `Ceremony::drop` releases only the guard, never the count.
- **Owner-loop, connection, or router restart:** none creates a `State`. Only `register` does.
- **Process replacement:** needs the OS lease (§2). **In-process re-registration** after full teardown also yields a fresh 10 ([P5-F-003](findings.md#p5-f-003)).

Attempted construction of 11 or more contributions under one live `State` failed on every path above. This is recorded as the false positive [P5-F-013](findings.md#p5-f-013). Guard plus budget is one critical section, and the race test `it::shared_guard_race_has_one_winner` exercises it.

## 6. Production `unsafe` inventory

All bindings are generated `windows-sys 0.59` declarations, with no handwritten `extern`. "Holds" means the reviewer tried to construct a violation and could not.

| # | Location | Operation | Safety invariant | Pointer or handle provenance | Lifetime, size, alignment, thread | Failure behavior | Verdict |
|---|---|---|---|---|---|---|---|
| 1 | `lib.rs:591` | `unsafe impl Send for Lease` | `OVERLAPPED` is zeroed (null `hEvent`); the handle is synchronous, so the OS keeps no reference to `OVERLAPPED` after `LockFileEx`/`UnlockFileEx` return | Own fields | Locks belong to the file object, so `UnlockFileEx` from another thread is valid | — | Holds. No `SAFETY:` comment (prose comment above it). |
| 2 | `lib.rs:617` | `mem::zeroed::<OVERLAPPED>()` | All-zero is a valid C value | — | — | — | Holds |
| 3 | `lib.rs:618` | `LockFileEx` | Live handle from the owned `File`; `&mut OVERLAPPED` outlives a synchronous call | `File::as_raw_handle` | Call-scoped | `ERROR_LOCK_VIOLATION` → Unavailable; else Uncertain; `File` dropped | Holds |
| 4 | `lib.rs:639` | `UnlockFileEx` | Same handle and the same `OVERLAPPED` offset | Same | Call-scoped | Failure → Uncertain; handle closed afterwards | Holds |
| 5 | `lib.rs:658` | `OpenProcessToken` | Pseudo-handle; valid out-pointer | `GetCurrentProcess()` | — | Failure → Unavailable | Holds |
| 6 | `lib.rs:664` | `CloseHandle` (RAII) | Constructed only after success | Token | Drop | Result ignored (no recovery possible) | Holds |
| 7 | `lib.rs:669` | `GetTokenInformation` size query | Null buffer, length 0 | Token | — | Return ignored by design; size 0 → Unavailable | Holds |
| 8 | `lib.rs:676` | `GetTokenInformation` fill | `info` has exactly `size` bytes, exclusively borrowed | `Vec<u8>` | Call-scoped | Failure → Unavailable; returned size > buffer → Unavailable | Holds |
| 9 | `lib.rs:696/701` | `GetUserProfileDirectoryW` | Buffer of `chars` `u16`s | `Vec<u16>` | Call-scoped | Failure → Unavailable | Holds |
| 10 | `lib.rs:720` | `ptr::read_unaligned::<TOKEN_USER>` | `len >= size_of` checked; plain data | `info` | Copy | — | Holds (20.1 fix) |
| 11 | `lib.rs:724` | `IsValidSid(sid)` | `sid` non-null **and inside `info`** | OS-written pointer | `info` borrowed | Invalid → Unavailable | **Range not checked** → [P5-F-004](findings.md#p5-f-004) |
| 12 | `lib.rs:728` | `GetLengthSid(sid)` | After `IsValidSid` | Same | — | Out of 8..=68 → Unavailable | Holds given #11 |
| 13 | `lib.rs:734` | `slice::from_raw_parts(sid, len)` | `[sid, sid+len)` inside `info`; `u8` alignment 1 | Same | Copied while `info` is alive | — | **Range not checked** → [P5-F-004](findings.md#p5-f-004) |
| 14 | `windows_owner_loop.rs:719` | `WSAPoll(fds, len, wait)` | Exclusive, initialized slice of at most 17 `WSAPOLLFD`; sockets owned by live adapters and the listener for the whole call; the OS writes only `revents` | `&mut [WSAPOLLFD]` | Call-scoped, single owner thread | `SOCKET_ERROR` → `WSAGetLastError` → loop fails closed (except `WSAEINTR`) | Holds |
| 15 | `windows_owner_loop.rs:722` | `WSAGetLastError()` | Same thread, immediately after the failure | — | — | — | Holds |

Review-only Clippy reported 10 `unsafe` blocks and 1 `unsafe impl` in `lib::os_lock` without `// SAFETY:` comments (only `token_user_sid` and `wsa_poll` have them). That is an assurance-documentation observation and not a defect. No code was changed.

## 7. Win32 and OS error map

| API | Success condition | Failure mapping | Partial or ambiguous outcome | Review result |
|---|---|---|---|---|
| `OpenProcessToken`, `GetTokenInformation`, `GetUserProfileDirectoryW` | Non-zero return | `OwnershipUnavailable` | None changes external state | Correct: nothing to clean up beyond the RAII token |
| `fs::create_dir` (lock directories) | `Ok` | `OwnershipUnavailable` | It may have created the directory before failing elsewhere; a re-check failing → `OwnershipUncertain` | Fail-closed. A leftover empty directory is harmless. Racing creation → spurious Unavailable (§1). |
| `symlink_metadata` | `Ok` | NotFound → create; other → `OwnershipUncertain` | — | Correct |
| `OpenOptions::open` (create) | `Ok` | `OwnershipUnavailable` | May leave an empty lock file | Harmless: the file holds no state |
| `File::metadata` on the lock handle | `Ok` | `OwnershipUncertain` | — | Correct |
| `LockFileEx` | Non-zero | `ERROR_LOCK_VIOLATION` → Unavailable; other → Uncertain | Synchronous; no partial lock | Correct. `ERROR_IO_PENDING` cannot occur on a synchronous handle and would be Uncertain anyway. |
| `UnlockFileEx` | Non-zero | `OwnershipUncertain` | The handle closes afterwards regardless | Conservative |
| `WSAPoll` | `>= 0` | `WSAEINTR` → no progress; other → loop fails closed | — | Correct |
| `accept` | `Ok` | WouldBlock/Interrupted → nothing; other → listener dropped | — | Correct |
| `set_nonblocking` | `Ok` | Socket and permit dropped; nothing becomes live | — | Correct |
| `read` | `Ok(n > 0)` | `Ok(0)` → EOF teardown; WouldBlock/Interrupted → nothing; other → teardown; `n > buf` → `InvalidData` teardown | — | Correct |
| `write` | `Ok(n > 0)` | `Ok(0)` → `WriteZero` teardown; WouldBlock/Interrupted → nothing; other → teardown; `n > len` → `InvalidData` | **Bytes may have left before an error.** The run is torn down, the opportunity stays consumed, and no result exists. | Correct: no refund, and no success after a failed write |
| `shutdown` | — | Ignored (best effort) | — | Correct |
| `WSAPoll` `revents` with `POLLHUP` | — | Connection closed **without reading** | **Bytes received before a graceful FIN are still readable** | Defect [P5-F-001](findings.md#p5-f-001) |

No API was found where a failure that may already have changed external state is reported as a clean, certain outcome that later allows exposure.

## 8. R-OWNER-012 manual cross-session evidence

- **Is automation feasible?** Not usefully on GitHub-hosted runners. The runner service and any Task Scheduler S4U task both run in session 0, so a CI job would repeat same-session contention, which CI already covers. A genuine second logon session needs an interactive or RDS session on a self-hosted runner.
- **Would it improve assurance materially?** Only slightly. As §1 shows, lock derivation uses no session identifier. What session-dependence remains is whether two sessions of one SID resolve the same profile directory, which is an environmental assumption about the target Windows configuration.
- **Can it be added without changing production behavior?** Yes, as a self-hosted job that runs the existing `ownership_probe --file-control` procedure. It is recommended for P6 or a release gate only if a self-hosted Windows runner with two logon sessions becomes available.

**Conclusion:** keep the dated manual evidence as it is. Do not promote it to automated. No P5 change.
