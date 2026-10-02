# P5 Assumptions and Boundaries

This file separates what the P4 core itself guarantees from what a consumer or deployment must provide, so later reviewers do not file findings against behavior that is intentionally external. Each entry is backed by source reading in this review. Where the core violates its own stated boundary, that is a finding, not an entry here.

## Core guarantees (as implemented and reviewed)

Each holds only for the tested Windows account-scoped configuration and the experimental profile. None is a production-security guarantee.

| Area | What the core enforces | Where |
|---|---|---|
| Authority exclusivity | One process holds a canonical identity at a time, through an OS `LockFileEx` lease on a lock file named from the token SID and the canonical identity under the Windows profile. One in-process registration per identity. Uncertain results fail closed. | `lib::TrustedAuthority::register`, `lib::os_lock` |
| Exposure accounting | One guard and 10 opportunities per registration, shared by both roles, every thread, router, session, and connection. The reservation is atomic and precedes every contribution. No refund. | `CeremonyExecutor::reserve`, `RemoteCeremony::expose_key` |
| Authorization boundary | Only `TrustedAuthority` issues per-ceremony, one-shot authorizations. The executor cannot. Network input never creates one. | `TrustedAuthority::authorize`, compile-fail doctest |
| Pre-exposure controls | START limiter (burst 4, 1 per 5 s, 12 per rolling 60 s), 4 pending Responders, 2 preliminary operations, a 60 s pending lifetime, 16 live connections, 4 accept-work tasks, and 4 + 1 incomplete frames with 10 s / 2 s frame deadlines. All authority-wide, unkeyed by peer labels. | `start_limiter`, `lib`, `transport` |
| Canonical codec | Exact framing, field counts, widths, maxima, and grammar. Cryptographic inputs use received bytes. | `protocol` |
| Ceremony | P3 message order, commitment, contributory DH, transcript identity, SAS context, approval, completion, and CANCEL MACs. Terminal irreversibility (I1) and SAS withdrawal (I2). Deadlines. | `ceremony`, `crypto`, `deadline` |
| Routing | `(session, request_id)` routing, exact-instance local callbacks, session-fatal unknown routes, linearized teardown. | `router`, `host` |
| Experimental Windows TCP adapter and owner loop | Bounded nonblocking I/O, one retained outbound frame, confirmation of the final ACK only after a complete local write, bounded `WSAPoll` scheduling. | `windows_tcp`, `windows_owner_loop` |

## Consumer and deployment responsibilities

These are not core defects when absent. A future binding (P7–P10) must provide them.

| Responsibility | Why it is external | Reviewer note |
|---|---|---|
| **Trusted authority-scope mapping** | P3 §11.1.2(1–2) and decision 0003 assign scope issuance, alias rejection, and conflicting-mapping detection to the trusted registry. `register(&[u8])` treats any distinct byte string as a distinct authority with its own guard and budget. | The registry must never derive a scope from peer data, a request ID, or a peer bootstrap. The public `register(&[u8])` must not be exposed unchanged to untrusted callers in P7. |
| **Local authorization source** | The core cannot prove that a human consented. Whoever holds `TrustedAuthority` decides. | A Responder authorization is "blind": the core API offers the consumer only a `RunRef`, not the unauthenticated peer bootstrap. What to show the user before consent is P7/P10 design. |
| **SAS UI** | The core withdraws `SasPresentation` and rejects stale decisions (I2). Rendering, removing it from the screen, and comparison procedure, accessibility, and localization are the consumer's. | `SasPresentation` is `Clone`, so copies held by UI code outlive withdrawal. Only the core's state decides acceptance. |
| **Expected-peer provenance and partial constraints** | P3 §8 makes the open or expected mode, the provenance of expected values, and partial constraints consumer-owned. The core accepts one complete expected bootstrap. | A binding must not fall back to open mode when expected data is missing. |
| **Bind, interface, port, loopback or LAN choice, kernel backlog** | The core takes an already-bound listener or connected stream and inspects no address. | Exposure to an untrusted network makes [P5-F-002](findings.md#p5-f-002) reachable by any peer that can connect. |
| **Discovery** | Not implemented. Network locality is never trust (P3). | — |
| **Firewall** | Not configured by the core. | — |
| **Power and resume notification** | The core provides `recheck_after_resume`; subscribing to OS power events is integration work. | Whether `Instant` counts suspended time is unverified ([P5-F-011](findings.md#p5-f-011)). |
| **TLS and proof of possession** | The pairing result authenticates exact bootstrap bytes. It proves no possession of the private key. | A later TLS 1.3 exchange must verify the exact pinned `(key_algorithm, public_key)` and a `CertificateVerify`. |
| **Persistent trust after pairing** | `PairingResult` is local and ceremony-scoped, and outcomes may be asymmetric. Storing trust is the consumer's decision. | See [P5-F-001](findings.md#p5-f-001) and [P5-F-007](findings.md#p5-f-007): either side may succeed alone. Consumers must not assume the peer stored trust. |
| **Panic containment across a future FFI boundary** | Rust panics must not unwind across a C ABI. | P7 must choose `panic = "abort"` or a `catch_unwind` boundary ([P5-F-005](findings.md#p5-f-005)). |
| **Connection lifecycle policy** | The adapter does not close a connection after a ceremony ends. The owner closes connections explicitly. | Combined with no idle lifetime, this is [P5-F-002](findings.md#p5-f-002). |

## Environmental assumptions the core relies on

1. **One profile directory per SID.** The lock location is `GetUserProfileDirectoryW(token)\AppData\Local\sas-pairing\authority-locks`. Two concurrent processes of one SID must resolve the same directory. Path-string aliasing (8.3 names, case) is harmless because the same directory is reached; a genuinely different directory for the same SID would split ownership. This was not observed. It is an assumption of decision 0003's tested configuration, not a verified property.
2. **No attacker inside the same Windows profile, and no administrator/SYSTEM attacker** (decision 0003; [P5-F-008](findings.md#p5-f-008)).
3. **OS entropy available.** `Sas::new()` panics if seeding fails ([P5-F-005](findings.md#p5-f-005)). Request IDs fail closed on `getrandom` errors.
4. **No fork, snapshot, restore, or duplicated authority state** ([P5-F-009](findings.md#p5-f-009)).
5. **Honest OS API results.** Win32 calls return well-formed structures. [P5-F-004](findings.md#p5-f-004) records the one place where an out-of-range OS result is not bounded.
6. **Dependency correctness.** vodozemac 0.11.0, x25519-dalek 3.0.0, hkdf/hmac 0.13.0, sha2, rand 0.10.3, getrandom 0.4.3, and base64 0.23.1 (including its default `simd-unsafe` engine, [P5-F-006](findings.md#p5-f-006)) behave as their source states.
7. **Monotonic clocks.** `std::time::Instant` (QueryPerformanceCounter) is non-decreasing. Backwards and missing readings are handled fail-closed. Suspend behavior is not verified.
8. **Availability is not guaranteed.** P3 §11.1.1 states the defaults are not DoS guarantees ([P5-F-012](findings.md#p5-f-012)).
