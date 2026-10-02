# P5 Analysis — Secrets, Logging, Panics, Allocation, Side Channels, Dependencies, Static Analysis

Reviewed at `e21ff0b`, with the exact cached crate sources for the versions in `core/Cargo.lock`.

## 1. Secret lifetime

| Material | Created | Held by | Dropped | Zeroized | `Debug` / `Clone` |
|---|---|---|---|---|---|
| Initiator `EphemeralSecret` | `expose_key`, after `reserve` | `EphemeralSas` in `InitiatorAwaitResponderKey` | Consumed by DH, or state drop on any terminal path | Yes (x25519-dalek `Drop`, `zeroize` enabled by vodozemac) | Neither |
| Responder `EphemeralSecret` | Admission, before ACCEPT | `ResponderAcceptSentAwaitInitiatorKey` | Consumed by DH, or state drop | Yes | Neither |
| X25519 `SharedSecret` (`EstablishedSas`) | DH | `Established` in `ResponderAwaitAuthorization`, then `SasSession` | State drop at terminal or success, before guard release | Yes | `Established` derives `Debug`; vodozemac's `EstablishedSas` `Debug` prints **only the two public keys**. No `Clone` |
| HKDF PRK, MAC keys (`Box<[u8; 32]>`), HMAC state | Each `bytes`/`calculate_mac`/`verify_mac` call | vodozemac temporaries | End of call | **No** | — |
| SAS bytes `[u8; 6]`, decimal `String` | `SasSession::new` | `SasSession`; `SasPresentation` clones handed to the consumer | Session drop; consumer copies live on | No | `SasPresentation` is `Debug + Clone`. The SAS is not a secret (threat model) |
| vodozemac `SasBytes` | `Established::sas` | Temporary | End of `SasSession::new` | No | `Debug + Clone` (upstream) |
| Authorization seal | `authorize` | `Ceremony` and the token | `reserve` (consumed) or terminate | Not secret | `Debug` redacted |
| `PairingResult` | Success | Consumer | Consumer | Public data | `Debug + Clone` |

No copy of a secret survives a terminal transition inside the core, except where noted: upstream temporaries, compiler or stack copies, and swap or crash dumps are not covered. That is the documented boundary in P3 §5, recorded as [P5-F-010](findings.md#p5-f-010). No memory-forensic resistance is claimed.

## 2. Logging and `Debug`

- Production code has no `println!`, `eprintln!`, `dbg!`, `tracing`, or `log`. `eprintln!` appears only in tests.
- The types that hold secrets (`State`, `SasSession`, `EphemeralSas`) implement neither `Debug` nor `Clone`. `Error` and `CeremonyError` `Display` print variant names only.
- `ownership_probe --file-control` (evidence tooling, not the library) writes the token SID, Windows session ID, scope, and canonical identity to a log file in the caller-chosen directory. That is identifying but non-secret data, and it is documented in the core README.

## 3. Panic and abort surfaces

| Site | Reachable from | Verdict |
|---|---|---|
| `protocol.rs:529,573` `try_into().unwrap()` on 4-byte slices | — | Unreachable: the slices are exactly 4 bytes after bounds checks |
| `crypto.rs:284` `expect("ASCII prefix and Base64url")` | — | Unreachable: ASCII prefix plus Base64url output |
| `router.rs:743` `expect("run not yet installed")` | — | Unreachable: taken once per loop iteration |
| `router.rs:935` `expect("only a new responder claims")` | — | Unreachable: claims are made only with `claim_new` |
| `ceremony.rs` `unreachable!()` (9 sites) | — | Unreachable: each follows a match on the same state |
| Indexing and slicing (37 sites, review Clippy) | — | Each guarded (triaged one by one: field counts, `bounded`, extent checks, `start ≤ end ≤ 8192`, `offset < len`, index valid until `retain`) |
| `debug_assert!`s (`retain` slot free, event count, `fds` length) | — | Invariants hold. In release builds `retain` would overwrite silently, but every caller checks the slot first |
| `vodozemac` internal `expect`s (HKDF expand of 6 or 32 bytes, HMAC new) | — | Unreachable |
| **`Sas::new()`** (rand `ThreadRng` seeding or reseeding failure) | Responder admission (peer START), Initiator `expose_key` (local) | Reachable only on OS entropy failure. Accounting and no-success hold (P4 test). The unwind leaves Router and adapter state conservatively stuck ([P5-F-005](findings.md#p5-f-005)) |
| Allocation failure | Anywhere | Aborts (Rust default). Out of scope |
| Integer overflow in release builds | Counters (`+=`/`-=`) | Every decrement is paired with an `Option` or flag taken exactly once; `remaining` is checked `> 0`. No wrap path ([P5-F-020](findings.md#p5-f-020)) |

No panic is reachable from peer input, consumer input, socket events, or clock values, apart from the entropy case above.

## 4. Allocation and integer safety

Every declared length is validated before allocation (`wire_frame_extent`; `Partial::extend` with `reserve_exact` toward a validated target ≤ 65,536). Field counts are fixed per type. Generated Base64url strings are sized with checked arithmetic and capped at 65,536 bytes. `scope.len() ≤ u32::MAX` is checked before the cast. SID length is 8–68. `fds.len() ≤ 17` before the `u32` cast. `SOCKET`-to-`usize` casts are lossless on Windows. One transient: `protocol::parse` collects up to `len / 4` field slices for arbitrary public `decode` input (about 256 KiB at most); transport-delimited frames have at most 5. No finding.

## 5. Side channels (within realistic scope)

- MAC tags: `digest` 0.11.3 `verify_slice` compares in constant time (`ctutils::CtEq`). X25519 is constant time upstream.
- Non-constant-time comparisons exist only on **public or local** values: the commitment (`==` on a public digest), the transcript digest against `ceremony_identity` (public), the final-ACK bytes (local), and bootstrap or context bytes (public). Recorded as the false positive [P5-F-016](findings.md#p5-f-016).
- Timing of HKDF and HMAC over variable-length public inputs reveals only public lengths.
- Cache, power, and microarchitectural attacks on the endpoint are outside the remote attacker model. Upstream constant-time claims were trusted, not measured. **PARTIAL** in [coverage](coverage.md).

## 6. Dependencies

| Crate | Locked version | Enabled features (relevant) | Pin |
|---|---|---|---|
| vodozemac | 0.11.0 (checksum `ba935af0…2574`, matches decision 0002) | `default-features = false` | `=0.11.0` |
| x25519-dalek | 3.0.0 | `zeroize`, `reusable_secrets`, `static_secrets`, `serde` (via vodozemac and hpke) | Lockfile |
| curve25519-dalek | 5.0.0 | — | Lockfile |
| rand / rand_core | 0.10.3 / 0.10.1 | `std`, `std_rng`, `thread_rng`, `sys_rng` | Lockfile |
| getrandom | 0.4.3 (direct and via rand) | No `default` feature exists in 0.4.3. Windows backend: `ProcessPrng` | `0.4.3` (caret) + lockfile |
| hkdf / hmac | 0.13.0 / 0.13.0 | — | Lockfile |
| sha2 | 0.10.9 (core: commitment, transcript, lock name) and 0.11.0 (vodozemac: HKDF and HMAC) | — | `0.10` (caret) + lockfile |
| zeroize | 1.9.0 | — | Lockfile |
| base64 | 0.23.1 | **`default` = `std` + `simd-unsafe`** (enabled by vodozemac and by the core) | `0.23` (caret) + lockfile |
| windows-sys | 0.59.0 (only version in the lock; Windows target only) | The eight Win32 features listed in `Cargo.toml` | `0.59` + lockfile |

- **Duplicate versions:** `sha2`, `digest`, `block-buffer`, `crypto-common`, and `cpufeatures` each appear at two versions; `syn` 2/3 at build time only. The core's own SHA-256 uses (commitment, transcript, lock name) are project constructions defined by P3, not a bypass of vodozemac's pinned SAS, HKDF, or MAC path. No project code calls `x25519-dalek`, `hkdf`, or `hmac` directly (searched).
- **Unused but compiled:** vodozemac's non-optional `aes`, `cbc`, `chacha20poly1305`, `hpke`, `ed25519-dalek`, `serde_json`. Unreachable from the core.
- **Supply-chain hardening (observation):** CI runs `cargo test` without `--locked`, so a manifest change that disagreed with the lockfile would be resolved silently in CI. This is not a finding today (the lock is committed and consistent). Recommended for P6 as CI hygiene.
- **`base64` SIMD engine:** [P5-F-006](findings.md#p5-f-006).

### Advisory scan

- **Tool:** OSV `querybatch` API (`https://api.osv.dev/v1/querybatch`; the database includes RustSec). `cargo audit` was not installed, and installing tools was avoided.
- **Date:** 2026-10-02T09:01Z.
- **Scope:** all 96 crates.io packages in `core/Cargo.lock`.
- **Result:** **no advisories**. A control query with known-vulnerable versions (`time 0.1.43`, `smallvec 1.6.0`) returned their RustSec and GHSA IDs, confirming the query works.
- **Applicability:** not applicable, since nothing was reported.
- The dependency graph was not changed. No dependency was upgraded.

## 7. Static analysis

| Check | Result |
|---|---|
| `cargo fmt --check` | Pass |
| `cargo clippy --all-targets -D warnings` (Windows) | Pass |
| `cargo clippy --all-targets -D warnings --target x86_64-unknown-linux-gnu` | Pass |
| Review-only lints on `--lib --bins` (`undocumented_unsafe_blocks`, `unwrap_used`, `expect_used`, `panic`, `indexing_slicing`, `arithmetic_side_effects`, `cast_*`, `as_conversions`) | 109 library and 26 probe hits, all triaged. Security-relevant result: none beyond the `unsafe` documentation observation in [ownership and FFI §6](ownership-and-ffi.md#6-production-unsafe-inventory) and the triage above. No code was changed |

`cargo-miri` is installed, but Miri cannot execute the Win32 FFI that holds the remaining `unsafe`, so it was not used.
