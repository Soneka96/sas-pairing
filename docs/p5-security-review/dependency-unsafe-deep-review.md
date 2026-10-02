# P5.3 — Dependency, Unsafe/FFI, and Secret-Lifetime Deep Review

Increment P5.3 of the [P5 review](README.md). It deepens the two surfaces P5.1 left `PARTIAL`, side channels (#32) and dependency assumptions (#33), and the native boundaries next to them: P5-F-004 (`TOKEN_USER` range), P5-F-005 (entropy panic), P5-F-006 (`base64` SIMD), P5-F-009 (fork and snapshot), and P5-F-010 (secret remanence).

> Internal, AI-assisted review evidence. Not a professional audit, formal verification, or constant-time proof. Production behavior and the dependency graph are unchanged: P5.3 added review-only tests (one `#[cfg(test)]` module declaration each in `crypto.rs`, `windows_tcp.rs`, and `windows_owner_loop.rs`, plus one integration test). It upgraded nothing and changed no feature.

| Item | Value |
|---|---|
| Starting commit | `c4f26e2776d564f3768576aadbf2caa748f9703a` (P5.2), branch `feature/p5-security-review`, 6 ahead / 0 behind `main` (`e21ff0b`) |
| Toolchain | `rustc 1.99.0 (b940084d7 2026-09-28)`, `cargo 1.99.0 (5f94df478 2026-08-27)` |
| Host | Windows 11 Pro 10.0.26200, x86_64, AMD Ryzen 9 5900HX (AVX2 and SHA-NI detected at run time) |
| Date | 2026-10-02 |

## Results at a glance

| Item | Result |
|---|---|
| P5-F-004 | **Reclassified: ACCEPTED-LIMITATION**, INFO, HIGH. The unsafe reads rely on a Windows postcondition that the documented API implies but does not state in words. On real Windows the SID lies inside the returned buffer (empirical test). |
| P5-F-005 | **Strengthened**: INFO, HIGH, OPEN. Deterministically reproduced through the Router, the TCP adapter, and the owner loop. Security properties hold. One residue is new: an Initiator-side panic leaves one authority-wide live-connection slot held for the life of the registration. |
| P5-F-006 | **Reclassified: FALSE-POSITIVE**, INFO (if real), HIGH. `URL_SAFE_NO_PAD` is the scalar, safe `GeneralPurpose` engine. The `simd-unsafe` engines are compiled but no crate in the graph reaches them. The production encoder matched an independent reference for **every** length 0..=65,536. |
| P5-F-009 | Unchanged (wording confirmed). |
| P5-F-010 | **Strengthened**, still ACCEPTED-LIMITATION. rand's `ThreadRng` keeps the raw ephemeral-key bytes in its output buffer and can regenerate them from its ChaCha state until the next reseed, beyond x25519-dalek's zeroizing drop. |
| New findings | None (P5-F-023 unused). |
| Coverage #32, #33 | Both **COMPLETE** for the current threat scope (§9, §12). |

## 1. Locked dependency graph

Commands (all with `--locked`, all succeeded, so `Cargo.lock` agrees with `Cargo.toml`): `cargo metadata`, `cargo tree`, `cargo tree -e features`, `cargo tree -d`. The resolve has **97 packages: the local crate plus 96 from crates.io**, the same count P5.1 recorded.

**Direct dependencies** (`core/Cargo.toml`): `base64 = "0.23"` → 0.23.1; `getrandom = "0.4.3"` → 0.4.3; `sha2 = "0.10"` → 0.10.9; `vodozemac = "=0.11.0"` (default features off) → 0.11.0; `windows-sys = "0.59"` (Windows only; 8 Win32 features) → 0.59.0; dev: `serde_json = "1"` → 1.0.151.

**Security-sensitive versions, all as P5.1 recorded (no deviation):**

| Crate | Locked | Checksum (first 16 hex) | Enabled features (resolved) |
|---|---|---|---|
| vodozemac | 0.11.0 | `ba935af014ca0ae5` | none (`default-features = false`; `libolm-compat`, `precomputed-tables` off) |
| x25519-dalek | 3.0.0 | `e7e8131a03190127` | `zeroize`, `reusable_secrets`, `static_secrets`, `serde` (all from vodozemac) |
| curve25519-dalek | 5.0.0 | `b5eed333089e2e1c` | `digest`, `rand_core`, `serde`, `zeroize`; **no `precomputed-tables`** |
| rand / rand_core | 0.10.3 / 0.10.1 | `65c9fb96cbc91e34` / `63b8176103e19a26` | rand: `std`, `std_rng`, `sys_rng`, `thread_rng`, `alloc`, `default` |
| chacha20 | 0.10.2 | `65c35e4b699c7e15` | `rng`, `cipher`, `xchacha` (ThreadRng core) |
| getrandom | 0.4.3 | `300e883d756b2e4e` | `std`, `sys_rng` |
| hkdf / hmac | 0.13.0 / 0.13.0 | `4aaa26c720c68b86` / `6303bc9732ae41b0` | none; **`hmac/zeroize` off** |
| digest | 0.10.7 and 0.11.3 | `9ed9a281f7bc9b75` / `f1dd6dbb58419379` | 0.11.3: `mac`, `oid`, `rand_core`, `block-api`, `alloc`; **`zeroize` off** |
| sha2 | 0.10.9 and 0.11.0 | `a7507d819769d01a` / `446ba717509524cb` | 0.11.0: `alloc`, `oid`; **`zeroize` off** |
| ctutils / cmov / subtle | 0.4.2 / 0.5.4 / 2.6.1 | `7d5515a3834141de` / `0c9ea0ac24bc397a` / `13c2bddecc57b384` | subtle: `std`, `i128`, `const-generics` (no `core_hint_black_box`) |
| cpufeatures | 0.2.17 and 0.3.1 | `59ed5838eebb26a2` / `5ca28b0ae3115b88` | none |
| zeroize | 1.9.0 | `e13c156562582aa8` | `alloc`, `derive` |
| base64 | 0.23.1 | `ac07cdecf99051d9` | **`default` = `std` + `simd-unsafe`**, `alloc` |
| windows-sys | 0.59.0 | `1e38bc4d79ed67fd` | the eight `Win32_*` features in `Cargo.toml` |

**Feature provenance.** `base64/simd-unsafe` comes from `default` features requested by both the core (`base64 = "0.23"`) and vodozemac (`[dependencies.base64] version = "0.23.1"`, defaults on). Turning it off in the core alone would not remove it, because features unify. `x25519-dalek/zeroize` and `curve25519-dalek/zeroize` come from vodozemac. rand's `thread_rng` (and with it `chacha20/rng` and `getrandom/sys_rng`) comes from vodozemac's default-feature `rand = "0.10.2"`. `hpke`'s `getrandom`, `chacha`, and `x25519` come from vodozemac. No feature of a security-sensitive crate comes from the dev-dependency.

**Duplicates** (`cargo tree -d`): `sha2` 0.10.9/0.11.0, `digest` 0.10.7/0.11.3, `block-buffer` 0.10.4/0.12.1, `crypto-common` 0.1.7/0.2.2, `cpufeatures` 0.2.17/0.3.1 (all crypto), and `syn` 2/3 (proc macros only). Analysis in §12.

**Target-specific.** `windows-sys`, `windows-targets`, and `windows_x86_64_msvc` are built only for `cfg(windows)`. Other resolved targets (`libc`, `r-efi`, `fiat-crypto`, the non-x86_64-msvc `windows_*` import crates) are not built on the CI or reviewed host. curve25519-dalek's build script selects `curve25519_dalek_backend = "simd"` on x86_64 with 64-bit limbs (AVX2 at run time, serial fallback). AVX-512 needs compile-time target features this build does not enable.

## 2. Source provenance

Every one of the 96 `.crate` archives in `~/.cargo/registry/cache` hashes (SHA-256) to its `Cargo.lock` checksum: **96 verified, 0 mismatched**. For the 20 security-relevant crates (vodozemac, x25519-dalek, curve25519-dalek, rand, rand_core, chacha20, getrandom, hkdf, hmac, digest 0.11.3, sha2 ×2, ctutils, cmov, subtle, cpufeatures ×2, zeroize, base64, windows-sys), every file in the extracted `~/.cargo/registry/src` tree was compared byte for byte with the verified archive: **0 differences**. All upstream citations below refer to this locked source, not to any online branch.

## 3. Runtime crypto call graph

| Path | Project call | Upstream chain (locked versions) | Secret / public inputs | Output | Errors and panics |
|---|---|---|---|---|---|
| **Ephemeral key** | `crypto.rs:58` `EphemeralSas::new` (Responder `ceremony.rs:652`, Initiator `ceremony.rs:1600`) | vodozemac `Sas::new` (`sas.rs:223`) → `rand::rng()` (`thread.rs:201`, thread-local `BlockRng<ReseedingCore<ChaCha12>>`) → `EphemeralSecret::random_from_rng` (x25519 `x25519.rs:88`, `fill_bytes` of 32 bytes) → on refill `chacha20` `rng.rs:49` (AVX2 / SSE2 / soft by `cpufeatures`) → on seed or reseed `getrandom::SysRng` → `backends/windows.rs:50` `ProcessPrng` (bcryptprimitives, `raw-dylib`). Public key: `EdwardsPoint::mul_base_clamped` → `variable_base_mul` (`backend.rs:253`, AVX2 or serial) → `to_montgomery` | No input. Secret scalar out | `[u8; 32]` public key | Initial seed failure: `panic!("could not initialize ThreadRng")` (`thread.rs:163`). Reseed failure after 64 KiB per thread: `panic!("could not reseed ThreadRng")` (`thread.rs:70`). `ProcessPrng` ≠ TRUE → `Error::UNEXPECTED` → that panic |
| **DH** | `crypto.rs:66-72` `establish(peer)` | vodozemac `diffie_hellman` (`sas.rs:242`) → x25519 `EphemeralSecret::diffie_hellman` (`x25519.rs:83`, consumes `self`) → `MontgomeryPoint::mul_clamped` (`montgomery.rs:150`) → ladder `mul_bits_be` (`:183`, serial `FieldElement51`, `subtle` conditional swap) → `was_contributory` (`x25519.rs:335`) = `!is_identity` = `subtle` `ct_eq` against all-zero | Secret scalar; **peer-controlled** 32-byte `u` | `EstablishedSas` or `KeyError::NonContributoryKey` → `Error::NonContributory` | Length ≠ 32 → `InvalidPeerKeyLength`. No panic |
| **SAS / HKDF** | `crypto.rs:78-83` `Established::sas(info)` | vodozemac `bytes` (`sas.rs:275`) → `get_hkdf` (`:403`, `Hkdf::<Sha256>::new(None, shared_secret)`) → `expand(info, 6)` → `SasBytes::decimals` | Shared secret; public `info` (Base64url SAS context) | `SasBytes` (6 bytes) and decimal `String` | `expect` on a 6-byte expand: unreachable |
| **MAC calculate** | `crypto.rs:86-95` | vodozemac `calculate_mac` (`sas.rs:314`) → `get_mac` → `get_mac_key` (`:407`, `Box<[u8; 32]>` from HKDF expand) → `Hmac::<Sha256>::new_from_slice` → `update(input)` → `finalize` | Shared secret; public input and info strings | 32-byte tag (sent on the wire) | `expect`s unreachable (32-byte expand, 32-byte key); a tag of another length → `MacMismatch` |
| **MAC verify** | `crypto.rs:98-104` | vodozemac `verify_mac` (`sas.rs:384`) → `Mac::verify_slice` (digest `mac.rs:139`): length check, then `ctutils` `CtEq` for `[u8]` → `cmov` `CmovEq for [u8]` (`slice.rs:208`, word-wise `cmovne` in x86 `asm!`) | Shared secret; **peer-controlled** tag | `Ok` or `MacMismatch` | None |
| **Base64url** | `crypto.rs:261-285` `capped_base64url` | `URL_SAFE_NO_PAD.encode` → `Engine::encode` (`engine/mod.rs:148`) → `encode_with_padding` → `GeneralPurpose::internal_encode` (`general_purpose/mod.rs:85-87`) → `encode_helper(…, \|_, _\| (0, 0))` → `encode_scalar_tail` (safe, bounds-checked) | Public frames. The approval frame contains the 6 SAS bytes | ASCII string ≤ 65,536 bytes | Over the cap → `Oversized` before encoding. `expect`s unreachable |
| SHA-256 (project) | `crypto.rs` commitment and transcript; `lib.rs` lock name | sha2 0.10.9 → `compress` (`sha256/x86.rs:102`, SHA-NI if `cpufeatures` 0.2 detects it, else soft) | Public data only | Digests | None |
| SHA-256 (vodozemac) | inside HKDF and HMAC | sha2 0.11.0 → `compress` (`sha256.rs:62`, SHA-NI via `cpufeatures` 0.3, else soft) | Shared secret and keys (as HMAC/HKDF state) | — | None |

**Direct-bypass search.** Production source never names `x25519_dalek`, `hkdf`, `hmac`, `Hkdf`, or `Hmac` (searched; only vodozemac types are imported in `crypto.rs:5-10`). The core's own `sha2` use is limited to the P3-defined commitment, transcript, and lock-name constructions. The vodozemac SAS/DH/MAC path is not bypassed.

## 4. Reachable upstream `unsafe`

Only `unsafe` reachable from the paths in §3 is listed. "Attacker input" means bytes a remote peer chooses.

| Crate | Unsafe site | Why reached | Invariant | Attacker input? | Verdict |
|---|---|---|---|---|---|
| curve25519-dalek 5.0.0 | `backend/vector/avx2/*` via `#[unsafe_target_feature("avx2")]`, entered from `variable_base_mul` (`backend.rs:253`) | Public-key generation: no precomputed tables, so basepoint × secret takes the variable-base path | AVX2 code runs only after `cpufeatures` (`avx2` plus OS YMM support via `xgetbv`) returned true (`backend.rs:55-74`); otherwise serial | No (fixed basepoint, local secret) | Holds. Runtime dispatch is the established upstream pattern. Serial ladder for DH has no `unsafe` |
| subtle 2.6.1 | `black_box` (`lib.rs:224`, `read_volatile` of an owned `Copy` value) | Every `Choice` in the ladder swap and the identity check | Pointer to a live local value | Indirectly (DH result) | Holds (trivially sound). It is an optimization barrier, not a guarantee |
| cmov 0.5.4 | x86 `asm!` `cmov`; `slice_as_chunks` (`split_at_unchecked`, `from_raw_parts` with length rounded down) | HMAC tag comparison (`verify_slice`) | Chunk length is a multiple of the word size by construction; asm is `pure, nomem, nostack` | Yes (the peer's tag bytes), as values only | Holds. Lengths are fixed (32 vs 32) |
| chacha20 0.10.2 | `backends::{avx2,sse2}::rng_inner` (`rng.rs:49-82`) | Every ThreadRng refill (256-byte block) | Called only when the `cpufeatures` token says AVX2 or SSE2; reads the 64-byte state via `loadu` | No | Holds |
| rand 0.10.3 | `UnsafeCell` deref in `ThreadRng::try_fill_bytes` (`thread.rs`) | Every `Sas::new` | One mutable borrow at a time on one thread (`Rc`, `!Send`); not reentrant | No | Holds; documented upstream rationale |
| getrandom 0.4.3 | `ProcessPrng(ptr, len)` FFI (`windows.rs:43, 50`); `slice_as_uninit_mut` | Seed and reseed; request IDs (`request_id.rs`) | Writable buffer of `len` bytes for the call | No | Holds |
| sha2 0.10.9 / 0.11.0 | SHA-NI `compress` (`x86.rs:102`; `sha256.rs:62`); 0.10.9 `compress256` cast `GenericArray<u8, U64>` → `[u8; 64]` | Commitment, transcript, HKDF, HMAC | SHA-NI only after `cpufeatures` (`sha`, `sse2`, `ssse3`, `sse4.1`); `loadu` unaligned loads | Message bytes only (values, not lengths beyond slices) | Holds |
| cpufeatures 0.2.17 / 0.3.1 | `__cpuid`, `_xgetbv` | Every dispatch above | CPUID is always available on x86_64; XGETBV only if OSXSAVE is set | No | Holds |
| zeroize 1.9.0 | `ptr::write_volatile` (`lib.rs:735, 748`) | x25519 `EphemeralSecret` / `SharedSecret` `Drop` | Writes within the owned array | No | Holds |
| base64 0.23.1 | `engine/simd.rs` (the only `unsafe` in the crate; `#![deny(unsafe_code)]` elsewhere) | **Not reached** (§8) | — | — | Compiled, unreachable |

No reachable upstream `unsafe` invariant depends on attacker-controlled lengths. The reviewed sites take attacker data only as fixed-size values (the 32-byte DH input, the 32-byte tag).

## 5. Project `unsafe` and FFI re-audit

Searched production source for `unsafe`, `from_raw_parts`, `read_unaligned`, `zeroed`, `as_raw_handle`, `as_raw_socket`, `cast::<`, `transmute`, `extern`. **Production library: 16 sites = 15 `unsafe` blocks + 1 `unsafe impl`.** All are in `lib.rs::os_lock` (13 blocks and the impl) and `windows_owner_loop.rs::wsa_poll` (2 blocks). P5.1's 15-row table merged the two `GetUserProfileDirectoryW` calls (`lib.rs:696, 701`) into one row; the sites themselves are unchanged. `ownership_probe` (evidence tooling, not the library) has one block (`bin/ownership_probe.rs:112`). No `transmute`, no handwritten `extern`. `as_raw_handle` (`lib.rs:620, 641`) and `as_raw_socket` (`windows_tcp.rs:95`, `windows_owner_loop.rs:113`) are safe accessors; `RawSocket as SOCKET` is lossless (both are pointer-sized on Windows).

**Bindings.** Every Win32 call uses a generated `windows-sys 0.59.0` declaration that matches the documented prototype: `LockFileEx(HANDLE, LOCK_FILE_FLAGS, u32, u32, u32, *mut OVERLAPPED) -> BOOL`, `UnlockFileEx(HANDLE, u32, u32, u32, *mut OVERLAPPED) -> BOOL`, `OpenProcessToken(HANDLE, TOKEN_ACCESS_MASK, *mut HANDLE) -> BOOL`, `GetTokenInformation(HANDLE, TOKEN_INFORMATION_CLASS, *mut c_void, u32, *mut u32) -> BOOL`, `GetUserProfileDirectoryW(HANDLE, PWSTR, *mut u32) -> BOOL`, `IsValidSid(PSID) -> BOOL`, `GetLengthSid(PSID) -> u32`, `CloseHandle(HANDLE) -> BOOL`, `WSAPoll(*mut WSAPOLLFD, u32, i32) -> i32`, `WSAGetLastError() -> WSA_ERROR (i32)`. Success and failure interpretation is as in [ownership and FFI §6–7](ownership-and-ffi.md#6-production-unsafe-inventory); P5.3 found no change.

**Safety-comment classification:**

| Sites | Classification |
|---|---|
| `wsa_poll` `WSAPoll`, `WSAGetLastError` (`windows_owner_loop.rs:719, 722`) | Sound and documented |
| `token_user_sid` `read_unaligned` (`lib.rs:720`) | Sound and documented |
| `token_user_sid` `IsValidSid`, `GetLengthSid`, `from_raw_parts` (`lib.rs:724, 728, 734`) | Sound **given a Windows postcondition**. The comments state "points into the still-borrowed `info`" as a fact, while the documentation only implies it ([§6](#6-p5-f-004-token_user-range)). Weakly worded, not unsupported |
| `unsafe impl Send for Lease` (`lib.rs:591`) | Sound; prose comment, no `// SAFETY:` |
| `zeroed`, `LockFileEx`, `UnlockFileEx`, `OpenProcessToken`, `CloseHandle`, both `GetTokenInformation`, both `GetUserProfileDirectoryW` (`lib.rs:617–701`) | Sound but undocumented (10 blocks without `// SAFETY:`, as P5.1 recorded) |

No invariant is unsupported, and none is a finding. Better comments are optional P6 hygiene.

## 6. P5-F-004: `TOKEN_USER` range

### Windows contract (primary sources, Microsoft Learn, fetched 2026-10-02)

- **`GetTokenInformation`** (updated 2025-07-01): `TokenInformation` is "a pointer to a buffer the function fills with the requested information". `ReturnLength` "receives the number of bytes needed for the buffer"; if that exceeds `TokenInformationLength`, "the function fails and stores no data in the buffer". It says nothing about where pointers inside the returned structure point.
- **`TOKEN_INFORMATION_CLASS`** (updated 2026-09-30): for `TokenUser`, "the buffer receives a TOKEN_USER structure that contains the user account of the token".
- **`TOKEN_USER`** / **`SID_AND_ATTRIBUTES`** (updated 2024-02-22): `User` is a `SID_AND_ATTRIBUTES`; its `Sid` member is "a pointer to a SID structure". No statement about the storage it points to.
- **`ZwQueryInformationToken`** (WDK, the native call behind `GetTokenInformation`; updated 2024-12-03): `ReturnLength` "receives the actual length, in bytes, of the information returned in the TokenInformation buffer", and on a short buffer "the actual number of bytes needed to store the requested information"; for `TokenUser`, "this returned buffer contains an SID_AND_ATTRIBUTES structure with the user SID". It also requires that "all structures must be aligned on a 32-bit boundary".
- **`IsValidSid`** (updated 2025-07-01): validates revision and sub-authority count; `pSid` "cannot be NULL" (a NULL pointer causes an access violation). It makes no promise for a non-null invalid pointer.
- **`GetLengthSid`** (updated 2025-07-01): "the structure is assumed to be valid"; for an invalid SID "the return value is undefined"; call `IsValidSid` first.
- Microsoft's archived sample "Getting the Logon SID in C++" (updated 2021-12-02) sizes the buffer with the two-call pattern, uses `ptg->Groups[i].Sid` directly with `GetLengthSid`/`CopySid` (with no range check or `IsValidSid`), and then frees only the buffer.

### Answers

1. **Does the documented contract guarantee that the SID pointer refers to storage associated with the returned buffer?** Not in explicit words. It is strongly implied. The caller supplies the only output storage. The required size is "the bytes needed to store the requested information", and for `TokenUser` that is larger than the 16-byte header (44 bytes here). No other allocation is returned or has to be freed. Microsoft's own sample frees only the buffer after using the pointer.
2. **Does the layout stay valid until the caller frees or modifies the buffer?** By the same implication, yes. It is not stated.
3. **Is the returned size documented to include the referenced SID storage?** Implicitly: `ReturnLength` is the size "needed to store the requested information" (WDK) and the information is the user SID.
4. **Is it sound for Rust FFI code to rely on this OS postcondition under the supported-OS assumption?** Yes, to the same standard as any Win32 FFI. The proof needs only that `User.Sid` points at a valid SID that is readable while `info` is borrowed. That is the API's whole purpose, and the threat model already treats the endpoint OS as trusted ([threat model](../threat-model.md): a compromised endpoint or OS security boundary is out of scope; [assumptions §5](assumptions-and-boundaries.md#environmental-assumptions-the-core-relies-on)). The current `SAFETY:` wording ("points into the still-borrowed `info`") is stronger than the documentation, which only implies it.

**Documented contract vs empirical behavior.** The statements above are documentation. The following is observation only. Test `core/tests/p5_review_evidence.rs::p5_f_004_token_user_sid_lies_inside_the_returned_buffer_on_this_windows` performs 100 rounds × 2 buffer sizes (exact and +64 bytes) × 6 buffer starts. It proves the SID range by address arithmetic **before** any dereference, reads the SID header from its own slice, and only then calls `IsValidSid`/`GetLengthSid` on a pointer already shown to be inside the live buffer. No invalid pointer is ever dereferenced. Results (2026-10-02, this host): required 44 bytes; SID at offset 16 (directly after the header), length 28; `returned == required`; identical in every round; 4- and 8-aligned starts succeed. **Buffer starts at offsets 1, 2, and 3 are refused with error 998 (`ERROR_NOACCESS`)**, matching the WDK alignment rule. Production's `vec![0u8; size]` is in practice 16-aligned (Rust's Windows system allocator uses `HeapAlloc`). If it ever were not, the call would fail and the core would return `OwnershipUnavailable`, which is fail-closed.

**Rust `unsafe` reasoning.** `read_unaligned` copies a plain-data header (sound for any bytes). A null `Sid` is rejected. For a non-null pointer, `IsValidSid` and `GetLengthSid` are sound **iff** it points to readable SID memory, which is exactly the OS postcondition. `from_raw_parts(sid, len)` additionally needs `len` readable bytes. With an honest OS, `len` equals the SID's own length (8..=68 is enforced). A hooked or compromised API could break this, but it could equally lie about the identity itself, so a range check would not restore the property that matters (the account identity). It would only turn some memory-safety failures into refusals.

**Disposition: reclassified to `ACCEPTED-LIMITATION`, INFO, confidence HIGH.** This is defense in depth against a violated OS contract, which the normative baseline already excludes. It is not a defect under supported assumptions. **P6 recommendation (optional, low effort):** add the range checks (`sid ≥ base + 16`, `sid + 8 ≤ end` before reading the count, `sid + len ≤ end` after) and reword the `SAFETY:` comments to name the OS postcondition. The P5.3 test can then stay as an OS-fact pin.

## 7. P5-F-005: entropy panic

### Upstream panic origin (locked source)

- `vodozemac::sas::Sas::new` (`sas.rs:223`) calls `rand::rng()` and `EphemeralSecret::random_from_rng`. It returns `Sas`, not `Result`.
- rand 0.10.3 `ThreadRng`: the thread-local initializer seeds `ChaCha12` from `SysRng` and **panics** "could not initialize ThreadRng" on failure (`thread.rs:163`). On failure no `ThreadRng` exists; the thread-local is not left half-initialized with an unseeded core. Each `generate` first checks `block_pos >= 1024` (64 KiB of output per thread, about 2,048 `Sas::new` calls) and reseeds from `SysRng`, **panicking** "could not reseed ThreadRng" on failure (`thread.rs:70`). The check comes before the keystream block is produced. `BlockRng` keeps its index at "exhausted", so after a caught reseed panic the next use tries to reseed again; **no output is reused and no output is produced past the threshold without a successful reseed**. Both panics are documented in rand's `# Panics` sections.
- getrandom 0.4.3 on Windows: `ProcessPrng` (bcryptprimitives.dll, linked `raw-dylib`, so the DLL is resolved at process load). The backend comment cites Microsoft's Windows RNG whitepaper: on Windows 10 and later `ProcessPrng` "is documented to always return TRUE". A failure is representable (`Error::UNEXPECTED`), but the upstream comment names only Windows 8 and Wine/emulation layers as returning anything else.

**Triggerability.** A remote peer controls when Responder admission (and so `Sas::new`) runs, so it can drive reseeds at the START-limiter rate. It cannot make `ProcessPrng` fail. On supported Windows the panic is practically unreachable. It is a fault-model case, not an attacker capability.

### Deterministic reproduction

The existing P4 pause points `ResponderAdmitted` and `InitiatorReserved` fire immediately before `EphemeralSas::new()`. A hook panics there, and the test catches the unwind around the real Router, adapter, or owner-loop call. All tests are PASSING EVIDENCE TESTS in CI.

| ID | Test | Observed after the caught panic | Next operation |
|---|---|---|---|
| F005-001 | `windows_tcp::tests::p5_entropy_panic_review::p5_f005_001_router_responder_admission_panic_leaves_only_an_orphan_claim` | No ACCEPT. Pending slot and permit released by unwinding. Limiter charge kept (tokens 4→3). `Ready { remaining: 10 }`. **`Admitting` claim survives** (1 route) | Exact START copy → `Duplicate` (no charge). A frame for that key → `InvalidState`, claim marked conflicted; the START is then refused too. Other keys on the session work. `close_session` → `Ok`, 0 routes, 0 sessions, all counts 0 |
| F005-002 | `…p5_f005_002_adapter_responder_admission_panic_replays_as_a_duplicate` | Panic escapes `on_readable`. Adapter open. START still retained as unread input (`suffix.start` was not advanced) | Next `on_readable` re-feeds the START → `StartDuplicate`, nothing written. `close` → everything released |
| F005-003 | `…p5_f005_003_adapter_initiator_exposure_panic_poisons_the_run` (four variants) | Panic escapes `expose_key`. Nothing written. `Busy`, `remaining 9` (consumed, no refund). Route, request-ID reservation, and guard held by the **poisoned** run | Presentation, deadline poll, an inbound frame, or `close` → `OwnershipUncertain`; adapter ends. The run is detached and dropped, so guard and reservation are released → `Ready { remaining: 9 }`. **The Router session stays CLOSING and one authority-wide live-connection slot stays held, also after the adapter drops.** The peer Responder is untouched (pending, bounded by its own deadlines) |
| F005-004 | `windows_owner_loop::tests::p5_entropy_panic_loop::p5_f005_004_owner_loop_responder_panic_escapes_drive_once_and_replays_as_duplicate` | Panic escapes `drive_once`. Loop open and listening, connection live | Next drive → `StartDuplicate`, no ACCEPT ever written. `close` → all released |
| F005-005 | `…p5_f005_005_owner_loop_initiator_panic_then_the_loop_fails_closed` | Panic escapes `WindowsOwnerLoop::expose_key`. Loop still open | Next drive: sweep finds the poisoned run → `failure: OwnershipUncertain`, loop closed (listener dropped, 0 connections). Guard released (`Ready { remaining: 9 }`). **Live slot and CLOSING session remain after the loop drops** |

The P4 test `ceremony::tests::an_ephemeral_generation_panic_exposes_nothing_and_refunds_nothing` remains the ceremony-level evidence.

### Security questions (availability separate from authentication)

1. **Pairing result?** No. No path produces a result (all five tests; terminal state before generation).
2. **Key exposed without consuming the opportunity?** No. The Initiator reserves before generation (`remaining 9`). The Responder's key is generated before any reservation but never leaves the core (no ACCEPT).
3. **Opportunity refunded?** No (`remaining` stays 9 after teardown and drops).
4. **Guard reusable incorrectly?** No. It stays held (Busy, fail-closed) while the poisoned run exists, and is released only when that run is dropped during teardown, with the opportunity spent. It is never released while the run could still act.
5. **Stale route accepting later input?** No. The Responder's orphan claim only ignores exact duplicates or refuses. The poisoned Initiator route refuses everything as uncertain.
6. **Resource leaked indefinitely?** Partly, availability only. An Initiator-side panic, once caught and followed by any next operation, leaves **one authority-wide live-connection slot and one CLOSING Router session held for the lifetime of the authority registration**. Sixteen such events would exhaust the live cap. The Responder-side orphan claim is bounded by its session.
7. **Crossing a future C/Dart/.NET ABI?** Today no ABI exists. On this toolchain (Rust ≥ 1.81) a panic unwinding out of an `extern "C"` function aborts the process. Unwinding across the boundary is UB only if a binding uses `extern "C-unwind"`. A future binding must still choose explicitly (`panic = "abort"`, or `catch_unwind` at every export).
8. **Remotely triggerable?** No (see Triggerability).

**Disposition: strengthened. INFO, confidence HIGH, OPEN.** Previously derived from source; now reproduced deterministically at every layer. The availability residue (live slot plus CLOSING session per Initiator panic) is new detail. Severity stays INFO: there is no attacker control, no security-state corruption, and the effect follows a catastrophic, practically unreachable event that P3 §5 already allows to unwind or terminate. It stays OPEN for the panic-policy owner decision. **P6/P7 recommendation:** choose `panic = "abort"` for the native library (simplest; a caught unwind can no longer leave state), or `catch_unwind` at every future ABI export that then discards the whole authority. Optionally add Router RAII for the `Admitting` claim and treat a poisoned run as terminal-and-released for transport accounting. P5 implements none of these.

## 8. P5-F-006: `base64` SIMD

- **Feature provenance:** `simd-unsafe` is in `base64`'s `default`, requested by both the core and vodozemac (§1).
- **What the feature does in 0.23.1:** it compiles `engine/simd.rs`, the only `unsafe` in the crate (`lib.rs:284-285`: `forbid(unsafe_code)` without the feature, `deny` with it). That module defines three **separate** engines: `Simd` (runtime `is_x86_feature_detected!("avx2")` / `is_aarch64_feature_detected!("neon")`, with scalar fallback), `Avx2`, and `Neon` (gated `target_arch = "aarch64"` plus `target_feature = "neon"`).
- **What the project calls:** `URL_SAFE_NO_PAD` is `GeneralPurpose::new(&URL_SAFE, NO_PAD)` (`general_purpose/mod.rs:472`). Its `internal_encode` is `encode_helper(&self.encode_table, input, output, |_, _| (0, 0))` (`:85-87`): the SIMD prefix is the no-op closure, and `encode_scalar_tail` is safe, bounds-checked code. The crate documents `GeneralPurpose` as using "no vector CPU instructions", and `base64::engine::Scalar` is a type alias for it. vodozemac's own `utilities` likewise use a `GeneralPurpose` engine. **No crate in the graph constructs `Simd`, `Avx2`, or `Neon`.** Decoding is never on the core's path (it only encodes).
- **Alphabet and padding:** URL-safe or not and padding or not change only the table and the tail; the scalar path is the same.
- **Unsafe invariants (source-reviewed, unreachable):** AVX2 `encode_bulk` requires a detected CPU (checked by `Simd::new`) and keeps its 32-byte loads and stores within `i + 32 ≤ input.len()` and `o + 32 ≤ output.len()`. `encode_helper`'s contract (whole 3-byte groups, `output_written == input_consumed / 3 * 4`) is `debug_assert`ed. No violation was found.

**Reference-encoder evidence** (`core/src/crypto/tests/p5_dependency_review.rs`). The oracle is a dependency-free bit-indexed encoder: character `k` is the 6-bit window at input bit `6k`, from the RFC 4648 §5 alphabet. It is checked against the RFC 4648 §10 vectors and the `-`/`_` positions.

| ID | Scope | Result |
|---|---|---|
| B64-REF-001 (CI) | Every length 0..=256 and each of 16, 32, 48, 64, 96, 128, 255, 256, 511, 512, 1023, 1024, 4095, 4096, 8191, 8192, 16383, 16384, 32767, 32768, 49152, 65535, 65536 at ±2 (306 lengths) × 4 patterns (zero, 0xff, ascending, xorshift). Compared `URL_SAFE_NO_PAD.encode` and `capped_base64url` with the empty prefix and the longest production prefix (`…/cancel/`); exact cap edges checked | 2,372 capped comparisons equal; 76 refusals, each exactly `Oversized` beyond the cap, never truncated. 0 mismatches. 0.33 s |
| B64-REF-002 (deep, `#[ignore]`) | **Every** length 0..=65,536, mixed and ascending patterns, each length encoded independently by the production engine call (and by `capped_base64url` up to 49,152). The expected value is assembled from the reference of the whole buffer's 3-byte groups plus an independent reference of the tail, and that assembly is checked against a fully independent reference every 257 lengths | 131,074 encodings, **0 mismatches**, 48.9 s (debug build, 2026-10-02) |
| B64-ENGINE-001 (CI) | Compile-time: `URL_SAFE_NO_PAD` has type `base64::engine::Scalar` (= `GeneralPurpose`) | Holds |
| B64-ENGINE-002 (CI, x86_64 only, **not the project path**) | The crate's `Simd::url_safe(NO_PAD)` against the reference on the CI set | Matches; AVX2 detected on this host |

**Architectures.** Source-reviewed: the scalar path (the only project path), AVX2, and NEON. Executed: scalar on x86_64 Windows (this host and CI) and on x86_64 Linux CI. The unused AVX2 engine was executed only on this host. **NEON was never executed**, and nothing here infers its correctness. It is also unreachable.

**Impact if a backend ever differed.** An encoding difference would make two peers derive different MAC or HKDF inputs, and verification would fail closed. No false authentication is possible: equal MAC inputs are required to verify. A memory-safety failure would need a reachable `unsafe` invariant violation, and there is none on the path.

**Disposition: reclassified to `FALSE-POSITIVE`** (severity if real: INFO; confidence HIGH). The premise that "the `simd-unsafe` engine encodes every MAC and HKDF input" is false at the locked versions. What remains is supply-chain footprint (an unused compiled `unsafe` module), not a remediation item. **Regression guard for P6 and beyond:** keep B64-ENGINE-001 and B64-REF-001. A future `base64` upgrade that made `GeneralPurpose` dispatch to SIMD would then need the deep run repeated, plus a decision on non-x86 targets.

## 9. Side channels (#32)

Threat scope: a remote network attacker observing timing over the network (P3 and threat model). Endpoint-local cache, power, and microarchitectural attacks are outside it (threat model: a compromised endpoint is out of scope; P5.1 §5). P3 does not treat the displayed SAS as a long-term secret.

| Operation | Secret? | Attacker-controlled operand? | Implementation (locked) | Constant-time requirement |
|---|---|---|---|---|
| X25519 scalar multiplication (DH) | Scalar: yes | Peer `u` | Montgomery ladder over all 255 bits, branch-free serial field arithmetic, `subtle` `conditional_swap` (`montgomery.rs:183`) | Yes. Met at source level (no secret-dependent branch or index) |
| Public-key generation | Scalar: yes | No | `variable_base_mul` (AVX2 or serial): fixed 64 windows, `LookupTable::select` (constant-time select) | Yes. Met at source level |
| Contributory (all-zero) check | Shared secret | Indirectly | `subtle` `ct_eq` of canonical bytes against zero; only the boolean (whether the peer chose a low-order point, which the peer already knows) affects control flow | Yes. Met; the outcome is public |
| HKDF extract and expand | PRK: yes | `info` only (public) | SHA-256 (SHA-NI or soft) over fixed-size secret blocks | Time depends only on public lengths |
| HMAC calculation | Key: yes | Input (public frame) | Same | Same |
| **HMAC verification** | Expected tag: yes | **Peer's tag** | digest 0.11.3 `verify_slice` (`mac.rs:139`): public length check, then `ctutils` → `cmov` word-wise `cmovne` in x86 `asm!` | **Yes. Met** (traced to the instructions) |
| SAS bytes and decimals | Short-lived, not a long-term secret | No | HKDF; bit arithmetic | Not required remotely |
| Commitment comparison (`crypto.rs:175-185`, `==`) | No: both operands are public (from START, revealed `R_pub`, received commitment) | Yes | Ordinary `==` | Not required |
| `ceremony_identity` comparisons (`ceremony.rs:1119, 1333`) | No (public transcript hash) | Yes / local | `==` | Not required |
| Final-ACK byte comparison (`ceremony.rs:1186`) | No (bytes the core itself built and sent) | No (local token) | `==` | Not required |
| Bootstrap and context comparisons (`ceremony.rs:566-569, 1880-1886`) | No (public) | Yes | `==` | Not required |
| Request ID, role, reason, sender comparisons | No (public routing fields) | Yes | `==` | Not required |
| Base64url encoding | Inputs are public frames, except the 6 SAS bytes in the approval frame | Partly | `GeneralPurpose` table lookups indexed by data, documented as not constant-time | Cache timing is local only; the SAS is not a long-term secret. Out of scope |

**Not performed:** timing measurement. No new dependency was added, and noisy timings would not prove constant-time behavior. Source-level tracing to the primitives is the evidence. Residual assumptions: the compiler preserves branch-free code (`subtle`'s `black_box` is best effort); the CPU executes the 64-bit multiplies and the `cmov` used here in data-independent time; local hardware side channels are out of scope.

**Coverage #32: COMPLETE for the current threat scope.** Every project comparison is classified. Every secret-dependent upstream path (DH, key generation, contributory check, HKDF, HMAC, tag verification) was traced in the locked source down to its constant-time primitive. The residual local side channels are recorded as outside the remote threat model. "Complete" does not mean formally proven constant-time. [P5-F-016](findings.md#p5-f-016) stays FALSE-POSITIVE, now with the comparison traced to the instruction level.

## 10. Secret lifetime and zeroization

| Item | Creation | Moves and copies | Owner | `Clone` / `Debug` | Zeroized? | Terminal drop | Caveats |
|---|---|---|---|---|---|---|---|
| Initiator / Responder `EphemeralSecret` | `random_from_rng` fills a local `[u8; 32]` and moves it into the struct | Moved into `Sas` → `EphemeralSas` → ceremony state (`mem::replace` moves); consumed by DH, which passes `self.0` **by value** to `mul_clamped` | `EphemeralSas` in the run state | Neither (compile-time check SECRET-TYPE-001) | **Yes, its own array**: x25519 `Drop` (`x25519.rs:112`) → `zeroize` volatile writes | DH or state drop on any terminal path | Moves may leave stack copies. `mul_clamped` builds a clamped `Scalar` copy (`Zeroize`, but **no** zeroize on drop). **The same 32 bytes stay in rand's `BlockRng` output buffer** (256 bytes, thread-local, not zeroized) until overwritten, and can be regenerated from the ChaCha12 state until the next reseed (rand's `ThreadRng` docs: "no further protections exist to in-memory state") |
| `SharedSecret` / `EstablishedSas` | DH | Moved into `Established` → `SasSession` | `SasSession` | Not `Clone`. `Debug` prints only the two public keys (exact output asserted by SECRET-TYPE-001) | **Yes**, x25519 `Drop` (`x25519.rs:348`) | Session drop at terminal or success, before guard release | Ladder intermediates (`ProjectivePoint`) not zeroized |
| HKDF PRK (`Hkdf` HMAC state) | Each `bytes` / `calculate_mac` / `verify_mac` call | Stack temporary | vodozemac | — | **No** (`hkdf` has no zeroize; `hmac`/`sha2`/`digest` `zeroize` features off) | End of call | Stack residue |
| MAC keys | `get_mac_key`: `Box<[u8; 32]>` | Heap | vodozemac | — | **No** | Freed at end of call | Heap residue until reused |
| HMAC state (`Hmac<Sha256>` ipad/opad) | `get_mac` | Stack | vodozemac | — | **No** | End of call | — |
| Computed tag (`Mac(Vec<u8>)`) | `calculate_mac` | Copied into the outbound frame | Wire data | — | No (public) | — | Public |
| SAS bytes `[u8; 6]` | `Established::sas` | Copied into `SasSession`, the approval frame, and its Base64 string | `SasSession` | `SasBytes` is `Clone + Debug` (upstream) | No | Session drop | Not a long-term secret (P3) |
| Decimal SAS `String` | Same | Cloned into `SasPresentation` for the consumer | `SasSession`; consumer copies | `SasPresentation` is `Debug + Clone` | No | Session drop; consumer copies live on | Not a long-term secret |
| `ceremony_identity` | Transcript hash | Copied widely | Public | `Clone`/`Copy` | n/a | — | Public |
| Authorization seal | `authorize` | Consumed by `reserve` | `Ceremony` / token | `Debug` redacted | n/a | — | Not secret |
| `PairingResult` | Success | Returned to consumer | Consumer | `Debug + Clone` | n/a | — | Public data |

Project code adds no secret copy of its own. It never reads the shared secret, MAC keys, or PRK. `Established` is moved, never cloned. Only public values and the non-secret SAS are copied.

**P5-F-010: strengthened, still ACCEPTED-LIMITATION (INFO).** The accepted boundary (x25519-dalek's zeroizing drop of `EphemeralSecret` and `SharedSecret`) is confirmed at the locked versions. Beyond it, P5.3 found two longer-lived **upstream** copies of the ephemeral private key that P5.1 did not record: rand's `ThreadRng` output buffer, and recomputation from its ChaCha12 state until the next reseed (up to 64 KiB of output per thread, without backtracking resistance). There is also a non-zeroized clamped `Scalar`. These are upstream copies, not project-owned, and need endpoint memory access, which is outside the threat model. P3 §5 already excludes "compiler/runtime copies… or other copies". So this is not a new finding. P6 may document it. If ever wanted, a fresh-key-erasure RNG or calling `ThreadRng::reseed` after generation would narrow it; that is not proposed for P5.

## 11. RNG, fork, and snapshot (P5-F-009)

- Process start: no RNG state exists until a thread first calls `Sas::new`. Each thread then seeds its own ChaCha12 from `ProcessPrng` (§7).
- Thread-local: every thread has an independent generator (`Rc`, `!Send`). The core calls `Sas::new` on whichever thread drives admission or exposure.
- Reseeding: after every 64 KiB of output per thread, from `ProcessPrng`, panicking on failure.
- Fork: rand documents "no automatic reseeding on process fork" and asks the caller to call `ThreadRng::reseed` (`thread.rs` docs). Windows has no `fork`, but any process or state duplication has the same effect.
- Snapshot and restore: a restored VM or process image replays the in-memory ChaCha12 state and buffer, so ephemeral keys repeat until the next reseed. This holds even if Windows reseeds `ProcessPrng` on restore (not verified here).

**P5-F-009: unchanged.** The existing wording ("A restored VM snapshot or duplicated process repeats `ThreadRng` state, and with it the ephemeral keys"; evidence: rand documents no reseed on fork) is accurate at the locked versions.

## 12. Dependencies (#33)

**Reachability classes** (A: compiled and reached at run time; B: compiled, unreachable from project paths; C: build or proc-macro only; D: target-specific, not built here):

| Class | Crates |
|---|---|
| **A** | vodozemac (only `sas` and `Curve25519PublicKey`), x25519-dalek, curve25519-dalek (Montgomery ladder, Edwards basepoint multiplication, `FieldElement51`, `Scalar`), subtle, rand, rand_core, chacha20 (RNG core), getrandom, hkdf, hmac, digest 0.11.3, ctutils, cmov, sha2 0.11.0, block-buffer 0.12.1, crypto-common 0.2.2, hybrid-array, typenum, sha2 0.10.9 with digest 0.10.7, block-buffer 0.10.4, crypto-common 0.1.7, generic-array (project SHA-256), cpufeatures 0.2.17 and 0.3.1, zeroize, base64 (scalar engine only), windows-sys / windows-targets / windows_x86_64_msvc (FFI declarations and import library), cfg-if |
| **B** | aes, cbc, cipher, inout, block-padding, cpubits, chacha20poly1305, aead, poly1305, universal-hash, hpke, ed25519-dalek, ed25519, signature, serdect, base16ct, base64ct, const-oid, arrayvec, serde, serde_core, serde_bytes, serde_json (normal via vodozemac; also the core's dev-dependency), itoa, memchr, zmij, prost, bytes, matrix-pickle, thiserror; vodozemac modules `cipher`, `ecies`, `hazmat`, `hpke`, `megolm`, `olm`, `types::ed25519` (`pk_encryption` and `libolm-compat` are not compiled); curve25519-dalek multiscalar and vartime vector modules; base64 `engine::simd` and decoding |
| **C** | serde_derive, thiserror-impl, zeroize_derive, curve25519-dalek-derive, matrix-pickle-derive, prost-derive, proc-macro2, quote, syn 2 and 3, unicode-ident, proc-macro-crate, toml_edit, toml_parser, toml_datetime, winnow, indexmap, hashbrown, equivalent, anyhow, itertools, either, rustc_version, semver, version_check |
| **D** | libc, r-efi, fiat-crypto, windows_aarch64_*, windows_i686_*, windows_x86_64_gnu / gnullvm |

Class B is supply-chain footprint (it is compiled and must be trusted not to misbehave at build time), not protocol attack surface: nothing in the project call graph reaches it. The release linker can drop unreferenced code; no claim is made about what a release binary contains.

**Duplicate crypto versions.** The core calls sha2 0.10.9 (with digest 0.10.7, block-buffer 0.10.4, crypto-common 0.1.7, cpufeatures 0.2.17) for exactly three P3/decision-0003 constructions: commitment, transcript identity, and lock-file name. vodozemac calls sha2 0.11.0 (digest 0.11.3, and so on) inside HKDF and HMAC. No single construction mixes the two: each always uses the same implementation on both peers in this binary. Both implement standard SHA-256, and the authoritative P3 vector (`crypto::deterministic_encoding_matches_authoritative_vector`) fixes the outputs. Feature unification differs between the copies only in non-behavioral features (`std`, `oid`, `alloc`). No duplicate creates two incompatible protocol paths. No finding.

**vodozemac pin.** `vodozemac = { version = "=0.11.0", default-features = false }`; the lock checksum `ba935af0…2574` matches decision 0002. The SAS, DH, HKDF, and MAC path is not bypassed (§3).

**Coverage #33: COMPLETE for the current threat scope.** The locked graph was rebuilt with `--locked`. Provenance was verified by checksum and byte comparison. Every security-sensitive crate was mapped to exact call sites and features, and reachable versus compiled-only dependencies were separated. All reachable upstream `unsafe` was inspected (§4), duplicates were analyzed, the pin and bypass were checked, and a fresh advisory scan was run (§13). Residual assumption, stated plainly: upstream correctness is trusted beyond the inspected paths, and no upstream fuzzing or formal verification was performed.

## 13. Advisory scan

- **Mechanism:** OSV `querybatch` (`https://api.osv.dev/v1/querybatch`, includes RustSec). `cargo audit` and `cargo deny` are not installed and were not installed.
- **Date:** 2026-10-02T15:23:01Z.
- **Scope:** all 96 crates.io packages in `core/Cargo.lock` at their exact versions.
- **Result:** **0 advisories.** The control query (`time 0.1.43`, `smallvec 1.6.0`) returned `GHSA-wcg3-cvx6-7396`/`RUSTSEC-2020-0071` and `GHSA-43w2-9j62-hq99`/`RUSTSEC-2021-0003`, confirming that the query works.
- **Applicability:** nothing to assess.

## 14. Reproducibility and CI hygiene

`core/Cargo.lock` is committed and consistent: every `--locked` command above succeeded. Both CI workflows run `cargo fmt`, `cargo clippy`, and `cargo test` **without `--locked`**, so CI uses the lockfile as long as it satisfies the manifest. A manifest edit that the lockfile no longer satisfied would be silently re-resolved in CI rather than failing. Today's caret requirements (`base64 = "0.23"`, `sha2 = "0.10"`, `getrandom = "0.4.3"`, `windows-sys = "0.59"`, `serde_json = "1"`) are all satisfied by the lock, so no drift occurs. **Recommendation for P6 (CI hygiene, not a security finding):** add `--locked` to the CI cargo commands. Optionally add an advisory job using an already-vetted tool. Workflows were not changed in P5.3.

## 15. Miri and sanitizers

Not run. Only the `cargo-miri` rustup proxy exists; no installed toolchain (stable or nightly) has the `miri` component, and installing it was out of scope. Sanitizers (nightly-only `-Zsanitizer`) were not attempted. The Win32 FFI paths cannot run under Miri anyway. The new review helpers are safe Rust apart from the FFI evidence test.

## 16. Residual assumptions

1. Windows honors the implied `GetTokenInformation(TokenUser)` postcondition ([P5-F-004](findings.md#p5-f-004), accepted).
2. `ProcessPrng` does not fail on supported Windows; if it does, the panic policy decision of [P5-F-005](findings.md#p5-f-005) applies.
3. The compiler and CPU preserve the constant-time properties of the traced primitives.
4. Upstream crates are correct beyond the inspected paths. Unreachable compiled code is not audited.
5. No endpoint memory access ([P5-F-010](findings.md#p5-f-010)), and no duplicated process or VM state ([P5-F-009](findings.md#p5-f-009)).

## 17. New findings and coverage conclusion

**No new finding.** Each candidate was checked against the false-positive discipline: rand's buffer remanence is upstream-owned and already within F-010; the live-slot residue is part of F-005; the misaligned-buffer refusal fails closed; the `--locked` gap is hygiene. **Coverage after P5.3:** #32 and #33 are COMPLETE. **No `PARTIAL` surface remains** in the [coverage matrix](coverage.md). This does not complete P5: final synthesis and closure are a separate increment.
