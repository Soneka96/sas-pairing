//! P5.3 review-only evidence (NOT part of the product; changes no production behavior):
//! P5-F-006 and the locked `base64` 0.23.1 encoder on the authentication path. Families
//! `B64-REF-*` and `B64-ENGINE-*` in `docs/p5-security-review/dependency-unsafe-deep-review.md`.
//!
//! The oracle is a dependency-free bit-indexed Base64url encoder written only for this review:
//! output character `k` is the 6-bit window starting at input bit `6k`, looked up in the
//! RFC 4648 §5 alphabet, with no padding. It shares no code or structure with the crate's
//! 3-byte-group encoder.
use super::*;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// RFC 4648 §5 "URL and Filename safe" alphabet.
const REFERENCE_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Independent unpadded Base64url: `ceil(8n / 6)` characters, character `k` taken from the
/// six input bits starting at bit `6k` (most significant bit first), missing bits zero.
fn reference_base64url(input: &[u8]) -> String {
    let chars = (input.len() * 8).div_ceil(6);
    let mut out = String::with_capacity(chars);
    for k in 0..chars {
        let bit = 6 * k;
        let (byte, offset) = (bit / 8, bit % 8);
        let high = u16::from(input[byte]);
        let low = u16::from(input.get(byte + 1).copied().unwrap_or(0));
        let window = (high << 8) | low;
        let index = (window >> (10 - offset)) & 0x3f;
        out.push(char::from(REFERENCE_ALPHABET[usize::from(index)]));
    }
    out
}

/// The four deterministic contents of the review plan.
#[derive(Clone, Copy, Debug)]
enum Pattern {
    Zero,
    Ones,
    Ascending,
    Mixed,
}
const PATTERNS: [Pattern; 4] = [
    Pattern::Zero,
    Pattern::Ones,
    Pattern::Ascending,
    Pattern::Mixed,
];

fn pattern(pattern: Pattern, len: usize) -> Vec<u8> {
    match pattern {
        Pattern::Zero => vec![0; len],
        Pattern::Ones => vec![0xff; len],
        Pattern::Ascending => (0..len).map(|i| i as u8).collect(),
        Pattern::Mixed => {
            // xorshift32 with a fixed seed: deterministic, every byte value occurs.
            let mut state = 0x9e37_79b9_u32;
            (0..len)
                .map(|_| {
                    state ^= state << 13;
                    state ^= state >> 17;
                    state ^= state << 5;
                    (state >> 24) as u8
                })
                .collect()
        }
    }
}

/// The structural boundaries of the plan (and of the AVX2 engine's 24/32-byte blocks and
/// 128-byte minimum), each probed at `n-2..=n+2`, plus the production cap edge 49,152.
const BOUNDARIES: [usize; 23] = [
    16, 32, 48, 64, 96, 128, 255, 256, 511, 512, 1023, 1024, 4095, 4096, 8191, 8192, 16383, 16384,
    32767, 32768, 49152, 65535, 65536,
];

/// Every length 0..=256 and every boundary length, deduplicated and ascending.
fn ci_lengths() -> Vec<usize> {
    let mut lengths: Vec<usize> = (0..=256).collect();
    for n in BOUNDARIES {
        lengths.extend(n.saturating_sub(2)..=n + 2);
    }
    lengths.sort_unstable();
    lengths.dedup();
    lengths
}

/// The largest input whose unpadded encoding plus `prefix` fits the 65,536-byte cap.
fn largest_capped_input(prefix: &[u8]) -> usize {
    let room = CRYPTO_INPUT_LIMIT - prefix.len();
    room / 4 * 3
        + match room % 4 {
            0 | 1 => 0,
            2 => 1,
            _ => 2,
        }
}

/// The oracle itself against RFC 4648 §10 vectors (in their URL-safe, unpadded form) and the
/// two alphabet positions that differ from standard Base64.
#[test]
fn p5_b64_ref_000_reference_encoder_matches_rfc_4648_vectors() {
    for (input, expected) in [
        (&b""[..], ""),
        (b"f", "Zg"),
        (b"fo", "Zm8"),
        (b"foo", "Zm9v"),
        (b"foob", "Zm9vYg"),
        (b"fooba", "Zm9vYmE"),
        (b"foobar", "Zm9vYmFy"),
        // Standard "+/8" and "+/+/": positions 62 and 63 are '-' and '_' in Base64url.
        (&[0xfb, 0xff][..], "-_8"),
        (&[0xfb, 0xef, 0xbe][..], "----"),
        (&[0xff, 0xff, 0xff][..], "____"),
    ] {
        assert_eq!(reference_base64url(input), expected, "{input:?}");
    }
    // Length law: ceil(8n/6), i.e. 4 per 3-byte group plus 0, 2, or 3 for the tail.
    for n in 0..64 {
        assert_eq!(
            reference_base64url(&vec![0; n]).len(),
            n / 3 * 4 + [0, 2, 3][n % 3]
        );
    }
}

/// `B64-REF-001`, CI tier. Production `capped_base64url` (and the exact engine call it makes)
/// against the independent reference for every length 0..=256 and every boundary ±2 up to
/// 65,538, for all four patterns, with the empty prefix and with the longest production prefix.
/// Inputs over the cap must be refused as `Oversized` by `capped_base64url`, never truncated;
/// the engine call itself is still compared there.
#[test]
fn p5_b64_ref_001_production_encoder_matches_reference_ci_set() {
    let lengths = ci_lengths();
    let mut compared = 0usize;
    let mut capped = 0usize;
    for kind in PATTERNS {
        let longest = pattern(kind, *lengths.last().unwrap());
        for &n in &lengths {
            let input = &longest[..n];
            let expected = reference_base64url(input);
            assert_eq!(URL_SAFE_NO_PAD.encode(input), expected, "{kind:?} len {n}");
            for prefix in [&b""[..], CANCEL_PREFIX] {
                match capped_base64url(prefix, input) {
                    Ok(encoded) => {
                        assert!(n <= largest_capped_input(prefix), "{kind:?} len {n}");
                        assert_eq!(&encoded.as_bytes()[..prefix.len()], prefix);
                        assert_eq!(&encoded[prefix.len()..], expected, "{kind:?} len {n}");
                        compared += 1;
                    }
                    Err(error) => {
                        assert_eq!(error, Error::Oversized, "{kind:?} len {n}");
                        assert!(n > largest_capped_input(prefix), "{kind:?} len {n}");
                        capped += 1;
                    }
                }
            }
        }
    }
    // Exact cap edges: 49,152 bytes encode to exactly 65,536 characters.
    assert_eq!(largest_capped_input(b""), 49_152);
    assert_eq!(
        capped_base64url(b"", &[0; 49_152]).map(|s| s.len()),
        Ok(65_536)
    );
    assert_eq!(capped_base64url(b"", &[0; 49_153]), Err(Error::Oversized));
    let edge = largest_capped_input(CANCEL_PREFIX);
    assert_eq!(
        capped_base64url(CANCEL_PREFIX, &vec![0; edge]).map(|s| s.len() <= CRYPTO_INPUT_LIMIT),
        Ok(true)
    );
    assert_eq!(
        capped_base64url(CANCEL_PREFIX, &vec![0; edge + 1]),
        Err(Error::Oversized)
    );
    eprintln!(
        "B64-REF-001: {} lengths x {} patterns; {compared} capped_base64url comparisons, \
         {capped} Oversized refusals beyond the cap",
        lengths.len(),
        PATTERNS.len()
    );
}

/// `B64-REF-002`, manual deep tier: EVERY input length 0..=65,536 for the mixed and ascending
/// patterns, each length encoded independently by the production engine call and compared with
/// the reference. Run with `--ignored`. The reference for length `n` is assembled from the
/// reference encoding of the whole buffer (its first `4 * (n / 3)` characters, which depend only
/// on the first `n - n % 3` bytes) plus an independent reference encoding of the `n % 3`-byte
/// tail; that assembly is itself checked against a fully independent reference every 257 lengths.
#[test]
#[ignore = "P5.3 deep run: every length 0..=65,536 (about 4.3 GB of encoding)"]
fn p5_b64_ref_002_every_length_up_to_the_frame_maximum() {
    let started = std::time::Instant::now();
    let max = 65_536;
    let mut checked = 0usize;
    for kind in [Pattern::Mixed, Pattern::Ascending] {
        let input = pattern(kind, max);
        let whole = reference_base64url(&input);
        for n in 0..=max {
            let groups = n / 3 * 4;
            let mut expected = String::with_capacity(groups + 3);
            expected.push_str(&whole[..groups]);
            expected.push_str(&reference_base64url(&input[n - n % 3..n]));
            if n % 257 == 0 {
                assert_eq!(
                    expected,
                    reference_base64url(&input[..n]),
                    "assembly at {n}"
                );
            }
            assert_eq!(
                URL_SAFE_NO_PAD.encode(&input[..n]),
                expected,
                "{kind:?} len {n}"
            );
            if n <= largest_capped_input(b"") {
                assert_eq!(
                    capped_base64url(b"", &input[..n]).as_deref(),
                    Ok(&*expected)
                );
            }
            checked += 1;
        }
    }
    eprintln!(
        "B64-REF-002: {checked} independent encodings (every length 0..={max}, 2 patterns) \
         matched the reference in {:?}",
        started.elapsed()
    );
}

/// `B64-ENGINE-001`. The engine on the authentication path is the scalar `GeneralPurpose`
/// engine (compile-time type check, not a convention): `base64::engine::Scalar` is its alias,
/// and its `internal_encode` passes the no-op SIMD prefix `|_, _| (0, 0)` (base64 0.23.1
/// `src/engine/general_purpose/mod.rs:85-87`), so the `simd-unsafe` engines are compiled but
/// never reached through `URL_SAFE_NO_PAD`.
#[test]
fn p5_b64_engine_001_the_authentication_path_uses_the_scalar_engine() {
    const SCALAR: &base64::engine::Scalar = &URL_SAFE_NO_PAD;
    let _: &base64::engine::GeneralPurpose = SCALAR;
    assert_eq!(
        URL_SAFE_NO_PAD.encode([0xfb, 0xff]),
        "-_8",
        "URL-safe alphabet"
    );
    assert_eq!(URL_SAFE_NO_PAD.encode([0]), "AA", "no padding");
}

/// `B64-ENGINE-002`, supplementary and NOT the project path: the crate's runtime-dispatched
/// `Simd` URL-safe engine (AVX2 when detected) also matches the reference on the CI set on this
/// x86_64 host. It records which backend this machine would select. It says nothing about NEON.
#[cfg(target_arch = "x86_64")]
#[test]
fn p5_b64_engine_002_unused_simd_engine_agrees_on_this_x86_64_host() {
    use base64::engine::{Simd, general_purpose::NO_PAD};
    let simd = Simd::url_safe(NO_PAD);
    let avx2 = std::is_x86_feature_detected!("avx2");
    for kind in PATTERNS {
        let longest = pattern(kind, 65_538);
        for n in ci_lengths() {
            let input = &longest[..n];
            assert_eq!(
                simd.encode(input),
                reference_base64url(input),
                "{kind:?} len {n}"
            );
        }
    }
    // The same detection decides the runtime backends of the reachable SHA-256 (SHA-NI) and
    // curve25519-dalek / chacha20 (AVX2) code on this host; recorded, not asserted.
    let sha_ni = std::is_x86_feature_detected!("sha")
        && std::is_x86_feature_detected!("sse4.1")
        && std::is_x86_feature_detected!("ssse3");
    eprintln!("B64-ENGINE-002: AVX2 detected = {avx2}, SHA-NI detected = {sha_ni}");
}

/// Compile-time negative trait check: `<T as AmbiguousIfClone<_>>::NOT` names exactly one impl
/// when `T: !Clone` and is ambiguous (a compile error) when `T: Clone`.
trait AmbiguousIfClone<Marker> {
    const NOT: () = ();
}
impl<T: ?Sized> AmbiguousIfClone<()> for T {}
struct IsClone;
impl<T: Clone> AmbiguousIfClone<IsClone> for T {}

/// The same check for `Debug`.
trait AmbiguousIfDebug<Marker> {
    const NOT: () = ();
}
impl<T: ?Sized> AmbiguousIfDebug<()> for T {}
struct IsDebug;
impl<T: ?Sized + std::fmt::Debug> AmbiguousIfDebug<IsDebug> for T {}

/// `SECRET-TYPE-001`. Secret-bearing types on the core's path cannot be cloned (no second copy
/// outlives the zeroizing drop through a `Clone`), and the ephemeral state has no `Debug` at
/// all. The established session's only `Debug` (vodozemac's manual impl) prints the two public
/// keys and nothing else. Type properties only: this says nothing about compiler or stack copies.
#[test]
fn p5_secret_type_001_secret_holders_are_not_clone_and_debug_shows_only_public_keys() {
    let () = <EphemeralSas as AmbiguousIfClone<_>>::NOT;
    let () = <EphemeralSas as AmbiguousIfDebug<_>>::NOT;
    let () = <Established as AmbiguousIfClone<_>>::NOT;
    let () = <vodozemac::sas::Sas as AmbiguousIfClone<_>>::NOT;
    let () = <vodozemac::sas::Sas as AmbiguousIfDebug<_>>::NOT;
    let () = <vodozemac::sas::EstablishedSas as AmbiguousIfClone<_>>::NOT;

    let (ours, theirs) = (EphemeralSas::new(), EphemeralSas::new());
    let (our_key, their_key) = (ours.public_key(), theirs.public_key());
    let established = ours.establish(&their_key).unwrap();
    let b64 = |key: &[u8; 32]| base64::engine::general_purpose::STANDARD_NO_PAD.encode(key);
    assert_eq!(
        format!("{established:?}"),
        format!(
            "Established(EstablishedSas {{ our_public_key: {:?}, their_public_key: {:?}, .. }})",
            b64(&our_key),
            b64(&their_key)
        )
    );
}
