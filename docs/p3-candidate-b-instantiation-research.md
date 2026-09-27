# P3.2 — Candidate B cryptographic instantiation research

> **RESEARCH / NOT A PROFILE / NOT PRODUCTION READY**
>
> This document evaluates concrete instantiation options for Candidate B selected in P2. It does not choose a wire format, hash, commitment, parameter set, or production implementation.

## 1. Question

Can Candidate B be instantiated with practical standard primitives while retaining the theorem and assumptions selected in P2? In particular, can its commitment and random-oracle calls be mapped to precise bytes and a maintained Rust implementation without claiming that a real hash is a random oracle?

**STOP:** the paper does not specify a concrete commitment formula or encoding, and its theorem models the SAS hash as a random oracle. The evidence reviewed here does not justify replacing that oracle with a named hash as a theorem-preserving instantiation. No cryptographic component is **SELECTED**.

## 2. Candidate B source construction

**SELECTED in P2 (construction direction only).** Candidate B is the mutual protocol \(\pi_{SAS}^{\times}\) of Beskorovajnov and Müller-Quade, Theorem 3 of the revised ePrint manuscript. The construction details below are paper-specified, not an instantiation choice. For one session, the Sender S has `m_S`; the Receiver R supplies `m_R` and a fresh uniform `κ`-bit `r_R`. S samples fresh uniform `κ`-bit commitment coins `r_S` and computes:

```text
(C, d) ← Commit(sid || m_S; r_S)
S → R: C
R → S: (m_R, r_R)
S → R: Open(C, d)       // reveals the opening, including m_S and r_S
Verify(C, sid || m_S, d) must accept
s = Trunc_t(H(sid || m_S || m_R || r_S || r_R))
S and R submit (SAS, sid, s) to the synchronous ideal OOB comparator
```

On exact OOB equality, R outputs `m_S` and S outputs `m_R`; otherwise both abort. `d` is the commitment opening witness. In the paper’s proof and simulator the opening reveals `(m_S, r_S)`. `r_S` is both the fresh commitment randomness and a SAS input. `r_R` is a separate independent uniform challenge, sent with `m_R`; it is not commitment randomness.

The paper’s commitment definition provides `Commit(m; r) → (C,d)` and `Verify(C,m,d) → {0,1}` with correctness, computational hiding, and computational binding. The security proof uses both hiding and binding. The sender’s SID is supplied by the environment or, if absent, freshly sampled as a uniform `κ`-bit value and sent to R. In either case one `sid` tags the session and its subroutine calls. In this protocol it is prepended to `m_S` inside the commitment and is the first SAS input.

The paper models `H : {0,1}* → {0,1}^n` as a random oracle. `Trunc_t` takes a fixed `t`-bit portion; the proof’s coupling treats it as the prefix of the `n`-bit output. No byte order or mapping from hash-output bytes to displayed bits is fixed. The mutual SAS input order is exactly `sid, m_S, m_R, r_S, r_R`. The paper writes concatenation (`||`) and does not define a byte-level tuple encoding or additional protocol/domain tag.

Theorem 3 assumes computationally hiding and binding `Com`, the random-oracle SAS, and the synchronous ideal OOB equality functionality; S and R remain honest. The ideal functionality permits one active forgery attempt per SID with `ε = 2^-t`. The real/ideal distinguishing argument also has commitment hiding/binding advantages, a pre-reveal random-oracle hit term bounded by `2 q_H(κ) 2^-κ`, and negligible terms. It is not an aggregate bound across unlimited SIDs, a model of human error, or a claim about a deployed hash.

**ACNS publication check.** The peer-reviewed ACNS 2026 chapter’s accessible Appendix A, Theorem 5, states the analogous one-sided `π_SAS` result and assumptions. The complete mutual protocol and Theorem 3 details cited above are in the revised ePrint manuscript; the publication page’s preview does not expose the full chapter. The two versions agree on the construction direction and theorem assumptions visible in the publication, but this research does not claim line-by-line identity.

## 3. Commitment requirements

| Requirement | Paper support | Engineering consequence |
|---|---|---|
| Correct opening | `Verify(C,m,d)` accepts honestly generated openings except with negligible probability. | Receiver must verify the exact committed `sid || m_S` before calculating the SAS or succeeding. |
| Computational hiding | Explicit theorem assumption; paper’s definition compares equal-length challenge messages. | `C` must not reveal the committed message before the opening, within the message-length model justified by the profile. |
| Computational binding | Explicit theorem assumption: no efficient party opens one `C` to two distinct messages. | The profile must preserve one unique accepted message for the commitment. |
| Randomness | `r_S ← {0,1}^κ`, fresh and uniform; hidden until opening; included in the SAS input. The proof’s pre-hit bound relies on guessing it. | Use an approved CSPRNG, keep `r_S` secret through commitment, and never reuse it across sessions. Carrying P2’s 256-bit SID default through the paper’s shared `κ` is a mapping candidate described below. |
| SID and tags | `sid` is part of committed message; the paper gives no separate commitment tag or version tag. | Distinct commitment/SAS tags may be useful engineering separation, but adding them is a profile choice requiring review. |
| Parameters | `r_S` has `κ` bits; the paper leaves the concrete commitment primitive, output encoding, and parameter profile abstract. | Commitment digest length, computational target, and any maximum message length remain unresolved. |

**CANDIDATE mapping for review:** P2 sets a fresh 256-bit SID as the profile default. The paper uses one `κ` for a sampled SID, `r_S`, and `r_R`; carrying the P2 SID default through therefore maps `κ=256` and makes both nonces 256 bits. This records the theorem-faithful consequence of the existing SID choice, not a new choice based on convention. P2 does not separately spell out this cross-field mapping; it must be confirmed in profile review. The hash output length `n` and SAS length `t` remain separate and unresolved.

The paper states that its main constructions instantiate `Commit` as “hash-then-open in the random-oracle model,” with binding and computational hiding attributed to Bellare–Rogaway. It does **not** specify the commitment hash formula, whether it is the same oracle call domain as the SAS hash, the digest length/encoding, a concrete primitive, or a wire representation for `d`. Therefore the paper specifies a construction family and proof model, not an implementable commitment profile. Do not fill this gap by assuming `H(r || m)`, `H(m || r)`, or a convenient crate’s `commit` API is the paper’s exact formula.

## 4. Candidate commitment instantiations

These are **PROJECT INSTANTIATION DECISIONS**, not formulas specified by the paper.

### C1 — SHA-256 salted hash-then-open (**CANDIDATE**)

```text
message = canonical_encode(sid, m_S)
C       = SHA-256(canonical_encode(commit-domain, message, r_S))
d       = (message, r_S)
Verify  = recompute C and compare in constant time
```

`r_S` would be fresh, uniform, and `κ` bits as required by the theorem; the encoded message must reproduce the exact committed `sid || m_S` meaning. In a random-oracle model, a secret uniform salt makes the digest hide a message before opening, subject to query work against the salt; two distinct valid openings yield a hash collision, supporting binding. With real SHA-256 these are heuristic reductions to concrete-hash behavior, not the paper’s literal oracle argument. Domain and encoding fields above are proposed engineering choices and need review.

### C2 — SHA3-256 salted hash-then-open (**CANDIDATE**)

Use the same opening and verification shape as C1, replacing SHA-256 with SHA3-256. The hiding and binding rationale has the same random-oracle/collision-resistance gap. SHA3-256 is separately specified by FIPS 202, but that standard does not prove the Candidate B commitment theorem for SHA3-256.

Neither candidate is **SELECTED**. Each still requires confirmation of the `κ=256` mapping, a complete injective encoding, exact domain separation, full reduction/assumption analysis, and independent cryptographic review. No existing Rust crate found in this review implements the Candidate B commitment protocol itself.

### Author reference implementation (**RESEARCH ONLY**)

The author-linked NoisyTransfer source at commit [`9747fe1`](https://github.com/collapsinghierarchy/noisytransfer-protocol/tree/9747fe19980a1cc6f1e9a0c2798a61b1dbe37b34) computes a commitment as `H(DS || LP(label) || LP(data) || LP(nonce))`, defaults to a 32-byte nonce, and supports SHA3-256/SHA-256. Its SAS uses a different transcript containing protocol/room/session/commit identifiers and derives decimal digits through SHAKE128 rejection sampling. This is useful implementation evidence for length-prefixed inputs, but it is **not Candidate B’s formula or SAS**, and the Candidate B theorem does not cover it. At the cited revision the package is experimental `@noisytransfer/noisyauth` 0.2.4, Node 20+, AGPL-3.0-only; no independent audit was identified in the reviewed repository/package materials. It is JavaScript, not a Rust implementation for this project.

## 5. Random-oracle/hash requirements

**PAPER-SPECIFIED SAS call:**

```text
s = Trunc_t(H(sid || m_S || m_R || r_S || r_R))
```

The paper models one random oracle `H` with `n` output bits, then applies fixed `t`-bit truncation. Its proof relies on unseen distinct inputs receiving independent uniform outputs and bounds pre-reveal hits by guessing the hidden uniform `r_S`. A proposed profile must specify a concrete primitive and output size, serialization of each field, all lengths/ordering, domain and version tags, which output bits are retained, and byte/bit ordering.

SHA-256 and SHA3-256 are standard hash functions specified respectively by [NIST FIPS 180-4](https://csrc.nist.gov/pubs/fips/180-4/upd1/final) and [NIST FIPS 202](https://csrc.nist.gov/pubs/fips/202/final). They are practical candidates, not literal random oracles. A proof in the random-oracle model does not automatically become a proof for either function. At most, a reviewed profile could make an explicit heuristic/assumption-based claim about a concrete hash; this research cannot justify reusing the paper’s complete bound as a concrete-system bound.

**Candidate hash profile H1 — SHA-256 — CANDIDATE.** Use a standard 32-byte SHA-256 output, with a reviewed encoding that includes all five ordered inputs and the exact profile/domain identifier. The theorem’s output length is `n`; selecting SHA-256 sets `n=256` as an engineering decision. `t`, retained bit range, and endianness are still not selected. The RustCrypto [`sha2` crate](https://docs.rs/crate/sha2/latest) supplies SHA-256, but does not implement Candidate B or justify its random-oracle assumption.

**Candidate hash profile H2 — SHA3-256 — CANDIDATE.** Same input/encoding requirements, with FIPS 202 SHA3-256 and `n=256`. The RustCrypto [`sha3` crate](https://docs.rs/crate/sha3/latest) supplies the primitive only. It does not provide Candidate B’s proof or domain/encoding policy.

**BLAKE3 — RESEARCH ONLY.** It has a public specification and official Rust implementation, 256-bit default output, multiple architecture backends, and an actively released crate. It is a technically practical hash candidate, but it is not one of the NIST SHA-2/SHA-3 standards above, and offers no better theorem mapping. Include only if a future requirements review accepts it for separate analysis; no performance argument is needed for this design-stage choice.

The [RFC 9380](https://www.rfc-editor.org/rfc/rfc9380.html) domain-separation discussion is relevant engineering guidance for distinct hash domains, but its hash-to-curve suites do not specify this protocol’s transcript encoding or repair the random-oracle assumption. A profile could use fixed purpose/version tags and unambiguous encodings; that remains a project decision.

## 6. Encoding and domain-separation requirements

**STOP for profile selection until inputs have one unique byte representation.** The final network format is out of scope. Cryptographic inputs nevertheless need:

- Encode the ordered tuple `(sid, m_S, m_R, r_S, r_R)` injectively. Fixed-width fields or canonical length-prefixed fields are suitable patterns for review; raw concatenation of variable-length `m_S` and `m_R` is ambiguous.
- Fix `sid`, `r_S`, and `r_R` lengths once parameters are selected. A SID supplied by the caller still needs canonical validation and safe uniqueness/lifecycle handling.
- Encode commitment input `sid || m_S` consistently with the opening and `Verify`; a commitment tag, profile version, and purpose tag are engineering choices, not values chosen in the paper.
- Reject alternate/noncanonical encodings before hashing. Delimiters alone are insufficient unless escaping and parsing make the encoding injective.
- Specify the exact output-bit extraction: paper proof uses a `t`-bit prefix of the random-oracle bit string. A byte-level profile must define what “first” means and how partial-byte truncation maps to bits.

These requirements avoid encoding ambiguity; they do not establish that the selected concrete hash behaves as a random oracle.

## 7. Rust implementation evidence

| Primitive/library | Evidence checked | Scope and limits |
|---|---|---|
| RustCrypto `sha2` 0.11.0 | Released 2026-03-25; pure Rust, MIT OR Apache-2.0; SHA-256 and other SHA-2 algorithms; portable software plus x86/AArch64, WebAssembly SIMD, and experimental RISC-V backends are documented. The crate is `no_std` capable. | Hash primitive only. No Candidate B commitment/protocol. The reviewed upstream materials include a vulnerability reporting policy but no audit report for this instantiation. No `unsafe` use appeared in the inspected top-level source; the complete crate/dependency unsafe surface was not audited. |
| RustCrypto `sha3` 0.12.0 | Released 2026-05-15; SHA-3-family crate, MIT OR Apache-2.0; SHA3-256 and SHAKE in adjacent `shake` crate. Crate is `no_std`/pure Rust and the RustCrypto project documents bare-metal and WebAssembly use; no per-target matrix was found. | Hash primitive only. The crate root forbids unsafe code; its `keccak` dependency was not audited here. No Candidate B commitment/protocol or audit report for this instantiation was identified in the reviewed upstream materials. |
| Official `blake3` 1.8.7 | Released 2026-08-20; official Rust/C implementation; CC0-1.0 OR Apache-2.0 options; documents x86 SIMD, NEON and WASM implementations and x86 runtime CPU detection. | A hash implementation, not the Candidate B protocol. Reviewed crate docs do not state an unsafe footprint; optimized backend unsafe use was not assessed. No independent audit report was identified in official materials reviewed. A separate choice and analysis would be needed. |
| `curve25519-dalek` 5.0.0 | Current docs describe a pure-Rust Ristretto/Curve25519 group library, BSD-3-Clause, platform/MSRV policy, constant-time APIs except explicitly variable-time functions, and no significant `unsafe` code (SIMD backend uses it internally). | Group arithmetic, not a byte-string commitment. A Pedersen-style option would add group parameters and a reviewed byte-string-to-group/scalar construction; this crate is not a drop-in Candidate B commitment and is not evaluated as a profile candidate here. |

**RESEARCH ONLY:** these maintained libraries provide implementation evidence, not a security selection. Their recent releases and licenses are compatible with the repository’s dual MIT/Apache licensing direction. Audit statements above are limited to the materials consulted; no production dependency is added. The hash APIs implement algorithms, not Candidate B, the paper’s abstract `Commit` interface, canonical transcript encoding, or human comparison.

## 8. Security assumption gaps

1. **Concrete hash versus random oracle — STOP.** FIPS compliance or a mature crate does not make SHA-256/SHA3-256 a random oracle. The theorem’s uniform-independent-output argument, pre-hit analysis, and exact bound do not follow solely from a named standard hash.
2. **Commitment underspecification — STOP.** The paper names hash-then-open in the ROM but omits the concrete formula, digest, oracle separation, encoding, and opening wire shape. A project formula is a new instantiation decision requiring proof mapping and review.
3. **Encoding — STOP until specified.** Variable-length concatenation without injective framing can collapse distinct tuples onto identical hash inputs, so theorem inputs would no longer represent the protocol fields uniquely.
4. **Bounds — unresolved.** `2^-t` is one online forgery attempt per SID in the ideal functionality. It is not an aggregate limit across retries/SIDs and omits concrete hash/commitment advantages, pre-hit probability, and human error from a deployed-system statement.
5. **Reference implementation — insufficient.** NoisyTransfer has a materially different commitment and SAS; code resemblance cannot transfer Candidate B’s theorem.

## 9. Decision matrix

| Item | Classification | Reason |
|---|---|---|
| Candidate B mutual construction and abstract properties | **SELECTED** (P2 result retained) | The project’s P2 decision selected this construction under its stated theorem assumptions; this does not select an instantiation. |
| SHA-256 randomized hash-then-open commitment | **CANDIDATE** | Practical standard primitive and plausible salted-hash commitment; concrete proof mapping, formula, encoding, parameters, and independent review remain missing. |
| SHA3-256 randomized hash-then-open commitment | **CANDIDATE** | Same gaps as SHA-256; standard algorithm does not close the ROM gap. |
| SHA-256 SAS profile | **CANDIDATE** | Standard and mature implementation support; concrete-hash theorem gap, input encoding, `t`, truncation bit order, and review unresolved. |
| SHA3-256 SAS profile | **CANDIDATE** | Same. |
| BLAKE3 SAS profile | **RESEARCH ONLY** | Practical, specified implementation; no stronger theorem mapping and not advanced to profile review. |
| NoisyTransfer implementation as Candidate B | **RESEARCH ONLY** | Author-linked implementation evidence, but materially different protocol/formula and AGPL-3.0-only JS package. |
| Any concrete commitment/hash combination for the P3 profile | **STOP** | Current sources do not justify the real-hash instantiation or fully specify commitment inputs/encoding. |

## 10. Recommendation

**STOP concrete cryptographic selection.** Retain Candidate B as P2’s construction direction, but do not freeze a commitment, hash, `t`, SAS bit order, or byte encoding in P3 on this evidence.

**Recommended next task: P3.3 — primary-source clarification of Candidate B’s intended concrete commitment/hash instantiation.** Contact the paper authors and inspect any supplementary material they identify before proposing a project-specific mapping for independent cryptographic review. Keep all concrete commitment, hash, encoding, and parameter choices unselected until that evidence is obtained.

Ask the authors:

1. What exact hash-then-open commitment construction is intended for `Commit(m; r)` in Candidate B?
2. Is there a concrete formula or supplementary construction considered faithful to Theorem 3?
3. Are the commitment hash and SAS random-oracle call intended to use the same oracle/domain, domain-separated calls to one oracle, or conceptually separate oracles?
4. What concrete encoding or framing is intended for concatenations such as `sid || m_S || m_R || r_S || r_R`?
5. Is a standard hash such as SHA-256 or SHA3-256 with explicit injective encoding and domain separation considered a reasonable engineering instantiation of the ROM construction?
6. If so, what security claim do the authors consider defensible for such a real-hash instantiation?
7. Is there a more faithful or complete reference implementation of the mutual Candidate B construction than the reviewed NoisyTransfer implementation?
8. Does the paper’s RO-free direction offer a more appropriate path for a reusable production-oriented library? If so, what exact construction or source should be evaluated?

If the clarification supports a concrete proposal, submit that mapping for independent cryptographic review before selecting it. If it does not, retain STOP and record the unresolved gap.

## 11. What remains unresolved

- Exact hash-then-open formula intended by the paper and whether commitment hashing shares the SAS oracle.
- Concrete commitment formula and evidence for hiding/binding with the required uniform `κ`-bit `r_S`.
- A rigorous, honestly stated assumption connecting a concrete hash to the ROM proof, or a separately analyzed construction that removes the ROM.
- Injective encodings, maximum sizes, domain/version tags, and byte/bit ordering.
- `κ`, `n`, `t`, session/attempt accounting, and resulting aggregate bound.
- Mature, suitable Rust commitment implementation support; no such Candidate B implementation was found in the reviewed sources.
- Independent cryptographic review.

## Sources reviewed

### Primary sources

1. Beskorovajnov and Müller-Quade, [IACR ePrint 2025/1598](https://eprint.iacr.org/2025/1598), revised 2025-09-11: Definition 2, Sections 3.1–3.2, mutual protocol `π_SAS^×`, Theorem 3 and proof. The full PDF was downloaded and inspected; the archive metadata identifies the author manuscript and revision.
2. Beskorovajnov and Müller-Quade, [ACNS 2026 chapter](https://doi.org/10.1007/978-3-032-32560-0_15), LNCS 16571, pp. 415–443, first online 2026-07-22: publication record/abstract and accessible Appendix A, Theorem 5. The preview exposes the one-sided theorem, not the full mutual theorem.
3. Authors’ [NoisyTransfer commitment source](https://github.com/collapsinghierarchy/noisytransfer-protocol/blob/9747fe19980a1cc6f1e9a0c2798a61b1dbe37b34/packages/crypto/src/commitment.js), [SAS source](https://github.com/collapsinghierarchy/noisytransfer-protocol/blob/9747fe19980a1cc6f1e9a0c2798a61b1dbe37b34/packages/crypto/src/sas.js), and [package manifest](https://github.com/collapsinghierarchy/noisytransfer-protocol/blob/9747fe19980a1cc6f1e9a0c2798a61b1dbe37b34/packages/noisyauth/package.json), all pinned to the revision already recorded in P2.
4. [NIST FIPS 180-4](https://csrc.nist.gov/pubs/fips/180-4/upd1/final), [NIST FIPS 202](https://csrc.nist.gov/pubs/fips/202/final), and [RFC 9380](https://www.rfc-editor.org/rfc/rfc9380.html) for SHA-2, SHA-3, and scoped domain-separation guidance.
5. Maintainer documentation, source, security policy, and package metadata: RustCrypto [`sha2`](https://docs.rs/crate/sha2/0.11.0), [top-level source](https://docs.rs/sha2/0.11.0/src/sha2/lib.rs.html), and [security policy](https://github.com/RustCrypto/hashes/security/policy); RustCrypto [`sha3`](https://docs.rs/crate/sha3/0.12.0), [source](https://docs.rs/sha3/0.12.0/src/sha3/lib.rs.html), and [RustCrypto supported targets](https://github.com/RustCrypto/hashes); official [`blake3`](https://docs.rs/crate/blake3/1.8.7), and [`curve25519-dalek`](https://docs.rs/crate/curve25519-dalek/5.0.0).

### Repository sources

P2’s [construction selection](construction-selection.md), [protocol status](protocol-status.md), [draft profile](protocol-profile-v1-draft.md), [threat model](threat-model.md), and [P3 roadmap](../roadmap/P3-protocol-profile-and-vectors.md) were used to preserve project decisions and boundaries. No blog/tutorial/forum source supports a security conclusion in this document.
