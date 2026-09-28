# P3.3 — Candidate B public-source instantiation research

## Status

**Outcome A — enough public evidence to define a concrete project proposal for independent review.** Public sources support a conventional salted hash commitment as one way to fill Candidate B’s abstract `Commit` interface, and they explain the standard random-oracle heuristic for mapping ideal calls to a concrete hash. They do not show that SHA-256, SHA3-256, or any real hash is a random oracle, nor do they prove the resulting implementation under Candidate B’s exact theorem.

**P3.2 STOP retained for selection and production use.** This research proposes one fully described mapping for P3.4 review; it does not select a production profile. No parameter, hash, encoding, dependency, or implementation is SELECTED.

## Question

Can public primary sources and established cryptographic literature define a practical commitment/hash mapping for Candidate B without asking its authors, while stating honestly what the ROM theorem does and does not prove?

## Existing P3.2 STOP

P3.2 correctly records that Candidate B’s paper leaves its concrete commitment formula, hash, encoding, and truncation profile unspecified. The public literature now supports a concrete **PROJECT-PROPOSAL** and a defensible heuristic claim, so the “no mapping can yet be proposed” rationale can advance to independent review. The STOP against choosing or claiming a concrete production instantiation remains until that review resolves the profile and its finite security bounds.

## Sources and methodology

Primary-source PDFs were inspected for ePrint 2025/1598, Bellare–Rogaway (1993), Laur–Asokan–Nyberg (ePrint 2005/424), Boneh–Shoup’s cryptography text, and RFC 9380. The Candidate B ePrint record lists a full PDF and no separate supplementary files; its history shows the last of two revisions on 2025-09-11. The manuscript PDF was downloaded and checked page by page for its commitment definition, protocol, Theorem 3, and Appendix F. The ACNS publisher page and its accessible theorem preview were checked against that complete author manuscript. Search snippets were used only to locate material, not as the basis for conclusions.

Important claims below use these labels:

- **PAPER-SPECIFIED** — explicit in Candidate B’s manuscript or publication.
- **CITED-CONSTRUCTION** — present in a cited construction, but not necessarily adopted by Candidate B.
- **ESTABLISHED-PRACTICE** — supported by independent cryptographic literature or a standard.
- **PROJECT-PROPOSAL** — one possible mapping for `sas-pairing`; it is not the paper’s specification.
- **UNKNOWN** — the reviewed evidence does not resolve it.

The full ACNS 2026 chapter PDF is subscription-only. Its Springer publication record and accessible Appendix A/Theorem 5 preview were inspected; the complete revised ePrint author manuscript supplies the full mutual protocol, Theorem 3, and Appendices. No discrepancy was visible in the portions available from both versions. The complete conference chapter and any publisher-only supplementary material could not be checked line by line, so version identity beyond the publicly visible material remains unknown. The findings below are bounded to the full author ePrint and the available publisher evidence.

## Candidate B construction recovery

**PAPER-SPECIFIED.** Candidate B is the mutual protocol \(\pi_{\mathrm{SAS}}^{\times}\), a UC cross-authentication protocol. It authenticates exact role-positioned messages for one SID and does not itself return a reusable shared key or prove long-term private-key possession.

For S’s message `m_S` and R’s message `m_R`, its abstract flow is:

```text
r_S ← {0,1}^κ
(C,d) ← Commit(sid || m_S; r_S)                 S → R: C
r_R ← {0,1}^κ; R supplies m_R                   R → S: (m_R,r_R)
S opens C                                         S → R: Open(C,d)
both compute Trunc_t(H(sid || m_S || m_R || r_S || r_R))
both submit (SAS,sid,s) to the ideal OOB comparator
```

R outputs the exact `m_S` and S outputs the exact `m_R` only after an equal comparison; otherwise both abort. `r_S` is the fresh commitment randomness and also an SAS input. `r_R` is an independent uniform challenge and SAS input. The paper specifies `r_S,r_R ∈ {0,1}^κ`; it does not set a numerical `κ`.

Theorem 3 uses a single global random-oracle table for the SAS calls across parties, simulator, and adversary. Its ideal functionality includes one active forgery attempt per SID with `ε = 2^-t`; the real/ideal distinguishing terms also include commitment hiding and binding advantages and the pre-reveal random-oracle hit bound `2 q_H(κ) 2^-κ`, plus negligible terms. This is not an aggregate bound for unlimited SIDs, a human-error bound, or a guarantee about an implementation’s hash.

## Commitment provenance

**PAPER-SPECIFIED.** Definition 2 gives `Commit(m;r) → (C,d)` and deterministic `Verify(C,m,d) → {0,1}`. Honest openings must verify; the scheme must be computationally hiding and computationally binding. The proof uses both properties. In `π_SAS^×`, the committed value is `sid || m_S`; the sender opens it after R contributes. The opening reveals the committed message and `r_S` (the paper says the coins are contained in `d`; its simulator opens the message with the commitment randomness).

The paper says its main constructions use “hash-then-open in the random-oracle model” and cites Bellare–Rogaway [3]. It does **not** state a hash formula, opening encoding, digest length, purpose tag, or whether commitment calls share the SAS oracle. Bellare–Rogaway’s cited paper contains no commitment scheme at all; it describes the random-oracle-to-hash heuristic. The citation therefore does not establish that Candidate B intended either `H(m || r)` or `H(r || m)`.

Laur, Asokan, and Nyberg’s MANA-IV-related paper [5] supplies useful predecessor context. It defines a generic commitment and describes a simple `C = h(x,r)`, `d = (x,r)` hash commitment, but says that a real collision-resistant hash alone gives no hiding guarantee for this form. Its suggested OAEP-style alternative is more specific: `s = (x || 0^k || 0) XOR G(r)`, `t = r XOR H(s)`, and `c = h(s,t)`, with opening randomness `r`; the argument uses a PRG, a random-oracle call, and a collision-resistant hash, and discusses the stronger non-malleability goals of MANA-IV. It also cautions that generalizing the OAEP CCA argument to this hash-based setting is conjectural. This alternative is not stated by Candidate B and is not a drop-in formula from Candidate B’s paper.

Boneh and Shoup [6, §8.12, pp. 345–347] give the generic hash commitment `c = H(m,o)`, reveal `o`, and verify by recomputation. They derive binding from collision resistance and hiding from an additional “input-hiding” property. They say that a large nonce space—giving 512 bits as an example for SHA-256—makes input hiding plausible; this is not a theorem that SHA-256 has that property. This independent source supports a salted-hash **construction family**, not a concrete-hash proof for Candidate B.

### Proposed commitment mapping — PROJECT-PROPOSAL

Use a fresh uniform 512-bit `r_S` and the following injective, canonical framing proposal. `LP(x)` is `U32BE(byte_length(x)) || x`; reject fields longer than `2^32−1` bytes. For this proposal, `sid` is a 32-byte caller-supplied value, and `m_S` is the exact canonical message bytes already defined by a later profile review:

```text
LP(x) = U32BE(byte_length(x)) || x
DS_COMMIT = ASCII("sas-pairing/commit/v1")
DS_SAS    = ASCII("sas-pairing/sas/v1")
C = SHA-256(LP(DS_COMMIT) || LP(sid || m_S) || LP(r_S))
d = (sid || m_S, r_S)
Verify(C, x, d) = constant-time-equal(C, SHA-256(LP(DS_COMMIT) || LP(x) || LP(r_S)))
SAS = Trunc_t(SHA-256(LP(DS_SAS) || LP(sid) || LP(m_S) || LP(m_R) || LP(r_S) || LP(r_R)))
```

The tags, `LP` framing, 32-byte supplied SID, and hash are project choices; they are not in the Candidate B paper. The framing preserves the exact committed value `sid || m_S` and gives the SAS tuple one unique byte representation. In the ROM, a uniform hidden salt makes the committed value computationally hiding up to the salt-guessing query bound, and two distinct accepted openings yield a collision in the oracle input. With SHA-256, binding relies on a collision-resistance assumption and hiding on a separate input-hiding/random-looking-output heuristic; collision resistance alone does not imply hiding. A 256-bit digest also gives at most roughly 128-bit generic collision strength, so a concrete bound and target must be reviewed.

The proposal sets the paper’s nonce parameter `κ` to 512 for `r_S` and `r_R`. If the profile supplies a 256-bit SID from outside the protocol, its SID length can remain 256; the paper permits an environment-supplied SID. If S instead generates the SID under the paper’s “not provided” branch, that branch samples `κ` bits, so it would generate 512 bits. This is only a mapping proposal; no `κ` is selected here.

## Random Oracle to real-hash analysis

Bellare and Rogaway [3, §§1.1, 6, pp. 63–64, 69] explicitly describe the process as proving a protocol with a public random oracle and then replacing it by a carefully chosen hash function. They call that final replacement heuristic; they also caution that ordinary hash functions are not automatically good oracle replacements. Their §6 discusses ways to separate applications/oracles, but does not specify a Candidate B commitment.

Canetti, Goldreich, and Halevi [4, §§1, 4] show that there are contrived signature/encryption schemes secure in the ROM with no secure implementation by any function ensemble. They also state that this does not show that schemes in the literature are necessarily uninstantiable. The result rules out a general theorem that security transfers automatically; it does not prove Candidate B fails with SHA-256 or SHA3-256.

RFC 9380 [7, §§2.2.5, 3.1] explains domain-separation tags as a way to model separate random-oracle domains through one oracle: tagged inputs occupy disjoint input sets, whose random-oracle outputs are independent. Its specific requirements concern hash-to-curve, so its concrete tag rules are guidance here, not a Candidate B profile.

### Explicit answers: SAS hash

**11. Exact input:** `sid || m_S || m_R || r_S || r_R`.

**12. Ordering:** fixed as written by `π_SAS^×`: SID, S message, R message, S commitment coins, R nonce.

**13. Injectivity:** not byte-level. The paper treats these as ordered mathematical fields and writes `||`; it does not define a byte serialization. A profile needs an injective encoding to preserve distinct field tuples as distinct oracle inputs.

**14. Shared oracle:** the SAS proof uses one global `H` shared by parties, adversary, simulator, and sessions. The commitment is an abstract primitive with hiding/binding assumptions; the paper does not say whether an eventual hash-based `Com` must call that same `H`.

**15. Domain-separated calls:** in the ideal model, fixed distinct purpose tags plus injective framing are compatible with one global random oracle: they make separate disjoint input domains. With a real hash, tags reduce cross-purpose aliasing but do not establish random-oracle behavior or a concrete proof.

**16. SHA-256 / SHA3-256:** FIPS 180-4 and FIPS 202 [8] specify these algorithms; neither says they are random oracles or proves Candidate B with them. The RustCrypto `sha2` and `sha3` crates implement the respective algorithms [9]. That is implementation availability only.

**17. Defensible wording:**

> “The protocol is proved in the Random Oracle Model. This proposed profile uses SHA-256 for the commitment and SAS hash calls as a heuristic instantiation of the modeled random oracle, with separate framed domains. The ROM theorem does not itself prove the concrete SHA-256 implementation secure; that mapping and its finite security bounds require independent review.”

This wording describes Statement 1 and the heuristic nature of Statement 2. Statement 3—“Theorem 3 proves our SHA-256 implementation secure”—is false.

## Encoding and domain separation

**18. Serialization:** neither Candidate B nor its cited commitment references defines wire bytes for the abstract tuples.

**19. Injective encoding:** yes. An injective canonical encoding maps each abstract tuple to a unique bit string, preserving equality and distinctness used by the ROM proof. It does not change which semantic fields the theorem authenticates.

**20. Requirements:** encode each ordered component unambiguously, include boundaries for variable-length fields, fix byte order/length representation, reject noncanonical encodings, and use the same definition for commitment, opening, and SAS verification. Delimiter-only framing is insufficient unless escaping/parsing guarantees injectivity.

**21. Context and tags:** protocol/profile/version/role/context values whose meaning must be authenticated belong in `m_S` and/or `m_R`, where Candidate B returns the exact messages. A purpose tag distinguishing commitment and SAS calls belongs in hash framing. A version tag may also be repeated in hash framing for domain separation, but that duplication is project hardening and is not required by Candidate B.

**22. Mapping versus hardening:** an injective encoding of the five paper-specified values is a theorem-preserving representation of the ordered tuple. Purpose tags preserve the ROM model when they merely select disjoint oracle inputs. Choosing particular tag bytes, version placement, field schema, length limits, and the policy to duplicate profile identifiers are PROJECT-PROPOSAL choices. SHA-256 replacing the RO is a heuristic assumption, not a theorem-preserving replacement.

## Parameters

**23. `κ = 256`: UNKNOWN / not selected.** Candidate B fixes only that `r_S` and `r_R` have `κ` bits. The ePrint leaves `κ` abstract. P3.2 records a 256-bit-SID-to-`κ=256` mapping as a candidate, not a selection; the protocol-profile draft itself selects no SID size. The hash-commitment literature’s SHA-256 example uses a 512-bit nonce for the input-hiding rationale, which makes `κ=512` a reviewable proposal when using this commitment family. Neither value is selected.

**24. `n = 256`: UNKNOWN / candidate only.** SHA-256 and SHA3-256 each output 256 bits, so choosing either would define `n=256`. Candidate B requires an abstract output length `n=n(κ)` and does not select 256 or a concrete hash. A fixed 256-bit digest also calls for a concrete, finite security analysis rather than copying asymptotic negligible terms literally.

**25. `t`: unresolved and not selected.** It is the number of random-oracle output bits retained for SAS; the ideal forgery term is `2^-t` per SID and the full theorem includes other terms. The final comparison budget and aggregate-attempt assumptions are outside this task.

**26. Commitment randomness:** `r_S` is exactly `κ` uniform bits in the paper and is the commitment randomness; the same `r_S` is included in SAS. Do not introduce independent hidden commitment coins without a new mapping. `r_R` is also exactly `κ` uniform bits. This research proposes reviewing 512-bit values; it does not select them.

## RO-free alternative

**27. Paper’s direction:** Appendix F proposes not hashing the transcript for SAS. The parties jointly obtain a public `t`-bit value `c` from a UC coin flip in a CRS hybrid, commit in both directions to `(m_S,r_S)` and `(m_R,r_R)`, reveal the message/nonces, MAC-bind `(sid,m_S,m_R,r_S,r_R,c)` under each still-hidden commitment opening value, open, verify, then compare `c` over OOB.

**28–29. Status and implementability:** the appendix lists required primitives and a message flow, but explicitly leaves the full proof for future work. It is a sketch, not a fully specified and proved replacement that this project can implement while claiming the paper’s theorem.

**30–31. Cost and fit:** it adds UC hiding/binding/non-malleable commitments in a CRS, UC coin flipping, a UF-CMA MAC, more message rounds, and new composition assumptions. This is a materially larger construction and introduces stronger setup/primitives than the one-hash proposal. It is research-only for this project until a complete proof and independently reviewed profile exist; “RO-free” alone is not a security justification.

## Public implementations

The paper cites the authors’ NoisyTransfer project [13]. At the inspected repository HEAD, its commit was `9747fe19980a1cc6f1e9a0c2798a61b1dbe37b34` (the revision previously recorded in P2). Its `commitment.js` computes `SHA3-256(DS || LP(label) || LP(data) || LP(nonce))`; `noisyauth` uses the label `noisyauth`. Its SAS code hashes a framed header containing protocol label, room/session identifiers and commitment plus both messages/nonces, then uses SHAKE128 and decimal rejection sampling. The code’s app roles can be mapped to the theorem’s committer/challenger roles, but it does not implement the exact theorem transcript: the commitment omits `sid`, the SAS preimage is different, and the displayed decimal code is not the theorem’s `t`-bit prefix. It is therefore **RELATED IMPLEMENTATION**, not a THEOREM-EQUIVALENT CANDIDATE. The README describes an experimental Node 20+ monorepo; no independent audit was identified in the inspected materials. Its current source is JavaScript/TypeScript rather than a drop-in Rust implementation.

The paper-linked [`noisytransfercli` repository](https://api.github.com/repos/collapsinghierarchy/noisytransfercli) currently returns GitHub 404. The author repositories [`rustytransfer`](https://github.com/collapsinghierarchy/rustytransfer) (short-code PAKE/file transfer) and [`qr-authentication`](https://github.com/collapsinghierarchy/qr-authentication) (account login) were checked and are not implementations of `π_SAS^×`. Searches for the ePrint identifier, exact paper title, `π_SAS`, the theorem transcript, and author names together with SAS/commitment found no other materially relevant public implementation. This is a bounded search, not proof that no other code exists.

## Citation and follow-up research

The author’s 2026 dissertation [10] cites ePrint 2025/1598 and discusses the general ROM replacement caveat in §5.1, but adds no Candidate B commitment formula or concrete hash mapping. The author’s ACNS 2026 talk transcript [11] says hash-based constructions are usable in the ROM and summarizes the commit/challenge/open flow; it gives no exact formula, concrete hash, or encoding. The author-linked practitioner article [12] likewise calls the use of a hash heuristic but gives no formula or profile. A bibliographic/citation search through 2026-09-28 found no independent paper or technical report that supplies a later Candidate B instantiation; OpenAlex’s ACNS record returned zero citing works at the time checked [14]. This result is bounded and is not evidence that no such follow-up exists.

## Candidate concrete mappings

The following is a review proposal, not a product decision:

```text
H = SHA-256                                  // 256-bit output, n=256
LP(x) = U32BE(byte_length(x)) || x
DS_COM = ASCII("sas-pairing/commit/v1")
DS_SAS = ASCII("sas-pairing/sas/v1")
C = H(LP(DS_COM) || LP(sid || mS) || LP(rS))
d = (sid || mS, rS)
SAS = Trunc_t(H(LP(DS_SAS) || LP(sid) || LP(mS) || LP(mR) || LP(rS) || LP(rR)))
sid = 32 bytes supplied by the caller; rS, rR = fresh uniform 512-bit strings
```

This proposes one global concrete hash with distinct framed domains, a 32-byte supplied SID, and a 512-bit internal `κ` for both nonce fields. P3.4 must review the shared-oracle composition, the commitment’s concrete hiding/binding assumptions, the message schema, whether this `κ` mapping fits the profile’s SID lifecycle, and the complete finite security bound. `t`, output truncation bit ordering, display, and production dependencies remain open.

| Option | Commitment | SAS hash | Proof relationship | Complexity | Rust support | Classification |
|---|---|---|---|---|---|---|
| SHA-256 / SHA-256, untagged | Project salted-hash formula | SHA-256 over paper tuple | ROM mapping is possible; untagged cross-purpose reuse is underspecified and concrete SHA remains heuristic | Low | `sha2` implements the primitive; no Candidate B scheme | CANDIDATE, not recommended without domain review |
| SHA3-256 / SHA3-256, untagged | Same salted-hash family | SHA3-256 over paper tuple | Same proof gap as SHA-256; FIPS 202 specifies the algorithm only | Low | `sha3` implements the primitive; no Candidate B scheme | CANDIDATE, not selected |
| SHA-256 or SHA3-256 with separate framed tags | Salted hash with `DS_COM`; SAS with `DS_SAS` | Tagged, injectively framed tuple | Tags model disjoint calls to one global RO in the ideal model; real-hash replacement remains heuristic | Low | Both primitives have RustCrypto crates; framing is profile code, no dependency needed for encoding | CANDIDATE for P3.4 review |
| Laur–Asokan–Nyberg OAEP-style commitment | `c=h(s,t)`, with OAEP masking from a PRG/RO and opening randomness | SAS hash remains a separate choice | MANA-IV literature gives a related construction and stronger properties; it is not specified as Candidate B’s `Com` | High | Requires additional primitives and analysis; no direct Candidate B Rust implementation found | RESEARCH ONLY |
| Authors’ NoisyTransfer at `9747fe1` | Domain/length-framed SHA3-256 | SHA3-256, then SHAKE128 decimal derivation | Related commit/open pattern, but different committed value and SAS inputs/output | Medium | JavaScript implementation, not Rust | RELATED IMPLEMENTATION |
| Appendix F RO-free sketch | Two UC commitments, opening MACs | UC coin-flipped `t`-bit `c` | Full proof expressly left for future work | High | No ready Candidate B Rust implementation identified | RESEARCH ONLY |

## What we may claim

- The paper proves `π_SAS^×` in the Random Oracle Model under its stated commitment, OOB, endpoint, and attempt assumptions.
- A concrete profile may explicitly say it uses SHA-256 or SHA3-256 **as a heuristic instantiation** of those ideal calls. That is a modeling/engineering assumption, not a preservation theorem.
- A carefully specified injective encoding and distinct hash-use tags can map the paper’s ordered abstract inputs into disjoint byte-string domains for analysis.
- The standard salted-hash commitment family has hiding/binding arguments under explicit assumptions: collision resistance plus input hiding for a concrete hash; in the ROM, hidden uniform salt and random-oracle behavior. These are the commitment’s assumptions, not proof that SHA-256 satisfies them.
- SHA-256 and SHA3-256 are standardized functions with Rust implementations available; those facts establish algorithm and implementation availability only.

## What we must NOT claim

- “SHA-256 is a random oracle” or “SHA3-256 is a random oracle.”
- “Theorem 3 directly proves the concrete SHA-256/SHA3-256 implementation secure.”
- “FIPS publication/approval proves Candidate B security.”
- “Collision resistance alone proves a salted real-hash commitment is hiding.”
- “Bellare–Rogaway [3] specified Candidate B’s exact commitment formula.”
- “The author’s NoisyTransfer implementation is identical to `π_SAS^×` or inherits Theorem 3.”
- “An authenticated public-key byte string proves possession or control of its private key.”
- “The `2^-t` term is an aggregate bound across unlimited SIDs or includes human comparison errors.”

## Decision matrix

**SELECTED:** none.

**CANDIDATE:** a SHA-256 salted hash-then-open commitment with injective framing and separate purpose tags; SHA-256 for the SAS oracle call; `n=256`; a `κ=512` nonce mapping for review. SHA3-256 with the same tagged, injective framing remains viable. All are proposals requiring independent cryptographic review; none changes the P3.2 STOP against selection.

**RESEARCH ONLY:** MANA-IV’s OAEP-style commitment as an alternative requiring more primitives; the Candidate B RO-free Appendix F sketch.

**STOP:** selecting a concrete production profile or claiming the exact ROM theorem for a named real hash. P3.4 must check the proposed shared-oracle composition, finite bounds, encoding, tag placement, `κ`/SID lifecycle, and all remaining profile decisions.

## Recommendation

Proceed to **P3.4 — independent cryptographic review of the proposed concrete mapping**. Ask the reviewers specifically to validate the shared-RO salted commitment and SAS domain framing, the 512-bit nonce/256-bit digest relationship, the κ/SID separation in the actual session lifecycle, and the finite bound for a fixed-output hash. Do not contact the paper authors on the evidence currently available.

## Remaining unknowns

- Whether Candidate B intended its commitment to share the SAS oracle; no source says.
- The independently reviewed commitment formula, domain tags, tuple encoding, and size limits.
- Whether `κ=512` is the right profile mapping; `κ=256` remains a documented candidate, not a decision.
- Whether `n=256` and SHA-256 or SHA3-256 meet the project’s chosen concrete security target.
- `t`, truncation bit/byte ordering, final SAS rendering, aggregate attempt budget, and production dependency.
- The finite-hash security bound replacing the paper’s asymptotic ROM/negligible terms.
- A complete, proved RO-free alternative.

## Sources reviewed

1. Wasilij Beskorovajnov and Jörn Müller-Quade, [“How to kickstart Secure Message Transfer with Short Authentication Strings and Out-Of-Band Communication”](https://eprint.iacr.org/2025/1598), IACR ePrint 2025/1598, last revised 2025-09-11. Inspected actual full PDF: Definition 2 and hash-then-open statement (§3.2, PDF p. 6); mutual `π_SAS^×` and Theorem 3 (§4.3, PDF p. 17); full RO-free sketch and limitation (Appendix F, PDF pp. 37–38). Supports Candidate B’s interface, inputs, assumptions, and incompleteness of the commitment specification.
2. Beskorovajnov and Müller-Quade, [ACNS 2026 chapter](https://doi.org/10.1007/978-3-032-32560-0_15), LNCS 16571, pp. 415–443, first online 2026-07-22. Checked publisher metadata/abstract and accessible Appendix A, Theorem 5. The full chapter PDF is subscription-only; the ePrint author manuscript above is the complete publicly available source inspected for the mutual theorem.
3. Mihir Bellare and Phillip Rogaway, [“Random Oracles are Practical: A Paradigm for Designing Efficient Protocols”](https://web.cs.ucdavis.edu/~rogaway/papers/ro-abstract.html), ACM CCS 1993, pp. 62–73. Inspected full PDF, §§1.1 and 6 (PDF pp. 63–64, 69). Supports the RO implementation heuristic and the warning that this step is not a theorem; the paper has no commitment scheme or formula.
4. Ran Canetti, Oded Goldreich, and Shai Halevi, [“The Random Oracle Methodology, Revisited”](https://arxiv.org/abs/cs/0010019), JACM 51(4), 2004, pp. 557–594; accepted manuscript first posted 2000. Inspected full HTML/PDF content, §§1.1–1.2 and 4. Supports impossibility of a universal theorem preserving all ROM schemes and clarifies its constructions are not a claim that Candidate B is uninstantiable.
5. Sven Laur, N. Asokan, and Kaisa Nyberg, [“Efficient Mutual Data Authentication Using Manually Authenticated Strings”](https://eprint.iacr.org/2005/424), IACR ePrint 2005/424, extended version. Inspected actual PDF: MANA/MA-3 and generic commitment (§3, PDF pp. 6–7), hash commitment and OAEP-style alternative (PDF pp. 14–15). Supports the related construction pattern and the warning that `H(x||r)` with only a concrete collision-resistant hash is not thereby hiding.
6. Dan Boneh and Victor Shoup, [A Graduate Course in Applied Cryptography](https://crypto.stanford.edu/~dabo/cryptobook/BonehShoup_0_6.pdf), version 0.6, January 2023. Inspected §8.12, pp. 345–347. Supports `c=H(m,o)`, opening `o`, binding from collision resistance, hiding under input hiding, and the 512-bit nonce-space example for SHA-256; it does not prove that SHA-256 has input hiding.
7. [RFC 9380, Hashing to Elliptic Curves](https://www.rfc-editor.org/rfc/rfc9380.html), August 2023, §§2.2.5 and 3.1. Supports domain separation as a method to model distinct oracle domains; its profile is specifically for hash-to-curve, not Candidate B.
8. NIST [FIPS 180-4](https://csrc.nist.gov/pubs/fips/180-4/upd1/final) and [FIPS 202](https://csrc.nist.gov/pubs/fips/202/final). Specify SHA-2 and SHA-3 families, including 256-bit variants. They do not analyze Candidate B or make a ROM replacement theorem.
9. RustCrypto [sha2 0.11.0](https://docs.rs/crate/sha2/0.11.0) and [sha3 0.12.0](https://docs.rs/crate/sha3/0.12.0), checked 2026-09-28. Support availability of Rust SHA-256/SHA3 implementations only; no dependencies were added.
10. Wasilij Beskorovajnov, [“Chekhov’s Guns and Damocles’ Swords in Real-World Information Security”](https://publikationen.bibliothek.kit.edu/1000190771/175554399), KIT dissertation, published 2026-02-20. Inspected actual PDF, §5.1 and bibliography entry [41] (PDF pp. 140–142 and 2076). Supports the author’s later high-level discussion of ROM caveats; it adds no Candidate B instantiation.
11. Wasilij Beskorovajnov, [ACNS 2026 talk transcript](https://www.linkedin.com/posts/wasilij-beskorovajnov-79a33a284_acns2026-activity-7475816986527236097-vmVd), posted 2026. Inspected the author’s transcript. Supports only the high-level statement that the constructions use hash-based commitments and SAS calls in the ROM; it gives no formula or concrete hash mapping.
12. Wasilij Beskorovajnov, [“How to kickstart Secure Message Transfer with Short Authentication Strings & Out-of-Band Channels”](https://whitenoise.systems/blog/eprint-2025-1598/), practitioner note dated 2025-09-28. Identifies itself as a discussion of the author’s ePrint and explicitly flags the hash as heuristic; it supplies no formula, bytes, or concrete profile. Used only as supporting author material, not as a security proof.
13. Authors’ [NoisyTransfer repository](https://github.com/collapsinghierarchy/noisytransfer-protocol/tree/9747fe19980a1cc6f1e9a0c2798a61b1dbe37b34), commit `9747fe19980a1cc6f1e9a0c2798a61b1dbe37b34`, checked 2026-09-28. Inspected `packages/crypto/src/commitment.js`, `sas.js`, and `packages/noisyauth/src/sender.js`/`receiver.js`. Supports the implementation facts above, not theorem equivalence.
14. OpenAlex, [ACNS 2026 DOI record](https://api.openalex.org/works/https://doi.org/10.1007/978-3-032-32560-0_15), checked 2026-09-28. Its citation count was zero at the time checked; this index result does not prove no follow-up work exists.
