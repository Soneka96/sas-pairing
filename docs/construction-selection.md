# P2 — Construction selection and formal mapping

## Status and scope

**Outcome: RESEARCH CONTINUES.** Candidate C remains the closest direct key-agreement result: a three-round SAS-AKA with a fresh bilateral shared key and an explicit concurrent-session bound, even while reusing long-term encryption keys. The focused analysis finds **NEW PROOF REQUIRED** to bind both participants’ application context to that key and **CONSTRUCTION-LEVEL PROOF REQUIRED** for P1-compatible terminal results under delayed or dropped messages. Theorem 1’s arbitrary-message Enc-MCA authentication does not extend Theorem 2’s fixed Enc-AKA result by itself. One combined proof/composition result remains missing; P3 stays gated.

This document evaluates three primary-source candidates against [P1](threat-model.md). Shortcake is implementation evidence only; it is not a separately proven candidate and is not assumed equivalent to PV. Other relevant work found in the bounded literature search is recorded after the candidate comparison, with reasons it is not carried forward as a project candidate.

## Candidate A — Pasini–Vaudenay, PKC 2006

### What the paper constructs

Pasini and Vaudenay define a generic SAS-based key-agreement transformation. It takes an underlying authenticated key-agreement protocol (AKA0) and a message cross-authentication (MCA) protocol. The MCA authenticates the exchanged protocol transcript and the final messages of AKA0; the participants then complete AKA0. Their Theorem 1 bounds the composed attack probability by the sum of the AKA0 and MCA attack probabilities, with a constant security-time overhead. The construction is not an arbitrary KEM wrapper.

The proposed three-move MCA appears in Figure 4 and Theorem 3. Alice has input message `m_A`; Bob has input message `m_B`. Its exact randomized commitment is:

```text
K  ← uniform {0,1}^κ
e  ← uniform {0,1}^ℓe, independently
c  = H(e, K, m_A)
d  = (e, K)
```

Here `H` is the paper’s random oracle with an `ℓ_c`-bit output. Alice sends `(m_A, c)`. Bob chooses independent uniform `R ← {0,1}^ρ` and sends `(m_B, R)`. Alice opens `c` with `d`, computes `SAS = R ⊕ h_K(m_B)`, and sends that SAS through the authenticated short-string channel. Bob checks the corresponding SAS, checks `m_A ≠ m_B` to prevent the paper’s stated reflection attack, and authenticates the SAS back. Successful outputs are the peer identity and the peer’s authenticated message. The opening value `e` is independent commitment randomness; replacing this commitment with a different hash formula is not the paper’s construction.

The hash family `h` is assumed `ε_h`-almost strongly universal, with `ρ`-bit digests. In the theorem’s stated model, if an attacker launches at most `Q` Alice or Bob instances and makes at most `q` queries to `H`, the MCA success probability is bounded by:

```text
ε = q²·2^(-ℓe) + 13q²·2^(-ℓc)
Pr[successful MCA attack] ≤ Q(Q−1)/2 · (2^(-ρ) + ε + ε_h)
```

The paper says this multi-instance bound is essentially tight in the relevant range. The `2^-ρ` term alone is therefore not the full theorem. Larger `Q`, `q`, or hash-family deviation worsens the bound. Applying Theorem 1 to the three-move AKA construction adds the separately established AKA0 attack probability; it does not erase it. For the paper’s DH instantiation, the AKA0 group and its security assumption must therefore be specified and analyzed as well. The paper gives estimates relating `ρ`, network size, allowed runs, and a target attack probability; those estimates are not a universal retry policy or a project-selected SAS target.

The proof uses a Bellare–Rogaway-style model with active control of insecure-channel messages, launches of concurrent protocol instances, test/reveal/corrupt queries, and an authenticated narrowband channel for short messages. The paper’s AKA definition explicitly sets aside inconsistent Alice/Bob end states by assuming mutual authentication is performed by further communication. Theorem 3 proves MCA security, not every property of the project’s ceremony and result contract.

### Paper-level assumptions and construction limits

- The 3-move MCA theorem is in the random-oracle model. It assumes the random-oracle commitment `H(e,K,m_A)`, including fresh independent `e`; an almost strongly universal hash family `h`; and the stated query and instance bounds. The authors say a standard hash may instantiate the random oracle only if that random-oracle instantiation is justified.
- The three-move AKA is obtained by composing that MCA with an AKA0, and the paper discusses classical Diffie–Hellman. Theorem 1 is generic over a secure AKA0, but is not a proof that an arbitrary contemporary KEM is a secure AKA0 or that an arbitrary KEM adaptation preserves the reduction.
- The model assumes an authenticated short-string channel. It does not quantify real human comparison errors, partial comparison, accidental approval, accessibility, or localization.
- The result is key agreement and message/peer authentication under that model. The paper does not specify the project’s exact ceremony identifier, context encoding, persistent attempt store, cancellation policy, or application result contract.
- Security claims do not transfer to an implementation merely because it is described as “based on” PV.

## Shortcake is not the analyzed paper construction

As accessed 2026-09-27, [Meta’s Shortcake repository](https://github.com/facebook/shortcake/tree/db73640a5531b5266bd1094d72e947ef22295cc1) was at `main` commit `db73640a5531b5266bd1094d72e947ef22295cc1`, tagged `v0.1.0-pre.4`. Its README says the implementation has not been audited. The current source describes a generic KEM protocol: the Initiator generates a KEM keypair and a 32-byte nonce, commits to the encapsulation key and nonce, the Responder encapsulates to that key and generates a nonce, and the Initiator reveals its nonce.

Shortcake’s commitment is a domain-separated hash over the encapsulation key and initiator nonce with length-prefixed fields (`shortcake-commitment-v1`, in `src/commitment.rs`). It does not use the PV paper’s independent `e` and committed random `K` in `H(e,K,m_A)`. Its SAS is the responder nonce XOR a hash of the initiator nonce and ciphertext; its session key is derived from the KEM shared secret and transcript. That is an implementation design, not evidence that the PV theorem covers this KEM construction or commitment. Shortcake itself warns that the session key must not be used until SAS verification, and its SAS bytes are caller-truncated. These observations are implementation facts, not security proof.

## Candidate B — Beskorovajnov and Müller-Quade, ACNS 2026

### Publication versions

The conference paper is Wasilij Beskorovajnov and Jörn Müller-Quade, “How to Kickstart \(\mathcal{F}_{\mathrm{SMT}}^{S\rightarrow R}\) with Short Authentication Strings and Out-of-Band Communication,” ACNS 2026, LNCS 16571, pp. 415–443, DOI [10.1007/978-3-032-32560-0_15](https://doi.org/10.1007/978-3-032-32560-0_15), first online 2026-07-22. The complete author manuscript is [IACR ePrint 2025/1598](https://eprint.iacr.org/2025/1598), revised 2025-09-11; its title is “How to kickstart Secure Message Transfer with Short Authentication Strings and Out-Of-Band Communication.”

The publisher abstract and accessible Appendix A, Theorem 5, state the same one-sided UC authentication result with \(\varepsilon=2^{-t}\) and the same commitment, random-oracle, and OOB assumptions described below. The full ePrint manuscript supplies the detailed one-sided, mutual, and SMT proofs (Theorems 2–4). The Springer page exposes the publication record and theorem excerpt, but its complete chapter PDF was not accessible here; no claim of full-text identity between versions is made. No material conflict appears in the accessible theorem statements, so the complete ePrint version is the source for the detailed mapping.

### What the paper constructs

This is not a direct reusable key-agreement protocol. Section 4 first proves UC realizations of authenticated-message functionalities, then Section 5 composes mutual SAS authentication with a one-shot, sender-to-receiver KEM/DEM secure-message-transfer protocol. The paper’s abstract and formal definitions distinguish the authentication building block from the final message-transfer functionality.

The synchronous OOB functionality \(\mathcal{F}_{\mathrm{OOB}}^{\mathrm{SAS}}\) receives `(SAS, sid, s)` from each honest endpoint, reveals those values to the network adversary, compares the two strings exactly, and immediately returns the equality bit to both endpoints. The adversary cannot suppress this comparison result. The paper assumes honest endpoints and uncompromised display/software for this idealization.

For one-sided \(\pi_{\mathrm{SAS}}\), the caller/environment supplies `sid`, or the Sender samples a fresh \(\kappa\)-bit `sid` and notifies the Receiver over the main channel. The Sender commits to `(sid || m_S)` with fresh commitment coins `r_S`, the Receiver sends fresh uniform `r_R`, and the Sender opens the commitment. If the opening verifies, both calculate:

```text
s = Trunc_t(H(sid || m_S || r_S || r_R))
```

Both submit `(SAS, sid, s)` to the OOB functionality. On equality, the Receiver outputs `m_S`; otherwise it aborts. The mutual \(\pi_{\mathrm{SAS}}^{\times}\) also sends `m_R` with `r_R`; the SAS input is `sid || m_S || m_R || r_S || r_R`. On equality each side outputs the other side’s message; on mismatch both abort. Thus roles and arbitrary caller-supplied context can be bound by their fixed positions as `m_S` and `m_R`, subject to the caller’s encoding and semantics.

The proof assumes a computationally hiding and binding commitment and models `H` as a random oracle. The paper says its main constructions instantiate `Commit` as hash-then-open in that model; the protocol uses `Commit(sid || m_S; r_S)` and opening witness `d`. The Sender’s `r_S` commitment coins and Receiver’s independent \(\kappa\)-bit `r_R` both enter the SAS input. This is not PV’s `H(e,K,m_A)` commitment.

Theorems 2 and 3 state that the one-sided and mutual protocols UC-realize their respective authenticated-channel functionalities with a per-session misbinding parameter \(\varepsilon=2^{-t}\), for one online forgery attempt per `sid`. This exact parameter is the ideal functionality’s Bernoulli gate; the UC real/ideal distinguishing bound additionally contains the commitment hiding/binding advantages, a negligible pre-reveal random-oracle hit term (bounded in the proof by \(2q_H2^{-\kappa}\)), and negligible terms.

Theorem 4 composes \(\pi_{\mathrm{SAS}}^{\times}\) with a fresh receiver KEM keypair, a one-time DEM, and a fresh sender signature keypair. The cross-authentication inputs are the sender’s signature verification key and receiver’s KEM public key. Sender-to-receiver payload ciphertexts are signed over a context containing the protocol name, `sid`, and direction; the Receiver verifies the signature before decapsulation/decryption. Under IND-CPA security of the KEM, one-time OT-CPA security of the DEM, EUF-CMA security of the signature, and the SAS-authentication theorem, the paper gives:

```text
Adv_UC ≤ 2^(-t) + Adv_EUF-CMA(Signature)
                  + Adv_IND-CPA(KEM) + Adv_OT-CPA(DEM) + negl(κ)
```

This is a one-shot secure message-transfer result with length-only leakage. It is not an application API that returns a reusable shared pairing key to both parties. The paper’s alternative MAC construction in Appendix A explicitly leaves its proof for future work and is not used as evidence for the theorem.

### OOB, SID, and lifecycle boundaries

The paper separates cryptographic misbinding probability from human reliability. It explicitly discusses an \(\varepsilon_{\mathrm{human}}\) extension for misreads, inattentive comparison, or UI confusion, but sets \(\varepsilon_{\mathrm{human}}=0\) in its proofs and leaves calibration to future work. Accordingly, \(2^{-t}\) is the cryptographic failure probability conditional on faithful comparison of all displayed bits, not a deployed-system error rate.

The formal `sid` is selected by the environment/caller or sampled by the Sender when absent; it is carried in the commitment tag, SAS hash input, OOB calls, authentication functionality, and SMT signed context. The proof is subroutine-respecting and has per-`sid` state; UC composition supports concurrent sessions with distinct session identifiers. The SID is not itself a peer identity or proof of a fresh ceremony across application restarts. The application still has to allocate unique, shared SIDs and prevent stale state or approval from being reused.

The ideal authentication functionalities allow one forge attempt per `sid`, and the SMT functionality similarly has one misbinding attempt before delivery. They do not impose a global budget over arbitrarily many SIDs, cooldowns, durable counters, or process-restart policy. The OOB functionality is synchronous and immediate. The paper sketches an asynchronous functionality with replay-resistant approvals and peer/session descriptors but explicitly leaves its formal treatment out of scope. Network messages can be delayed or dropped; invalid openings, unequal SAS, failed verification, and decapsulation errors abort. The paper does not define P1’s cancellation, expiry, continuation, or durable terminal-state contract.

The security theorems assume honest S and R and do not model endpoint corruption. No long-term identity keys are needed in the canonical SMT variant: KEM and signature keypairs are fresh per session. The ephemeral sender signature authenticates signed ciphertexts, but this does not establish proof-of-possession or ownership of a consumer’s long-term identity key. The KEM/DEM result uses the paper’s classical PPT notions; it does not by itself claim post-quantum security or validate an arbitrary implementation.

## Candidate A — P1 requirement mapping

Each status describes what the paper supports for the project requirement. “Supported with composition” means a project-level property still depends on an explicit profile or an additional proof. `NOT ESTABLISHED` is not evidence that an attack exists; it means the source does not establish the requested property.

| # | P1 requirement | Status | Evidence and boundary |
|---:|---|---|---|
| 1 | Active man-in-the-middle resistance | **SUPPORTED WITH COMPOSITION** | Theorem 3 bounds active MCA attacks; Theorem 1 composes MCA with AKA0. The resulting AKA bound includes AKA0’s own attack probability and assumes authenticated SAS delivery and theorem parameters. |
| 2 | Exact security result claimed | **SUPPORTED** | The paper claims a 3-move MCA secure in its random-oracle model, then a 3-move DH-based AKA by generic composition. It does not claim a generic KEM proof. |
| 3 | Concrete mathematical/security bound | **SUPPORTED** | Theorem 3 gives `Q(Q−1)/2 · (2^-ρ + ε + ε_h)` for up to `Q` instances and `q` queries to `H`, with `ε` as defined above. The generic AKA theorem adds the AKA0 bound. |
| 4 | SAS entropy and its effect on the bound | **SUPPORTED** | `ρ` is the SAS digest length and directly contributes `2^-ρ`; the multi-instance factor and `ε`, `ε_h` remain. The paper’s population/run examples are estimates, not a selected project target. |
| 5 | Repeated attacker attempts and composition | **SUPPORTED WITH COMPOSITION** | The theorem accounts for many concurrent/attacker-launched instances through `Q(Q−1)/2` and oracle queries through `q`. The project must map retries and lifetime use to enforceable global bounds and account for additional AKA0 risk. The paper specifies no persistence mechanism. |
| 6 | Ceremony freshness | **NOT ESTABLISHED** | The model gives each live instance a unique tag and short-term state; it does not define ceremony expiry, restart behavior, or a persistent freshness mechanism. |
| 7 | Binding to one exact ceremony and its human approval | **NOT ESTABLISHED** | The proof is instance-based, but there is no project ceremony identifier or specified binding of a human approval event to durable terminal state for exactly that ceremony. |
| 8 | Initiator/responder role binding | **SUPPORTED WITH COMPOSITION** | Alice/Bob are distinct roles in the formal model and message flow, and Figure 4 includes an Alice/Bob identity check against reflection. Project role tags and binding of approval/results still need an exact profile. |
| 9 | Replay resistance | **NOT ESTABLISHED** | The paper models fresh protocol instances and ephemeral randomness but does not specify replay/terminal-state tracking across retries, expiration, or process restarts as P1 requires. |
| 10 | Unknown-key-share resistance | **NOT ESTABLISHED** | AKA outputs include peer IDs, but the AKA definition explicitly excludes inconsistent endpoint states by assuming further mutual authentication. That does not establish P1’s UKS requirement. |
| 11 | Transcript binding/authentication | **SUPPORTED WITH COMPOSITION** | The generic construction feeds the transcript and relevant final AKA0 messages into MCA; Theorem 1 reduces attacks to MCA or AKA0. The exact context and profile encoding are outside the theorem. |
| 12 | Commitment requirements | **SUPPORTED** | The paper defines hiding and binding requirements for its commitment and uses both in the proof. The 3-move result relies on the specific random-oracle construction, not any commitment with a convenient API. |
| 13 | Exact commitment construction analyzed | **SUPPORTED** | Figure 4 and Section 2.3 specify `c=H(e,K,m_A)`, with opening `(e,K)`, random-oracle output `ℓ_c` bits, tag `m_A`, and independent uniform `ℓ_e`-bit `e`. |
| 14 | Commitment randomness/nonces | **SUPPORTED** | The committed key `K` and responder mask `R` are independent uniform values; commitment randomness `e` is separately and freshly uniform. The proof relies on it. The paper does not establish Shortcake’s alternative commitment. |
| 15 | Key-agreement assumptions | **SUPPORTED WITH COMPOSITION** | The generic proof explicitly requires an AKA0 with its own bound; the paper uses Diffie–Hellman as the example. Selecting the DH group and establishing its concrete security contribution remain separate work. |
| 16 | Whether the theorem covers an arbitrary modern KEM | **NOT ESTABLISHED** | No. A generic AKA0 interface is not a proof for any KEM. A KEM would need to satisfy the AKA0 definition and have a suitable security analysis in this composition. |
| 17 | Application-context binding | **SUPPORTED WITH COMPOSITION** | MCA authenticates arbitrary messages, so context could be included in both parties’ authenticated inputs. A canonical encoding, agreement/mismatch behavior, transcript placement, and proof that all relevant context is covered remain required. |
| 18 | Proof-of-possession of long-term identity keys | **NOT ESTABLISHED** | The construction is ephemeral AKA and does not prove control of an application-supplied long-term identity private key. |
| 19 | Whether proof-of-possession is intrinsic or composable | **NOT ESTABLISHED** | It is not intrinsic to the published construction. The paper gives no safe proof-of-possession composition for this project; do not make key-ownership claims based on its result. |
| 20 | Key confirmation | **NOT ESTABLISHED** | The paper’s AKA model says it does not consider inconsistent final states and assumes mutual authentication is done by further communications. It does not provide the project’s explicit key-confirmation contract. |
| 21 | Peer binding | **SUPPORTED WITH COMPOSITION** | The formal AKA output is `(key, peer ID)`, and MCA outputs an authenticated peer message/ID. Mapping project peers and any context to those modeled values, without unsupported identity claims, still needs specification. |
| 22 | Human SAS comparison assumptions | **SUPPORTED WITH COMPOSITION** | The theorem assumes an authenticated narrowband channel for SAS messages. It does not model imperfect human comparison or define UI guidance and assurance; P1’s human factors need a project-level error/attempt analysis. |
| 23 | Cancellation, abort, disconnect, and expiry | **NOT ESTABLISHED** | The paper’s normal-completion proofs do not define cancellation, expiry, safe resumption, or prevention of an old approval reviving a run. |
| 24 | Concurrent ceremonies | **SUPPORTED WITH COMPOSITION** | The formal model permits concurrent instances, tags their state, and the bound counts launched instances. Mapping this to project message routing and exact human approval per ceremony remains necessary. |
| 25 | Retry, attempt, and persistence requirements | **SUPPORTED WITH COMPOSITION** | The theorem quantifies `Q` instances and `q` oracle queries, so security depends on limiting total work. The paper does not prescribe application lifetime limits, storage, or restart-safe enforcement; those must be derived from a chosen target and bound. |
| 26 | Output/key material established | **SUPPORTED** | The AKA definition returns a shared key associated with the peer ID; the DH instantiation derives the Diffie–Hellman key. This does not by itself establish project authorization or explicit key confirmation. |
| 27 | What the construction does not establish | **NOT APPLICABLE** | This is a scope inventory rather than a candidate property. In particular, the paper does not establish every identity, lifecycle, application-context, human-error, KEM, or production-readiness property P1 requires. |
| 28 | Both participants accept compatible terminal outcomes | **NOT ESTABLISHED** | The paper explicitly excludes inconsistent endpoint states from its AKA success condition and assumes mutual authentication will be handled by further communication. It does not establish P1's terminal-outcome agreement. |
| 29 | Downgrade, ambiguity, or unmet requirements cannot silently produce success | **NOT ESTABLISHED** | The paper's theorem analyzes a fixed construction and does not define negotiation, profile mismatch, or project fail-closed behavior for ambiguous inputs. |
| 30 | Long-term private key material remains under participant control and is not disclosed | **NOT ESTABLISHED** | The paper's construction uses ephemeral DH and does not define a long-term identity-key lifecycle or prove a future key-bearing composition preserves this P1 property. |

## Candidate B — P1 requirement mapping

The row numbers below reuse Candidate A’s P1 requirement list above, including items 28–30 added from the full P1 threat model. Each classification is for the paper’s defined authentication/SMT construction, not for a hypothetical protocol that could be built around it.

| # | Status | Primary-source evidence and boundary |
|---:|---|---|
| 1 | **SUPPORTED WITH COMPOSITION** | Theorems 2–4 bound a one-shot active misbinding by the SAS gate and compose authentication with KEM/DEM/signatures. The formal OOB and primitive assumptions must hold. |
| 2 | **SUPPORTED** | Sections 4–5 claim UC realizations of one-way and mutual authenticated-message channels, then a one-shot \(\mathcal F_{\mathrm{SMT}}^{S\rightarrow R}(\varepsilon)\) message-transfer functionality. This is not a reusable AKE output. |
| 3 | **SUPPORTED** | Theorems 2–3 set the per-`sid` ideal misbinding parameter to \(\varepsilon=2^{-t}\); Theorem 4 bounds SMT distinguishing advantage by \(\varepsilon\), KEM, DEM, and signature advantages, plus negligible terms. |
| 4 | **SUPPORTED** | `t` is the number of truncated random-oracle output bits and the per-session ideal guess probability is \(2^{-t}\). This excludes human mistakes and multi-session aggregation. |
| 5 | **SUPPORTED WITH COMPOSITION** | The formal gate permits one online forge attempt per `sid`. Separate SIDs get separate gates; no aggregate retry target or global session budget is proved. |
| 6 | **SUPPORTED WITH COMPOSITION** | The environment/caller supplies `sid`, or the sender samples one if absent. It is included in commitment/SAS context and subroutine calls. P1 still needs a unique shared ceremony identifier across retries and restarts. |
| 7 | **SUPPORTED WITH COMPOSITION** | OOB returns the equality bit for `(SAS, sid)` to both parties, and `sid` is in the SAS input. This binds the formal session; a separate explicit UI approval event and durable approval-to-ceremony binding are not defined. |
| 8 | **SUPPORTED WITH COMPOSITION** | Sender/Receiver positions and `m_S`/`m_R` ordering are fixed and included in the mutual SAS. Project initiator/responder labels and approval/result routing still need mapping. |
| 9 | **SUPPORTED WITH COMPOSITION** | The SID is committed and hashed; ideal state delivers once per SID and SMT keys are fresh per session. Application uniqueness and restart-safe anti-replay state remain necessary. |
| 10 | **SUPPORTED WITH COMPOSITION** | Mutual cross-authentication returns each side’s authenticated contribution; including peer identifiers in `m_S`/`m_R` can bind them. The functionality does not define real-world identity or long-term-key ownership. |
| 11 | **SUPPORTED WITH COMPOSITION** | The mutual SAS input covers `sid`, both messages, and both random values; the SMT signature covers protocol context, SID, direction, and ciphertexts. Any additional app context must be encoded in authenticated fields. |
| 12 | **SUPPORTED** | Section 3.2 requires computationally hiding and binding commitments; Sections 4.2–4.3 use both properties in the UC proof. |
| 13 | **SUPPORTED WITH COMPOSITION** | The protocol commits to `(sid || m_S)` with `Commit(...; r_S)` and opens with `d`; the text says the main construction uses hash-then-open in the ROM. A concrete commitment implementation/profile is not frozen. |
| 14 | **SUPPORTED** | `r_S` is fresh commitment randomness and `r_R` is sampled uniformly by the Receiver; both values enter the SAS input. |
| 15 | **SUPPORTED WITH COMPOSITION** | The SMT proof assumes an IND-CPA KEM, one-time OT-CPA DEM, and EUF-CMA signature, with fresh keypairs per session. The SAS authentication result itself is not a KEM-based AKE. |
| 16 | **SUPPORTED WITH COMPOSITION** | Theorem 4 is generic for a KEM satisfying the stated classical IND-CPA notion, but it does not endorse every KEM implementation or establish quantum security. The DEM, signature, key freshness, and verify-before-decapsulate structure are also required. |
| 17 | **SUPPORTED WITH COMPOSITION** | The authentication layer accepts arbitrary messages and SMT signs a context including SID/direction. Application-specific fields, canonical encoding, and mismatch semantics remain project decisions. |
| 18 | **NOT ESTABLISHED** | The canonical construction does not prove possession of an application’s long-term identity private key. |
| 19 | **NOT ESTABLISHED** | It authenticates ephemeral public material; no long-term proof-of-possession composition is proved. |
| 20 | **NOT ESTABLISHED** | Equality of SAS authenticates the exchanged messages, but the one-way SMT protocol has no receiver-to-sender key-confirmation output or reusable paired-key contract. |
| 21 | **SUPPORTED WITH COMPOSITION** | The cross-authentication functionality binds the two exchanged messages in fixed roles, and SMT binds a fresh sender verification key to signed ciphertext. Peer identity semantics still belong in authenticated inputs and project policy. |
| 22 | **SUPPORTED WITH COMPOSITION** | Section 4.1 explicitly introduces a possible \(\varepsilon_{\mathrm{human}}\) for human fallibility, but sets it to zero in all proofs. The cryptographic \(2^{-t}\) result assumes correct full comparison. |
| 23 | **NOT ESTABLISHED** | Invalid openings, mismatches, and cryptographic failures abort, but cancellation, expiry, safe continuation, disconnect, and stale-state recovery are not specified. OOB itself is immediate and cannot be suppressed in the model. |
| 24 | **SUPPORTED WITH COMPOSITION** | UC realization and the composition theorem support concurrent sessions with per-session state, provided SIDs are distinct and subroutine calls reuse the same SID. The proof assumes honest endpoints. |
| 25 | **SUPPORTED WITH COMPOSITION** | One forge attempt is modeled per SID, but the paper does not set an overall attempt limit, cooldown, persistent counter, or restart policy. Repeated sessions aggregate risk. |
| 26 | **NOT ESTABLISHED** | The SMT construction transfers one payload and keeps the KEM/DEM content key internal. It does not output a reusable shared pairing key to both applications. |
| 27 | **NOT APPLICABLE** | This is a scope inventory. The source explicitly does not establish human-error rates, long-term identity ownership, or a reusable pairwise AKE result. |
| 28 | **NOT ESTABLISHED** | The mutual SAS-authentication subprotocol returns each peer’s message on equality, but the proved final SMT result reports payload delivery only to R and does not establish P1’s bilateral pairing terminal contract. |
| 29 | **SUPPORTED WITH COMPOSITION** | The fixed protocol aborts on invalid commitment/opening, SAS mismatch, signature failure, or KEM/DEM error. Negotiation, downgrade rules, and project ambiguity handling are not defined. |
| 30 | **NOT APPLICABLE** | The canonical construction uses fresh per-session KEM and signature keys, not long-term identity keys. If a project composition adds long-term secrets, their protection is unproved here. |

## Candidate C — Jarecki–Saxena, SCN 2010

### Source and version relationship

The conference source inspected is the author-hosted PDF of Stanisław Jarecki and Nitesh Saxena, “Authenticated Key Agreement with Key Re-use in the Short Authenticated Strings Model,” *Security and Cryptography for Networks (SCN 2010)*, LNCS 6280, pp. 253–270, DOI [10.1007/978-3-642-15317-4_17](https://doi.org/10.1007/978-3-642-15317-4_17), 18-page proceedings chapter. The exact source is [the authors’ SCN PDF](https://nsaxena.engr.tamu.edu/wp-content/uploads/sites/238/2019/12/js-scn10.pdf), inspected 2026-09-27. Relevant parts: Sections 1.2–1.4; Sections 2–3.3 (assumptions and games); Figure 2; Theorems 1–2; Section 4 proof; and Section 5.

The SCN paper states that the Enc-AKA Theorem 2 proof is omitted for space and refers to full version [8], “available from the authors (2010).” I also inspected the author-hosted 24-page version published as “Authenticated Key Agreement with Key Re-Use in the Short Authenticated Strings Model,” *Contemporary Mathematics* 582 (2012), pp. 151–173, [AMS chapter record](https://doi.org/10.1090/conm/582/11552), [author-hosted PDF](https://nsaxena.engr.tamu.edu/wp-content/uploads/sites/238/2019/12/js-ams12.pdf), inspected 2026-09-27. Its Section 5 contains the full proof of the same Theorem 2 and bound; its Appendix B explains why the Pasini–Vaudenay generic compilation does not generally cover shared cross-session state. The construction and stated bound agree with the SCN chapter. This later text is used to inspect the proof the conference version omits, not to replace the SCN publication record.

### Construction, output, and assumptions

Candidate C is the paper’s specific three-round encryption-based construction, `Enc-AKA`; it is not generic over arbitrary AKEs and does not use a DH exchange plus a SAS-MCA wrapper. In its `Enc-MCA` parent, the initiator `P_i` has a public/private key pair for a CCA-secure encryption scheme. The protocol assumes permanent `PK_i` / `SK_i` across sessions and a globally selected commitment parameter in the common-reference-string model. `Enc-AKA` is the specialization `m_i = null`, `m_j = K`: responder `P_j` samples a new uniform session key `K ∈ {0,1}^ℓ` for each run.

1. **Initiator:** sample fresh `R_i ∈ {0,1}^k` and nonce `s_i ∈ {0,1}^ℓ`; commit to `[m_i | s_i | PK_i | R_i]`; send `(m_i, s_i, PK_i, c_i)` over the attacker-controlled network. For `Enc-AKA`, `m_i` is null.
2. **Responder:** sample fresh `R_j ∈ {0,1}^k`, nonce `s_j ∈ {0,1}^ℓ`, and session key `K`; encrypt `[m_j | s_j | R_j]` under the received `PK_i` using the CCA-secure public-key encryption scheme; send ciphertext `e_j`. For `Enc-AKA`, `m_j=K`.
3. **Initiator and responder:** initiator decrypts `e_j`, opens `c_i`, and sends the decommitment; initiator computes `SAS_i = R_i ⊕ R_j`, responder computes `SAS_j = R_i ⊕ R_j`, and they exchange these k-bit values on the SAS channel. Each accepts only if its equality check passes. The initiator outputs the decrypted `K`; the responder outputs its sampled `K`.

The protocol also computes a session identifier from a collision-resistant hash of the sent and received transcript, including SAS messages; the paper says the proof also works with the concatenated fresh nonces `[s_i | s_j]`. The SID is local output, not a separately negotiated wire field. In the security model a session is locally indexed; two sessions are matching when peers and roles are reciprocal, and partnered when their transcript SIDs agree. Fresh random nonces make a session partner unique except with negligible probability. The formal AKA output is `(Peer, K, sid)`. Correctness says partnered sessions both accept and output the same key.

Theorem 1 proves the parent Enc-MCA’s message authentication; Theorem 2 states Enc-AKA’s key-security result. Given a `(T_C, ε_C)` non-malleable commitment and a `(T_E, ε_E)` single-secret CCA-secure encryption scheme, its attack bound is:

```text
Adv ≤ 2 n τ_t τ_c (2^-k + max(ε_C, ε_E))
T ≤ min(T_C, T_E) - μ
```

Here `n` is the number of players, `τ_t` bounds total sessions per player, `τ_c` bounds concurrently live sessions for each pair, and `μ` is a small constant overhead. Theorem 2’s game tests a partnered session key against random; the proof also uses Theorem 1’s cross-authentication result to rule out an accepted wrong key. The bound is not just `2^-k`: it includes the factor 2, session counts, and primitive advantages. The paper gives ROM hash-commitment parameters in terms of the hash query budget; it chooses no project-wide SAS length, total-attempt budget, or operational parameter.

The cited instantiations are OAEP-RSA in the ROM under the RSA assumption, and a randomness-reusing CCA-secure ElGamal variant under the DH assumption in the ROM. Vanilla ElGamal, plain ECDH, and a KEM are not interchangeable instantiations. The generic theorem can apply to a public-key encryption scheme only when that exact scheme satisfies the paper’s CCA notion and the commitment assumption. Turning a KEM into a KEM-DEM public-key encryption scheme would need its own composition argument under the required notion; the paper gives no post-quantum claim.

### Enc-MCA messages and context binding

The Enc-MCA inputs `m_i` and `m_j` are arbitrary strings. Section 2 describes the encrypted plaintext space as `[m | R]`, where `m` is an adversarially chosen string; Figure 2 commits to `[m_i | s_i | PK_i | R_i]` and encrypts `[m_j | s_j | R_j]`. Callers can represent structured values as bytes, but the paper specifies no structured encoding, field semantics, or validation rule.

Enc-MCA outputs the peer’s authenticated message on each side. Successful authentication means the peer actually sent that message in some session, except for the Theorem 1 attack bound; it does not mean that the two application messages are equal or meet an application policy. Both messages participate in the transcript-derived session identifier. Changing either message therefore changes the transcript and, except for a hash collision, the SID. An attacker’s substitution is an authentication event covered by Theorem 1’s bound. If a peer itself sends a different value, Enc-MCA authenticates and returns that value rather than rejecting it; the caller must check it against its expected input.

Roles are part of the formal instance model: matching sessions require reciprocal peer inputs and opposite initiator/responder roles, and partnering also requires equal SIDs. The ordered protocol messages and transcript SID distinguish the two message positions. This supports formal peer, role, and per-session binding for Enc-MCA’s authenticated messages. It does not give those messages application meaning or prove that the key output by Enc-AKA is bound to them.

### Why Theorem 2 does not cover application context

Figure 2 and the Enc-AKA definition fix `m_i = null` and `m_j = K`, with the responder sampling a fresh uniform `K` for each session. Theorem 2’s proof first reduces an initiator accepting a key different from the responder’s session key to the Enc-MCA authentication reductions, then reduces distinguishing that responder key from random to SS-CCA security. Its challenge ciphertext contains the fresh key, and its security game tests the key output by a partnered session. The proof does not state a theorem parameterized by extra application context or changes to either Enc-AKA message.

The proof relies on these exact roles for the values:

- `m_i = null` is the fixed initiator input in the Enc-AKA protocol being proved. The proof does not analyze a variable initiator application-context value.
- `m_j = K` makes the responder’s fresh uniform `K` exactly the value encrypted to the initiator and output as the session key. In the SS-CCA reduction, the challenge ciphertext contains one of two candidate keys; after the Enc-MCA reductions rule out acceptance of a different key, distinguishing the tested output from random breaks SS-CCA.
- The Enc-MCA reductions and SAS equality checks justify delivery/authentication of that encrypted responder value in a partnered session. They do not ensure that both endpoints reach local output when SAS delivery is delayed or dropped.

Theorem 1 alone cannot fill this gap: it proves authenticity of arbitrary Enc-MCA messages, not secrecy of an Enc-AKA key jointly bound to those messages. Nor does the paper prove that running Enc-MCA beside Enc-AKA, or changing the two Enc-AKA inputs to include context, preserves Theorem 2. The desired substitution/composition therefore requires a new proof. No KDF or other custom composition is inferred here.

P1 may eventually require binding generic protocol/domain identifiers, profile versions, roles, ceremony identifiers, opaque context from each participant, and any public-key claim the result intends to authenticate. This list does not select fields or an encoding. Enc-AKA’s theorem does not include these context inputs. Formal peer, role, and SID partnering does not establish that two context-extended sessions sharing a key agree on those values. The paper neither proves nor supplies a counterexample for a state such as “A: `K` with B and context X; B: `K` with A and context Y”; it leaves that context-confusion question outside its theorem. A context value separately authenticated by Enc-MCA is not thereby proven bound to the Enc-AKA key.

### Terminal outputs and key confirmation

Each participant outputs locally after its own SAS equality check. In Figure 2 the initiator outputs after receiving the responder’s SAS, while the responder outputs after receiving the initiator’s SAS. The paper permits SAS messages to be delayed or dropped. If the responder’s SAS arrives but the initiator’s SAS is dropped, the initiator can output `K` while the responder has not accepted; reversing which SAS arrives gives the symmetric incomplete state. Theorem 2’s correctness statement only says partnered sessions both accept and output equal keys. Its security game tests a completed partnered session and does not require every local accept to have a partnered terminal accept.

The SAS checks provide directional protocol-level evidence that the peer processed the corresponding commitment or encrypted response. They do not confirm that both applications committed success. The construction has no final acknowledgement authenticated under `K`, and Theorem 2 does not prove an added confirmation exchange or P1’s bilateral terminal-result contract. A profile-only success rule cannot treat an unpartnered local output as bilateral success; adding cryptographic confirmation and defining its behavior under loss needs a separate construction-level justification. Long-term identity proof-of-possession remains outside this pairing-key claim unless a result claims ownership of such a key.

The theorem’s symbolic parameters (`n`, `τ_t`, `τ_c`, `k`, `ε_C`, `ε_E`) do not require project-specific numeric values to decide whether this is a possible construction family. Any selected profile would still have to choose and enforce applicable limits and instantiate the assumptions. Theorem 2 assumes a non-malleable commitment in the CRS model and SS-CCA public-key encryption. The generic theorem does not itself assume the random-oracle model; the paper’s concrete hash-based commitment and cited OAEP-RSA and ElGamal instantiations do. Concrete primitives, SAS length, human comparison procedure, attempt values, wire format, and state machine remain profile decisions, not P2 blockers.

### Concurrency, human channel, and key reuse

Section 3 explicitly permits concurrent instances, including the timeout/restart situation where one device starts again while its peer remains in an older run. The attacker may interleave network messages and choose which session’s SAS message to deliver. Sessions have local indices, reciprocal peer/role matching, and transcript-derived SIDs; `τ_t` counts total sessions and `τ_c` counts live sessions per pair, and both enter the theorem bound. This is formal session separation, not a durable application ceremony identifier. The protocol does not store terminal SIDs, couple UI approval to them, survive application restarts with anti-replay state, or put consumer context into Enc-AKA (`m_i` is null). The introductory channel description permits replay of SAS messages; the formal `SAS-send` game removes each queued SAS message after delivery, so duplicate delivery of the same SAS message is not represented there. The insecure network does allow replay, delay, drop, modification, and injection.

The SAS channel is public, authenticated, and source/target authenticated for each ordered player pair. The attacker can read its values and can delay, drop, replay, and reorder them, but cannot modify or inject them. Section 3’s game permits observing, stalling, deleting, and reordering queued SAS values, while its consume-once queue does not model duplication. This is a formal authenticated-channel assumption; it is not a model of a person comparing displays. The paper gives no error model for misreading, partial comparison, blind approval, repeated-mismatch fatigue, accessibility, or rendering. Its cryptographic result therefore assumes the authenticated SAS channel works as defined and says nothing about real user error.

“Key re-use” means reusing long-term encryption key material across protocol sessions (including the same DH random contribution in the specialized ElGamal variant). It does **not** mean reusing the output pairing key: `K`, both k-bit `R_i/R_j` masks, both `s_i/s_j` nonces, and commitment coins are freshly sampled per ceremony. Encryption randomness is scheme-specific; the paper’s ElGamal instantiation explicitly reuses a DH random contribution. Reusing `SK_i` is central to the result’s efficiency and is explicitly non-forward-secret. The model uses static corruption and does not provide forward secrecy. Later compromise of a reused decryption secret can expose recorded responder ciphertexts and their past session keys, as well as compromise future runs; compromise of a reused DH exponent similarly exposes recorded shared values. The project has no stated requirement to reuse private keys, so this performance feature is not itself a reason to choose Candidate C.

### Candidate C — P1 requirement mapping

Rows use the same numbered P1 requirements and classification meanings as Candidate A and B. “With composition” marks work that belongs in a project profile or consumer enforcement layer and is not supplied by the theorem itself.

| # | Status | Primary-source evidence and boundary |
|---:|---|---|
| 1 | **SUPPORTED WITH COMPOSITION** | Theorems 1–2 cover active network interference, message authentication, and partnered-key secrecy under the SAS-channel, commitment, and CCA assumptions and the stated `n, τ_t, τ_c` bounds. Human comparison is not proved. |
| 2 | **SUPPORTED** | Figure 2’s `Enc-AKA` is a direct three-round SAS authenticated key-agreement construction, not an arbitrary compilation. Theorem 2 states its partnered-session key-security result. |
| 3 | **SUPPORTED** | Theorem 2 gives `2 n τ_t τ_c (2^-k + max(ε_C, ε_E))` with time bound `T ≤ min(T_C,T_E)-μ`; it is not a parameter-free or single-attempt `2^-k` claim. |
| 4 | **SUPPORTED** | The SAS is k bits; `2^-k` is multiplied by `2 n τ_t τ_c` and added to commitment/encryption advantages. No deployed k or human-error term is selected. |
| 5 | **SUPPORTED WITH COMPOSITION** | The bound includes total sessions per player and concurrently live sessions per pair. The project must choose/enforce `τ_t` and `τ_c`, account for hash-query terms in `ε_C`, and persist any required lifetime/retry limits. |
| 6 | **SUPPORTED WITH COMPOSITION** | Fresh `s_i/s_j` and the transcript-derived SID distinguish formal runs, with negligible collision probability. Durable uniqueness across app restarts and the consumer’s definition of one ceremony are outside the paper. |
| 7 | **NOT ESTABLISHED** | No explicit human-approval event or approval-to-session contract exists; the formal SID does not itself prove a user approved that ceremony. |
| 8 | **SUPPORTED WITH COMPOSITION** | Formal sessions have `init` / `resp` roles, matching requires opposite roles, and partnering also requires reciprocal peers and the same SID. UI routing and any role-tag encoding are not specified. |
| 9 | **SUPPORTED WITH COMPOSITION** | The main-channel attacker may replay messages; fresh nonces, commitment, CCA encryption, SAS checks, and transcript SID are in the construction. Durable terminal-state replay handling is absent, and the formal SAS channel prose/game differ on duplicate delivery. |
| 10 | **SUPPORTED WITH COMPOSITION** | Partnering requires reciprocal `Peer` values, opposite roles, and equal SIDs, and the SAS channels authenticate source and target. This is not a long-term identity or application-key ownership proof. |
| 11 | **SUPPORTED WITH COMPOSITION** | SAS values depend on the committed/decrypted random masks, and SID hashes the transcript including SAS messages. Application context is absent from Enc-AKA and its binding to the output key is unproved. |
| 12 | **SUPPORTED** | Sections 2 and 4 require a non-malleable commitment; Theorem 1 and the Enc-AKA proof include its advantage `ε_C`. |
| 13 | **SUPPORTED WITH COMPOSITION** | The exact commitment target is `[m_i | s_i | PK_i | R_i]`; the generic assumption is non-malleability in a CRS. The paper gives a ROM hash commitment and an encryption-derived option, but a project instantiation/CRS profile remains to be justified. |
| 14 | **SUPPORTED** | Figure 2 samples fresh `R_i,R_j`, `s_i,s_j`, and key `K` each run; the commitment is randomized. Encryption randomness depends on the selected scheme: the paper’s ElGamal instantiation reuses a DH random contribution. |
| 15 | **SUPPORTED** | The construction directly assumes an SS-CCA public-key encryption scheme plus non-malleable commitments, with the paper’s theorem reducing to those advantages. |
| 16 | **SUPPORTED WITH COMPOSITION** | The theorem is generic over an encryption scheme meeting its CCA notion. Its examples are OAEP-RSA and a specialized randomness-reusing ElGamal scheme in the ROM. Plain ECDH or a KEM does not directly instantiate it; KEM-DEM or post-quantum support is not proved. |
| 17 | **NOT ESTABLISHED** | Enc-MCA authenticates arbitrary strings and includes them in the transcript SID (Theorem 1; Figure 2), but Enc-AKA fixes `m_i=null` and `m_j=K`. Theorem 2 does not prove a context-extended key result or a separate Enc-MCA/Enc-AKA composition. |
| 18 | **NOT ESTABLISHED** | The result does not claim ownership of a consumer’s long-term identity key. Its protocol encryption key is not a consumer identity credential. |
| 19 | **NOT ESTABLISHED** | No proof-of-possession protocol or composition for an unrelated application identity key is given. |
| 20 | **SUPPORTED WITH COMPOSITION** | Partnered-session correctness requires equal outputs. The initiator’s SAS check shows the responder processed the commitment; the responder’s check shows the initiator processed the encrypted response. Neither proves both applications committed success; there is no final `K`-authenticated confirmation flight. |
| 21 | **SUPPORTED WITH COMPOSITION** | The formal result returns `(Peer,K,sid)` and partnering binds reciprocal peers. Mapping that peer to a user-intended device/person or an application identity requires separate consumer policy. |
| 22 | **SUPPORTED WITH COMPOSITION** | The proof assumes the ideal public authenticated SAS channel. It does not account for any human comparison error; user-interface assurance remains a separate requirement. |
| 23 | **NOT ESTABLISHED** | Invalid decryptions, openings, or mismatched SAS values reject, but cancellation, expiry, disconnect, safe resumption, and stale-state recovery are not specified. |
| 24 | **SUPPORTED WITH COMPOSITION** | Sections 3.2–3.3 explicitly allow concurrent runs and forced restarts while another session remains live; partnering uses peer, complementary role, and SID. `τ_t` and `τ_c` bound the theorem. Consumer routing and approval association remain necessary. |
| 25 | **SUPPORTED WITH COMPOSITION** | Total attempts and concurrent sessions appear directly in the bound. The paper provides no numeric limits, cooldown, persistent counters, or restart policy; these are enforcement/profile decisions derived from the chosen bound. |
| 26 | **SUPPORTED** | The responder samples a fresh uniform `K` per session, sends it inside the CCA-protected ciphertext, and both partnered parties output the same key plus peer and SID. |
| 27 | **NOT APPLICABLE** | This row inventories omitted properties; it is not a candidate requirement. The paper’s limits are itemized in the other rows. |
| 28 | **NOT ESTABLISHED** | Each side outputs after its own SAS check. Since SAS delivery may be delayed or dropped, one side can output while the other remains incomplete. Partnered-session correctness does not require bilateral terminal acknowledgement or compatible application commit. |
| 29 | **SUPPORTED WITH COMPOSITION** | The fixed construction rejects failed opens, decryptions, and SAS mismatches; it has no negotiation or fallback. A project profile still must reject ambiguous or unsupported parameters. |
| 30 | **NOT ESTABLISHED** | Static-key reuse is assumed and adaptive compromise is outside the model. The theorem does not establish endpoint storage/control or confidentiality after key compromise. |

## Candidate comparison

| Security question | Candidate A — Pasini–Vaudenay 2006 | Candidate B — Beskorovajnov–Müller-Quade 2026 | Candidate C — Jarecki–Saxena 2010 |
|---|---|---|---|
| Direct reusable pairing-key result | Generic SAS-MCA + separately secure AKA0; direct DH-based instance discussed. | No: final theorem delivers one sender-to-receiver message; no shared reusable output. | Yes: `Enc-AKA` has a fresh bilateral shared `K` and `(Peer,K,sid)` output. |
| Bilateral agreement | Key agreement is modeled, but the paper sets aside inconsistent final states for further mutual authentication. | Mutual SAS message authentication is composed into one-way SMT; not bilateral key delivery. | Partnered sessions accept and output the same `K`; no guarantee that every local terminal event has a peer terminal acknowledgement. |
| Concurrency | Concurrent instances, bound via `Q`; project routing remains. | UC composition with distinct SIDs and per-SID state. | Concurrent, timed-out/restarted sessions are explicit; `τ_t` total sessions per player and `τ_c` live sessions per pair bound the result. |
| Session binding | No project ceremony SID or durable restart semantics. | SID appears in commitment, SAS input, functionality calls, and signed SMT context. | SID derives from full transcript (or fresh nonces); partnering additionally requires reciprocal peers and opposite roles. It is not a durable UI ceremony handle. |
| Replay / UKS | P1 replay and UKS semantics need mapping. | SID-bound replay controls in ideal functionalities, but no application restart store or global replay policy. | Main-channel replay is modeled; nonces and transcript partnering bind protocol runs. SAS-channel duplicate semantics differ between prose and game. No long-term identity semantics. |
| Exact security result / bound | Theorem 3 MCA bound depends on `Q`, hash queries, SAS `ρ`, hash-family/commitment error; AKA adds AKA0 risk. | Per-SID gate `2^-t`; SMT adds KEM/DEM/signature advantages and negligible terms. | Theorems 1–2: `2 n τ_t τ_c (2^-k + max(ε_C,ε_E))`; includes players, total sessions, concurrency, and primitive advantages. |
| Human-channel assumption | Authenticated narrowband SAS channel; human errors not modeled. | Ideal synchronous exact comparison, values public, `ε_human=0` in proof. | Public authenticated, peer/source-bound SAS channel; attacker reads/delays/drops/reorders/replays but cannot modify/inject; no human-error model. |
| Commitment | Specific `H(e,K,m_A)` ROM commitment; theorem fixes construction. | Generic hiding/binding commitment; main hash-then-open instance in ROM. | Non-malleable commitment in CRS; paper gives ROM hash and CCA-encryption-derived options. Exact project profile not selected. |
| Primitive compatibility | Generic over justified AKA0; example DH. No arbitrary KEM proof. | Generic classical IND-CPA KEM + one-time DEM + signature, for SMT only. | Generic over SS-CCA public-key encryption; examples OAEP-RSA and specialized CCA ElGamal in ROM. No direct KEM or post-quantum result. |
| Key confirmation | No project-level confirmation or compatible terminal rule. | No bilateral key output / receiver confirmation in SMT theorem. | Each SAS check provides directional evidence of peer processing; no final `K`-authenticated acknowledgement or bilateral application commit. |
| Context, identity, and PoP | Authenticated messages can carry context, but application encoding and identity PoP are not proved. | Arbitrary messages can carry context; long-term identity PoP not proved. | Enc-MCA authenticates arbitrary strings, but Theorem 2 covers only Enc-AKA’s `m_i=null`, `m_j=K`; no context-to-key composition or unrelated identity PoP is proved. |
| Abort / terminal outcome | Mismatch rejects; consistent final states are assumed or deferred. | Fixed errors abort; no bilateral terminal contract. | Invalid open/decrypt/SAS rejects; no cancellation/expiry or bilateral terminal acknowledgement. |
| Attempt enforcement | Bound counts instances; no lifetime persistence policy. | One forge attempt per SID; no aggregate budget or durable counter. | Bound counts `τ_t` total sessions and `τ_c` concurrent sessions; no chosen values, cooldown, or persistence design. |
| New unaudited composition required | Justify AKA0 and profile ceremony, approval, context, terminal behavior. | Must derive bilateral shared pairing key from one-way SMT or prove a new composition. | A new proof must cover context-to-key binding and the P1 terminal-result contract; the existing key-agreement result remains the strongest direct candidate. |

The symbolic bound does not require choosing project values during P2: `n`, `τ_t`, `τ_c`, `k`, `ε_C`, and `ε_E` can be selected and enforced when a construction can proceed to profile work. Human UX, SAS length, concrete primitives, wire format, and application proof-of-possession for any unrelated long-term identity key are likewise not this construction-selection blocker. The blockers here are proof-level: the current Enc-AKA theorem has no context input, and the parent Enc-MCA theorem establishes message authentication, not secrecy of the resulting context-bound pairing key; neither theorem requires bilateral terminal application success.

## Bounded search and related work

The earlier bounded 2015–2026 search found no other directly comparable two-party SAS-AKE in that date range with a better fit to P1; it did not include Candidate C, which predates that search. A relevant adjacent primary result is Naor, Rotem, and Segev, “[Out-of-Band Authenticated Group Key Exchange: From Strong Authentication to Immediate Key Delivery](https://eprint.iacr.org/2019/1458),” ePrint 2019/1458, published at ITC 2020. It proves a group OOB-AKE from a passively secure key-exchange protocol, with a bound of approximately \(2(n-1)(1/2+o(1))^\ell\), and addresses abort-driven immediate key delivery. The authors explicitly leave concurrent executions to future work, so it does not meet P1’s coexistence of concurrent ceremonies as published; it is recorded as related work, not a carried-forward candidate. The 2026 paper also surveys MANA-IV and deployed SAS uses. ZRTP and Bluetooth Numeric Comparison are useful deployed/protocol references, not additional modern proof candidates here. This is a bounded search, not an exhaustive literature survey.

## P2 outcome

### RESEARCH CONTINUES

Candidate C resolves the central reusable bilateral shared-key gap and has explicit concurrency and retry variables in its bound. P1-compatible terminal completion remains unresolved: delayed or dropped SAS delivery can leave local views incomplete, and the paper has no bilateral terminal acknowledgement. The ideal SAS-channel assumption still needs a human procedure; `sid`, roles, and peer partnering still need project-level approval routing; `τ_t` / `τ_c` need enforceable values and persistence; long-term application identity PoP is outside the claim; and no PFS is provided. These profile, consumer, and application-policy boundaries must stay separate from the theorem. Candidate C’s long-term key reuse is optional for this project and is not the same as reuse of the fresh output key `K`.

### Blocker assessment

| Existing blocker | Candidate C effect | Boundary |
|---|---|---|
| Reusable bilateral shared-key result | **Resolved** | Enc-AKA directly outputs the same fresh secret `K` to partnered initiator/responder sessions (Theorem 2; Figure 2). |
| Exact ceremony/session binding | **Partial** | Transcript SID and fresh nonces distinguish formal sessions; human approval association, restart uniqueness, and consumer context are not part of the protocol. |
| Replay / unknown-key-share | **Partial** | Network replay, roles, peers, and partnering are modeled; there is no durable terminal replay store or application identity semantics, and SAS duplicate modeling is inconsistent between prose and game. |
| Key confirmation | **Partial** | The two SAS checks give directional evidence that the peer processed protocol data, but there is no final `K`-authenticated acknowledgement and no proof of a bilateral application commit. |
| Compatible terminal outcomes | **Unresolved** | Each endpoint outputs on its local SAS check. With an independently delayed or dropped SAS message, one can output while its peer remains incomplete; the partnered-session correctness condition does not prevent that. |
| Human comparison | **Partial** | The theorem is for an authenticated, public SAS channel; it has no model of human misread, partial comparison, blind approval, fatigue, or accessibility. |
| Attempt budgets / persistence | **Partial** | `τ_t` and `τ_c` are explicit in the concrete bound, but project values, persistent counters, cooldown, and restart enforcement are not prescribed. These are derived consumer/security enforcement duties. |
| Long-term identity PoP | **Unresolved** | The protocol’s encryption key is not an unrelated consumer identity key; no PoP composition is proved. The library must not claim ownership without one. |
| Primitive selection | **Partial** | The theorem accepts exact SS-CCA public-key encryption and non-malleable commitments; only classical RSA/ElGamal examples are analyzed. KEM, PQ, and project profiles are not selected. |

### Composition and terminal-result classifications

**Composition answer: NEW PROOF REQUIRED.** Enc-MCA’s arbitrary-message result authenticates each peer’s message and incorporates the transcript into the SID. Enc-AKA’s Theorem 2 is for the fixed `null`/fresh-`K` substitution. The paper does not prove that changing those inputs or composing a separate Enc-MCA instance preserves key secrecy, context agreement, or the concurrency bound.

**Terminal-result classification: CONSTRUCTION-LEVEL PROOF REQUIRED.** The local SAS checks are not agreement that both applications committed success. A profile rule cannot upgrade an unpartnered local key output into bilateral success. An added key-authenticated confirmation affects the protocol and has no proof or loss-handling result in this paper; a confirmation message could itself be delayed or dropped.

### Single remaining proof-level blocker

P2 remains **RESEARCH CONTINUES** for exactly one missing result: a proof or already-established composition theorem for a context-bound Enc-AKA result that binds both participants’ generic context inputs to the same fresh key and provides P1-compatible terminal outcomes despite delayed or dropped messages, while retaining the key authentication/secrecy and concurrent-session guarantees. The current sources do not provide this result. This is not a request to search for more protocol candidates.

No KEM, SAS target, rendering, wire format, state machine, or API is selected here. P2 remains current; P3 remains gated. This outcome is not a production-security claim.

## Primary and implementation sources

1. Sylvain Pasini and Serge Vaudenay, “[SAS-Based Authenticated Key Agreement](https://www.iacr.org/archive/pkc2006/39580401/39580401.pdf),” PKC 2006, LNCS 3958, pp. 395–409, DOI [10.1007/11745853_26](https://doi.org/10.1007/11745853_26). Relevant material: Section 2 model and commitment construction; Section 4 and Theorem 1 generic AKA reduction; Figure 4 and Theorem 3, including its proof and repeated-instance discussion. Accessed 2026-09-27.
2. Wasilij Beskorovajnov and Jörn Müller-Quade, “[How to Kickstart \(\mathcal{F}_{\mathrm{SMT}}^{S\rightarrow R}\) with Short Authentication Strings and Out-of-Band Communication](https://doi.org/10.1007/978-3-032-32560-0_15),” ACNS 2026, LNCS 16571, pp. 415–443, first online 2026-07-22; and the complete author version, “[How to kickstart Secure Message Transfer with Short Authentication Strings and Out-Of-Band Communication](https://eprint.iacr.org/2025/1598),” IACR ePrint 2025/1598, revision dated 2025-09-11. EPrint Sections 3.2–3.4, 4.1–4.3, 5, Theorems 2–4, and Appendix A (MAC proof limitation); conference Appendix A, Theorem 5 cross-checks the one-sided UC claim. Accessed 2026-09-27.
3. Moni Naor, Lior Rotem, and Gil Segev, “[Out-of-Band Authenticated Group Key Exchange: From Strong Authentication to Immediate Key Delivery](https://eprint.iacr.org/2019/1458),” IACR ePrint 2019/1458, published at ITC 2020. Relevant material: Sections 1.1, 3–5 and Theorem 5.1. The paper explicitly leaves concurrent executions for future work. Accessed 2026-09-27.
4. Meta, [facebook/shortcake](https://github.com/facebook/shortcake/tree/db73640a5531b5266bd1094d72e947ef22295cc1), `main` commit `db73640a5531b5266bd1094d72e947ef22295cc1`, also tag `v0.1.0-pre.4`; especially [`src/commitment.rs`](https://github.com/facebook/shortcake/blob/db73640a5531b5266bd1094d72e947ef22295cc1/src/commitment.rs), [`src/initiator.rs`](https://github.com/facebook/shortcake/blob/db73640a5531b5266bd1094d72e947ef22295cc1/src/initiator.rs), [`src/responder.rs`](https://github.com/facebook/shortcake/blob/db73640a5531b5266bd1094d72e947ef22295cc1/src/responder.rs), and [`src/sas.rs`](https://github.com/facebook/shortcake/blob/db73640a5531b5266bd1094d72e947ef22295cc1/src/sas.rs). Accessed 2026-09-27. Implementation reference only; its README states the implementation has not been audited.
5. Stanisław Jarecki and Nitesh Saxena, “Authenticated Key Agreement with Key Re-use in the Short Authenticated Strings Model,” SCN 2010, LNCS 6280, pp. 253–270, DOI [10.1007/978-3-642-15317-4_17](https://doi.org/10.1007/978-3-642-15317-4_17), [author-hosted proceedings PDF](https://nsaxena.engr.tamu.edu/wp-content/uploads/sites/238/2019/12/js-scn10.pdf). Inspected 2026-09-27: Sections 1.2–1.4, 2–3.3, Figure 2, Theorems 1–2, and Section 4; Theorem 2 proof is referred to the full version. Also inspected Jarecki and Saxena, “Authenticated Key Agreement with Key Re-Use in the Short Authenticated Strings Model,” *Contemporary Mathematics* 582 (2012), pp. 151–173, [AMS chapter record](https://doi.org/10.1090/conm/582/11552), [author-hosted full-version PDF](https://nsaxena.engr.tamu.edu/wp-content/uploads/sites/238/2019/12/js-ams12.pdf). Its Section 5 contains the full Theorem 2 proof and Appendix B discusses limits of the PV compilation; it is the full/later version referenced by the SCN paper’s omitted proof. Inspected 2026-09-27.
