# P2 — Construction selection and formal mapping

## Status and scope

**Outcome: RESEARCH CONTINUES.** PV is a credible direct SAS-AKE direction, while Beskorovajnov–Müller-Quade provide a UC SAS-authentication and one-shot KEM/DEM message-transfer composition. Neither result establishes the project’s full reusable, bilateral pairing contract, so the evidence does not justify selecting either direction or proceeding to P3. Both leave P1 requirements needing demonstrated composition or explicit treatment.

This document evaluates two primary-source candidates against [P1](threat-model.md). Shortcake is implementation evidence only; it is not a separately proven candidate and is not assumed equivalent to PV. Other relevant work found in the bounded literature search is recorded after the candidate comparison, with reasons it is not carried forward as a project candidate.

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

## Candidate comparison

| Security question | Candidate A — PV 2006 | Candidate B — Beskorovajnov/Müller-Quade 2026 | Assessment for this project |
|---|---|---|---|
| Proof model | Game-based AKA/MCA reductions in a random-oracle setting; concurrent instances appear in the model. | UC authentication functionalities plus a UC KEM/DEM/signature SMT composition. | B exposes a cleaner composable authentication interface; its functionality assumptions are still not a full application/session proof. |
| Active-attack bound | MCA bound grows with instance count `Q`, oracle queries, SAS length, and hash-family/commitment terms; AKA adds the AKA0 risk. | One forgery gate per SID with `ε=2^-t`; SMT adds primitive advantages and negligible terms. | B has the clearer per-session contract; both require global accounting across repeated sessions. |
| Session / ceremony binding | No explicit project ceremony SID in the analyzed construction. | SID is committed, hashed into SAS, passed to OOB/auth functionality, and included in SMT signed context. | B is stronger for live session separation; project SID uniqueness and persistent approval binding remain. |
| Concurrency and replay | Concurrent instances modeled, but no project replay/terminal-state store or restart semantics. | UC composition covers concurrent distinct SIDs and one release per SID. | B gives clearer concurrent composition; neither specifies P1’s durable lifecycle policy. |
| Roles, UKS, context | AKA model labels Alice/Bob and outputs peer IDs, but excludes inconsistent final states; generic MCA authenticates messages. | Mutual authentication binds fixed S/R message positions; arbitrary context can be included in the messages. | B is clearer for two-way message binding. Neither defines this project’s identity semantics or field encoding. |
| Human comparison | Assumes an authenticated short-string channel; no error model. | OOB functionality performs exact synchronous comparison, leaks strings to attacker, and cannot suppress delivery. It discusses human error but proves with `εhuman=0`. | Both cryptographic bounds assume correct comparison; B makes the gap explicit. |
| Commitment | Specific PV ROM commitment `H(e,K,m_A)` with independent `e` and committed key; exact proof for that construction. | Generic hiding/binding commitment; hash-then-open in ROM is the paper’s stated main instantiation. | A’s commitment is more precisely fixed by the theorem; B’s profile still must pick an implementation satisfying its assumptions. |
| Key establishment / KEM | Direct DH-based AKA composition; generic theorem needs a separately secure AKA0 and does not prove an arbitrary KEM. | Generic IND-CPA KEM + one-time OT-CPA DEM + EUF-CMA signature is proved for one-way SMT, with fresh keys. | B resolves a generic KEM/DEM message-transfer composition, not a reusable mutual pairing key. |
| Confirmation and output | Produces an AKA key/peer state, but paper sets aside inconsistent final states and assumes later mutual authentication. | Mutual auth returns peer messages; final SMT delivers plaintext to R only and has no reusable session-key output or sender acknowledgment. | Neither directly supplies P1’s complete pairing result/key-confirmation contract. |
| Long-term identity keys | No long-term proof-of-possession composition. | Fresh ephemeral signing/KEM keys; no long-term identity PoP composition. | Both leave consumer identity and key ownership outside the proof. |
| Attempts / persistence | Quantifies total launched instances, but gives no durable retry policy. | One online attempt per SID, with no global attempt budget or persistent store. | Both need P1-derived global limits and restart-safe enforcement. |
| Project-specific work remaining | Bind ceremony, roles, context, approval, and lifecycle around an AKA0 without exceeding its proof. | Decide how one-shot SMT becomes the project’s two-peer pairing/key result without an unproved composition; bind UI approval and lifecycle. | B is a stronger modular transfer foundation, but neither is currently selected for `sas-pairing`. |

## Bounded search and related work

The bounded 2015–2026 search found no other directly comparable two-party SAS-AKE with a better fit to P1. A relevant adjacent primary result is Naor, Rotem, and Segev, “[Out-of-Band Authenticated Group Key Exchange: From Strong Authentication to Immediate Key Delivery](https://eprint.iacr.org/2019/1458),” ePrint 2019/1458, published at ITC 2020. It proves a group OOB-AKE from a passively secure key-exchange protocol, with a bound of approximately \(2(n-1)(1/2+o(1))^\ell\), and addresses abort-driven immediate key delivery. The authors explicitly leave concurrent executions to future work, so it does not meet P1’s coexistence of concurrent ceremonies as published; it is recorded as related work, not a carried-forward candidate. The 2026 paper also surveys MANA-IV and deployed SAS uses. ZRTP and Bluetooth Numeric Comparison are useful deployed/protocol references, not additional modern proof candidates here. This is a bounded search, not an exhaustive literature survey.

## P2 outcome

### RESEARCH CONTINUES

Neither candidate currently justifies selecting a construction for `sas-pairing`. PV is the direct SAS-AKE direction and has a concrete result for its exact MCA plus a generic AKA0 composition. Beskorovajnov–Müller-Quade provide a cleaner UC authentication interface, explicit per-session `sid` binding, and a generic KEM/DEM/signature composition. Their proved final result is one-shot sender-to-receiver message transfer, not a reusable two-party pairing key with a bilateral result contract. Turning it into that contract would require a further construction and proof. The stronger composability result does not erase the ideal OOB or per-session assumptions.

Blocking research questions before selection:

1. Which direction can establish the project’s reusable shared pairing key and bilateral success contract without an unproved composition: PV with a justified AKA0, or a rigorously proved extension around the 2026 authentication/SMT building blocks?
2. How will the exact `sid` semantics bind a unique ceremony, peer, roles, context, and human approval, including after retries and process restarts?
3. What human-error model and usability evidence will complement the ideal exact-comparison OOB functionality? The 2026 proof sets \(\varepsilon_{\mathrm{human}}=0\).
4. What global attempt budget and attack target follow from each per-instance/per-SID bound, and how will persistent counters enforce it across concurrent sessions and restarts?
5. What explicit key-confirmation and terminal-result rule ensures both endpoints accept the same ceremony and key, particularly if using the one-way SMT composition?
6. Which application context and peer identity claims are authenticated, and is long-term proof-of-possession required? Neither candidate proves a long-term identity-key composition.
7. Which exact AKA0 or KEM/DEM/signature profile is justified by the corresponding theorem? The 2026 theorem uses classical PPT primitive notions and fresh per-session keys; it does not establish quantum security for a chosen suite.
8. Can the needed additions be justified within an existing theorem or compositional proof, without creating a new unaudited protocol? If not, reject the candidate or revisit P1 through review.

No KEM, SAS target, rendering, wire format, state machine, or API is selected here. P2 remains current; P3 remains gated. This outcome is not a production-security claim.

## Primary and implementation sources

1. Sylvain Pasini and Serge Vaudenay, “[SAS-Based Authenticated Key Agreement](https://www.iacr.org/archive/pkc2006/39580401/39580401.pdf),” PKC 2006, LNCS 3958, pp. 395–409, DOI [10.1007/11745853_26](https://doi.org/10.1007/11745853_26). Relevant material: Section 2 model and commitment construction; Section 4 and Theorem 1 generic AKA reduction; Figure 4 and Theorem 3, including its proof and repeated-instance discussion. Accessed 2026-09-27.
2. Wasilij Beskorovajnov and Jörn Müller-Quade, “[How to Kickstart \(\mathcal{F}_{\mathrm{SMT}}^{S\rightarrow R}\) with Short Authentication Strings and Out-of-Band Communication](https://doi.org/10.1007/978-3-032-32560-0_15),” ACNS 2026, LNCS 16571, pp. 415–443, first online 2026-07-22; and the complete author version, “[How to kickstart Secure Message Transfer with Short Authentication Strings and Out-Of-Band Communication](https://eprint.iacr.org/2025/1598),” IACR ePrint 2025/1598, revision dated 2025-09-11. EPrint Sections 3.2–3.4, 4.1–4.3, 5, Theorems 2–4, and Appendix A (MAC proof limitation); conference Appendix A, Theorem 5 cross-checks the one-sided UC claim. Accessed 2026-09-27.
3. Moni Naor, Lior Rotem, and Gil Segev, “[Out-of-Band Authenticated Group Key Exchange: From Strong Authentication to Immediate Key Delivery](https://eprint.iacr.org/2019/1458),” IACR ePrint 2019/1458, published at ITC 2020. Relevant material: Sections 1.1, 3–5 and Theorem 5.1. The paper explicitly leaves concurrent executions for future work. Accessed 2026-09-27.
4. Meta, [facebook/shortcake](https://github.com/facebook/shortcake/tree/db73640a5531b5266bd1094d72e947ef22295cc1), `main` commit `db73640a5531b5266bd1094d72e947ef22295cc1`, also tag `v0.1.0-pre.4`; especially [`src/commitment.rs`](https://github.com/facebook/shortcake/blob/db73640a5531b5266bd1094d72e947ef22295cc1/src/commitment.rs), [`src/initiator.rs`](https://github.com/facebook/shortcake/blob/db73640a5531b5266bd1094d72e947ef22295cc1/src/initiator.rs), [`src/responder.rs`](https://github.com/facebook/shortcake/blob/db73640a5531b5266bd1094d72e947ef22295cc1/src/responder.rs), and [`src/sas.rs`](https://github.com/facebook/shortcake/blob/db73640a5531b5266bd1094d72e947ef22295cc1/src/sas.rs). Accessed 2026-09-27. Implementation reference only; its README states the implementation has not been audited.
