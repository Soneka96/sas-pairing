# P2 — Construction selection and formal mapping

## Status and scope

**Outcome: RESEARCH CONTINUES.** Pasini–Vaudenay (PV) is a credible SAS-based key-agreement direction, but the evidence does not justify selecting it for this project or proceeding to P3. The proof covers a particular random-oracle message cross-authentication construction composed with a separately secure authenticated key-agreement protocol. Several P1 requirements still need a demonstrated composition or explicit treatment.

This document evaluates the PV construction against [P1](threat-model.md). It treats the published 3-move construction as the main candidate. Shortcake is inspected only as current implementation evidence; it is not a separately proven candidate and is not assumed equivalent to the paper. No other sufficiently relevant primary-source candidate was established in this review, so no comparison table is padded with unrelated protocols.

## Candidate and formal result

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

## P1 requirement mapping

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

## P2 outcome

### RESEARCH CONTINUES

PV remains a plausible construction direction: the paper gives a concrete active-attack result for its exact MCA construction and a generic composition theorem. The result is not sufficient to select a project construction. Moving directly to a profile would require treating unproved compositions and deployment assumptions as if the source had already established them.

Blocking research questions before selection:

1. Which AKA0 will be composed with MCA? If DH, identify and justify its group/profile and concrete security contribution. If a KEM is proposed, prove that exact KEM exchange is a suitable AKA0 and that the PV reduction applies; do not infer this from Shortcake.
2. How will the authenticated short-string channel in the proof correspond to the project’s human comparison, including human-error, partial-comparison, and attacker-induced-run assumptions?
3. What system-level attempt budget and target attack probability will be justified from the `Q`, `q`, and `ρ` bound, and how will required counters survive retries and restarts?
4. What exact project values identify the ceremony, roles, peers, and application context in the authenticated transcript, and what evidence establishes replay, UKS, and approval-to-ceremony binding?
5. What protocol-level key-confirmation/result rule is needed, given the paper’s explicit assumption that inconsistent final states are handled by further communication?
6. Will the project make any long-term public-key ownership claim? If yes, identify a separately justified proof-of-possession composition; otherwise keep such claims outside the result contract.
7. Can these required compositions be justified without defining a new, unaudited protocol? If not, reject PV for this project or change the requirements/architecture through review; do not silently patch the construction.

No KEM, SAS target, rendering, wire format, state machine, or API is selected here. P2 remains current; P3 remains gated. This outcome is not a production-security claim.

## Primary and implementation sources

1. Sylvain Pasini and Serge Vaudenay, “[SAS-Based Authenticated Key Agreement](https://www.iacr.org/archive/pkc2006/39580401/39580401.pdf),” PKC 2006, LNCS 3958, pp. 395–409, DOI [10.1007/11745853_26](https://doi.org/10.1007/11745853_26). Relevant material: Section 2 model and commitment construction; Section 4 and Theorem 1 generic AKA reduction; Figure 4 and Theorem 3, including its proof and repeated-instance discussion. Accessed 2026-09-27.
2. Meta, [facebook/shortcake](https://github.com/facebook/shortcake/tree/db73640a5531b5266bd1094d72e947ef22295cc1), `main` commit `db73640a5531b5266bd1094d72e947ef22295cc1`, also tag `v0.1.0-pre.4`; especially [`src/commitment.rs`](https://github.com/facebook/shortcake/blob/db73640a5531b5266bd1094d72e947ef22295cc1/src/commitment.rs), [`src/initiator.rs`](https://github.com/facebook/shortcake/blob/db73640a5531b5266bd1094d72e947ef22295cc1/src/initiator.rs), [`src/responder.rs`](https://github.com/facebook/shortcake/blob/db73640a5531b5266bd1094d72e947ef22295cc1/src/responder.rs), and [`src/sas.rs`](https://github.com/facebook/shortcake/blob/db73640a5531b5266bd1094d72e947ef22295cc1/src/sas.rs). Accessed 2026-09-27. Implementation reference only; its README states the implementation has not been audited.
