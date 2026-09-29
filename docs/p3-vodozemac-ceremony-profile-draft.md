# Generic vodozemac SAS Ceremony Profile — Draft 01

> **CANDIDATE PROFILE — NOT SELECTED — REQUIRES INDEPENDENT SECURITY REVIEW**
>
> Profile identifier: `sas-pairing-vodozemac-profile-draft-01`
> Status: a protocol proposal for review, not a production protocol, implementation, or protocol freeze.

## 1. Purpose and status boundary

This document defines one candidate remote pairing ceremony using the currently researched `vodozemac::sas` operations. It is intended to make the proposal reviewable against the requirements in [P1](threat-model.md). It does not establish that the proposal satisfies those requirements.

**Candidate B remains the SELECTED P2 construction for the current remote authenticated-bootstrap profile.** This vodozemac profile is a separate, unselected candidate. It does not replace Candidate B, change the production direction, or authorize implementation. The project remains pre-alpha and not production-ready. No production cryptography is added or approved here.

The ceremony authenticates the exact peer-supplied bootstrap bytes within one run, subject to the independent review and unresolved gates below. Authenticating public-key bytes does not establish possession of the corresponding private key, external identity truth, or application authorization. No reusable pairing secret is a result.

Normative words such as **MUST**, **MUST NOT**, and **SHOULD** describe this draft only. A reviewer may reject or change any candidate choice. Security properties of Matrix or vodozemac do not automatically transfer to this generic mapping.

For decision rationale and review history, see the [P3 vodozemac security decisions log](p3-vodozemac-security-decisions.md). This log is non-normative; this profile remains the normative candidate source.

## 2. Roles and fixed profile values

There are exactly two protocol roles:

- **Initiator (I)** asks the shared security core to create and reserve a request ID, then sends `START`.
- **Responder (R)** accepts that exact start or rejects it. R creates and commits to its ephemeral public key before receiving I's ephemeral public key.

Roles are fixed for the lifetime of a ceremony. A peer cannot change role mid-run. Network address, device type, UI label, and application identity do not determine role.

This draft proposes one suite, with no negotiation or fallback:

| Item | Candidate value | Classification |
|---|---|---|
| Protocol domain | ASCII `org.sas-pairing` | Project adaptation |
| Profile identifier | ASCII `sas-pairing-vodozemac-profile-draft-01` | Project adaptation |
| Wire/profile version | unsigned integer `1` | Project adaptation; draft-local only |
| Ephemeral agreement | vodozemac SAS Curve25519/X25519 | vodozemac API |
| SAS HKDF | vodozemac `EstablishedSas::bytes(info)`; SHA-256 HKDF as implemented by vodozemac | vodozemac API |
| SAS rendering | Matrix decimal SAS: three 13-bit groups | Matrix representation exposed by vodozemac |
| Commitment digest | SHA-256 | Matrix ceremony precedent; generic input is a project adaptation |
| Bootstrap/completion MAC | vodozemac `calculate_mac` / `verify_mac` (HMAC-SHA-256) | vodozemac API; generic contexts are project adaptations |

An unsupported version, profile, or suite is rejected. There is no algorithm negotiation and no downgrade path. A future incompatible candidate requires a different profile identifier or version and independent review.

## 3. Canonical bytes and framing

All protocol and cryptographic inputs are bytes. No JSON, locale-sensitive formatting, platform serializer, whitespace, or implicit text normalization participates in the protocol.

### 3.1 Frame encoding

Every wire message and nested record uses this exact binary frame:

```text
ASCII("SASPAIR")       7 bytes
version                 u16 big-endian; exactly 0x0001
message_type            u8; assigned by the tables below
fields                  fields in the exact listed order for that type
```

Every **wire message** has two common fields immediately after `message_type`: the exact profile-identifier ASCII bytes, then the opaque `request_id` bytes. The type-specific fields follow. `START` carries the request ID; every later message repeats it for routing and correlation. A receiver checks both common fields before dispatch. The bootstrap and context frames are not wire messages and contain only the fields specified for them.

Each field is encoded as `u32be(byte_length) || value`. Fields are present exactly once, in table order. No unknown, duplicate, reordered, omitted, or trailing fields are accepted. A field with a fixed length MUST have that length. A frame ends exactly at the end of its final field. All integers are unsigned big-endian fixed-width values. A parser MUST reject truncation, overflow, noncanonical representation, and trailing bytes before changing ceremony state.

The `u32be` length encoding and its theoretical range of `0..=2^32-1` bytes remain unchanged. The candidate profile imposes a complete wire-frame maximum of 65,536 bytes and a complete bootstrap-frame maximum of 16,384 bytes; declarations or aggregates above those limits MUST be rejected. These are exact candidate-profile resource maxima for deterministic parsing, bounded memory, and bounded cryptographic input. A deployment MAY enforce stricter limits but MUST NOT raise them while claiming conformance. A future reviewed profile/version may choose larger values.

For every declared variable-length field, a parser MUST read the encoded length, validate it against the field-specific maximum, validate checked aggregate frame and nested-frame arithmetic, and only then allocate, retain, or consume the declared payload. It MUST use checked arithmetic for offsets, lengths, aggregate frame size, nested bootstrap size, and Base64url output sizing; overflow fails closed. It MUST NOT allocate from an unvalidated declaration, rely on wrapping arithmetic, or rely on transport size limits alone. A complete frame includes the header, common fields, all field-length prefixes, nested frames, and type-specific fields. Fragmented transport input MUST be bounded before allocation: implementations MAY buffer incrementally up to the cap or use a bounded streaming parser, and MUST stop/reject once a declaration or aggregate exceeds the cap. The profile has no compressed wire representation; implementations MUST NOT transparently decompress protocol frames before applying these bounds. Any future compression requires independently reviewed limits on decompressed data.

Cryptographic inputs use the complete accepted canonical frame, never a decoded-and-reserialized approximation. Every complete generated Base64url cryptographic input MUST be at most 65,536 bytes; where the existing construction prepends a fixed profile/purpose prefix, that prefix is included in the same maximum. This applies to SAS/HKDF contexts where applicable, bootstrap approval MAC inputs, completion authentication inputs, cancellation authentication inputs, and every other profile-defined Base64url cryptographic input. The complete generated input string crossing the vodozemac string-API boundary is capped, without changing any existing construction or Base64url canonicalization.

The fixed text constants in this document are ASCII byte strings. Text fields use ASCII only and must match their stated byte grammar. Other application values are opaque byte strings; they are not decoded as text and receive no Unicode normalization.

### 3.2 Cryptographic context encoding

For HKDF `info` and vodozemac MAC `info`, encode a context as a frame with the same header and version, a distinct context-type byte, and the fields specified below. Convert that complete frame to **unpadded Base64url** as defined by RFC 4648 §5. Use only ASCII characters `A-Z`, `a-z`, `0-9`, `-`, and `_`; omit `=` padding. The consumer MUST reject padding, other characters, impossible lengths, and noncanonical encodings (decode, re-encode, and require byte-for-byte equality).

The API receives the exact ASCII string:

```text
"sas-pairing-vodozemac-profile-draft-01/" || purpose || "/" || base64url(context_frame)
```

`purpose` is one of the fixed ASCII strings defined below. This transformation is injective for each purpose and preserves arbitrary context bytes across the vodozemac API's `&str` boundary. It is a project encoding rule, not a Matrix rule. Before constructing this string, implementations MUST use checked arithmetic to size the entire resulting string, including this prefix, and reject it if it would exceed 65,536 bytes.

## 4. Request ID and bootstrap record

For an honest local Initiator, the shared security core MUST generate each `request_id` as exactly 16 raw bytes using its reviewed OS-backed CSPRNG. Before emitting `START`, the core MUST atomically check and reserve the ID in the applicable active local routing namespace. If the generated ID collides with another active local request in that namespace, the core MUST regenerate before emitting `START`; no colliding local active state may be sent on the wire. The ID is public, non-secret, network-observable routing and diagnostic context. It MAY be logged subject to application privacy/logging policy. Applications SHOULD receive the generated ID for correlation, logs, diagnostics, and integration routing, but SHOULD NOT choose it under this candidate architecture.

Incoming wire syntax remains any canonical, nonempty opaque `request_id` of 1–64 bytes. A parser MUST accept syntactically valid values in that range without an entropy or randomness check; values outside the range MUST be rejected. The Responder MUST treat every incoming value as peer-controlled and MUST NOT assume it is random, unique, unpredictable, or honestly generated. Knowing or possessing the ID MUST NOT authorize a message, state transition, approval, result retrieval, reset, or SAS-accounting behavior.

The ID provides pre-establishment routing/correlation and an active local collision-resistant handle only. It is not a freshness proof, authoritative ceremony identity, peer identity, authentication secret, possession proof, authorization, or globally/historically unique identifier. Protocol authentication does not depend on ID unpredictability: predictable IDs alone MUST NOT break authentication. The OS-backed CSPRNG is the required honest-generation mechanism for accidental-collision margin, simplicity without persistent counters, reduced cross-session linkability, and avoiding predictable pairing-volume/restart patterns. A monotonic counter could theoretically provide routing uniqueness if perfectly coordinated, but would add restart/process coordination and possibly persistent state, reveal activity patterns, and increase linkability without benefit over a fixed 16-byte random handle. This request-ID CSPRNG requirement is separate from the cryptographic-entropy requirements for ephemeral DH/SAS state.

Before establishment, state MUST be bound to the local connection/session context together with `request_id`, or to an equivalent internal state-object binding. A peer-controlled request ID alone MUST NOT be the sole authoritative state identity when multiple connections/sessions are possible. The transport/session layer supplies sufficient local connection/session identity for safe dispatch; it does not make the request ID an authenticated identity. The shared security core owns honest ID generation and active-local collision reservation, protocol state association, and the security semantics that prevent the ID from becoming ceremony authority.

The same ID on distinct connections/sessions denotes separate independent candidate runs and MUST NOT alias state; the Responder may accept both when resource policy allows. Each admitted run consumes its own responder slot; each run that reaches the SAS exposure boundary independently consumes an SAS attempt under the existing global accounting policy. Within one active routing key, the existing duplicate rules apply: an exact byte-for-byte duplicate `START` is ignored idempotently without creating state or repeating output/key generation; a conflicting `START` fails the active state closed. It MUST NOT overwrite or merge state, silently restart, inherit approval, or reset resource/SAS accounting. A message received on one connection/session MUST NOT be accepted into another connection's state merely because its request ID matches. Dispatch/validation also checks expected role/state, exact message sequencing, and the existing commitment, transcript, and MAC bindings.

Because `START` contains the request ID, its exact bytes are included in the established transcript and transitively bound by its digest. Once the transcript through `RESPONDER_KEY` is fixed, the transcript-derived SHA-256 `ceremony_identity` is the authoritative cryptographic ceremony identifier. SAS display, approval, MACs, completion, and result semantics remain bound to `ceremony_identity`; the request ID may remain for routing, diagnostics, and correlation but MUST NOT replace that identity for security decisions. Equal request IDs do not imply equal established ceremonies.

At process restart, every in-flight request/ceremony state and pending approval is discarded, ephemeral secrets are destroyed, and no state resumes. Historical request IDs are not persisted merely to prevent reuse. A later replayed `START` may be accepted as a new attempt subject to the adopted candidate accounting and resource policies; fresh responder state creates a new transcript identity, and a run reaching SAS exposure consumes a new attempt. Reuse MUST NOT inherit an earlier approval or result, bypass resource limits or SAS accounting, or imply the same established ceremony. The accounting epoch and consumed count MUST survive restart; deployment-specific storage and atomic-update guarantees remain **REVIEW REQUIRED**. Ceremony replay persistence and attempt accounting are separate concerns. This draft does not silently assume that volatile state enforces the aggregate bound.

Each participant supplies one canonical bootstrap record before the ceremony starts:

| Field | Required bytes and meaning |
|---|---|
| `application_identity` | 1–1,024 opaque bytes identifying the application principal being described. Exact bytes are authenticated; the protocol does not establish their external truth. |
| `key_algorithm` | 1–64 ASCII bytes matching `[a-z0-9][a-z0-9.-]*`; identifies the interpretation the consumer assigns to the following key. |
| `public_key` | 1–4,096 exact public-key bytes associated by the sender with `key_algorithm`; the consumer validates encoding and expected-peer policy. |
| `shared_context` | 0–8,192 opaque bytes describing the security-relevant application context. It is mandatory and may be empty. Both participants MUST require byte-for-byte equality before SAS approval. |

The bootstrap record is a frame of type `0x20`, version `1`, with exactly those four fields in that order. Each field is length-prefixed by the frame rule. The complete canonical bootstrap frame, including its header and all four length prefixes and values, MUST be at most 16,384 bytes. Both the individual field caps and the complete bootstrap cap apply independently; a set of individually valid fields that produces a larger bootstrap MUST be rejected. There are no extension or optional fields in this draft. Adding a field changes the profile/version. These exact canonical bytes are used for validation and cryptographic binding: oversized values MUST be rejected, never truncated or normalized.

R MUST compare the `shared_context` received in `START` with the exact `shared_context` in R's locally supplied bootstrap before sending `ACCEPT`. I MUST compare the value in R's `ACCEPT` with I's locally supplied value before sending `INITIATOR_KEY`. Either mismatch aborts before SAS display or approval. Thus each side checks the same bytes against its own local application input.

The sender owns the bytes it supplies. The peer authenticates the exact record received, not a consumer's decoded display of it. Algorithm/key syntax validation, expected-identity checks, and authorization remain consumer responsibilities. Even when a record contains a public key, successful pairing means only that these bytes were supplied by the peer in this ceremony; proof of private-key possession requires a later protocol that verifies a signature or other reviewed proof under the exact pinned key.

## 5. Commitment and ephemeral key exchange

R creates one fresh `vodozemac::sas::Sas` object before sending `ACCEPT`, retaining it only for this ceremony. Let `R_pub` be its 32-byte public key and `START` the complete canonical start frame. R computes:

```text
commit_input = ASCII("sas-pairing-vodozemac-profile-draft-01/commit/v1")
               || u32be(len(START)) || START
               || R_pub
commitment = SHA-256(commit_input)                 // exactly 32 bytes
```

`R_pub` is exactly 32 bytes, and `START` is length-framed; together with the fixed domain, this gives the specified input an unambiguous encoding. I verifies against its exact sent canonical `START` bytes and the revealed 32-byte key, then compares all 32 digest bytes. A mismatch aborts the ceremony and produces no SAS, MAC, or result.

The commitment has one narrow purpose: within one accepted attempt, R must fix its ephemeral public key before learning I's ephemeral public key. The order is:

1. R creates fresh ephemeral SAS state and fixes its 32-byte `R_pub`.
2. R computes the commitment over the exact canonical `START` and `R_pub` using the formula above.
3. R sends `ACCEPT`, including its bootstrap and the commitment.
4. I validates and accepts `ACCEPT`, then sends `I_pub`.
5. R reveals the previously committed `R_pub`; I verifies it before DH or SAS derivation.

**Binding assumption.** For one fixed exact canonical `START`, if a malicious R can reveal two distinct accepted `R_pub` values that verify against the same commitment, then the two values produce distinct encoded SHA-256 inputs with the same digest. This profile therefore relies on SHA-256 collision resistance for the single-attempt binding claim. R chooses the commitment, so collision resistance is the relevant conservative assumption; this is not characterized merely as second-preimage resistance. Exact canonical `START` verification and framing are part of the argument. The claim is specific to this encoded construction and is not a formal proof of the ceremony.

**Hiding assumption.** This commitment is deterministic: it hashes public `START` bytes together with the unrevealed `R_pub`. A deterministic hash is not generally a hiding commitment for arbitrary low-entropy secrets. The narrower candidate assumption is that honest R generates its ephemeral key through the reviewed vodozemac cryptographic RNG path and that the resulting unrevealed `R_pub` has enough fresh unpredictable entropy to make feasible enumeration impossible. Before reveal, an observer knows `START` but not that high-entropy `R_pub`; the profile assumes SHA-256 behaves sufficiently like a random oracle, or produces a sufficiently pseudorandom-looking output, on these hidden high-entropy inputs that the commitment does not feasibly reveal useful information about the honestly sampled key. Collision resistance and ordinary preimage resistance alone do not prove this hiding property. This is not information-theoretic hiding, generic commitment hiding, chosen-message hiding for arbitrary candidate keys, or a theorem for concrete SHA-256. No exact min-entropy is claimed: the selected implementation must provide enough fresh unpredictable entropy in responder key generation for the assumption to hold against the intended adversary and query budget. The exact release, complete RNG/key-generation path, and entropy analysis remain review gates.

The commitment alone does not authenticate R, establish identity, prove possession of bootstrap keys, limit retries, prevent abort-and-retry or concurrent multi-session grinding, or replace human SAS comparison. **Matrix boundary:** Matrix `m.sas.v1` is precedent for responder commit-before-reveal, committing to responder ephemeral public-key material together with initiator start content, using SHA-256, and having I reveal its key before R reveals its committed key. It does not establish this binary encoding, domain string, generic bootstrap fields, hiding argument, or complete generic ceremony. This construction is a sas-pairing adaptation requiring independent review.

**Attempt-security boundary.** Within one attempt, after I accepts one commitment, R cannot choose a different `R_pub` after seeing `I_pub` without violating the binding assumption. Across attempts, R may abort after learning `I_pub`, abort after deriving or displaying SAS, begin another attempt, create concurrent sessions, or precompute independent ephemeral keys and commitments for separate attempts. These actions do not break the commitment. The candidate accounting policy charges each such opportunity against the shared epoch maximum, while independent review must still confirm the per-opportunity `2^-39` assumption for the complete construction. Optional cooldown/lockout behavior remains separate and is not selected here.

R's bootstrap is not included in the commitment formula because R sends it inside `ACCEPT`, before R receives `I_pub`; it is therefore fixed before R sees the Initiator key. The bootstrap is later bound into the SAS context, authoritative transcript identity, and approval/bootstrap authentication. Adding it to the commitment would redundantly include data already fixed at that point.

I creates one `Sas` object after validating `ACCEPT`, sends its 32-byte public key, and R reveals the public key for its retained object. Each side passes the peer's exact 32-byte value to `Sas::diffie_hellman`. A non-contributory/invalid peer key is a terminal failure. No public-key text encoding is used on the wire.

The resulting `EstablishedSas` object is retained only while the ceremony needs SAS and MAC operations. Implementations MUST destroy the ephemeral `Sas`, shared-secret state, derived SAS bytes, and temporary MAC inputs on any terminal outcome, cancellation, expiry, or process teardown, using the destruction guarantees actually provided by the selected library/runtime. Whether upstream zeroization guarantees suffice is **REVIEW REQUIRED**. The DH secret MUST NOT be returned, persisted as application trust, or reused as a pairing key.

## 6. Exact message flow

Only the following messages exist in this draft. Every network message has the global frame header and the exact fields shown. Sender role is implicit in message type, and a message received from the wrong role fails closed. Except for `START`, `ACCEPT`, and key-exchange messages, the message body is authenticated by a direction-specific vodozemac MAC as specified in §§8–11.3. For `CANCEL`, the wire message type is `0x09`; the separate non-wire `CancelAuthFrame / 0x34` defined in §11.3 is used only as MAC input/context. There are no transport-level acknowledgements that alter protocol state.

| # | Message/type | Sender → receiver | Fields after header | Permitted state and effect |
|---|---|---|---|---|
| 1 | `START` / `0x01` | I → R | common fields; I bootstrap frame | R accepts only as a policy-eligible new attempt and validates the bootstrap; historical reuse of the request ID alone is not grounds to treat it as the same established ceremony. |
| 2 | `ACCEPT` / `0x02` | R → I | common fields; 32-byte commitment; R bootstrap frame | R has already generated its ephemeral key and fixed the commitment. I validates profile, request ID, bootstrap/context equality, and policy before continuing. |
| 3 | `INITIATOR_KEY` / `0x03` | I → R | common fields; 32-byte `I_pub` | I sends only after accepting `ACCEPT`; R accepts only once for this ceremony. |
| 4 | `RESPONDER_KEY` / `0x04` | R → I | common fields; 32-byte `R_pub` | R reveals only after accepting `INITIATOR_KEY`; I verifies the commitment before DH. |
| 5 | `BOOTSTRAP_MAC` / `0x05` | I ↔ R, one each | common fields; role code (`0x01` I, `0x02` R); raw 32-byte MAC | Sender sends only after local match approval. The authenticated statement covers that approval, the full SAS, and bootstrap. |
| 6 | `INITIATOR_FINISH` / `0x06` | I → R | common fields; transcript digest (32 bytes); raw 32-byte MAC | I sends only after its approval MAC was sent and R's approval MAC was verified. |
| 7 | `RESPONDER_FINISH_ACK` / `0x07` | R → I | common fields; same transcript digest; raw 32-byte MAC | R sends only after its approval MAC was sent, I's approval MAC was verified, and valid `INITIATOR_FINISH`. |
| 8 | `INITIATOR_FINISH_ACK` / `0x08` | I → R | common fields; same transcript digest; raw 32-byte MAC | I sends only after verifying `RESPONDER_FINISH_ACK`. I may return its result after sending this message. |
| 9 | `CANCEL` / `0x09` | either → peer | common fields; sender role code; reason code; raw 32-byte MAC after shared SAS establishment | After successful MAC verification, terminates only the exact named active ceremony. Before shared SAS establishment, cancellation is local behavior; no authenticated remote `CANCEL` exists and an unauthenticated wire `CANCEL` is not peer-cancellation evidence. |

For `CANCEL`, reason codes are `0x01` user rejection, `0x02` user cancellation, `0x03` timeout, and `0x04` local policy failure. The reason is diagnostic and does not change failure semantics. If no shared secret exists, cancellation is local transport closure; it is never accepted as evidence of peer authentication.

I and R may send their `BOOTSTRAP_MAC` messages concurrently after their own user approves. Either may arrive first. No other reordering is legal. For the same active run and sender, a byte-for-byte exact copy of a previously accepted message is ignored without state change, repeated output, repeated approval, or regenerated cryptographic state. If a message type already accepted for that run and sender arrives with different bytes, the run enters terminal `Failed`. Any message that is neither such an exact duplicate nor the legal next message for the current state also enters terminal `Failed`. Messages are never queued for a future state. After `Succeeded` or `Failed`, later messages are ignored or rejected at the protocol boundary without changing terminal state or result; an emitted result is immutable.

## 7. SAS derivation and human comparison

After commitment verification and successful DH, each participant constructs one identical SAS context frame of type `0x30` with these fields, in this order:

1. protocol domain ASCII `org.sas-pairing`;
2. profile identifier ASCII `sas-pairing-vodozemac-profile-draft-01`;
3. version `u16be(1)`;
4. request ID bytes;
5. complete canonical `START` frame;
6. complete canonical `ACCEPT` frame;
7. `I_pub` (32 bytes);
8. `R_pub` (32 bytes).

Both call `EstablishedSas::bytes` with purpose `sas` and the exact context-string construction in §3.2. This binds domain, profile, version, roles (by fixed key ordering), request ID, both bootstraps (inside `START` and `ACCEPT`), commitment, and both ephemeral keys. The SAS is derived only after all inputs are fixed. This is a project-specific HKDF context; Matrix's identity/device-specific context is not copied. Independent review must confirm that this use binds the intended peer/context and does not claim properties beyond the API and construction.

The retained candidate representation is exactly `SasBytes::decimals()`: three unsigned values formed by the vodozemac/Matrix decimal mapping, each in `1000..=9191`, rendered as four ASCII decimal digits separated by one ASCII space, for example `1234 5678 9012`. Leading digits are not omitted. The underlying representation uses 3 × 13 bits, or 39 bits of exact-match space (`2^39` possible full values). This representation remains defensible only conditional on a reviewed bounded aggregate-attempt model, its cryptographic assumptions, and honest complete comparison; it is not a claim that the whole system is simply “39-bit secure.”

Under the candidate assumptions of fresh unpredictable ephemeral state, pseudorandom SAS derivation, correct commitment ordering, no unaccounted adaptive grinding, and honest full-value human comparison, one charged attacker SAS opportunity contributes a random exact-match term of at most `p = 2^-39`, subject to independent review. The candidate adopts aggregate target `ε = 10^-8` per local SAS security-accounting epoch and maximum `N = 5,497` charged opportunities per epoch. For `N` independent opportunities, `P(N) = 1 - (1 - p)^N`; at `N = 5,497`, `P ≈ 9.9989848 × 10^-9`. Conservatively, `P ≤ N × 2^-39 ≈ 9.9989848 × 10^-9 < 10^-8`. This bounds only the SAS random-match component under the stated assumptions; it is not a complete protocol failure-probability bound. Human partial/mistaken comparison, compromised endpoint/display, RNG failure, implementation bugs, other protocol vulnerabilities, social engineering, and external identity truth are excluded.

**The representation and aggregate policy are candidate requirements, not production selections or proof of security.** Independent review must determine whether the complete construction justifies the per-opportunity `≤ 2^-39` term and the resulting epoch bound. No user types or transcribes this SAS. Consumers SHOULD present all three groups clearly; the human-comparison assumption is that the entire value is compared correctly and approval occurs only on an exact match. The protocol does not claim protection against partial comparison, accidental approval, habituation, coercion, compromised displays, or compromised endpoints. No quantitative human-error multiplier is selected.

Each consumer displays the complete value only after the established transcript and its ceremony identity are fixed. Each participant has a local action associated with that exact identity: `MATCH/APPROVE`, `MISMATCH/REJECT`, or `CANCEL`. Approval callbacks and state MUST be keyed to the transcript-derived identity, not solely to the request ID. Approval from another transcript, even one with the same request ID, cannot satisfy this ceremony. A mismatch/reject or cancellation is terminal. Partial comparison, automatic matching, prior approval, or a display from another ceremony cannot authorize success. Both participants must approve their own displayed SAS and satisfy the authenticated completion flow. The bound assumes the human completes the comparison as intended; it does not account for arbitrary human error, coercion, display compromise, or a perfect authenticated human channel.

## 8. Bootstrap MAC and expected-peer validation

After local SAS approval, each side authenticates one exact approval statement. For sender role `r` (`I=0x01`, `R=0x02`), define an approval frame of type `0x33` with fields in this order: protocol domain; profile identifier; version; sender role code; the 32-byte authoritative ceremony identity (the transcript digest); the exact six raw `SasBytes`; the sender's complete canonical bootstrap frame. This states that the sender approves the full displayed SAS for this exact established transcript and authenticates that sender's exact bootstrap.

Define a context frame of type `0x31` with fields in this order: protocol domain; profile identifier; version; purpose ASCII `match-approve-bootstrap`; sender role code; receiver role code; authoritative ceremony identity (the transcript digest). The request ID and exact key/bootstrap messages are already bound by that digest. The MAC info string is the §3.2 context string with purpose `mac` and this frame.

Because vodozemac accepts UTF-8 strings, transform the complete approval frame into exactly `input = unpadded_Base64url(approval_frame)` using the §3.1 canonicality rules. The sender calls `EstablishedSas::calculate_mac(input, info)` and sends the 32 raw bytes from `Mac::as_bytes()`. The receiver reconstructs the expected approval frame using the peer's role, this ceremony's six SAS bytes, and the exact peer bootstrap, then constructs `Mac::from_slice(received_32_bytes)` and calls `verify_mac(input, info, &tag)`. The wire tag MUST be exactly 32 bytes. No Matrix key-ID-list MAC semantics or legacy invalid-Base64 compatibility method is used.

This MAC authenticates the sender's explicit match-approval statement, the complete SAS value, the exact bootstrap bytes, and direction for this established ceremony, under the SAS shared secret, subject to review of the complete construction. A verification error, wrong role, wrong ceremony identity, wrong context, or unexpected peer bootstrap is terminal and returns no result. The protocol cannot establish that a human actually compared correctly; it assumes each honest endpoint emits this statement only after its own explicit approval.

Before or during the ceremony, the consumer may provide expected peer properties. The consumer MUST compare them to the decoded/authenticated bootstrap fields using exact byte equality and its own key-format rules; a mismatch rejects pairing. The responsibilities remain distinct:

1. **Protocol authentication:** verifies the exact peer-supplied bytes and context for this ceremony.
2. **External truth:** determines whether the claimed application identity or key is known/valid; the ceremony cannot prove this.
3. **Authorization:** decides what the local application permits; pairing does not grant it.
4. **Proof of possession:** must be established later by a protocol that verifies a fresh proof under the exact authenticated/pinned key bytes.

If the consumer has no expected-peer policy, the result remains authenticated peer-supplied data only. “Whatever identity the peer supplied” MUST NOT be silently promoted to externally trusted identity.

## 9. Completion and result semantics

The authoritative `ceremony_identity` is the existing transcript digest, exactly SHA-256 of `ASCII("sas-pairing-vodozemac-profile-draft-01/transcript/v1")` followed by the complete canonical `START`, `ACCEPT`, `INITIATOR_KEY`, and `RESPONDER_KEY` frames, each preceded by `u32be(length)`. It covers the profile/domain-separated exact messages, including the request ID in `START`, the responder commitment and bootstrap in `ACCEPT`, and both exact ephemeral-key messages. It becomes available once this transcript through `RESPONDER_KEY` is fixed. I computes it after receiving and verifying `RESPONDER_KEY`; R computes it when the canonical `RESPONDER_KEY` bytes are fixed for transmission. Both hash the same canonical frame bytes. No digest is included in the transcript it hashes.

This identity is authoritative only after establishment; the request ID remains the pre-establishment routing handle. Since `ACCEPT` commits to fresh responder key material and the revealed fresh key is in the transcript, replaying an old request that causes R to generate fresh ephemeral material yields a different established ceremony identity, subject to the digest's collision resistance. This is a candidate security property requiring independent review, not a formally proven theorem.

Completion MAC contexts use type `0x32` and include protocol domain, profile identifier, version, purpose, fixed sender/receiver role codes, and the authoritative ceremony identity. This digest is carried in each completion wire message and MUST match the receiver's locally computed digest.

Each completion MAC uses a separate, non-wire `CompletionAuthFrame`. The frame is encoded canonically under §3.1 and has these fields in exactly this order: protocol domain ASCII `org.sas-pairing`; profile-identifier ASCII bytes; version `u16be(1)`; sender role code (`0x01` I or `0x02` R); receiver role code (the other role); the 32-byte authoritative ceremony identity; and completion-purpose ASCII bytes. Its frame type and purpose are fixed by this mapping:

| Wire message | Wire type | Non-wire auth-frame type | Purpose | Direction |
|---|---:|---:|---|---|
| `INITIATOR_FINISH` | `0x06` | `0x35` | `initiator-finish` | I → R |
| `RESPONDER_FINISH_ACK` | `0x07` | `0x36` | `responder-finish-ack` | R → I |
| `INITIATOR_FINISH_ACK` | `0x08` | `0x37` | `initiator-finish-ack` | I → R |

The auth-frame type is a non-wire discriminator for this structure; the purpose and role fields also distinguish the authenticated operation and direction. The wire message and its `CompletionAuthFrame` are different structures: the wire message contains its actual wire type, common fields, transcript digest, and raw 32-byte MAC; the auth frame contains the fields above and never contains a MAC. The auth frame is never transmitted as a separate protocol message. The MAC input is exactly the unpadded Base64url encoding of the complete canonical non-wire `CompletionAuthFrame`, with no wire fields omitted. The sender calculates/verifies the MAC with the existing vodozemac MAC API and §3.2 context-string construction, using type `0x32` context, the matching purpose, and the same domain, profile, version, roles, and authoritative ceremony identity. The receiver reconstructs the expected authentication frame and context from the received wire message plus local ceremony state before verification. It verifies the raw 32-byte MAC before any state transition. A completion message for another transcript or ceremony identity fails closed.

The local result conditions and authenticated knowledge at each result point are:

- **Initiator (I):** I has locally approved the displayed SAS, sent its own `BOOTSTRAP_MAC`, verified R's `BOOTSTRAP_MAC`, verified `RESPONDER_FINISH_ACK`, and sent `INITIATOR_FINISH_ACK`. The verified responder approval MAC authenticates R's approval statement and bootstrap. The verified finish acknowledgement proves R received and verified I's `INITIATOR_FINISH` after R had sent its approval MAC and verified I's approval MAC. I does not know that R received `INITIATOR_FINISH_ACK`, returned a local result, or durably stored trust.
- **Responder (R):** R has locally approved the displayed SAS, sent its own `BOOTSTRAP_MAC`, verified I's `BOOTSTRAP_MAC`, verified `INITIATOR_FINISH`, sent `RESPONDER_FINISH_ACK`, and verified `INITIATOR_FINISH_ACK`. The verified initiator finish authenticates I's progress after I received R's approval MAC; the final verified acknowledgement proves I received R's finish acknowledgement and sent the final authenticated message. R does not know that I durably stored trust or that either application's persistence completed atomically.
- A disconnect before a participant's local condition is met produces failure locally and no result. A sent message is not evidence of delivery or durable application storage.

The result is **local verified completion for one exact ceremony**, not atomic bilateral success across both processes. I may meet its local result condition after sending `INITIATOR_FINISH_ACK` even if that message is lost, leaving R without a result. If both participants return results, their authoritative ceremony identities, roles, bootstrap data, and bound context are compatible by the checks above. Message loss may cause asymmetric observation, but cannot permit conflicting successful results. The exchange does not guarantee simultaneous local success, common knowledge, or atomic durable trust persistence. Consumers MUST treat each result as ceremony-scoped and MUST NOT claim both applications durably stored trust.

The abstract protocol result is:

```text
PairingResult {
    request_id: exact original routing/request handle bytes,
    ceremony_identity: exact 32-byte transcript digest,
    peer_role: Initiator | Responder,
    authenticated_peer_bootstrap: exact canonical bootstrap frame bytes,
    authenticated_shared_context: exact shared_context bytes,
    profile_identifier: "sas-pairing-vodozemac-profile-draft-01",
    profile_version: 1,
}
```

Consumers use `ceremony_identity` to identify the successfully authenticated ceremony. `request_id`, if retained for routing or diagnostics, is only the original request handle; consumers MUST NOT infer exact-ceremony identity from it alone. The result contains no ephemeral DH secret, reusable pairing secret, local authorization decision, external identity verdict, or proof-of-possession claim. Its exact authenticated bootstrap and context bytes are bounded by the field and complete-bootstrap maxima above, which also bound result-size growth; the result contract is unchanged and does not replace exact bytes with hashes. This is a protocol-domain shape, not a language API.

## 10. Normative state machine

The states below form one state machine and one state object per run. Before transcript establishment, local state is correlated by `request_id` plus local connection/session state as needed. Once the transcript through `RESPONDER_KEY` is fixed, that state object records the authoritative `ceremony_identity`; SAS display, approval flags/callbacks, MACs, and results are then associated with that identity. State transitions are atomic with message validation. While a run is active, any invalid message, failed validation, explicit rejection, timeout, or cancellation transitions it to terminal `Failed`; after either terminal state, later messages cannot change state or result. The cause may be retained for diagnostics but must not change acceptance behavior.

| State | Legal incoming message / local action | Transition and forbidden behavior |
|---|---|---|
| `Idle` | I local `Start` with a new in-flight request handle and bootstrap; R valid `START` | I → `AwaitAccept`; R validates the complete frame and bootstrap and atomically reserves one responder slot before creating active ceremony state. If admitted, R → `AwaitInitiatorKey`, generates fresh R key material, and sends `ACCEPT`. A valid `START` is a resource event; it is not by itself a SAS attempt. Any message other than a legal next message fails. Every wire message repeats the exact profile ID and request ID. |
| `AwaitAccept` (I) | Legal next message: one valid `ACCEPT` for exact request ID/profile | Validate bootstrap/context and commitment format; atomically and durably reserve one SAS attempt from the common local budget; only after successful persistence create/send `INITIATOR_KEY`; → `AwaitResponderKey`. Reservation failure fails closed before key release. |
| `AwaitInitiatorKey` (R) | Legal next message: one valid 32-byte `INITIATOR_KEY` | Validate `I_pub`; atomically and durably reserve one SAS attempt from the common local budget; only after successful persistence construct and send `RESPONDER_KEY`, record the transcript digest as `ceremony_identity`, and perform DH; → `AwaitLocalApproval`. Reservation failure fails closed before key release. No SAS before the transcript is fixed. |
| `AwaitResponderKey` (I) | Legal next message: one 32-byte `RESPONDER_KEY` | Verify commitment, fix the transcript and record its digest as `ceremony_identity`, then perform DH; → `AwaitLocalApproval`. No SAS before commitment succeeds and the identity is fixed. |
| `AwaitLocalApproval` | Local display; `MATCH/APPROVE`, `MISMATCH/REJECT`, `CANCEL`; peer approval MAC may arrive before or after local action | Match records one ceremony-scoped approval and sends own `BOOTSTRAP_MAC` containing the authenticated approval statement; rejection/cancel → `Failed`; once the local match and peer approval MAC are verified → I sends `INITIATOR_FINISH` and enters `AwaitResponderFinish`, R enters `AwaitInitiatorFinish`. No completion before all conditions. |
| `AwaitResponderFinish` (I) | Valid `RESPONDER_FINISH_ACK` after I sent `INITIATOR_FINISH` | After valid ACK, send `INITIATOR_FINISH_ACK`, return result, → `Succeeded`. |
| `AwaitInitiatorFinish` (R) | Valid `INITIATOR_FINISH` | R has already sent its approval MAC and verified I's; verify finish and send `RESPONDER_FINISH_ACK`; → `AwaitInitiatorFinishAck`. |
| `AwaitInitiatorFinishAck` (R) | Valid `INITIATOR_FINISH_ACK` matching transcript | Verify; return result; → `Succeeded`. |
| `Succeeded` | No protocol message or local action | Terminal. Later messages are ignored or rejected at the protocol boundary; state and emitted result never change. |
| `Failed` | No protocol message or approval | Terminal. Later messages are ignored or rejected at the protocol boundary; state cannot change, and state, approval, and secrets cannot be reused. A retry creates a new ceremony. |

For every active run, implementations retain sufficient canonical accepted-message state to compare a later duplicate; they MUST NOT create additional retained copies of exact duplicate bytes or repeat cryptographic state/work for them. An exact duplicate is ignored with no state change and no repeated output or cryptographic work. A changed duplicate or any message that is not the legal next message is terminal failure. After a terminal state, later messages cannot cause a transition or second result. Where a table transition says “both MACs,” each party has verified the peer's single bootstrap MAC and locally computed its own; receipt of both wire MACs is not required if own MAC was sent. The transcript, request handle, established identity, approval flags, role, and peer identity remain attached to the one state object. Approval is associated with the authoritative identity and cannot satisfy another transcript.

## 11. Retry, replay, time, cancellation, and failure policy

### 11.1 Attempts and rate policy

One SAS attempt is one protocol opportunity where the peer gains enough information to derive a candidate SAS against the honest endpoint. A `START`, connection, UI prompt, displayed value, or approval is not itself the attempt definition.

- **Honest Initiator:** the attempt MUST be atomically and durably reserved before sending `INITIATOR_KEY / I_pub`. Once a Responder attacker has its own already-fixed private key and receives `I_pub`, it can derive its candidate SAS opportunity; reserving after sending `I_pub` is too late.
- **Honest Responder:** after validating `I_pub`, the attempt MUST be atomically and durably reserved before revealing `RESPONDER_KEY / R_pub`. An Initiator attacker can derive its candidate SAS opportunity once it receives R's public key.
- If a later profile change exposes sufficient information earlier, accounting MUST occur before that earlier exposure.

Every opportunity shares one **SAS security-accounting epoch**: a durable local accounting record shared by all applicable remote SAS ceremonies enforced by that local security core/store. It covers both roles, all peers, request IDs, bootstrap claims, application contexts in that accounting scope, retries, concurrent runs, replay-triggered fresh runs, and successful and unsuccessful attempts. It MUST NOT depend on a peer-supplied identity being trustworthy and is independent of consumer trust records, application authorization, remote peer identity, and transcript identity lifecycle. Before successful pairing, claimed peer identity, bootstrap key, request ID, network address, connection, shared-context value, and other unauthenticated labels are attacker-rotatable; a per-peer counter alone therefore cannot enforce the aggregate bound. Optional narrower peer, application-context, transport, identity, or deployment limits MAY supplement the global budget but MUST NOT replace it. Concurrent reservations MUST update this same budget atomically. Each independent opportunity counts, whether serial or parallel, and continuing only a favorable session does not avoid charging the others. Applications may limit displayed comparisons for UX, but the protocol remains correct with multiple ceremonies active.

Once the SAS exposure boundary is crossed, that charged attempt is never refunded for mismatch/rejection, timeout, disconnect, cancellation, malformed later input, MAC or completion failure, a commitment failure discovered after exposure, attacker or consumer abort, unsuccessful pairing, replay-triggered runs, or successful pairing. A reservation may conservatively be spent even if key release ultimately did not occur, and a charged reservation is not refunded. An attacker may derive its candidate, dislike it, abort, and retry; commitment binding fixes the responder key within one attempt but does not prevent serial grinding, parallel grinding, or post-exposure aborts. Each such opportunity remains charged.

Three policies remain separate:

- **Resource/DoS policy** protects CPU, memory, parsing, connection state, and responder work from unauthenticated floods. It may begin when `START` is accepted; that event is not automatically one SAS guess.
- **SAS-security attempt policy** bounds statistically meaningful SAS opportunities at the role-specific key-exposure boundary above. This counter is the one relevant to the aggregate SAS probability claim.
- **Human UX/fatigue policy** addresses repeated prompts, habituation, confusion, and accidental approval. Warnings, cooldowns, and limits on simultaneously displayed comparisons may help, but MUST NOT substitute for the SAS counter unless formally justified.

### 11.1.1 Resource maxima and responder admission

The byte, frame, field, and generated Base64url limits in §3–§4 are exact v1 candidate-profile maxima. They are required for deterministic parsing, bounded memory, and bounded cryptographic input. They apply to Initiators and Responders. A conforming implementation MUST enforce them in the protocol/core; an application or transport MAY impose stricter limits but MUST NOT raise them. An oversized field declaration, complete frame, nested bootstrap, generated Base64url input, truncation, integer overflow, unknown/repeated/missing field, noncanonical representation, or trailing byte is rejected before ceremony-state advancement. Oversized or malformed input received for an active ceremony is terminal invalid input under the existing state machine. An oversized initial `START` MUST be rejected before allocating active ceremony state. Resource rejection before the SAS exposure boundary MUST NOT charge a SAS attempt, reset the SAS epoch, refund a charged attempt, or bypass the 5,497 limit.

The Responder MUST allow at most **8 simultaneously active responder ceremonies globally per applicable local security core**. This is an engineering/resource-safety candidate maximum to bound attacker-controlled simultaneous responder state. It is not a cryptographic-security bit parameter, does not enter the SAS probability calculation, and is not claimed to be universally optimal. The count is global across connections, request IDs, claimed identities, bootstrap keys, network addresses, application contexts, and all other unauthenticated peer labels; a per-peer cap is insufficient. If independent processes or core instances expose the same endpoint/profile, they MUST share or coordinate the bound so that each does not independently admit eight ceremonies while claiming one shared resource bound. This is an integration/resource requirement; this profile does not prescribe IPC or storage.

Admission MUST reserve a slot atomically before allocating active ceremony state or generating Responder ephemeral key material. With eight slots active, a ninth incoming `START` MUST be rejected before active-state creation, key generation, `ACCEPT`, or SAS-attempt reservation. It MUST NOT evict an active ceremony. No new wire message is introduced: implementations SHOULD use generic rejection, connection/flow closure, or local policy failure without disclosing an unauthenticated reason. Existing ceremonies retain their slots until legitimate terminal cleanup; cleanup makes the slot reusable. A finite local ceremony timeout is required to release abandoned state, but its duration remains **REVIEW REQUIRED**. Timeout alone does not replace the eight-slot cap.

Initiators use all the same parser, field, frame, and generated-cryptographic-input caps. The hard eight-active-ceremony rule applies specifically to remotely created Responder work. Implementations MAY impose separate, stricter limits on locally initiated ceremonies; this profile adds no normative initiator count.

The active-slot maximum bounds simultaneous work, not serial request rate. A serial attacker may repeatedly send valid near-cap `START` messages. Global admission/rate control, connection admission, and CPU/hash-work throttling remain explicit resource-specific review requirements; no numeric rates are selected here. The `5,497` SAS accounting counter MUST NOT be used as a generic network rate limiter.

Reservation uses conceptual behavior `reserve_attempt(); persist successfully; release I_pub or R_pub`. Releasing key material and incrementing later is unacceptable because a crash can create an uncounted opportunity. Recovery may conservatively spend an attempt not ultimately exposed, but MUST NOT forget one that may have been exposed. If storage is unavailable, a write fails, the transaction result is ambiguous, or corrupt state prevents safely establishing the remaining budget, the core MUST fail closed before key release.

The candidate adopts `ε = 10^-8` and `N = 5,497` per local epoch. This integer is not rounded upward. For `p = 2^-39`, `P(N) = 1 - (1 - p)^N`; at `N = 5,497`, `P ≈ 9.9989848 × 10^-9`. The union bound gives `P ≤ N × 2^-39 ≈ 9.9989848 × 10^-9 < 10^-8`. Therefore the candidate limit is below its target even under union-bound aggregation, PROVIDED independent review accepts a per-charged-opportunity term of at most `2^-39`. This claim covers only the SAS random-match component, not complete protocol failure probability.

The initiator MUST atomically and durably reserve before sending `INITIATOR_KEY / I_pub`. The responder MUST reserve after validating `I_pub` and before revealing `RESPONDER_KEY / R_pub`. If a future profile exposes sufficient SAS-derivation material earlier, it MUST reserve earlier. The charged attempt is never refunded after exposure, including success, mismatch/rejection, cancellation, timeout, disconnect, later malformed input, MAC or completion failure, attacker/local abort, replay-triggered run, or post-exposure failure. Successful pairing MUST NOT reset or refund the counter.

At minimum, persisted accounting state represents its format/version, current epoch identifier, and consumed count (or an equivalent remaining count); the counter supports atomic concurrent reservation. A monotonically increasing epoch number and concrete serialization/storage API are not selected. All concurrent opportunities reserve against the same epoch: if 5,496 opportunities are consumed, at most one of two concurrent reservations may obtain the last slot.

When 5,497 opportunities are consumed, the remote SAS profile is exhausted for that epoch. Before opportunity 5,498, the core MUST fail closed without releasing key material that would create another SAS opportunity. It MUST NOT exceed or wrap the budget, automatically reset or replenish it by timer/window, downgrade, or fall back to a weaker profile. Exhaustion is local; no remaining-budget negotiation is required on the wire. A stricter local limit is permitted.

Recovery requires an explicit locally authorized security reset. Reset atomically persists a new epoch and zero consumed count; if that transaction is ambiguous or fails, the core MUST fail closed. The transition MUST leave exactly one current epoch: a crash cannot create two active epochs, restore/replenish the old epoch, or lose exhausted state without a completed reset. A reset MUST NOT be caused solely by untrusted network input, happen automatically after success, restart/reboot, cooldown/time, or exhaustion, or silently erase the exhausted state. An attacker controlling only the untrusted pairing network cannot authorize or trigger reset. Deployment-specific trusted-user, OS-authenticated, or administrator action may satisfy this property; this draft selects no exact UI mechanism or OS API. A reset creates a new epoch but does not erase earlier statistical exposure: for epoch risks `ε_1 … ε_k`, cumulative risk is `1 - Π(1 - ε_i)` under independent epoch events, or at most `Σ ε_i` by union bound. Unlimited authorized resets therefore provide no finite lifetime `10^-8` claim.

The epoch and consumed count MUST survive process restart/crash, device reboot, and application update; these events MUST NOT replenish the budget. Unless an external durable security anchor preserves accounting, uninstall/reinstall begins a new epoch, and the generic library MUST NOT claim one continuous `10^-8` aggregate bound across that loss of state. Generic rollback detection is not claimed: restoring an old valid store may restore unused budget. Rollback/restore lies outside the continuous per-epoch claim unless the deployment provides rollback-resistant or monotonic storage. Deployments claiming security across rollback must provide those storage guarantees.

Both endpoints enforce the same candidate maximum of `5,497` per local epoch independently; no wire exchange of remaining count, epoch ID, exhaustion, or reset state is required. The remote budget does not define a same-device profile. A separately selected OS-authenticated same-device profile has its own security boundary; same-device pairing MUST NOT be used as fallback for a remote peer after exhaustion, and same-device activity does not reset the remote epoch. Test/development or intentionally insecure environments MUST use isolated accounting state and MUST NOT consume or reset production accounting; they MUST NOT claim this aggregate bound if required accounting is disabled.

Attempt semantics and enforcement belong to the shared security protocol/core. An application or platform MAY provide required durable storage through a persistence capability, but the caller cannot omit it and retain the same security claim. Reservation timing, atomicity, counter semantics, and fail-closed behavior are core/profile requirements. The numeric target and policy are now candidate decisions; the per-opportunity assumption, complete construction, and deployment persistence guarantees remain subject to independent review, and this profile remains unselected.

### 11.2 Freshness, replay, and concurrency

- For an active ceremony, a byte-for-byte exact copy of a previously accepted inbound message for the same sender and message type is ignored without state change, repeated output, approval, or cryptographic state generation. A second message of an already accepted type with different bytes causes terminal failure.
- Any message that is not an exact duplicate under that rule and is not the legal next message for the current state causes terminal failure. This includes reordered messages and messages for another ceremony or role.
- A message is routed using the request ID and local connection/session state; it cannot be attached to another active state object. A message for a different established identity cannot satisfy this run.
- The same request ID on different connections/sessions is separate state and consumes a separate responder slot; each run that reaches SAS exposure consumes its own attempt. A message on one connection MUST NOT dispatch into another connection's state based only on an equal ID.
- Within one active routing key, an exact duplicate `START` is idempotently ignored with no new state, key generation, or repeated `ACCEPT`; a changed/conflicting `START` is terminal failure under the changed-duplicate/illegal-state rule. It cannot replace or merge the active state or inherit approval/accounting.
- Messages other than `START` cannot create state for an unknown request ID and fail closed. A valid `START` may create a new attempt, including after restart, subject to the adopted attempt/resource policy.
- After `Succeeded` or `Failed`, all later messages are ignored or rejected at the protocol boundary and cannot change state or emit another result. A late message does not transition `Succeeded` to `Failed`.
- On process restart, all in-flight state and approvals are lost and the run is aborted. A replayed old `START` is a new resource event and may be accepted as a new attempt: R allocates fresh state, generates fresh ephemeral key material, and sends a new `ACCEPT`. That run has a new established transcript and ceremony identity; it is not the old authenticated ceremony. If it reaches the SAS-attempt boundary, it consumes a new attempt, and reuse of an old `request_id` does not exempt it. Old SAS-derived approval/completion MACs cannot authenticate under the new ephemeral state, volatile local approval is discarded, and an old terminal result is not authority for the new run. Replay is rendered ineffective as replay of the old authenticated ceremony; the old packet is not necessarily rejected.
- Historical request IDs need not be kept in a durable replay database solely for ceremony authentication. Durable attempt accounting is separate and mandatory for any claim that requires it; it survives ordinary restart/lifecycle events, while rollback resistance is required only if the claim spans those rollback cases.
- No approval or result survives as authority for a later ceremony. A replayed `START` alone does not inherit approval; if further messages establish a new SAS, UI/application state and callbacks bind any approval only to that new ceremony identity, even if the request ID matches an earlier run.

### 11.3 Timeouts, cancellation, and cleanup

Each implementation enforces a monotonic local ceremony deadline, but its exact duration is **REVIEW REQUIRED**. Local timeout immediately makes the ceremony terminal, discards its ephemeral state, and best-effort sends authenticated `CANCEL` if a shared SAS state exists. The peer's receipt is not required to make local cancellation terminal. A peer timeout, disconnect, or cancellation also terminates locally. No resumption is supported.

Cancellation before shared SAS establishment is local behavior: the participant closes its local flow, and no authenticated remote `CANCEL` exists. A received wire `CANCEL` before shared SAS establishment is invalid input and MUST NOT be interpreted as authenticated peer cancellation; while a ceremony is active it causes terminal protocol failure under §11.4.

After shared SAS establishment, the wire message remains `CANCEL / 0x09` as defined in §6. The sender includes its role, a reason code, and the raw 32-byte MAC. To calculate that MAC, construct the separate **non-wire** `CancelAuthFrame / 0x34` using the canonical frame encoding in §3.1, with these fields in exactly this order: protocol domain ASCII `org.sas-pairing`; profile-identifier ASCII bytes; version `u16be(1)`; sender role code (`0x01` I or `0x02` R); receiver role code (the other role); authoritative ceremony identity (the transcript digest); reason code. The `0x34` value is only this authentication frame's type byte; it is never a network message type. The receiver role is included to bind direction.

The MAC input is exactly the unpadded Base64url encoding of the complete canonical `CancelAuthFrame` bytes. The sender calculates the MAC with the §3.2 context-string construction, purpose `cancel`, and a context containing the same protocol domain, profile identifier, version, sender role, receiver role, authoritative ceremony identity, and reason code. The wire MAC field is excluded from both the authentication frame and its input, so there is no circular definition. The receiver reconstructs the expected frame and context from the received wire `CANCEL` and local ceremony state, then verifies the raw 32-byte tag before terminating only that exact active ceremony. A missing, malformed, or invalid tag is terminal failure and is not authenticated peer cancellation. A valid cancel for an unknown or stale ceremony identity cannot affect another flow. Secret cleanup occurs on every terminal path, including malformed input and panic/exception teardown to the extent guaranteed by implementation/runtime; cleanup guarantees require review against vodozemac's actual version.

### 11.4 Fail-closed cases

Malformed/truncated/noncanonical frame; unsupported profile/version; repeated or missing field; invalid bootstrap; context mismatch; invalid or non-contributory key; commitment mismatch; SAS mismatch/rejection; MAC mismatch; expected-peer mismatch; or, while active, a non-`START` message for an unknown/stale request ID, a changed duplicate, wrong-state/reordered message, or wrong-role message causes terminal failure and no result. A valid `START` for a reused or historically seen request ID may instead begin a new policy-eligible attempt. An exact duplicate of a previously accepted inbound message for the same active run and sender is ignored without state change or repeated output. Before shared SAS establishment, a wire `CANCEL` is invalid and is not authenticated peer cancellation. After `Succeeded` or `Failed`, later messages are ignored or rejected at the protocol boundary and cannot change state or emit another result. There is no silent fallback to Candidate B, another vodozemac API mode, Matrix identity semantics, same-device pairing, or a weaker suite. Candidate B remains the project's selected remote construction independently of this candidate's outcome.

## 12. Vector schema (values deferred)

No final vector values are claimed in this draft. The following fixed-input/fixed-output schema is required for a later vector task after independent review resolves or accepts the profile. Later state-machine/security tests must cover: a fixed synthetic 16-byte honest-generated request ID (not a live CSPRNG output); active local collision causing regeneration before `START`; valid incoming request IDs of 1 and 64 bytes and rejection above 64; no entropy validation for attacker-chosen incoming values; equal IDs on distinct connections remaining separate state and consuming separate slots/attempts; exact duplicate `START` idempotence and conflicting same-routing-key `START` failure; cross-connection injection rejection despite equal IDs; historical ID reuse without approval/result inheritance; request-ID reuse not bypassing SAS accounting; and differing transcript inputs yielding distinct transcript identities despite an equal request ID. Also cover reservation before Initiator key release; reservation before Responder key release; persistent reservation failure; no refund after abort; concurrent atomic reservation; replayed `START` reaching the SAS boundary; restart with preserved accounting; every variable field at its exact maximum and maximum+1 rejection; zero where forbidden; nested bootstrap exactly 16,384 and 16,385 bytes; total frame exactly 65,536 and rejection at 65,537; generated Base64url input exactly 65,536 and rejection at 65,537; fragmented maximum-valid frame; declared-length and aggregate-arithmetic overflow; truncation and trailing data; capacity 8 accepted and ninth Responder ceremony rejected before active state, key generation, or `ACCEPT`; slot reuse after legitimate terminal cleanup; and no SAS charge for capacity rejection. Do not generate vectors or cryptographic values in this task.

- profile identifier/version, role, request ID, and both bootstrap field values;
- the established transcript bytes: the exact canonical `START`, `ACCEPT`, `INITIATOR_KEY`, and `RESPONDER_KEY` frames;
- the transcript digest / authoritative ceremony identity;
- fixed test-only initiator and responder ephemeral private inputs, their public keys, and invalid/non-contributory-key cases;
- canonical `START`, `ACCEPT`, key, MAC, cancellation, and completion frame bytes;
- commitment preimage and SHA-256 output;
- SAS context frame and exact HKDF `info` string;
- raw six SAS bytes and three decimal values/rendered string;
- both canonical bootstrap frames, each MAC context/info string, stringified MAC input, and raw MAC tag;
- all approval/completion MAC inputs, contexts, and tags;
- a replay case using the same request ID with fresh responder material, demonstrating a different transcript digest / authoritative ceremony identity;
- positive full ceremony result and negative mutation cases for role, request ID, profile/version, context, key, commitment, bootstrap, MAC, transcript, ordering, replay, and completion.

Test private inputs MUST be clearly synthetic and MUST NOT be used in production. Vectors show encoding/interoperability only; they do not prove protocol security. Produce actual vectors only when the exact construction is accepted for vectorization; do not backfill values by guessing unresolved policies.

## 13. Source traceability

| Mechanism | Source and what is inherited | What this profile adds / classification |
|---|---|---|
| Application-neutral roles, per-ceremony approval, exact authenticated bootstrap, no possession claim | P1 threat model and P2 selected result requirements | Role-specific candidate vodozemac flow; project adaptation, not P2 Candidate B |
| Curve25519 SAS key generation, contributory DH rejection, HKDF-derived bytes, decimal SAS, HMAC-SHA-256 MAC API | Current vodozemac `Sas`, `EstablishedSas`, and `SasBytes` API/source | The composed ceremony and contexts are new; candidate, review required |
| Commit-before-reveal ordering | Matrix Client-Server v1.18 `m.sas.v1` uses responder commit-before-reveal tied to initiator start content, with I revealing its key before R reveals its committed key | Protocol-purpose precedent only; the complete generic ceremony remains a project adaptation |
| Exact binary commitment input | No exact generic encoding is inherited from Matrix | Domain, length framing, canonical `START`, and exact `R_pub` encoding are sas-pairing-specific |
| Single-attempt binding | Matrix specifies SHA-256 in its own ceremony | This profile relies on SHA-256 collision resistance for the exact encoded input; profile-specific assumption, not inherited proof |
| Hiding of the unrevealed responder key | No hiding proof for this generic construction is inherited from Matrix | High-entropy vodozemac key generation plus a random-oracle-style SHA-256 assumption; profile-specific and subject to independent review |
| Three 13-bit decimal groups, 39 exact-match bits | Matrix decimal SAS representation and vodozemac `SasBytes::decimals()` | Retained candidate representation; defensible only under a reviewed bounded aggregate-attempt model and honest complete-comparison assumptions; not a production selection or proof |
| Canonical binary frame and strict unpadded Base64url string bridge | No canonical generic encoding is inherited from Matrix/vodozemac | Entire framing, context-purpose strings, and bootstrap schema are project adaptations requiring review |
| Aggregate attempt security | Candidate requirement: `p = 2^-39`, `ε = 10^-8`, `N = 5,497` per durable local epoch | Candidate scope, enforcement, reset, persistence, and exhaustion policy are defined here; independent review must accept the per-opportunity bound and complete construction |
| Request-ID generation and routing policy | Candidate policy defined in §4; request IDs are public routing context, not an authentication or freshness assumption | Independent review must assess the complete profile; the separate vodozemac ephemeral-key RNG/entropy path, deadline, storage implementation, and any rollback-resistant guarantees remain unresolved |
| Completion messages and asymmetric local return guarantee | P1 requires mutually authenticated local completion evidence and compatible results | Three-message confirmation and its exact limitation are project adaptations requiring independent review against the clarified local-result contract |
| External identity, authorization, and proof of possession | P1/P2 distinguish authenticated bytes from external truth and key control | Consumer validation boundary restated; protocol claim deliberately limited |

Primary references checked for this draft: [Matrix Client-Server Specification v1.18 SAS verification](https://spec.matrix.org/v1.18/client-server-api/#short-authentication-string-sas-verification); [vodozemac `sas` API](https://docs.rs/vodozemac/latest/vodozemac/sas/index.html), [`EstablishedSas` API](https://docs.rs/vodozemac/latest/vodozemac/sas/struct.EstablishedSas.html), and [SAS source](https://github.com/matrix-org/vodozemac/blob/main/src/sas.rs); [RFC 4648 Base64url](https://www.rfc-editor.org/rfc/rfc4648.html#section-5); project [P1 threat model](threat-model.md), [P2 construction selection](construction-selection.md), [P3 profile foundation](protocol-profile-v1-draft.md), [Candidate B instantiation research](p3-candidate-b-instantiation-research.md), and [P3.4 vodozemac reuse assessment](p3-vodozemac-reuse-assessment.md).

## 14. Required independent-review decisions

This candidate is reviewable as a precise message/encoding proposal but is not complete enough for selection or implementation. Review must explicitly answer:

1. Does SHA-256 collision resistance adequately provide the required single-attempt binding for this exact encoded commitment input?
2. Is the random-oracle-style hiding assumption acceptable for an honestly generated high-entropy vodozemac responder public key, given that collision resistance and ordinary preimage resistance alone do not prove hiding?
3. Does the selected vodozemac release and its complete RNG/key-generation path provide adequate unpredictability/min-entropy against the intended adversary and query budget?
4. Does the complete candidate justify the assumed per-charged-attempt `2^-39` statistical term against active and concurrent attackers, and are abort-and-retry opportunities all charged?
5. Does the transcript/role/domain binding cover reflection, unknown-key-share, and misbinding cases?
6. Does vodozemac's current released API and zeroization behavior support this lifecycle, canonical byte-to-string mapping, and the proposed generic SAS/MAC contexts? Which exact upstream version is acceptable and reviewed?
7. Does independent review accept the candidate's per-opportunity bound of at most `2^-39` and the resulting `ε = 10^-8`, `N = 5,497` aggregate SAS random-match policy per local epoch?
8. Does the specified accounting scope, charging boundary, fail-closed exhaustion, and locally authorized atomic reset preserve that candidate bound under the complete construction?
9. Does the deployment's selected persistence mechanism provide the required atomicity, and does any deployment claim across restore/rollback have suitable rollback-resistant guarantees?
10. Is full-value comparison guidance adequate for the intended UI/accessibility environment?
11. Are the defined request-ID generation, collision reservation, and routing rules correctly separated from authentication and freshness? What cooldown, exact timeout/lifetime, global resource-rate thresholds, and persistence-failure behavior are justified?
12. Do the adopted field, frame, Base64url, and eight-slot maxima adequately bound resource use for intended deployments, including integration across multiple processes or cores?
13. Does the three-message completion contract provide the required compatible local results under asymmetric message loss, without claiming simultaneous success or distributed atomic commit?
14. Are mandatory equal `shared_context` bytes the right generic application-context semantics, and how should expected-peer validation be represented without asserting external identity truth?
15. Does the transcript-derived authoritative ceremony identity, incorporating fresh responder material and all bound transcript values, adequately render replayed pre-establishment requests ineffective as replay of an old authenticated ceremony?
16. Does this candidate satisfy each P1 property under its actual cryptographic, transport, endpoint, human-comparison, and attempt assumptions? If not, identify the requirement that must be narrowed or reject this candidate.

The target, maximum, accounting epoch, exhaustion, reset, field/frame/Base64url caps, and responder-slot choices in this draft are adopted candidate decisions, not unspecified policy values; they still require independent review because this vodozemac profile remains unselected. Timeout duration, global resource-rate thresholds, and deployment-wide coordination details remain unresolved. The profile remains **CANDIDATE — NOT SELECTED — REQUIRES INDEPENDENT SECURITY REVIEW**. Candidate B remains selected for the existing P2 remote profile. The next gate is independent protocol/security review of this complete candidate document, not production implementation.
