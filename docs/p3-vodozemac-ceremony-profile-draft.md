# Generic vodozemac SAS Ceremony Profile — Draft 01

> **CANDIDATE PROFILE — NOT SELECTED — REQUIRES INDEPENDENT SECURITY REVIEW**
>
> Profile identifier: `sas-pairing-vodozemac-profile-draft-01`
> Status: a protocol proposal for review, not a production protocol, implementation, or protocol freeze.

> **CURRENT OWNER POLICY:** One live exposed remote ceremony per pairing authority, across both roles, all remote connections, and all relevant instances; plus 10 exposed opportunities per process/session across both roles. The guard and opportunity reservation are atomic. For two endpoints within a joint 10/10 window, the pair-count maximum is 19. The per-pair argument is conditional and remains open for independent verification. Historical multi-ceremony, eight-slot, and `5,497`-epoch rules below are non-normative historical material only. The transcript-encoding correction in §9 remains consistent with the deterministic vector.

## 1. Purpose and status boundary

This document defines one candidate remote pairing ceremony using the currently researched `vodozemac::sas` operations. It is intended to make the proposal reviewable against the requirements in [P1](threat-model.md). It does not establish that the proposal satisfies those requirements.

**Candidate B was the historical P2 abstract construction selection.** The owner later reopened the implementation-direction choice because concrete instantiation would entail substantial project-owned cryptographic design and proof-mapping/maintenance; this is not a finding that Candidate B is insecure. Candidate B remains a formal reference and possible fallback. This vodozemac profile is the **FAVORED CANDIDATE — NOT SELECTED** because maintained primitives may reduce custom-crypto ownership. It does not replace Candidate B or authorize implementation. It still requires project-specific security analysis and independent review. No remote construction is currently ready for final selection. The project remains pre-alpha and not production-ready. No production cryptography is added or approved here.

Subject to this profile's assumptions and independent review, successful local completion means: **the human-approved ceremony peer supplied the exact authenticated bootstrap bytes returned in this exact ceremony, under a `shared_context` that matched the participant's independently supplied local context, and the candidate's authenticated completion conditions were satisfied locally.** A “human-approved ceremony peer” is the protocol peer participating in this run whose complete SAS was compared and approved. This does not establish a known person, OS account, database account, device, or application principal. Authenticating public-key bytes does not establish possession of the corresponding private key, external identity truth, or application authorization. No reusable pairing secret is a result.

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

The same ID on distinct connections/sessions denotes separate pre-exposure candidate runs and MUST NOT alias state. Multiple pre-exposure requests may be handled under local resource policy, but no second ceremony may cross exposure while the pairing-authority guard is occupied. Each ceremony that crosses its role-specific exposure boundary acquires the shared guard and consumes one process/session opportunity. Within one active routing key, an exact byte-for-byte duplicate `START` is ignored idempotently without creating state or repeating output/key generation; a conflicting `START` fails the active state closed. It MUST NOT overwrite or merge state, silently restart, inherit approval, or change accounting. A message received on one connection/session MUST NOT be accepted into another connection's state merely because its request ID matches. Dispatch/validation also checks expected role/state, exact message sequencing, and the existing commitment, transcript, and MAC bindings.

Because `START` contains the request ID, its exact bytes are included in the established transcript and transitively bound by its digest. Once the transcript through `RESPONDER_KEY` is fixed, the transcript-derived SHA-256 `ceremony_identity` is the authoritative cryptographic ceremony identifier. SAS display, approval, MACs, completion, and result semantics remain bound to `ceremony_identity`; the request ID may remain for routing, diagnostics, and correlation but MUST NOT replace that identity for security decisions. Equal request IDs do not imply equal established ceremonies.

At process restart, every in-flight request/ceremony state and pending approval is discarded, ephemeral secrets are destroyed, and no state resumes. Historical request IDs are not persisted merely to prevent reuse. Restart begins a new local process/session opportunity budget; it does not establish a lifetime bound. A later replayed `START` may be processed as pre-exposure traffic, but crossing exposure requires fresh local authorization, a fresh ephemeral key, and the new session's atomic guard/opportunity reservation. Reuse MUST NOT inherit an earlier approval or result or imply the same established ceremony.

Each participant supplies one canonical bootstrap record before the ceremony starts:

| Field | Required bytes and meaning |
|---|---|
| `application_identity` | 1–1,024 opaque bytes asserting an application identity. The protocol authenticates these exact bytes, not their external meaning or truth. |
| `key_algorithm` | 1–64 ASCII bytes matching `[a-z0-9][a-z0-9.-]*`; the exact identifier supplied with the key. |
| `public_key` | 1–4,096 exact public-key bytes supplied with `key_algorithm`. The pair `(key_algorithm, public_key)` is the asserted key; this does not prove private-key possession. |
| `shared_context` | 0–8,192 opaque bytes for application-level security-domain binding. It is mandatory and may be empty. Each participant MUST compare it byte-for-byte with its independently supplied local context before SAS exposure. |

The bootstrap record is a frame of type `0x20`, version `1`, with exactly those four fields in that order. Each field is length-prefixed by the frame rule. The complete canonical bootstrap frame, including its header and all four length prefixes and values, MUST be at most 16,384 bytes. Both the individual field caps and the complete bootstrap cap apply independently; a set of individually valid fields that produces a larger bootstrap MUST be rejected. There are no extension or optional fields in this draft. Adding a field changes the profile/version. These exact canonical bytes are used for validation and cryptographic binding: oversized values MUST be rejected, never truncated or normalized.

R MUST compare the `shared_context` received in `START` with the exact `shared_context` in R's independently supplied local bootstrap before reserving a responder slot or sending `ACCEPT`. I MUST compare the value in R's `ACCEPT` with I's independently supplied local context before reserving a SAS attempt or sending `INITIATOR_KEY`. A participant's local context MUST come from its own application state/input; copying the current peer's context into local state is invalid. Either mismatch aborts before SAS exposure. `shared_context` is opaque exact bytes: sas-pairing does not parse or normalize it. The consumer owns its meaning and any canonical encoding of structured data. It binds application-level scope, separate from protocol domain separators such as `org.sas-pairing`, the profile identifier, and purpose strings.

Empty `shared_context` is valid and means that this field requests no additional application-level context separation. No universal default is added and context is not derived from `application_identity`. If an application's security decision depends on distinguishing an application, environment, tenant, account, purpose, or other domain that is not otherwise independently bound, that distinction MUST be represented in the independently supplied `shared_context`. A deployment with no such additional distinction may intentionally use empty context. Context and all bootstrap fields are visible to the network attacker; `shared_context` is not a secret, and applications MUST NOT put passwords, bearer tokens, or secret credentials in these fields expecting SAS to encrypt them.

The sender owns the bytes it supplies. The peer authenticates the exact record received, not a consumer's decoded display of it. The consumer owns the external meaning of `application_identity`, its mapping to local principal/account/device records, and whether that mapping is independently trusted. The consumer also owns supported-algorithm policy and semantic interpretation; where required, algorithm support and public-key encoding are checked before SAS exposure. An expected public key always compares `(key_algorithm, public_key)` together by exact byte equality; matching raw key bytes under a different algorithm identifier is a mismatch. A successful ceremony authenticates the exact supplied algorithm and key bytes but does not prove possession of the private key.

## 5. Commitment and ephemeral key exchange

### Candidate dependency and runtime requirements

The exact P3 candidate dependency is `vodozemac = 0.11.0 exact`: the candidate is analyzed against exactly vodozemac 0.11.0. This is a documentation/specification pin, not a Cargo dependency. If this candidate advances to P4, the intended dependency declaration is:

```toml
vodozemac = { version = "=0.11.0", default-features = false }
```

P4 MUST implement and revalidate this same choice and record/review the actual P4 workspace `Cargo.lock` dependency graph. The 0.11.0 manifest uses semver-compatible dependency ranges and does not freeze `rand`, `rand_core`, `getrandom`, `hmac`, `sha2`, `x25519-dalek`, or their transitives. The vodozemac source repository's own lockfile does not determine the consumer workspace's resolved graph.

Disabling default features disables `libolm-compat` and `precomputed-tables`. `libolm-compat` is not needed: this candidate uses standard SAS MAC behavior and MUST NOT use legacy invalid-Base64 compatibility behavior. `precomputed-tables` is not needed for correctness; disabling it is a binary-size/performance choice, not a cryptographic-strength improvement. Candidate SAS results and X25519 contributory validation do not depend on those tables. Do not enable `low-level-api`, `insecure-pk-encryption`, `experimental-session-config`, or `wasm_js` unless a future target-specific analysis explicitly requires one. Disabling vodozemac defaults does NOT disable X25519 zeroization: the exact 0.11.0 manifest declares `x25519-dalek` with `default-features = false` and explicitly enables `zeroize` (as well as `serde`, `reusable_secrets`, and `static_secrets`).

The tagged-source SAS key-generation path is:

```text
Sas::new()
  → rand::rng()
  → ThreadRng
  → SysRng
  → rand_core / getrandom
  → operating-system entropy source
  → EphemeralSecret::random_from_rng(...)
```

The candidate relies on the exact locked Rand/getrandom dependency path successfully obtaining cryptographically secure randomness from the supported operating system for ephemeral-key generation. vodozemac does not itself implement an entropy source. `Sas::new()` returns `Sas`, not `Result<Sas, ...>`; Rand's infallible `ThreadRng` path may panic if system seeding or reseeding fails. No pairing success may be produced from failed entropy generation; depending on panic/runtime policy, failure may unwind or terminate the process. P4 integration MUST ensure such a failure cannot be converted into protocol success and MUST NOT promise a graceful terminal protocol error from this upstream API.

**Ephemeral freshness requirement:** Every exposed ceremony MUST use newly generated, unpredictable ephemeral private-key material. A private key or SAS object MUST NOT be reused across ceremonies, including after termination, failure, retry, reconnect, or request-ID reuse. Implementations MUST account for process forking, VM snapshots, restored process state, RNG failure, and duplicated cryptographic state: if any condition can repeat or clone RNG state, the affected process MUST NOT expose another key until a verified mechanism restores fresh unpredictability. Do not claim snapshot/rollback resistance without a verified mechanism. Rand `ThreadRng` does not automatically reseed after process `fork()`; a supported fork-based deployment therefore needs a verified child reseed or another verified way to obtain independent fresh key material. If a target dependency/runtime cannot guarantee this property under a deployment condition, that deployment cannot claim this profile's argument under that condition. P4 must verify the exact dependency/runtime behavior and document supported deployment limits; this profile does not prescribe an RNG implementation.

An RNG seeding/reseeding failure MUST NOT produce an exposed key or pairing success. The upstream `Sas::new()` path is infallible at its Rust type boundary and may panic on system entropy failure; P4 must ensure panic/unwind/runtime failure cannot be converted into protocol success. The profile makes no promise of graceful terminal protocol error from that API.

Request-ID generation remains a separate core operation: the sas-pairing core generates its 16-byte request IDs with its selected OS-backed CSPRNG; vodozemac generates only SAS ephemeral keys through the path above. These are separate operations and separate review claims, even if they eventually use the same OS entropy ecosystem.

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

**Binding assumption.** For one fixed exact canonical `START`, if a malicious R can reveal two distinct accepted `R_pub` values that verify against the same commitment, then the two values produce distinct encoded SHA-256 inputs with the same digest. This profile therefore relies on SHA-256 collision resistance for commitment binding. R chooses the commitment, so collision resistance is the relevant conservative assumption; this is not characterized merely as second-preimage resistance. Exact canonical `START` verification and framing are part of the argument. This is an assumption, not a proof that concrete SHA-256 meets it.

**Hiding assumption.** This deterministic commitment hashes public `START` bytes together with unrevealed `R_pub`. The proposed argument assumes random-oracle-style hiding behavior for SHA-256 on these inputs, together with fresh unpredictable high-entropy responder key generation. Collision resistance and ordinary preimage resistance alone do not establish hiding. This is not information-theoretic or generic commitment hiding, and concrete SHA-256 has not been proven to behave as a random oracle. No exact min-entropy is claimed. P4 must verify entropy and freshness on each supported target and identify unsupported deployment conditions.

**X25519/input assumptions.** The argument assumes honest ephemeral private keys are fresh and unpredictable and that peer public inputs are exactly 32 bytes and accepted under the pinned API's input rules, with contributory DH checked by `was_contributory()`. Malformed-length and non-contributory inputs fail closed before SAS derivation. The argument does not assume that an accepted public key proves identity or private-key possession; independent review must confirm the API's accepted-input set and the relevant X25519 assumptions.

The commitment alone does not authenticate R, establish identity, prove possession of bootstrap keys, limit retries, prevent abort-and-retry or concurrent multi-session grinding, or replace human SAS comparison. **Matrix boundary:** Matrix `m.sas.v1` is precedent for responder commit-before-reveal, committing to responder ephemeral public-key material together with initiator start content, using SHA-256, and having I reveal its key before R reveals its committed key. It does not establish this binary encoding, domain string, generic bootstrap fields, hiding argument, or complete generic ceremony. This construction is a sas-pairing adaptation requiring independent review.

**Attempt-security boundary.** Within one attempt, after I accepts one commitment, R cannot choose a different `R_pub` after seeing `I_pub` without violating the binding assumption. Across attempts, an attacker may adaptively schedule, selectively abort, or learn one leg's SAS before choosing a contribution for the other leg. The argument does not assume cross-leg commit-before-learning. It instead relies on each ceremony's own message order, fresh unpredictable honest ephemeral material, commitment assumptions, and the exposure/accounting boundary described in §7. The one-live-ceremony rule prevents parallel exposed ceremonies under one pairing authority; it does not eliminate adaptive sequential scheduling.

R's bootstrap is not included in the commitment formula because R sends it inside `ACCEPT`, before R receives `I_pub`; it is therefore fixed before R sees the Initiator key. The bootstrap is later bound into the SAS context, authoritative transcript identity, and approval/bootstrap authentication. Adding it to the commitment would redundantly include data already fixed at that point.

I creates one new `Sas` object only after validating `ACCEPT` and successfully reserving its exposure opportunity. Its ephemeral key material is fresh for this ceremony and never reused. R creates its ceremony's `Sas` before `ACCEPT`, but that key material is also fresh and single-use. Each side's parser MUST reject peer-key fields whose length is not exactly 32 bytes before constructing a vodozemac `Curve25519PublicKey`. Each side passes the exact 32-byte value to `Sas::diffie_hellman`; vodozemac checks the resulting X25519 shared secret with `was_contributory()` and returns `KeyError::NonContributoryKey` for a non-contributory peer key. Either malformed length or non-contributory result is terminal. No public-key text encoding is used on the wire.

`Sas::diffie_hellman` consumes the `Sas`, so its `EphemeralSecret` is dropped when the call returns. On success, `EstablishedSas` owns the X25519 `SharedSecret` for as long as SAS/MAC operations are required. Implementations MUST retain that native session only for the active ceremony and drop `Sas`/`EstablishedSas` on every terminal outcome, cancellation, expiry, and ordinary teardown before returning control to the caller. The DH shared secret MUST NOT be returned, persisted as application trust, or reused as a pairing key.

The tagged vodozemac manifest enables `x25519-dalek/zeroize`. In the inspected published `x25519-dalek 3.0.0` source, `Drop` zeroizes both `EphemeralSecret` and `SharedSecret`; vodozemac's consumed-secret and owned-session lifetimes therefore invoke those drops for that resolved version. The P4-resolved x25519-dalek version must be captured and its same behavior revalidated. This is the specific guarantee boundary. It does not establish complete memory sanitization: derived `SasBytes`, HKDF output, HMAC key/state temporaries, MAC/input buffers, compiler/runtime copies, swapped pages, crash dumps, or other copies are not all comprehensively guaranteed to zeroize. Those temporary-material limits and whether this boundary is adequate remain for independent review. A panic may unwind and run destructors or may terminate the process according to runtime policy; no cleanup or graceful failure promise is made for process termination.

## 6. Exact message flow

Only the following messages exist in this draft. Every network message has the global frame header and the exact fields shown. Sender role is implicit only for message types that are direction-specific and can legally be sent by exactly one ceremony role. A message type valid in both directions carries its explicit sender-role field; the receiver MUST verify that the encoded sender role is the expected peer role for the active ceremony and reject a mismatch as a protocol error. Except for `START`, `ACCEPT`, and key-exchange messages, the message body is authenticated by a direction-specific vodozemac MAC as specified in §§8–11.3. For `CANCEL`, the wire message type is `0x09`; the separate non-wire `CancelAuthFrame / 0x34` defined in §11.3 is used only as MAC input/context. There are no transport-level acknowledgements that alter protocol state.

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

The retained candidate representation is exactly `SasBytes::decimals()`: three unsigned values formed by the vodozemac/Matrix decimal mapping, each in `1000..=9191`, rendered as four ASCII decimal digits separated by one ASCII space, for example `1234 5678 9012`. The complete value has 39 exact-match bits (`2^39` possible values). No user types or transcribes it.

### Proposed conditional security argument — not established

The target event for one tested candidate pair is equality of the complete six-byte/three-group SAS values for two distinct live ceremonies between honest endpoints A and B, with the network attacker mediating both. A partial match is not the event bounded here. The attacker controls delivery, can delay, reorder, replay, abort, selectively schedule ceremonies, observe protocol messages and any SAS available on an attacker-controlled leg, and can choose its own key contributions adaptively. It cannot bypass the owner's one-live-exposed-ceremony guard or create a fresh exposed ceremony without explicit local authorization. The argument does not assume the attacker fixes one leg before it learns the other leg's SAS.

For each ceremony, the argument uses its actual message ordering. If the honest endpoint is I, the peer's commitment is accepted before I generates fresh ephemeral key material; I generates it only after validating `ACCEPT`. If the honest endpoint is R, R generates fresh key material and commits before receiving I's contribution, while the commitment is assumed to hide `R_pub` until reveal. Thus the contribution that remains unknown for that ceremony is protected by the applicable ordering and assumptions even if the attacker has learned the other leg's SAS and schedules or chooses its contribution adaptively. Under fresh unpredictable key generation, commitment binding/hiding, and the idealized HKDF assumption below, the remaining honest contribution makes the full SAS on that leg unpredictable at the relevant boundary.

The conditioning point is immediately before that remaining honest contribution becomes available to the attacker: for honest I, after `ACCEPT` validation and before its fresh private key/public contribution is exposed; for honest R, after the attacker has supplied `I_pub` but before the committed `R_pub` is revealed. Condition on the attacker's prior view, including any SAS learned on another leg, its fixed contribution for this leg, prior aborts, and the adaptive scheduling decision—but not on an attacker view containing both completed SAS values. The candidate pair becomes countable once both SAS values are fixed by live ceremonies and their live intervals overlap; count each pair once at the exposure/establishment of its later member. A fresh candidate is not available for prior evaluation before that ceremony's exposure boundary under the stated key-freshness and commitment-hiding assumptions.

The idealized claim is that for each such conditioned candidate pair the exact full-SAS match event has probability at most `2^-39`, plus assumption-dependent error. This relies on SHA-256 collision resistance for commitment binding; random-oracle-style hiding for the deterministic SHA-256 commitment; random-oracle-style behavior of the relevant HKDF-SHA256 construction for the unknown honest contribution and bound context; fresh unpredictable ephemeral keys; valid X25519 handling; correct ordering; and atomic single-ceremony enforcement. Ordinary HKDF PRF security alone is not asserted sufficient: on an attacker-controlled protocol leg the attacker knows that leg's derived secret, so a PRF argument under an unknown key cannot justify the cross-leg claim. Neither SHA-256 nor HKDF-SHA256 is proven to be a random oracle. The second adversarial AI review found no concrete attack exceeding the ideal term but concluded **PREVIOUS PROOF NOT ESTABLISHED** because the prior proof did not establish these assumptions and conditioning details. This reconstruction is conditional, not a standard-model proof.

Adaptive scheduling and selective aborts do not justify conditioning on two completed SAS values. A new pair is included when its second live candidate is established, regardless of whether the attacker later aborts or whether a user approves. The per-pair conditional bound must hold for every allowed prior view and scheduling choice; the union bound then counts each possible pair. Explicit retries consume another opportunity. This argument does not make selective abort harmless; it requires that every fresh exposure is charged and counted.

`P_per_pair ≤ 2^-39 + δ`, where `δ` denotes the relevant computational and cryptographic-assumption errors. With the owner policy's one-live-exposed-ceremony rule, for actual counts `n_A`, `n_B` during overlapping live intervals, the structural number of tested candidate pairs is at most `n_A + n_B - 1` when both are nonzero. Within a joint window where each endpoint remains within its 10-opportunity process/session budget, there are at most 19 pairs, giving:

`P_joint ≤ 19 × 2^-39 + ε`

Here `ε` collects the applicable computational and randomness terms for the joint argument; no exact numeric value is claimed without a supported derivation. `19 × 2^-39 ≈ 3.456 × 10^-11`. These are idealized SAS random-match bounds only—not a lifetime bound, a bound across arbitrary restarts, a real-human error probability, a complete end-to-end authentication guarantee, or a formal proof of the concrete implementation. Human comparison assumes people compare the currently live SAS values; software cannot enforce that they never remember or verbally reuse old codes. Human error, compromised endpoints/displays, RNG failures outside the assumptions, implementation defects, social engineering, and external identity truth are not included.

The 10-opportunity ceiling is an owner-selected conservative session safety limit, not a mathematically derived cryptographic constant. No persistent lifetime counter is implied. Restarts reset local budgets; longer-term structural counting uses actual total exposure counts and establishes no fixed lifetime numeric bound.

Each consumer displays the complete value only after the established transcript and its ceremony identity are fixed. Each participant has a local action associated with that exact identity: `MATCH/APPROVE`, `MISMATCH/REJECT`, or `CANCEL`. Approval callbacks and state MUST be keyed to the transcript-derived identity, not solely to the request ID. Approval from another transcript, even one with the same request ID, cannot satisfy this ceremony. A mismatch/reject or cancellation is terminal. Partial comparison, automatic matching, prior approval, or a display from another ceremony cannot authorize success. Both participants must approve their own displayed SAS and satisfy the authenticated completion flow. The bound assumes the human completes the comparison as intended; it does not account for arbitrary human error, coercion, display compromise, or a perfect authenticated human channel.

## 8. Bootstrap MAC and local validation

After local SAS approval, each side authenticates one exact approval statement. For sender role `r` (`I=0x01`, `R=0x02`), define an approval frame of type `0x33` with fields in this order: protocol domain; profile identifier; version; sender role code; the 32-byte authoritative ceremony identity (the transcript digest); the exact six raw `SasBytes`; the sender's complete canonical bootstrap frame. This states that the sender approves the full displayed SAS for this exact established transcript and authenticates that sender's exact bootstrap.

Define a context frame of type `0x31` with fields in this order: protocol domain; profile identifier; version; purpose ASCII `match-approve-bootstrap`; sender role code; receiver role code; authoritative ceremony identity (the transcript digest). The request ID and exact key/bootstrap messages are already bound by that digest. The MAC info string is the §3.2 context string with purpose `mac` and this frame.

Because vodozemac accepts UTF-8 strings, transform the complete approval frame into exactly `input = unpadded_Base64url(approval_frame)` using the §3.1 canonicality rules. The sender calls `EstablishedSas::calculate_mac(input, info)` and sends the 32 raw bytes from `Mac::as_bytes()`. The receiver reconstructs the expected approval frame using the peer's role, this ceremony's six SAS bytes, and the exact peer bootstrap, then constructs `Mac::from_slice(received_32_bytes)` and calls `verify_mac(input, info, &tag)`. The wire tag MUST be exactly 32 bytes. No Matrix key-ID-list MAC semantics or legacy invalid-Base64 compatibility method is used.

This MAC authenticates the sender's explicit match-approval statement, the complete SAS value, the exact bootstrap bytes, and direction for this established ceremony, under the SAS shared secret, subject to review of the complete construction. A verification error, wrong role, wrong ceremony identity, wrong context, or unexpected peer bootstrap is terminal and returns no result. The protocol cannot establish that a human actually compared correctly; it assumes each honest endpoint emits this statement only after its own explicit approval.

The consumer deliberately selects one of two local modes; no mode bit is added to the wire.

- **Open / first-contact mode:** the consumer supplies `expected_peer = none`. No pre-existing peer identity or key is constrained. SAS authenticates the exact bootstrap bytes supplied by the peer in this ceremony. The consumer may persist those exact bytes afterward, but success does not authorize or automatically establish durable trust in them. The strongest claim is that the approved ceremony peer supplied those exact bytes in this exact ceremony under the matched local context; it does not mean “this is definitely Alice.”
- **Expected-peer mode:** the consumer supplies one or more expected values from independent local state/input. Constraints may intentionally cover `application_identity`, `key_algorithm`, and/or the asserted key. A key constraint MUST supply and compare `(key_algorithm, public_key)` together; raw public-key bytes cannot be constrained while ignoring the algorithm. An algorithm-only constraint may constrain `key_algorithm` without asserting a particular key. Every supplied constraint uses exact bytes and MUST match. No field is required to be known if the consumer deliberately leaves it unconstrained.

Expected values MUST NOT be derived from the peer bootstrap currently being checked. In particular, copying an identity the peer just supplied into `expected_peer` provides no independent authentication. If expected-peer pairing was intended but its data is missing, malformed, unavailable, inconsistent, or cannot be checked, the ceremony MUST fail closed; it MUST NOT silently fall back to open mode. Open mode requires an explicit local consumer decision and needs no wire indication.

All locally knowable checks are completed before SAS exposure. On `START`, R validates the bounded canonical bootstrap, local-context equality, supplied expected-peer exact matches, and required algorithm support/key encoding before sending `ACCEPT`. On `ACCEPT`, I validates the frame/bootstrap/commitment field, local-context equality, supplied expected-peer exact matches, and required algorithm support/key encoding before explicit local authorization, atomic guard/opportunity reservation, fresh key generation, or sending `INITIATOR_KEY`. No known mismatch may be deliberately postponed. The consumer supplies these local constraints to the core before message handling; this profile does not require callbacks, database/network lookups, or arbitrary application policy execution during message processing.

A pre-exposure mismatch fails closed: no successful `PairingResult`, SAS display, consumed opportunity, trust persistence, or weaker fallback flow is allowed; a retry requires fresh explicit local authorization and a fresh ceremony. Once the public contribution is exposed, the opportunity remains consumed even if pairing fails. Resource/parser admission remains distinct from peer validation and SAS accounting: bounded parser/frame/field checks still precede semantic checks as needed to parse safely; resource admission remains applicable; and resource rejection is not an identity verdict.

Partial expectations narrow only the corresponding claim. Expected `(key_algorithm, public_key)` alone can establish equality to that locally expected pair but does not mean `application_identity` was previously known. Expected `application_identity` alone can establish equality to those locally expected bytes but does not establish key continuity. With no expectation, fields are authenticated as supplied only; unconstrained fields are not pre-validated or externally verified.

The responsibilities remain distinct:

1. **Protocol authentication:** verifies the exact peer-supplied bytes and context for this ceremony.
2. **External truth:** determines whether the claimed application identity or key is known/valid; the ceremony cannot prove this.
3. **Authorization:** decides what the local application permits; pairing does not grant it.
4. **Proof of possession:** must be established later by a protocol that verifies a fresh proof under the exact authenticated/pinned key bytes.

Expected-peer equality is not proof of external identity truth, private-key possession, or authorization. Friendly display names and later directory results do not alter the authenticated bytes. A later lookup by `application_identity` MUST NOT silently replace the authenticated `(key_algorithm, public_key)` with another key; any resolution to a different principal or key is a consumer-owned trust boundary and requires an independent authenticated basis. Persisted trust MUST preserve the exact authenticated algorithm/key bytes. The ceremony itself does not perform a durable trust write or guarantee atomic trust persistence at both endpoints.

Once local inputs are supplied, the shared core owns exact-byte comparison, binding expected keys as `(key_algorithm, public_key)`, pre-SAS timing, fail-closed mismatch behavior, the no-SAS/no-opportunity-consumption pre-boundary outcome, and preserving exact authenticated bytes in the result. The consumer owns open versus expected-peer selection, expected-value provenance and subset, context meaning and structured-context canonicalization, supported algorithms, external identity mapping, local authorization, trust persistence, friendly display-name mapping, and later proof-of-possession/reconnect behavior. A display name is not authenticated unless its mapping to the authenticated identity bytes is independently trusted. These semantics do not prescribe callbacks or language APIs.

## 9. Completion and result semantics

The authoritative `ceremony_identity` is the existing transcript digest, exactly SHA-256 of `u32be(len(domain)) || domain`, where `domain = ASCII("sas-pairing-vodozemac-profile-draft-01/transcript/v1")`, followed by the complete canonical `START`, `ACCEPT`, `INITIATOR_KEY`, and `RESPONDER_KEY` frames, each preceded by `u32be(length)`. It covers the profile/domain-separated exact messages, including the request ID in `START`, the responder commitment and bootstrap in `ACCEPT`, and both exact ephemeral-key messages. It becomes available once this transcript through `RESPONDER_KEY` is fixed. I computes it after receiving and verifying `RESPONDER_KEY`; R computes it when the canonical `RESPONDER_KEY` bytes are fixed for transmission. Both hash the same canonical frame bytes. No digest is included in the transcript it hashes.

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

The `PairingResult` shape remains unchanged: it adds no `identity_verified` flag or generic trust verdict. The protocol reports exact authenticated bytes; the consumer knows which independent local constraints it supplied. External identity truth, possession, authorization, and durable trust are separate claims and are not collapsed into a boolean.

## 10. Normative state machine

The states below form one state machine and one state object per run. Before transcript establishment, local state is correlated by `request_id` plus local connection/session state as needed. Once the transcript through `RESPONDER_KEY` is fixed, that state object records the authoritative `ceremony_identity`; SAS display, approval flags/callbacks, MACs, and results are then associated with that identity. State transitions are atomic with message validation. **I1 — Terminal irreversibility:** any invalid message, failed validation, explicit rejection, timeout, cancellation, or completion transitions an active run to an irrevocable terminal state. A terminal run can never become successful; delayed messages, callbacks, approvals, acknowledgements, or reconnects cannot revive it. The pairing-authority guard is released only after terminal state and invalidation are irrevocable. **I2 — SAS display lifetime:** a SAS is valid for human comparison only while its ceremony is live. Termination MUST invalidate the SAS, withdraw it from the consumer's active comparison interface, and reject later approval callbacks targeting that ceremony. Human comparison assumes people compare the currently live SAS values; software cannot prevent remembering or verbally reusing old codes. The cause may be retained for diagnostics but must not change acceptance behavior.

| State | Legal incoming message / local action | Transition and forbidden behavior |
|---|---|---|
| `Idle` | I local `Start` with a new in-flight request handle and bootstrap; R incoming `START` | I → `AwaitAccept`. For R: bounded frame intake and canonical structural `START` parsing → local pre-exposure resource checks → D14 canonical bootstrap, local-context, expected-peer, algorithm, and key validation → fresh ceremony-unique ephemeral generation → commitment / `ACCEPT`; then R → `AwaitInitiatorKey`. A known semantic mismatch is rejected before key generation. A valid `START` is pre-exposure traffic and does not consume an opportunity or acquire the exposed-ceremony guard. Every wire message repeats the exact profile ID and request ID. |
| `AwaitAccept` (I) | Legal next message: one valid `ACCEPT` for exact request ID/profile | Validate frame/bootstrap/commitment field, equality to independently supplied local `shared_context`, supplied expected-peer exact matches, and required algorithm support/key encoding. After successful validation and explicit local authorization, atomically acquire the pairing-authority guard and consume one process/session opportunity. Only then generate a fresh, unpredictable, ceremony-unique I ephemeral key and create/send `INITIATOR_KEY`; → `AwaitResponderKey`. Reservation or key-generation failure sends no key contribution. |
| `AwaitInitiatorKey` (R) | Legal next message: one valid 32-byte `INITIATOR_KEY` | Validate `I_pub`; obtain fresh explicit local authorization; atomically acquire the pairing-authority guard and consume one process/session opportunity; only after successful reservation reveal the already committed `RESPONDER_KEY`, record the transcript digest as `ceremony_identity`, and perform DH; → `AwaitLocalApproval`. If authorization, guard, or budget admission fails, do not reveal `R_pub`; terminate pre-exposure without consuming an opportunity. |
| `AwaitResponderKey` (I) | Legal next message: one 32-byte `RESPONDER_KEY` | Verify commitment, fix the transcript and record its digest as `ceremony_identity`, then perform DH; → `AwaitLocalApproval`. No SAS before commitment succeeds and the identity is fixed. |
| `AwaitLocalApproval` | Local display; `MATCH/APPROVE`, `MISMATCH/REJECT`, `CANCEL`; peer approval MAC may arrive before or after local action | Match records one ceremony-scoped approval and sends own `BOOTSTRAP_MAC` containing the authenticated approval statement; rejection/cancel → `Failed`; once the local match and peer approval MAC are verified → I sends `INITIATOR_FINISH` and enters `AwaitResponderFinish`, R enters `AwaitInitiatorFinish`. No completion before all conditions. |
| `AwaitResponderFinish` (I) | Valid `RESPONDER_FINISH_ACK` after I sent `INITIATOR_FINISH` | After valid ACK, send `INITIATOR_FINISH_ACK`, return result, → `Succeeded`. |
| `AwaitInitiatorFinish` (R) | Valid `INITIATOR_FINISH` | R has already sent its approval MAC and verified I's; verify finish and send `RESPONDER_FINISH_ACK`; → `AwaitInitiatorFinishAck`. |
| `AwaitInitiatorFinishAck` (R) | Valid `INITIATOR_FINISH_ACK` matching transcript | Verify; return result; → `Succeeded`. |
| `Succeeded` | No protocol message or local action | Irrevocably terminal. Invalidate/withdraw the SAS and reject stale callbacks; release the authority guard only after these effects are irrevocable. Later messages cannot alter result. |
| `Failed` | No protocol message or approval | Irrevocably terminal. Invalidate/withdraw the SAS, reject stale callbacks, and release the authority guard only after these effects are irrevocable. State, approval, and secrets cannot be reused. A retry requires fresh local authorization and a new ceremony. |

For every active run, implementations retain sufficient canonical accepted-message state to compare a later duplicate; they MUST NOT create additional retained copies of exact duplicate bytes or repeat cryptographic state/work for them. An exact duplicate is ignored with no state change and no repeated output or cryptographic work. A changed duplicate or any message that is not the legal next message is terminal failure. After a terminal state, later messages cannot cause a transition or second result. Where a table transition says “both MACs,” each party has verified the peer's single bootstrap MAC and locally computed its own; receipt of both wire MACs is not required if own MAC was sent. The transcript, request handle, established identity, approval flags, role, and peer identity remain attached to the one state object. Approval is associated with the authoritative identity and cannot satisfy another transcript. The active pairing-authority guard remains occupied until I1/I2 terminal effects are irrevocable.

## 11. Retry, replay, time, cancellation, and failure policy

### 11.1 Exposure, guard, and session accounting

The owner-selected policy is one live exposed remote ceremony per pairing authority and at most 10 exposed remote SAS opportunities per local process/session, across both Initiator and Responder roles. The 10-opportunity value is a conservative owner-selected session safety ceiling, not a cryptographic constant. It is volatile session accounting: process restart starts a new local session budget. No persistent lifetime counter, durable epoch, automatic reset, or fixed lifetime probability is selected.

The successful atomic reservation is the exposure-boundary operation and MUST occur immediately before release of the endpoint's SAS-enabling ephemeral public contribution: I sends `INITIATOR_KEY / I_pub`; R reveals `RESPONDER_KEY / R_pub`. It consumes exactly one opportunity. A refusal before reservation, including pre-exposure local admission failure and BUSY, consumes none. Once reservation succeeds, never refund it—even if the following release outcome is ambiguous or fails, or pairing later succeeds or fails.

Before either contribution is released, the implementation MUST atomically acquire the pairing-authority-wide active-ceremony guard and consume one available opportunity from the current process/session budget. The atomic operation covers guard acquisition and budget reservation: no race, concurrent callback, duplicate message, or competing request may cause an unguarded or uncharged release. A process-local mutex alone does not coordinate independent instances. All roles, remote connections, and relevant instances sharing the pairing authority MUST use coordination that enforces the single guard. If that scope cannot be coordinated, exposure fails closed. The guard remains occupied through all active states and is released only after irrevocable terminal transition.

**Initiator ordering:** I first validates `ACCEPT`, including profile, request ID, bootstrap/context, expected-peer, and key checks. Only after validation may it generate a fresh, unpredictable, ceremony-unique ephemeral key. Before releasing `I_pub`, I MUST obtain explicit local authorization for this fresh ceremony and atomically acquire the guard and consume one available session opportunity. Reservation failure means no `INITIATOR_KEY` is sent and no opportunity is counted. The ephemeral key is never reused.

**Responder ordering:** R may create fresh ephemeral state and send its commitment in `ACCEPT` before exposure, as specified above. Before revealing committed `R_pub`, after validating `I_pub`, R MUST obtain explicit local authorization for this fresh ceremony and atomically acquire the guard and consume one available session opportunity. If admission, authorization, guard acquisition, or budget reservation fails, R MUST NOT reveal `R_pub`. Its prepared state is discarded when that pre-exposure attempt terminates.

The Initiator and Responder procedures use the same guard and session budget. If the budget has consumed 10 opportunities, no remote ceremony can cross exposure for the remainder of that process/session. A process restart creates a new session budget. The budget does not imply a lifetime bound; structural pair counting over longer periods uses actual exposure counts.

Listening for remote `START` messages may remain continuously enabled. Continuous listening or acceptance of pre-exposure traffic is not authorization to expose a SAS contribution. Each fresh exposed ceremony requires explicit local user authorization; network input alone cannot supply it. This resolves continuous Responder acceptance only to the extent already stated in the owner decision. Product details for how the local authorization is obtained remain outside this protocol profile.

### 11.1.1 Resource and pre-exposure admission

The byte, frame, field, and generated Base64url limits in §§3–4 apply regardless of the one-live-exposed-ceremony policy. Malformed and oversized initial traffic is rejected before active state or unbounded work. A pre-exposure `START` may be parsed and a Responder commitment prepared under ordinary finite resource controls, but it does not acquire the exposed-ceremony guard or consume an SAS opportunity. A second ceremony may not cross exposure while the guard is occupied.

Implementations MAY impose pre-exposure resource controls. A `START`/resource refusal and BUSY response MUST be generic as appropriate and MUST NOT consume an exposed opportunity. The candidate's old eight-active-Responder-slot, persistent `5,497`-attempt counter, reset epoch, exhaustion procedure, and globally required rate-control rules are historical/non-normative and MUST NOT be implemented or cited as current owner policy. Any deployment resource limits are local operational controls, separate from the owner's cryptographic accounting ceiling.

### 11.1.2 Local authorization and atomic exposure

Remote network input MUST NOT authorize a ceremony. An Initiator starts from explicit local user action. A Responder may receive and validate a request and prepare a commitment before local authorization, but it MUST obtain fresh explicit local user authorization before revealing `R_pub`. Authorization is ceremony-specific and cannot survive termination, transfer to a retry, or be supplied by a stale callback.

Guard acquisition and session-budget consumption form one atomic admission decision at the pairing-authority scope. The authority-wide guard cannot be treated as a process-local mutex when separate processes or instances share that authority. **OPEN P4 integration obligation:** the integration must define which local processes/instances share one pairing authority and provide coordination with the required atomic behavior. This profile selects no authority identifier, IPC, or storage mechanism. Until the scope and coordination can be verified, no instance under that authority may cross exposure. A successful reservation is immediately committed to the local session count and never rolled back. If coordination or reservation has an ambiguous result, the implementation MUST NOT release a key contribution; it may conservatively consume the opportunity. A failure known to occur before the atomic reservation consumes none.

### 11.2 Freshness, replay, and concurrency

- For an active ceremony, an exact copy of a previously accepted inbound message for the same sender and type is ignored without state change, repeated output, approval, or cryptographic work. A changed duplicate is terminal failure.
- Any nonduplicate message that is not legal in the current state is terminal failure. No message, callback, or reconnect can transition an irrevocably terminal ceremony back to success (I1).
- Routing uses request ID plus local connection/session state or equivalent state-object binding. Equal IDs on different connections do not merge state or permit cross-connection dispatch.
- Multiple pre-exposure requests may be processed subject to operational resource limits. Only one ceremony per pairing authority may hold the exposed-ceremony guard. A competing request may not cross exposure while it is occupied.
- Every fresh exposure requires local authorization and atomic acquisition of the authority-wide guard plus reservation of one opportunity from that process/session's shared 10-opportunity budget. Concurrent callbacks/requests cannot produce a second exposure or an uncharged release. Separate instances sharing the authority must coordinate; a process-local mutex is insufficient.
- On process restart, in-flight ceremonies and approvals are discarded and cannot resume. The prior process/session budget ends; the new process/session begins a new budget of up to 10. No lifetime bound is implied. An old `START` may be handled as pre-exposure traffic, but any new exposure requires fresh local authorization, fresh unpredictable ephemeral material, and a new atomic reservation. No old result or approval carries over.
- Ephemeral key material is generated fresh and unpredictably for every ceremony and never reused. Forks, VM snapshots, restored state, RNG failure, or duplicated cryptographic state must not repeat key material; if freshness cannot be guaranteed after such an event, exposure fails closed until a verified freshness mechanism applies. No snapshot/rollback resistance is claimed without verification.
- Once a ceremony terminates, later network messages, callbacks, approvals, acknowledgements, and reconnects cannot revive it (I1). Termination invalidates and withdraws its SAS from the active comparison interface and rejects later approval callbacks (I2). The human-comparison assumption is that people compare currently live values; the software cannot prevent memory or verbal reuse of old codes.

### 11.3 Timeouts, cancellation, and cleanup

Each ceremony has a non-extendable absolute deadline of **5 minutes** and a **60-second machine/protocol inactivity deadline**. These are candidate timing values subject to independent review. The Initiator's absolute deadline starts when its local ceremony state is created. The Responder's starts when a valid bounded `START` passes local admission and is accepted for active ceremony creation; transport byte/frame receipt time and discovery traffic do not start it. Transport slowloris/time-to-receive-frame policy remains a transport/resource concern. Both deadlines use a suitable monotonic elapsed-time source; wall-clock changes MUST NOT extend a ceremony.

The 60-second inactivity deadline applies while the state machine waits for machine/protocol progress, including waits for `ACCEPT`, `INITIATOR_KEY`, `RESPONDER_KEY`, authenticated MACs, or completion messages. It does not apply while the complete SAS is displayed and the protocol is waiting for deliberate human match/approve, mismatch/reject, or cancel input. The 5-minute absolute deadline still applies during human approval. Only a valid expected state-advancing protocol event or meaningful protocol-local transition refreshes inactivity. Malformed or unrelated traffic, illegal messages, exact duplicates, replays, keepalives, and UI activity do not. No event or approval refreshes the absolute deadline.

An expired deadline makes the ceremony terminally fail. Timeout invalidates and withdraws the SAS, invalidates local approval, drops native SAS/session state, produces no success, and prevents later-message resurrection. The pairing-authority guard is released only after terminal state and SAS/callback invalidation are irrevocable. A timeout before atomic exposure reservation consumes no opportunity; once reservation succeeds, the opportunity remains consumed. The Initiator absolute timer starts at local state creation and the Responder absolute timer starts only after its bounded, locally admitted `START` is accepted into active state.

Deadlines MUST use a monotonic source suitable for the platform. On resume from system suspension, the endpoint MUST re-evaluate deadlines conservatively; if elapsed time cannot be established safely, it fails active ceremonies rather than extending them indefinitely. In-flight ceremonies do not survive process restart: restart aborts active runs, discards approvals, drops volatile secrets, and starts a new local process/session opportunity budget. A shared authority coordinator must ensure a crashed instance's guard cannot be mistaken for a live ceremony or released before the old state is irrevocably unable to succeed. A consumer may separately decide whether its local listening policy survives restart, but network input MUST never authorize an exposure.

As supporting engineering precedent only, the current Matrix Rust SDK SAS state implementation defines a five-minute `MAX_AGE` and a 60-second `MAX_EVENT_TIMEOUT`; this does not establish that those values are universally optimal or prove this candidate's policy.

Local timeout immediately makes the ceremony terminal and best-effort sends authenticated `CANCEL` if a shared SAS state exists. The peer's receipt is not required to make local cancellation terminal. A peer timeout, disconnect, or cancellation also terminates locally. No resumption is supported.

Cancellation before shared SAS establishment is local behavior: the participant closes its local flow, and no authenticated remote `CANCEL` exists. A received wire `CANCEL` before shared SAS establishment is invalid input and MUST NOT be interpreted as authenticated peer cancellation; while a ceremony is active it causes terminal protocol failure under §11.4.

After shared SAS establishment, the wire message remains `CANCEL / 0x09` as defined in §6. The sender includes its role, a reason code, and the raw 32-byte MAC. To calculate that MAC, construct the separate **non-wire** `CancelAuthFrame / 0x34` using the canonical frame encoding in §3.1, with these fields in exactly this order: protocol domain ASCII `org.sas-pairing`; profile-identifier ASCII bytes; version `u16be(1)`; sender role code (`0x01` I or `0x02` R); receiver role code (the other role); authoritative ceremony identity (the transcript digest); reason code. The `0x34` value is only this authentication frame's type byte; it is never a network message type. The receiver role is included to bind direction.

The MAC input is exactly the unpadded Base64url encoding of the complete canonical `CancelAuthFrame` bytes. The sender calculates the MAC with the §3.2 context-string construction, purpose `cancel`, and a context containing the same protocol domain, profile identifier, version, sender role, receiver role, authoritative ceremony identity, and reason code. The wire MAC field is excluded from both the authentication frame and its input, so there is no circular definition. The receiver reconstructs the expected frame and context from the received wire `CANCEL` and local ceremony state, then verifies the raw 32-byte tag before terminating only that exact active ceremony. A missing, malformed, or invalid tag is terminal failure and is not authenticated peer cancellation. A valid cancel for an unknown or stale ceremony identity cannot affect another flow. Secret cleanup on terminal paths follows the exact X25519 zeroization boundary and limitations in §5; no protocol success is possible after terminal cleanup.

### 11.4 Fail-closed cases

Malformed/truncated/noncanonical frame; unsupported profile/version; repeated or missing field; invalid bootstrap; context mismatch; invalid or non-contributory key; commitment mismatch; SAS mismatch/rejection; MAC mismatch; expected-peer mismatch; or, while active, a non-`START` message for an unknown/stale request ID, a changed duplicate, wrong-state/reordered message, or wrong-role message causes terminal failure and no result. A valid `START` for a reused or historically seen request ID may instead begin a new policy-eligible attempt. An exact duplicate of a previously accepted inbound message for the same active run and sender is ignored without state change or repeated output. Before shared SAS establishment, a wire `CANCEL` is invalid and is not authenticated peer cancellation. After `Succeeded` or `Failed`, later messages are ignored or rejected at the protocol boundary and cannot change state or emit another result. There is no silent fallback to Candidate B, another vodozemac API mode, Matrix identity semantics, same-device pairing, or a weaker suite. Candidate B's prior P2 abstract selection remains separate from this candidate; neither is currently selected for final remote-profile use.

## 12. Vector schema and current vector status

Deterministic candidate values remain in the [remote vodozemac fixture](../vectors/p3-remote-vodozemac-draft-01.json), documented in [P3 deterministic vectors](p3-deterministic-vectors.md). They specify bytes and derivations only; this remediation changes no vector bytes. The updated state/admission requirements are documented in the conformance matrix. Add documentation-only cases for Initiator key generation after ACCEPT validation; atomic authority-guard and session-opportunity reservation; rejection of a second exposure while occupied; no charge for pre-exposure refusal; no refund after exposure; explicit local authorization for each fresh exposure; terminal irreversibility; stale approval rejection; SAS invalidation/withdrawal; and the shared 10-opportunity limit across both roles. Keep the old 8-slot and 5,497-epoch cases clearly historical. These are documented cases, not executable tests.

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

Test private inputs MUST be clearly synthetic and MUST NOT be used in production. Future build/lifecycle checks MUST confirm the pinned 0.11.0 SAS API is available with the selected feature set, `libolm-compat` is absent, symmetric SAS derivation succeeds, non-contributory peers and malformed public-key lengths are rejected, and the native SAS session is destroyed on terminal paths. Do not attempt unsafe freed-memory zeroization tests. The existing vectors show encoding/derivation reproducibility only; they do not prove protocol security. Further boundary and state-machine cases remain in the conformance matrix.

## 13. Source traceability

| Mechanism | Source and what is inherited | What this profile adds / classification |
|---|---|---|
| Application-neutral roles, per-ceremony approval, exact authenticated bootstrap, no possession claim | P1 threat model and P2 selected result requirements | Role-specific candidate vodozemac flow; project adaptation, not P2 Candidate B |
| Exact candidate dependency and feature configuration | vodozemac 0.11.0 tag, tagged manifest, and crates.io package/index metadata | Documentation/specification pin only; no P3 Cargo dependency; P4 lockfile graph must be captured and reviewed |
| Curve25519 SAS key generation, contributory DH rejection, HKDF-derived bytes, decimal SAS, HMAC-SHA-256 MAC API | vodozemac 0.11.0 tagged `Sas`, `EstablishedSas`, and `SasBytes` API/source | The composed ceremony and contexts are new; candidate, review required |
| Commit-before-reveal ordering | Matrix Client-Server v1.18 `m.sas.v1` uses responder commit-before-reveal tied to initiator start content, with I revealing its key before R reveals its committed key | Protocol-purpose precedent only; the complete generic ceremony remains a project adaptation |
| Exact binary commitment input | No exact generic encoding is inherited from Matrix | Domain, length framing, canonical `START`, and exact `R_pub` encoding are sas-pairing-specific |
| Single-attempt binding | Matrix specifies SHA-256 in its own ceremony | This profile relies on SHA-256 collision resistance for the exact encoded input; profile-specific assumption, not inherited proof |
| Hiding of the unrevealed responder key | No hiding proof for this generic construction is inherited from Matrix | High-entropy vodozemac key generation plus a random-oracle-style SHA-256 assumption; profile-specific and subject to independent review |
| Three 13-bit decimal groups, 39 exact-match bits | Matrix decimal SAS representation and vodozemac `SasBytes::decimals()` | Retained candidate representation; defensible only under a reviewed bounded aggregate-attempt model and honest complete-comparison assumptions; not a production selection or proof |
| Canonical binary frame and strict unpadded Base64url string bridge | No canonical generic encoding is inherited from Matrix/vodozemac | Entire framing, context-purpose strings, and bootstrap schema are project adaptations requiring review |
| Owner-selected exposure accounting | One live exposed ceremony per pairing authority; 10 opportunities per process/session across roles | Owner decision. Structural pair count is `n_A + n_B - 1`; 19 applies only to a joint 10/10 window. No persistent lifetime accounting. |
| Proposed per-pair argument | `P_per_pair ≤ 2^-39 + δ`; `P_joint ≤ 19 × 2^-39 + ε` for a 10/10 joint window | Conditional reconstruction in §7. Second adversarial AI review verdict: PREVIOUS PROOF NOT ESTABLISHED. Independent qualified human verification remains open. |
| Request-ID generation and routing policy | Candidate policy defined in §4; request IDs are public routing context, not an authentication or freshness assumption | Independent review must assess routing isolation and the distinct ephemeral-key freshness requirements on supported targets |
| Completion messages and asymmetric local return guarantee | P1 requires mutually authenticated local completion evidence and compatible results | Three-message confirmation and its exact limitation are project adaptations requiring independent review against the clarified local-result contract |
| External identity, authorization, and proof of possession | P1/P2 distinguish authenticated bytes from external truth and key control | Consumer validation boundary restated; protocol claim deliberately limited |

Primary references checked for this draft: [Matrix Client-Server Specification v1.18 SAS verification](https://spec.matrix.org/v1.18/client-server-api/#short-authentication-string-sas-verification); vodozemac [0.11.0 SAS source](https://github.com/matrix-org/vodozemac/blob/db1b34820f3102307284e762f335b3f72c735bf0/src/sas.rs), [tagged Cargo manifest](https://github.com/matrix-org/vodozemac/blob/db1b34820f3102307284e762f335b3f72c735bf0/Cargo.toml), [crate metadata](https://crates.io/crates/vodozemac/0.11.0), and [published archive](https://static.crates.io/crates/vodozemac/vodozemac-0.11.0.crate); [Rand 0.10.2 ThreadRng source](https://github.com/rust-random/rand/blob/0.10.2/src/rngs/thread.rs) and [x25519-dalek 3.0.0 source](https://docs.rs/crate/x25519-dalek/3.0.0/source/src/x25519.rs); [RFC 4648 Base64url](https://www.rfc-editor.org/rfc/rfc4648.html#section-5); project [P1 threat model](threat-model.md), [P2 construction selection](construction-selection.md), [P3 profile foundation](protocol-profile-v1-draft.md), [Candidate B instantiation research](p3-candidate-b-instantiation-research.md), and [P3.4 vodozemac reuse assessment](p3-vodozemac-reuse-assessment.md).

## 14. Required independent-review decisions

This candidate is reviewable as a precise message/encoding proposal but is not complete enough for selection or implementation. Review must explicitly answer:

1. Does SHA-256 collision resistance adequately provide the required single-attempt binding for this exact encoded commitment input?
2. Is the random-oracle-style hiding assumption acceptable for an honestly generated high-entropy vodozemac responder public key, given that collision resistance and ordinary preimage resistance alone do not prove hiding?
3. Does the pinned vodozemac 0.11.0 release and its exact P4-resolved RNG/key-generation path provide adequate unpredictability/min-entropy against the intended adversary and query budget, on each supported target OS?
4. Does the proposed conditional argument in §7 justify `P_per_pair ≤ 2^-39 + δ` against adaptive scheduling and selective aborts under the explicit assumptions? Are all fresh exposures counted once?
5. Does the transcript/role/domain binding cover reflection, unknown-key-share, and misbinding cases?
6. Does vodozemac 0.11.0's released API and specific X25519 zeroization-on-drop boundary support this lifecycle, canonical byte-to-string mapping, and the proposed generic SAS/MAC contexts, and are its temporary-material limitations adequate?
7. Does the idealized conditional bound appropriately account for SHA-256 commitment binding/hiding, HKDF-SHA256, fresh key generation, and accepted X25519 inputs? Do not assign numeric values to `δ` or `ε` without a supported derivation.
8. Does the specified atomic authority guard plus 10-opportunity process/session reservation enforce one live exposure across roles, connections, and instances, with no lifetime claim across restarts?
9. Can an implementation enforce the atomic pairing-authority guard across every relevant process/instance while atomically reserving the local process/session opportunity? Is the fail-closed behavior adequate when coordination is unavailable or ambiguous?
10. Is full-value comparison guidance adequate for the intended UI/accessibility environment?
11. Are the request-ID rules and candidate 5-minute absolute and 60-second inactivity deadlines suitable? Which pre-exposure operational resource controls are needed without changing the owner-selected SAS exposure policy?
12. Do the adopted field, frame, and Base64url maxima adequately bound resource use for intended deployments? Which pre-exposure resource limits are needed operationally without changing the owner-selected SAS exposure policy?
13. Does the three-message completion contract provide the required compatible local results under asymmetric message loss, without claiming simultaneous success or distributed atomic commit?
14. Are the locally independent exact-context and expected-peer semantics in §8 appropriate, including deliberate open mode, partial expectations, fail-closed behavior, and the pre-exposure timing on both roles?
15. Does the transcript-derived authoritative ceremony identity, incorporating fresh responder material and all bound transcript values, adequately render replayed pre-establishment requests ineffective as replay of an old authenticated ceremony?
16. Does this candidate satisfy each P1 property under its actual cryptographic, transport, endpoint, human-comparison, and attempt assumptions? If not, identify the requirement that must be narrowed or reject this candidate.

The owner-selected pairing-authority guard, 10-opportunity process/session ceiling, explicit per-exposure local authorization, field/frame/Base64url caps, application-context/expected-peer semantics, and candidate timeout rules are recorded here, but remain subject to independent review. Historical eight-slot, durable `5,497`-epoch, and global rate-control decisions are non-normative. Cross-instance guard implementation, target-specific ephemeral freshness, RNG/fork/snapshot limitations, clock/suspend behavior, the separate same-device profile, and final conformance review remain open. Deterministic vectors do not establish security. The profile remains **CANDIDATE — NOT SELECTED — REQUIRES INDEPENDENT SECURITY REVIEW**. The immediate next step is focused independent verification of the corrected conditional argument and specification; it does not authorize production implementation.
