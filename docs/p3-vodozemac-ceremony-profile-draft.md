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

## 2. Roles and fixed profile values

There are exactly two protocol roles:

- **Initiator (I)** creates a ceremony identifier and sends `START`.
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

Every **wire message** has two common fields immediately after `message_type`: the exact profile-identifier ASCII bytes, then the ceremony-identifier bytes. The type-specific fields follow. `START` therefore carries its own new identifier; every later message repeats it. A receiver checks both common fields before dispatch. The bootstrap and context frames are not wire messages and contain only the fields specified for them.

Each field is encoded as `u32be(byte_length) || value`. Fields are present exactly once, in table order. No unknown, duplicate, reordered, omitted, or trailing fields are accepted. A field with a fixed length MUST have that length. A frame ends exactly at the end of its final field. All integers are unsigned big-endian fixed-width values. A parser MUST reject truncation, overflow, noncanonical representation, and trailing bytes before changing ceremony state.

The maximum encodable field length is exactly `2^32 - 1` bytes. The practical per-message and per-bootstrap resource cap is **REVIEW REQUIRED**; deployments MUST impose a bounded transport/parser cap and fail closed, but this draft does not choose a number without workload and denial-of-service analysis. Cryptographic inputs use the complete accepted canonical frame, never a decoded-and-reserialized approximation.

The fixed text constants in this document are ASCII byte strings. Text fields use ASCII only and must match their stated byte grammar. Other application values are opaque byte strings; they are not decoded as text and receive no Unicode normalization.

### 3.2 Cryptographic context encoding

For HKDF `info` and vodozemac MAC `info`, encode a context as a frame with the same header and version, a distinct context-type byte, and the fields specified below. Convert that complete frame to **unpadded Base64url** as defined by RFC 4648 §5. Use only ASCII characters `A-Z`, `a-z`, `0-9`, `-`, and `_`; omit `=` padding. The consumer MUST reject padding, other characters, impossible lengths, and noncanonical encodings (decode, re-encode, and require byte-for-byte equality).

The API receives the exact ASCII string:

```text
"sas-pairing-vodozemac-profile-draft-01/" || purpose || "/" || base64url(context_frame)
```

`purpose` is one of the fixed ASCII strings defined below. This transformation is injective for each purpose and preserves arbitrary context bytes across the vodozemac API's `&str` boundary. It is a project encoding rule, not a Matrix rule.

## 4. Ceremony identifier and bootstrap record

I creates one fresh, nonempty identifier before constructing `START`. The identifier is an opaque byte string of 1–`2^32 - 1` bytes, encoded as one length-prefixed field and copied unchanged into every context, wire message, and result for that ceremony. Its exact minimum entropy, generation method, and collision target are **REVIEW REQUIRED**; P1/P2 do not justify a numeric value. The profile cannot be selected until a reviewer accepts those values and the implementation's CSPRNG source.

An identifier MUST be unique among active ceremonies for the local participant. A collision with active or retained terminal state MUST fail closed and require a fresh identifier. Concurrent ceremonies use distinct identifiers and independent state. An unknown, expired, failed, or completed identifier cannot create state from a later message. A retry always starts a new ceremony with a new identifier; old messages and approvals never transfer.

At process restart, every in-flight ceremony is aborted; ephemeral secrets and pending approval are destroyed, and no ceremony resumes. Late messages are rejected as unknown. Whether terminal IDs need durable retention depends on the accepted identifier-reuse bound and attempt policy and is **REVIEW REQUIRED**. Any attempt accounting required by the security bound must survive restart and rollback; the storage and atomic-update requirements are also **REVIEW REQUIRED**. This draft does not silently assume that volatile state enforces a lifetime-wide limit.

Each participant supplies one canonical bootstrap record before the ceremony starts:

| Field | Required bytes and meaning |
|---|---|
| `application_identity` | 1–`2^32 - 1` opaque bytes identifying the application principal being described. Exact bytes are authenticated; the protocol does not establish their external truth. |
| `key_algorithm` | 1–64 ASCII bytes matching `[a-z0-9][a-z0-9.-]*`; identifies the interpretation the consumer assigns to the following key. |
| `public_key` | 1–`2^32 - 1` exact public-key bytes associated by the sender with `key_algorithm`; the consumer validates encoding and expected-peer policy. |
| `shared_context` | Opaque bytes describing the security-relevant application context. It is mandatory and may be empty. Both participants MUST require byte-for-byte equality before SAS approval. |

The bootstrap record is a frame of type `0x20`, version `1`, with exactly those four fields in that order. Each field is length-prefixed by the frame rule. The bootstrap's maximum accepted size is the unresolved resource cap above. There are no extension or optional fields in this draft. Adding a field changes the profile/version.

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

`R_pub` is fixed at 32 bytes, so the final concatenation is unambiguous; `START` is length-framed. R sends the commitment before it receives `I_pub`, and reveals `R_pub` only after receiving `I_pub`. I recomputes the digest over its exact sent `START` bytes and the revealed 32-byte key, then compares all 32 bytes. A mismatch aborts the ceremony and produces no SAS, MAC, or result.

The purpose is to prevent R from choosing or changing its ephemeral public key after seeing I's key: changing a previously committed key requires breaking SHA-256's binding property, while the commit-before-reveal ordering hides the unrevealed key under the hash assumption. **Source distinction:** Matrix `m.sas.v1` commits to the canonical start event and responder key before reveal and specifies SHA-256. This draft adapts that ordering and binding purpose to the binary `START` frame and explicit domain string; the exact generic construction and its security argument are project-specific and require independent review. Matrix's security properties are not claimed for this adaptation.

I creates one `Sas` object after validating `ACCEPT`, sends its 32-byte public key, and R reveals the public key for its retained object. Each side passes the peer's exact 32-byte value to `Sas::diffie_hellman`. A non-contributory/invalid peer key is a terminal failure. No public-key text encoding is used on the wire.

The resulting `EstablishedSas` object is retained only while the ceremony needs SAS and MAC operations. Implementations MUST destroy the ephemeral `Sas`, shared-secret state, derived SAS bytes, and temporary MAC inputs on any terminal outcome, cancellation, expiry, or process teardown, using the destruction guarantees actually provided by the selected library/runtime. Whether upstream zeroization guarantees suffice is **REVIEW REQUIRED**. The DH secret MUST NOT be returned, persisted as application trust, or reused as a pairing key.

## 6. Exact message flow

Only the following messages exist in this draft. Every network message has the global frame header and the exact fields shown. Sender role is implicit in message type, and a message received from the wrong role fails closed. Except for `START`, `ACCEPT`, and key-exchange messages, the message body is authenticated by a direction-specific vodozemac MAC as specified in §§8–11.3. There are no transport-level acknowledgements that alter protocol state.

| # | Message/type | Sender → receiver | Fields after header | Permitted state and effect |
|---|---|---|---|---|
| 1 | `START` / `0x01` | I → R | common fields; I bootstrap frame | R accepts only as a new, policy-eligible ID and validates the bootstrap; otherwise reject without creating successful state. |
| 2 | `ACCEPT` / `0x02` | R → I | common fields; 32-byte commitment; R bootstrap frame | R has already generated its ephemeral key and fixed the commitment. I validates profile, ID, bootstrap/context equality, and policy before continuing. |
| 3 | `INITIATOR_KEY` / `0x03` | I → R | common fields; 32-byte `I_pub` | I sends only after accepting `ACCEPT`; R accepts only once for this ceremony. |
| 4 | `RESPONDER_KEY` / `0x04` | R → I | common fields; 32-byte `R_pub` | R reveals only after accepting `INITIATOR_KEY`; I verifies the commitment before DH. |
| 5 | `BOOTSTRAP_MAC` / `0x05` | I ↔ R, one each | common fields; role code (`0x01` I, `0x02` R); raw 32-byte MAC | Sender sends only after local match approval. The authenticated statement covers that approval, the full SAS, and bootstrap. |
| 6 | `INITIATOR_FINISH` / `0x06` | I → R | common fields; transcript digest (32 bytes); raw 32-byte MAC | I sends only after its approval MAC was sent and R's approval MAC was verified. |
| 7 | `RESPONDER_FINISH_ACK` / `0x07` | R → I | common fields; same transcript digest; raw 32-byte MAC | R sends only after its approval MAC was sent, I's approval MAC was verified, and valid `INITIATOR_FINISH`. |
| 8 | `INITIATOR_FINISH_ACK` / `0x08` | I → R | common fields; same transcript digest; raw 32-byte MAC | I sends only after verifying `RESPONDER_FINISH_ACK`. I may return its result after sending this message. |
| 9 | `CANCEL` / `0x09` | either → peer | common fields; sender role code; reason code; raw 32-byte MAC after DH | Terminates only the named ceremony. Before DH, cancellation is local transport closure; no unauthenticated remote `CANCEL` is defined. |

For `CANCEL`, reason codes are `0x01` user rejection, `0x02` user cancellation, `0x03` timeout, and `0x04` local policy failure. The reason is diagnostic and does not change failure semantics. If no shared secret exists, cancellation is local transport closure; it is never accepted as evidence of peer authentication.

I and R may send their `BOOTSTRAP_MAC` messages concurrently after their own user approves. Either may arrive first. No other reordering is legal. An exact duplicate of a message already accepted for the current active ceremony is ignored without a second transition; a changed duplicate, stale/terminal message, out-of-order message, cross-ceremony message, or wrong-role message fails closed. Messages are never queued for a future state. A duplicate never triggers a second result.

## 7. SAS derivation and human comparison

After commitment verification and successful DH, each participant constructs one identical SAS context frame of type `0x30` with these fields, in this order:

1. protocol domain ASCII `org.sas-pairing`;
2. profile identifier ASCII `sas-pairing-vodozemac-profile-draft-01`;
3. version `u16be(1)`;
4. ceremony ID bytes;
5. complete canonical `START` frame;
6. complete canonical `ACCEPT` frame;
7. `I_pub` (32 bytes);
8. `R_pub` (32 bytes).

Both call `EstablishedSas::bytes` with purpose `sas` and the exact context-string construction in §3.2. This binds domain, profile, version, roles (by fixed key ordering), ceremony, both bootstraps (inside `START` and `ACCEPT`), commitment, and both ephemeral keys. The SAS is derived only after all inputs are fixed. This is a project-specific HKDF context; Matrix's identity/device-specific context is not copied. Independent review must confirm that this use binds the intended peer/context and does not claim properties beyond the API and construction.

The specified representation is exactly `SasBytes::decimals()`: three unsigned values formed by the vodozemac/Matrix decimal mapping, each in `1000..=9191`, rendered as four ASCII decimal digits separated by one ASCII space, for example `1234 5678 9012`. Leading digits are not omitted. The underlying representation uses 3 × 13 bits, or 39 bits of exact-match space.

**The representation is not an accepted security target.** Whether 39 bits is adequate under the required aggregate attempt model is **REVIEW REQUIRED**. The profile MUST NOT be selected or described as meeting P1's security target until that target and its attempt bound are justified. No user types or transcribes this SAS. It is compared in full, is not secret, is not a password, and is not a bearer credential.

Each consumer displays the complete value for this active ceremony. Each participant has a ceremony-scoped local action: `MATCH/APPROVE`, `MISMATCH/REJECT`, or `CANCEL`. Only an explicit full-value match approval proceeds. A mismatch/reject or cancellation is terminal. Partial comparison, automatic matching, prior approval, or a display from another ceremony cannot authorize success. Both participants must approve their own displayed SAS and satisfy the authenticated completion flow. The bound assumes the human completes the comparison as intended; it does not account for arbitrary human error, coercion, display compromise, or a perfect authenticated human channel.

## 8. Bootstrap MAC and expected-peer validation

After local SAS approval, each side authenticates one exact approval statement. For sender role `r` (`I=0x01`, `R=0x02`), define an approval frame of type `0x33` with fields in this order: protocol domain; profile identifier; version; sender role code; ceremony ID; the exact six raw `SasBytes`; the sender's complete canonical bootstrap frame. This states that the sender approves the full displayed SAS and authenticates that sender's exact bootstrap.

Define a context frame of type `0x31` with fields in this order: protocol domain; profile identifier; version; purpose ASCII `match-approve-bootstrap`; sender role code; receiver role code; ceremony ID; `I_pub`; `R_pub`; SHA-256 of the complete `START`; SHA-256 of the complete `ACCEPT`. The MAC info string is the §3.2 context string with purpose `mac` and this frame.

Because vodozemac accepts UTF-8 strings, transform the complete approval frame into exactly `input = unpadded_Base64url(approval_frame)` using the §3.1 canonicality rules. The sender calls `EstablishedSas::calculate_mac(input, info)` and sends the 32 raw bytes from `Mac::as_bytes()`. The receiver reconstructs the expected approval frame using the peer's role, this ceremony's six SAS bytes, and the exact peer bootstrap, then constructs `Mac::from_slice(received_32_bytes)` and calls `verify_mac(input, info, &tag)`. The wire tag MUST be exactly 32 bytes. No Matrix key-ID-list MAC semantics or legacy invalid-Base64 compatibility method is used.

This MAC authenticates the sender's explicit match-approval statement, the complete SAS value, the exact bootstrap bytes, and direction in this ceremony, under the SAS shared secret, subject to review of the complete construction. A verification error, wrong role, wrong ceremony, wrong context, or unexpected peer bootstrap is terminal and returns no result. The protocol cannot establish that a human actually compared correctly; it assumes each honest endpoint emits this statement only after its own explicit approval.

Before or during the ceremony, the consumer may provide expected peer properties. The consumer MUST compare them to the decoded/authenticated bootstrap fields using exact byte equality and its own key-format rules; a mismatch rejects pairing. The responsibilities remain distinct:

1. **Protocol authentication:** verifies the exact peer-supplied bytes and context for this ceremony.
2. **External truth:** determines whether the claimed application identity or key is known/valid; the ceremony cannot prove this.
3. **Authorization:** decides what the local application permits; pairing does not grant it.
4. **Proof of possession:** must be established later by a protocol that verifies a fresh proof under the exact authenticated/pinned key bytes.

If the consumer has no expected-peer policy, the result remains authenticated peer-supplied data only. “Whatever identity the peer supplied” MUST NOT be silently promoted to externally trusted identity.

## 9. Completion and result semantics

Completion MAC contexts use type `0x32` and include protocol domain, profile identifier, version, purpose, fixed sender/receiver role codes, ceremony ID, and SHA-256 of the complete transcript through `RESPONDER_KEY`. The transcript digest is exactly SHA-256 of `ASCII("sas-pairing-vodozemac-profile-draft-01/transcript/v1")` followed by the complete canonical `START`, `ACCEPT`, `INITIATOR_KEY`, and `RESPONDER_KEY` frames, each preceded by `u32be(length)`. This digest is carried in each completion message and MUST match the receiver's locally computed digest.

The completion-purpose strings are fixed ASCII values `initiator-finish`, `responder-finish-ack`, and `initiator-finish-ack`. Each message's MAC input is the unpadded Base64url encoding of its complete canonical message frame with the MAC field omitted; its MAC info uses the matching purpose and sender/receiver role order. Each receiver verifies the MAC before state transition. A completion message for another transcript or ceremony fails closed.

The completion conditions are:

- I returns `PairingResult` only after it sent its own approval MAC, verified R's approval MAC, verified `RESPONDER_FINISH_ACK`, and sent `INITIATOR_FINISH_ACK`.
- R returns `PairingResult` only after it sent its own approval MAC, verified I's approval MAC, verified `INITIATOR_FINISH`, sent `RESPONDER_FINISH_ACK`, and then verified `INITIATOR_FINISH_ACK`.
- A disconnect before a participant's condition is met produces failure locally and no result. A validly sent message is not evidence of delivery or of durable application storage.
- A MAC success without completed terminal messaging is not success. A late `done` equivalent is not defined: every late completion message is rejected after terminal state and cannot revive it.

This finite exchange does **not** implement atomic distributed commit. In particular, I can meet its return condition after sending `INITIATOR_FINISH_ACK` while that final message is lost; R then fails to observe completion. Thus one endpoint may return while the other does not under message loss. The precise guarantee is local verified completion under the conditions above, not common knowledge, simultaneous success, or atomic durable trust. Consumers MUST treat the result as ceremony-scoped and handle an unavailable peer according to their own trust policy; they MUST NOT claim both applications durably stored trust. A reviewer must decide whether this limitation satisfies P1's bilateral-completion requirement or requires a different result contract.

The abstract protocol result is:

```text
PairingResult {
    ceremony_id: exact opaque identifier bytes,
    peer_role: Initiator | Responder,
    authenticated_peer_bootstrap: exact canonical bootstrap frame bytes,
    authenticated_shared_context: exact shared_context bytes,
    profile_identifier: "sas-pairing-vodozemac-profile-draft-01",
    profile_version: 1,
}
```

It contains no ephemeral DH secret, reusable pairing secret, local authorization decision, external identity verdict, or proof-of-possession claim. This is a protocol-domain shape, not a language API.

## 10. Normative state machine

The states below are per role and per ceremony. State transitions are atomic with message validation. Any invalid message, failed validation, explicit rejection, timeout, or cancellation transitions to terminal `Failed`; the cause may be retained for diagnostics but must not change acceptance behavior.

| State | Legal incoming message / local action | Transition and forbidden behavior |
|---|---|---|
| `Idle` | I local `Start` with new ID and bootstrap; R valid `START` | I → `AwaitAccept`; R → `AwaitInitiatorKey` after validating `START`, recording it, generating R key, and sending `ACCEPT`. Other messages fail. Every message thereafter repeats the exact profile ID and ceremony ID in its common fields. |
| `AwaitAccept` (I) | One valid `ACCEPT` for exact ID/profile | Validate bootstrap/context and commitment format; create I ephemeral key, send `INITIATOR_KEY`; → `AwaitResponderKey`. Duplicate/reordered input fails. |
| `AwaitInitiatorKey` (R) | One 32-byte `INITIATOR_KEY` for exact ID | Reveal R public key; perform DH; → `AwaitLocalApproval`. No key reveal before this input. |
| `AwaitResponderKey` (I) | One 32-byte `RESPONDER_KEY` | Verify commitment, then perform DH; → `AwaitLocalApproval`. No SAS before commitment succeeds. |
| `AwaitLocalApproval` | Local display; `MATCH/APPROVE`, `MISMATCH/REJECT`, `CANCEL`; peer approval MAC may arrive before or after local action | Match records one ceremony-scoped approval and sends own `BOOTSTRAP_MAC` containing the authenticated approval statement; rejection/cancel → `Failed`; once the local match and peer approval MAC are verified → I sends `INITIATOR_FINISH` and enters `AwaitResponderFinish`, R enters `AwaitInitiatorFinish`. No completion before all conditions. |
| `AwaitResponderFinish` (I) | Valid `RESPONDER_FINISH_ACK` after I sent `INITIATOR_FINISH` | After valid ACK, send `INITIATOR_FINISH_ACK`, return result, → `Succeeded`. |
| `AwaitInitiatorFinish` (R) | Valid `INITIATOR_FINISH` | R has already sent its approval MAC and verified I's; verify finish and send `RESPONDER_FINISH_ACK`; → `AwaitInitiatorFinishAck`. |
| `AwaitInitiatorFinishAck` (R) | Valid `INITIATOR_FINISH_ACK` matching transcript | Verify; return result; → `Succeeded`. |
| `Succeeded` | No protocol message or local action | Terminal. Duplicates/late messages are ignored or rejected by the transport boundary and never change result or state. |
| `Failed` | No protocol message or approval | Terminal. State, approval, and secrets cannot be reused. A retry creates a new ceremony. |

Where a table transition says “both MACs,” each party has verified the peer's single bootstrap MAC and locally computed its own; receipt of both wire MACs is not required if own MAC was sent. The transcript, approval flags, role, and peer identity remain attached to the one ceremony state object. Approval for one ID cannot satisfy another.

## 11. Retry, replay, time, cancellation, and failure policy

### 11.1 Attempts and rate policy

Every rejection, SAS mismatch, failed MAC, timeout, or abandoned attempt terminates that ID. Any retry is a new ID, new ephemeral keys, new commitment, and new SAS. There is no unlimited retry guarantee.

The maximum attempts per peer, global attempt budget, accounting window, cooldown/lockout, timeout duration, ceremony lifetime, terminal-ID retention, and restart/rollback behavior are **REVIEW REQUIRED**. Candidate B's P2 theorem and the Matrix profile do not supply justified values for this distinct vodozemac ceremony. Until an independent analysis defines a bound and durable enforcement, no P1-level active-attacker security bound may be claimed and this profile cannot be selected. If the bound requires accounting, the required state MUST survive restart and rollback; inability to persist it means fail closed for new ceremonies until policy permits them.

### 11.2 Freshness, replay, and concurrency

- Replayed `START` for an active ID is ignored only if byte-identical to the accepted start; changed bytes fail. A start using a retained terminal ID is rejected and never replaces state.
- Replayed `ACCEPT`, key, bootstrap MAC, or completion message cannot advance a different state, role, or ID.
- A message from another concurrent ceremony is rejected as an ID mismatch and cannot satisfy this ceremony.
- Duplicate delivery in the one state that accepted a message is idempotent only for the exact previously accepted bytes. Changed duplicates fail.
- Reordered, delayed, unknown, expired, terminal, or wrong-role messages fail closed and never create a ceremony.
- On process restart, all in-flight state and approvals are lost and the run is aborted. Durable attempt accounting, if security analysis requires it, is separate and must not be reset by restart or rollback.
- No approval or result survives as authority for a later ceremony. Stale terminal messages cannot resurrect state.

### 11.3 Timeouts, cancellation, and cleanup

Each implementation enforces a monotonic local ceremony deadline, but its exact duration is **REVIEW REQUIRED**. Local timeout immediately makes the ceremony terminal, discards its ephemeral state, and best-effort sends authenticated `CANCEL` if a shared SAS state exists. The peer's receipt is not required to make local cancellation terminal. A peer timeout, disconnect, or cancellation also terminates locally. No resumption is supported.

Cancellation before key establishment closes the local flow; no remote cancellation message is accepted before DH. After establishment, the sender constructs a cancellation frame of type `0x34` containing protocol domain, profile identifier, version, sender role, ceremony ID, and reason code. Its MAC input is the unpadded Base64url encoding of that complete frame (without a tag field); its MAC info is the §3.2 context string with purpose `cancel` and the type-`0x34` frame's same values plus the receiver role. A receiver verifies the 32-byte tag with `verify_mac` before terminating the named active ceremony. A cancel for an unknown/stale ID cannot affect another flow. Secret cleanup occurs on every terminal path, including malformed input and panic/exception teardown to the extent guaranteed by implementation/runtime; cleanup guarantees require review against vodozemac's actual version.

### 11.4 Fail-closed cases

Malformed/truncated/noncanonical frame; unsupported profile/version; duplicate or missing field; invalid bootstrap; context mismatch; invalid or non-contributory key; commitment mismatch; SAS mismatch/rejection; MAC mismatch; expected-peer mismatch; unknown/stale ID; replay, duplicate-changed, out-of-order, or wrong-role input; timeout; cancellation; and duplicate completion all produce no result. There is no silent fallback to Candidate B, another vodozemac API mode, Matrix identity semantics, same-device pairing, or a weaker suite. Candidate B remains the project's selected remote construction independently of this candidate's outcome.

## 12. Vector schema (values deferred)

No final vector values are claimed in this draft. The following fixed-input/fixed-output schema is required for a later vector task after independent review resolves or accepts the profile:

- profile identifier/version, role, ceremony ID, and both bootstrap field values;
- fixed test-only initiator and responder ephemeral private inputs, their public keys, and invalid/non-contributory-key cases;
- canonical `START`, `ACCEPT`, key, MAC, cancellation, and completion frame bytes;
- commitment preimage and SHA-256 output;
- SAS context frame and exact HKDF `info` string;
- raw six SAS bytes and three decimal values/rendered string;
- both canonical bootstrap frames, each MAC context/info string, stringified MAC input, and raw MAC tag;
- transcript bytes/digest and all completion MAC inputs/contexts/tags;
- positive full ceremony result and negative mutation cases for role, ID, profile/version, context, key, commitment, bootstrap, MAC, transcript, ordering, replay, and completion.

Test private inputs MUST be clearly synthetic and MUST NOT be used in production. Vectors show encoding/interoperability only; they do not prove protocol security. Produce actual vectors only when the exact construction is accepted for vectorization; do not backfill values by guessing unresolved policies.

## 13. Source traceability

| Mechanism | Source and what is inherited | What this profile adds / classification |
|---|---|---|
| Application-neutral roles, per-ceremony approval, exact authenticated bootstrap, no possession claim | P1 threat model and P2 selected result requirements | Role-specific candidate vodozemac flow; project adaptation, not P2 Candidate B |
| Curve25519 SAS key generation, contributory DH rejection, HKDF-derived bytes, decimal SAS, HMAC-SHA-256 MAC API | Current vodozemac `Sas`, `EstablishedSas`, and `SasBytes` API/source | The composed ceremony and contexts are new; candidate, review required |
| Commit-before-reveal responder key tied to start | Matrix Client-Server v1.18 `m.sas.v1` structure uses a SHA-256 commitment over canonical start plus responder key | Binary framing, domain string, and generic roles/context are project adaptations; security equivalence is unresolved |
| Three 13-bit decimal groups, 39 exact-match bits | Matrix decimal SAS representation and vodozemac `SasBytes::decimals()` | Representation is specified; acceptance as a P1 security target is unresolved |
| Canonical binary frame and strict unpadded Base64url string bridge | No canonical generic encoding is inherited from Matrix/vodozemac | Entire framing, context-purpose strings, and bootstrap schema are project adaptations requiring review |
| Ceremony ID entropy, aggregate attempts, timeouts, persistence, restart policy | P1 identifies these as requirements; P2/P3.4 do not justify numeric policy for this candidate | Explicitly unresolved; no security value is invented |
| Completion messages and asymmetric local return guarantee | P1 requires bilateral completion; Matrix provides completion events, and P2 discusses message-loss limits | Three-message confirmation and its exact limitation are project adaptations; whether adequate for P1 is unresolved |
| External identity, authorization, and proof of possession | P1/P2 distinguish authenticated bytes from external truth and key control | Consumer validation boundary restated; protocol claim deliberately limited |

Primary references checked for this draft: [Matrix Client-Server Specification v1.18 SAS verification](https://spec.matrix.org/v1.18/client-server-api/#short-authentication-string-sas-verification); [vodozemac `sas` API](https://docs.rs/vodozemac/latest/vodozemac/sas/index.html), [`EstablishedSas` API](https://docs.rs/vodozemac/latest/vodozemac/sas/struct.EstablishedSas.html), and [SAS source](https://github.com/matrix-org/vodozemac/blob/main/src/sas.rs); [RFC 4648 Base64url](https://www.rfc-editor.org/rfc/rfc4648.html#section-5); project [P1 threat model](threat-model.md), [P2 construction selection](construction-selection.md), [P3 profile foundation](protocol-profile-v1-draft.md), [Candidate B instantiation research](p3-candidate-b-instantiation-research.md), and [P3.4 vodozemac reuse assessment](p3-vodozemac-reuse-assessment.md).

## 14. Required independent-review decisions

This candidate is reviewable as a precise message/encoding proposal but is not complete enough for selection or implementation. Review must explicitly answer:

1. Does this generic commit-before-reveal formula provide the needed hiding/binding and prevent adaptive responder-key choice under the stated ordering? Does the transcript/role/domain binding cover reflection, unknown-key-share, and misbinding cases?
2. Does vodozemac's current released API and zeroization behavior support this lifecycle, canonical byte-to-string mapping, and the proposed generic SAS/MAC contexts? Which exact upstream version is acceptable and reviewed?
3. Is Matrix decimal's 39-bit representation adequate for this project's target once human error, active concurrent sessions, aggregate attempts, and lifetime are modeled?
4. What ceremony-ID entropy/length, global and peer attempt limits, cooldown, timeout/lifetime, concurrency limits (if any), terminal-ID retention, and durable rollback-safe accounting are justified? Which state must persist, and what happens if atomic persistence fails?
5. What practical field/message caps are required to bound allocation and denial-of-service risk without excluding legitimate bootstrap values?
6. Does the three-message completion contract satisfy P1 despite possible asymmetric local success on message loss? If not, what application-level result semantics are supportable without claiming distributed atomic commit?
7. Are mandatory equal `shared_context` bytes the right generic application-context semantics, and how should expected-peer validation be represented without asserting external identity truth?
8. Does this candidate satisfy each P1 property under its actual cryptographic, transport, endpoint, human-comparison, and attempt assumptions? If not, identify the requirement that must be narrowed or reject this candidate.

Until these questions are resolved, the profile remains **CANDIDATE — NOT SELECTED — REQUIRES INDEPENDENT SECURITY REVIEW**. Candidate B remains selected for the existing P2 remote profile. The next gate is independent protocol/security review of this complete candidate document, not production implementation.
