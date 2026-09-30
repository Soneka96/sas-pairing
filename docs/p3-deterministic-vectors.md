# P3 deterministic vectors

> **DETERMINISTIC TEST VECTORS FOR CANDIDATE PROFILES — NOT PRODUCTION APPROVAL**

> **CR-01 LIMITATIONS:** The remote vector fixes ceremony bytes, not admission or attempt policy. Current owner policy is one owning process and one live exposed ceremony per pairing authority, with 10 opportunities shared across both roles, threads, and connections. The 19-pair maximum applies only to a joint 10/10 window where both endpoints remain within their process sessions; it is not a bound across arbitrary restarts. F-02 is a false positive under the stated idealized assumptions; the complete per-pair argument remains conditional and is not formally verified. The remote transcript bytes remain `u32be(len(domain)) || domain`; this documentation update changes no vector bytes.

## Status and scope

These fixtures instantiate the selected experimental remote vodozemac profile and the separate authenticated-local candidate. P2 historically selected Candidate B; the owner later reopened its implementation direction for custom cryptographic ownership reasons. Candidate B remains a formal reference and possible fallback, not disproven. The owner waived the qualified-human-review gate for experimental P4 only; no human audit is claimed. The local profile remains candidate-only, and the Windows adapter remains **CANDIDATE — PRINCIPAL-BOUND ONLY — NOT APPROVED**. The fixtures do not establish protocol security or production readiness.

| Candidate fixture | Profile identifier | Version |
|---|---|---:|
| Remote vodozemac | `sas-pairing-vodozemac-profile-draft-01` | `u16be(1)` |
| Authenticated-local | `sas-pairing-local-authenticated-profile-draft-01` | `u16be(1)` |

The fixtures are in [the remote JSON vector](../vectors/p3-remote-vodozemac-draft-01.json) and [the local JSON vector](../vectors/p3-local-authenticated-draft-01.json). All raw bytes are lowercase hexadecimal; lengths are byte counts. Frame integers use the widths and endianness in the profile. Every encoded frame includes the `SASPAIR` header, `u16be(1)` version, message/context type, and ordered `u32be(length) || value` fields. Remote wire frames include profile identifier and request ID as their first two fields. Local payloads are separately wrapped as `u32be(payload_length) || payload`; the prefix excludes itself.

## Deterministic inputs

The remote request ID, X25519 private inputs, and local nonces are fixed only to make these vectors reproducible. The request ID is exactly 16 bytes. **Production still requires the shared security core's OS-backed CSPRNG and active-ID collision handling.** Production vodozemac ephemeral keys still use the pinned dependency's RNG path. The fixed X25519 private inputs are public test fixtures: **TEST VECTOR ONLY — NOT SECRET — NEVER USE IN PRODUCTION**. They are not exposed by a test constructor and are never production inputs.

Both remote bootstrap records use the same exact opaque `shared_context`. The local fixture uses a separate shared context that matches independently in both local bootstrap records. Bootstrap fields use valid ASCII `ed25519` algorithm identifiers and synthetic 32-byte public keys; those keys are fixture data, not identity claims. Application identity values are simple ASCII strings with no normalization requirements.

## How the remote values were derived

The source basis is the pinned vodozemac **0.11.0** tagged commit `db1b34820f3102307284e762f335b3f72c735bf0` (tag object `9cdcc49ec1b213570a3a59cdeb40e8310999ea9e`; published crate SHA-256 `ba935af014ca0ae5fb468daa51da81a8a0df7daad23c052c878b7c690cdf2574`). The release's `Sas::new()` has no deterministic-key constructor: it obtains an ephemeral key from `rand::rng()`. For the fixture only, fixed raw X25519 test inputs reproduce the API's DH secret; no deterministic RNG or production API was added.

The tagged [`sas.rs`](https://github.com/matrix-org/vodozemac/blob/db1b34820f3102307284e762f335b3f72c735bf0/src/sas.rs) specifies the relevant behavior directly: `EstablishedSas::bytes(info)` expands HKDF-SHA256 with absent salt and `info.as_bytes()` to six bytes; `SasBytes::decimals()` uses the three exact bit expressions recorded in the JSON; and `calculate_mac(input, info)` derives a 32-byte HKDF key with the same shared secret and info, then computes HMAC-SHA256 over `input.as_bytes()`. The legacy invalid-Base64 method is not used.

Verification used two independent calculation paths after inspecting that source:

1. A source-derived calculation used Python `cryptography` X25519 plus standard-library SHA-256, HMAC, and explicit RFC 5869 HKDF extract/expand.
2. A separate Node/OpenSSL calculation independently derived both X25519 public keys and the shared secret, then recomputed HKDF, SHA-256, HMAC, the decimal mapping, frame parsing, and local record lengths.

The paths agreed for both public keys, the shared secret, commitment, transcript digest, six SAS bytes, decimal values, both bootstrap MACs, and all three completion MACs. The crate archive checksum also matched the pinned checksum. These checks establish fixture consistency with the inspected source operations; they are not an invocation of a deterministic vodozemac constructor or a security review.

The authenticated `CANCEL` material was added later under the same fixed test inputs. Before any CANCEL tag was derived, a fresh source-derived Python recomputation (pure-Python RFC 7748 X25519 plus standard-library SHA-256, HMAC, and RFC 5869 HKDF with absent salt, matching the pinned `get_mac_key`/`calculate_mac` path) rebuilt every frame from raw inputs and reproduced the checked-in public keys, shared secret, `START`/`ACCEPT`/key frames, `ceremony_identity`, six SAS bytes, both `BOOTSTRAP_MAC` tags and wire frames, and all three completion tags and wire frames byte-for-byte. Only then did it derive the CANCEL values. A separate Node/OpenSSL check derived the shared secret with OpenSSL X25519, re-reproduced an existing completion and bootstrap tag, strictly parsed every new CANCEL frame (magic, version, type, field count/order, big-endian length prefixes, no trailing bytes), checked the URL-safe unpadded Base64url strings and the exact `/cancel/` prefix, and recomputed each HKDF key and 32-byte tag. The scratch calculations are vector tooling only and are not committed; no production fixed-key constructor or project-owned production HMAC/HKDF code exists.

## Remote fixture walkthrough

The canonical bootstrap frames use type `0x20` and the ordered fields `application_identity`, `key_algorithm`, `public_key`, `shared_context`. `START`, `ACCEPT`, `INITIATOR_KEY`, and `RESPONDER_KEY` use wire types `0x01` through `0x04`, with the profile ID and 16-byte request ID common fields.

The commitment input is exactly:

```text
ASCII("sas-pairing-vodozemac-profile-draft-01/commit/v1")
|| u32be(len(START)) || START
|| R_pub
```

The authoritative transcript is:

```text
u32be(len(transcript_domain)) || transcript_domain
|| u32be(len(START)) || START
|| u32be(len(ACCEPT)) || ACCEPT
|| u32be(len(INITIATOR_KEY)) || INITIATOR_KEY
|| u32be(len(RESPONDER_KEY)) || RESPONDER_KEY
```

The SHA-256 digest is the authoritative 32-byte `ceremony_identity`. The completion transcript digest is this same transcript digest, not a second transcript.

| Output | Value |
|---|---|
| Commitment SHA-256 | `3c8739ad0efadd2a0453a0b7513a441764cbf5acae216543ae6494c654a2b571` |
| Remote `ceremony_identity` | `3c9d1e03323ba12046fa2021391fdd22d6883a6e69a493801c0ab8703ad70c1c` |
| Raw SAS bytes (6 bytes) | `6b94a8058875` |
| Matrix decimal SAS | `4442 5768 1708` |

The SAS context is canonical type `0x30`, with domain, profile identifier, `u16be(1)` version value, request ID, complete `START`, complete `ACCEPT`, `I_pub`, and `R_pub`, in that order. Its exact unpadded Base64url string is embedded in the vodozemac SAS `info` string. The raw six-byte SAS and exact three-number Matrix decimal rendering are in JSON.

Bootstrap approval uses canonical type `0x33` with the fixed SAS bytes, identity, sender role, and sender bootstrap. Its type `0x31` context binds purpose and both role codes. The MAC input is the complete approval frame's unpadded Base64url ASCII bytes. The sender role is explicit in both directional `BOOTSTRAP_MAC` wire frames (`0x01` Initiator, `0x02` Responder).

Each completion MAC has its own non-wire auth frame (`0x35`, `0x36`, `0x37`) and a type `0x32` context. The three actual wire frames (`0x06`, `0x07`, `0x08`) carry the common fields, transcript digest, and raw tag. JSON records every canonical frame, info string, Base64url input, derived test key, and raw MAC. The final result objects are semantic fixtures; they do not invent a binary `PairingResult` serialization.

### Authenticated CANCEL

The `cancellation` section and `wire_messages.CANCEL` record one authenticated cancellation per direction for the same established ceremony. Each uses the non-wire `CancelAuthFrame / 0x34` as MAC input and the non-wire `CancelMacContext / 0x38` as MAC context. Both frames carry the same seven fields in this order: protocol domain, profile identifier, `u16be(1)` version, sender role, receiver role, 32-byte `ceremony_identity`, and one-byte reason code; the context has no inner purpose field. The outer §3.2 purpose is `cancel`, never `mac`:

```text
input = unpadded_Base64url(complete canonical 0x34 CancelAuthFrame)
info  = ASCII("sas-pairing-vodozemac-profile-draft-01/cancel/")
        || unpadded_Base64url(complete canonical 0x38 CancelMacContext)
```

| Direction | Sender → receiver | Reason | Raw tag | Wire `CANCEL / 0x09` length |
|---|---|---|---|---:|
| Initiator | `0x01` → `0x02` | `0x02` user cancellation | `e4289b39d4ab4e17ef95398f926642bcdf203d21d3d93c33f16785838ebb7652` | 118 |
| Responder | `0x02` → `0x01` | `0x03` timeout | `61c6ca7fa28eba2cd2fd3e3fdc262f9253ffadb8586b3f2fe96d5c9889a4ad42` | 118 |

The two examples use different directions and different reason codes, so the same reason byte is visibly bound in the wire frame, auth frame, and context. JSON records each canonical auth frame, context frame, Base64url input, exact info string, test-only derived key, raw tag, and complete wire frame (common fields, sender role, reason, raw tag). The tags are derived from the public fixed test shared secret and are **TEST VECTOR ONLY**; they demonstrate deterministic encoding and derivation, not cancellation security.

## Local fixture walkthrough

The local vector fixes two 16-byte test nonces and matching local contexts. `LOCAL_START` (`0x40`) and `LOCAL_ACCEPT` (`0x41`) use the ordered schemas in the local profile. The transcript hashes the exact canonical payloads, excluding their outer length prefixes, under the documented local transcript domain. `LOCAL_APPROVE` (`0x42`) and alternate-branch `LOCAL_REJECT` (`0x43`) carry the same 32-byte identity with Responder-to-Initiator roles; `LOCAL_ACK` (`0x44`) carries that identity with Initiator-to-Responder roles. Each complete record is stored with its exact four-byte big-endian payload length.

The local identity is `7af1069f9b96f1c21d8eba7918bb4342ef42ecbb88c46450027f09628d3e51a`. Complete record lengths including the four-byte prefix are: START 238, ACCEPT 258, APPROVE 112, REJECT 112, and ACK 112 bytes.

The success result fixtures contain only the specified profile, version, peer role, authenticated peer bootstrap/context, and ceremony identity. They contain no request ID, nonce, OS principal, or `identity_verified` field.

## Limits

The vectors demonstrate byte and derivation agreement for one synthetic positive ceremony per profile. They do not establish vodozemac candidate selection, protocol security, production readiness, Windows behavior, OS credentials, or external review. Negative and boundary behavior is listed separately in [the conformance matrix](p3-conformance-cases.md). The authenticated-CANCEL addition is additive: it changes no pre-existing vector bytes.
