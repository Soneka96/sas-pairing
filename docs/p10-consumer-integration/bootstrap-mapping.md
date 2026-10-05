# P10.2 Canonical DovahLink Bootstrap v1 Mapping

> **Pre-alpha. DovahLink consumer mapping, not `sas-pairing` protocol.** This document specifies the exact bytes DovahLink supplies as the four `SasPairingBootstrap` fields, decided as [P10-D-002](decisions.md#p10-d-002--canonical-dovahlink-bootstrap-v1-mapping), and the application boundary around the result ([P10-D-003](decisions.md#p10-d-003--dovahlink-authentication-disposition-and-pop-boundary)). The `applicationIdentity`, `sharedContext`, and authority-scope encodings below are DovahLink-owned application data. They reuse a length-and-constant style but are **not** part of the `sas-pairing` protocol specification, which treats every field as opaque bytes ([P3 profile §4](../p3-vodozemac-ceremony-profile-draft.md#4-request-id-and-bootstrap-record)). Nothing here is implemented yet, and nothing is production-security approval.

Inputs: the frozen Bootstrap record of P3 §3.1 and §4 (bounds 1–1,024 / 1–64 ASCII `[a-z0-9][a-z0-9.-]*` / 1–4,096 / 0–8,192, complete frame at most 16,384 bytes, every byte authenticated exactly, nothing normalized); [ABI contract §17.5, §19, §20.4](../p7-native-abi/abi-contract.md#175-attach); the public Dart and .NET `SasPairingBootstrap` (four byte fields, no canonical-bytes getter) and `SasPairingResult` data (`ceremonyIdentity`, `peerRole`, `profileVersion`, `requestId`, `authenticatedPeerBootstrap` as the exact canonical frame, `authenticatedSharedContext`, `profileIdentifier`); DovahLink at `9f4e925` ([authentication audit](authentication-audit.md)); and three owner decisions taken on 2026-10-05: ECDSA P-256 for the Host as well as the Client ([P10-OD-05](decisions.md#pending-owner-decisions)), the binary RFC 9562 UUID form of `applicationIdentity` ([P10-OD-04](decisions.md#pending-owner-decisions)), and acceptance of the authentication replacement into P10 with a separate transport increment ([P10-D-003](decisions.md#p10-d-003--dovahlink-authentication-disposition-and-pop-boundary)).

Machine-readable vectors: [vectors/dovahlink-bootstrap-v1.json](vectors/dovahlink-bootstrap-v1.json), labelled **DovahLink consumer mapping vectors**; verified by `tooling/tests/test_p10_dovahlink_bootstrap_mapping.py`.

## 1. Mapping overview

| Field | Host bytes (Responder) | Client bytes (Initiator) | Source | Security purpose |
|---|---|---|---|---|
| `applicationIdentity` | `646f7661686c696e6b2e6170706c69636174696f6e2d6964656e746974792e7631` ‖ `01` ‖ `hostId` (16 bytes, RFC 9562 order); exactly 50 bytes | same domain ‖ `02` ‖ `clientId` (16 bytes); exactly 50 bytes | Host: `HostIdentityStore` UUID; Client: SDK `PersistedClientState.clientId` | DovahLink logical installation identity, role, and mapping version, domain-separated from every other consumer |
| `keyAlgorithm` | ASCII `dovahlink.ecdsa-p256.spki-der.v1` = `646f7661686c696e6b2e65636473612d703235362e73706b692d6465722e7631` (32 bytes) | identical | P10-D-002 constant | Names the exact key representation and use policy; `(keyAlgorithm, publicKey)` is compared together |
| `publicKey` | DER SPKI of the Host's long-term ECDSA P-256 key: `3059301306072a8648ce3d020106082a8648ce3d03010703420004` ‖ X (32) ‖ Y (32); exactly 91 bytes | DER SPKI of the Client's long-term ECDSA P-256 key, same form | Host key (P10.3); Client key (P10.4) | The exact verification key whose possession DovahLink later proves; also the Host TLS certificate key and the Client reconnect PoP key |
| `sharedContext` | ASCII `dovahlink.sas-pairing.bootstrap-v1.pairing` = `646f7661686c696e6b2e7361732d70616972696e672e626f6f7473747261702d76312e70616972696e67` (42 bytes) | identical, built independently | Each side's own P10-D-002 constant | Application security domain, purpose (pairing), and mapping version; rejects any other consumer, purpose, or mapping version before SAS exposure |

Each DovahLink Bootstrap frame is therefore exactly 241 bytes (10 header bytes, four 4-byte lengths, 50 + 32 + 91 + 42 field bytes), far below the 16,384-byte bound. No field is secret: every byte is network-visible and public.

## 2. Role assignment (P10-OD-10)

**Decision: Client = Initiator, Host = Responder.** Not chosen because "clients usually initiate", but because:

1. **Bootstrap lifetime.** A Responder's Bootstrap is fixed per listener at attach and given to every accepted connection ([ABI contract §17.5](../p7-native-abi/abi-contract.md#175-attach)); an Initiator's is supplied per run ([§20.4](../p7-native-abi/abi-contract.md#204-local-initiator-start)). The Host's Bootstrap holds only installation-static values (role, `hostId`, Host key, the constant context), so it fits the per-listener configuration exactly.
2. **Connection selection without network location.** The Initiator chooses the connection it starts on. Only the client can name its ceremony connection without addresses or timing: it is the client's own relay connection (E-02 measures the residual foreign-local-connection risk). A Host Initiator would have to pick one of its accepted connections, and before any message the only distinguishing facts are addresses, ports, and timing, which [P10-D-001](decisions.md#p10-d-001--consumer-boundary-platform-boundary-and-portability-discipline) item 14 forbids.
3. **Listen-only ABI and E-02.** The client relay binds a loopback listener for its own `sas-pairing` host, accepts its own relay connection, and starts the Initiator on it; START travels unchanged to the Host's pairing listener, where Responder runs appear through drive events. This is the topology of every two-sided proof so far.
4. **Host authority.** As Responder the Host validates the client's START (canonical Bootstrap, context) before ACCEPT and must obtain fresh, explicit local authorization before revealing its key ([P3 §11.1.3](../p3-vodozemac-ceremony-profile-draft.md#1113-local-authorization-and-atomic-exposure)); the Skyrim-side authorization point is P10.5's ([P10-OD-08](decisions.md#pending-owner-decisions)). The client's user starts the attempt, which is the Initiator's required explicit local action.
5. **Expected-peer mode.** Open (first-contact) mode on both sides: the Host's per-listener `expected` is null, and the client passes `expected = null` on first contact. For a deliberate re-pair with an existing Known Host pin, the client passes the pinned Host values as `expected` (P3 §8 expected-peer mode, values from independent local state).

## 3. `applicationIdentity`

```text
applicationIdentity = AI_DOMAIN || ROLE || UUID
AI_DOMAIN = ASCII "dovahlink.application-identity.v1"   33 bytes
            646f7661686c696e6b2e6170706c69636174696f6e2d6964656e746974792e7631
ROLE      = 0x01 (Host) | 0x02 (Client)                1 byte
UUID      = the 16 bytes of the hostId (Host) or clientId (Client) in RFC 9562 network order
total     = exactly 50 bytes
```

- **Domain separation.** `AI_DOMAIN` is a DovahLink-owned marker with its own version. It is distinct from `sas-pairing`'s protocol domain (`org.sas-pairing`) and from every byte string another consumer would choose; a different DovahLink identity scheme takes a new version (`…v2`).
- **Role separation.** The role byte makes Host UUID X and Client UUID X different identities (vector V03): a Host can never be mistaken for a Client with the same UUID, or the reverse.
- **No other content.** `hostName`, display names, `ShortId`, endpoints, addresses, ports, process or session identifiers, `stateAuthorityId`, `adapterInstanceId`, and Windows account names never appear. Network location never enters identity (vector-tested).
- **Validation.** A consumer accepts a peer identity only through exact frame equality (§10); it never parses partial identities. The nil UUID is not a DovahLink identity.

## 4. UUID canonical encoding

The 16 bytes are the UUID's 128 bits in RFC 9562 (formerly RFC 4122) network order: the order of the 32 hex digits of its `8-4-4-4-12` text form, most significant first. Text case, braces, and hyphenation are input forms only; every form of one UUID gives the same 16 bytes, so there is exactly one encoding per identity (DovahLink's Host already notes that `Guid.TryParse` accepts several aliasing text forms).

| UUID | RFC 9562 bytes (canonical) | .NET `Guid.ToByteArray()` (never canonical) |
|---|---|---|
| `00112233-4455-6677-8899-aabbccddeeff` | `00112233445566778899aabbccddeeff` | `33221100554477668899aabbccddeeff` |
| `0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0` | `0f1e2d3c4b5a69788796a5b4c3d2e1f0` | `3c2d1e0f5a4b78698796a5b4c3d2e1f0` |

**.NET rule.** `Guid.ToByteArray()` and `new Guid(byte[])` use the mixed-endian Microsoft layout (first three groups little-endian) and must not define the mapping. The Host writes the bytes with `Guid.TryWriteBytes(destination, bigEndian: true, out int written)` (available since .NET 8; DovahLink's Host targets a newer runtime) and reads them back with `new Guid(bytes, bigEndian: true)`. Both rows above were produced by .NET 10 (SDK 10.0.401) during P10.2. **Dart rule.** The SDK holds UUIDs as `8-4-4-4-12` strings; the client converts the 32 hex digits to bytes in text order. Vector V04 fails any implementation that uses the mixed-endian layout.

## 5. `keyAlgorithm`

Exactly the 32 ASCII bytes `dovahlink.ecdsa-p256.spki-der.v1`, for both roles (it matches `[a-z0-9][a-z0-9.-]*`). Its frozen meaning:

- the key is an elliptic-curve key on NIST P-256 (`secp256r1`, OID 1.2.840.10045.3.1.7), used only for ECDSA signatures (TLS 1.3 CertificateVerify by the Host; application PoP signatures by the Client);
- `publicKey` is its DER SubjectPublicKeyInfo with algorithm `id-ecPublicKey` (OID 1.2.840.10045.2.1), named-curve parameters, and an uncompressed point, exactly as §6;
- `v1` versions this whole policy. The signature hash and encoding of each proof are fixed by the protocol that uses them (TLS 1.3 `ecdsa_secp256r1_sha256` for the Host; P10.6 and S7 for the Client), not by this identifier.

DovahLink selected ECDSA P-256 for the Client key; the Host algorithm was unselected in DovahLink and decided by the owner on 2026-10-05 ([P10-OD-05](decisions.md#pending-owner-decisions)). A DovahLink-namespaced identifier is used instead of a bare `p256` or `ecdsa` so that its exact external meaning is the definition above. Any other algorithm or representation requires a new identifier and is a mismatch (vector V08).

## 6. `publicKey`

Exactly the 91 bytes of the long-term key's DER SubjectPublicKeyInfo:

```text
3059301306072a8648ce3d020106082a8648ce3d03010703420004   27-byte fixed prefix
X                                                        32 bytes, big-endian
Y                                                        32 bytes, big-endian
```

No PEM, Base64, hex text, compressed point, explicit-curve parameters, or language-native key-object serialization; the point must be on the curve (P10.3 / P10.4 validate with the platform import, for example .NET `ImportSubjectPublicKeyInfo`). DER is canonical for this structure: .NET 10 re-exports every vector key byte for byte. A compressed-point SPKI of the same key (59 bytes, vector V15) is not the canonical `publicKey`.

The full key is authenticated, not a fingerprint: later proof of possession must verify a signature against an actual public key, and only the full key gives the verifier that without a second, unauthenticated source. `SHA-256(SPKI DER)` in unpadded base64url remains DovahLink's display and storage index (its §5 and §6) and is derived from the authenticated bytes; it never replaces `publicKey` (the verifier rejects a fingerprint in its place).

The Host's `publicKey` is the SPKI of its TLS certificate key (forced by DovahLink's S6 guard: provisional TLS proof counts only if the certificate SPKI is the Host identity bound by the pairing construction). The Client's `publicKey` is the SPKI of its reconnect PoP key (forced: one Client cryptographic identity bound into KnownDevice, `identity-and-transport.md` §6, §9, §11). No private key enters `sas-pairing`, the Bootstrap, or any log.

## 7. `sharedContext`

```text
sharedContext = ASCII "dovahlink.sas-pairing.bootstrap-v1.pairing"   42 bytes
                646f7661686c696e6b2e7361732d70616972696e672e626f6f7473747261702d76312e70616972696e67
```

It binds: DovahLink (the application security domain), `sas-pairing` (the construction), the mapping version (`bootstrap-v1`), and the purpose (`pairing`, which covers first pairing and deliberate re-pairing). It deliberately does not repeat `hostId` or `clientId` (already bound, role-separated, in `applicationIdentity`) and holds no per-attempt value (§8).

**Independent construction.** Each endpoint takes these 42 bytes from its own code: the Host's .NET adapter and the client's Dart adapter each compile the constant. Neither reads it from the peer, the network, the provisional DovahLink session, discovery, or the result. The two values are byte-equal because both implement the same frozen constant (vector V06), not because one copied the other, which satisfies P3 §4 ("a participant's local context MUST come from its own application state/input"). Copying `receivedPeerSharedContext` into local state is forbidden (the verifier fails a reference that does). After a result, each side also checks `authenticatedSharedContext` equals its own constant exactly.

Because the Responder Bootstrap is fixed per listener, a constant context is also the only kind a Host Responder can supply without re-attaching its listener per attempt (§8).

## 8. Ceremony-specific anti-confusion

**The fresh attempt identity is `ceremony_identity`.** It is the SHA-256 transcript digest over START (with the core's 16-byte CSPRNG request ID and the Initiator Bootstrap), ACCEPT (with the commitment and the Responder Bootstrap), and both fresh ephemeral keys ([P3 §9](../p3-vodozemac-ceremony-profile-draft.md#9-completion-and-result-semantics)). Each endpoint computes it independently from the bytes it sent and received; each Bootstrap MAC binds the sender's exact Bootstrap and the full SAS to it. A substitution in the transcript changes the affected side's transcript, `ceremony_identity`, and SAS inputs; an attacker who substitutes must therefore mediate two distinct ceremonies. For two such attacker-mediated ceremonies, the human SAS values are expected to mismatch, but exact equality of the full SAS is not claimed impossible: [P3 §7](../p3-vodozemac-ceremony-profile-draft.md#proposed-conditional-security-argument--not-established) bounds that exact full-SAS match event (39 exact-match bits) conditionally, at `P_per_pair ≤ 2^-39 + δ` per mediated candidate pair and `P_joint ≤ 19 × 2^-39 + ε` within the joint 10/10 opportunity window, under its stated idealized assumptions. A mismatch is rejected by the users; an accidental exact match remains within that documented boundary. A human MATCH is therefore security evidence subject to P3's conditional SAS argument and attempt limits, not a deterministic cryptographic proof that no mediation occurred, and not a formal, lifetime, human-error, or end-to-end authentication guarantee. This is the "equivalent fresh anti-confusion context" that DovahLink's §10 requires its pairing construction to bind, and it stays the **authoritative** attempt identity for MATCH / MISMATCH / CANCEL and for Pair / Reject / Block. No DovahLink nonce or context value ever substitutes for it.

**Two-sided nonce candidate, analysed and not selected.** The candidate: the Host generates a fresh public nonce `N_H`, the client a fresh public nonce `N_C`; each sends its own over the provisional DovahLink session; each builds `sharedContext = domain ‖ hostId ‖ clientId ‖ N_H ‖ N_C`.

- *Independence.* Each side's context mixes its own nonce with a value received from the peer over another, unauthenticated channel. It is not a copy of the peer's ceremony context, so it does not break the letter of P3 §4, but half of it is peer-supplied and unauthenticated until the ceremony compares it.
- *Active substitution:*

| Attacker changes | Effect |
|---|---|
| `N_H` on the way to the client | The two contexts differ: both sides abort with `SHARED_CONTEXT_MISMATCH` before SAS exposure (denial of service only), or the attacker runs a separate ceremony on each leg with that leg's context, so it must mediate two distinct ceremonies whose exact full SAS values are subject to P3's bounded exact-match probability (§7 of the profile): a mismatch is rejected by the users; an exact collision is not claimed impossible |
| `N_C` on the way to the Host | Same |
| `hostId` on either leg | Same; additionally the exact-frame check (§10) fails on the client |
| `clientId` on either leg | Same; additionally the exact-frame check fails on the Host |

  The nonces are public, so they bind nothing an active attacker cannot reproduce; they add only a pre-exposure consistency check between the provisional session and the ceremony as seen by two honest endpoints. They do not strengthen the SAS: with or without them, a mediated pair of ceremonies is bounded by the same 39-bit P3 exact-match argument and the same attempt accounting.
- *ABI cost.* A per-attempt Host context needs a per-attempt Host Bootstrap. The Host is Responder (§2), whose Bootstrap is fixed per listener; changing it per attempt means detach and re-attach, which invalidates every connection and run on that listener (other pre-exposure candidates and the live ceremony included), or making the Host the Initiator, which §2 rejects.
- *What supplies exact-attempt cross-channel binding instead:* `ceremony_identity` inside the client's pairing-PoP signature on the provisional TLS session, together with TLS proof of the authenticated Host key on that same session (§11). That binding is cryptographic; nonce equality is not.

Therefore no fresh per-attempt contribution is selected (vector V11 records "not applicable"; a context with any appended attempt bytes fails exact comparison).

**`request_id` is never authority.** It is routing, correlation, and diagnostics only ([P3 §4](../p3-vodozemac-ceremony-profile-draft.md#4-request-id-and-bootstrap-record)): never a durable identity, application authorization, freshness proof, or pending-Pair key.

## 9. Canonical Bootstrap frame (for exact comparison)

DovahLink builds the expected peer frame with the P3 §4 record grammar, reproduced here only so the comparison can be implemented; it is the `sas-pairing` record, not a DovahLink redefinition:

```text
53 41 53 50 41 49 52        ASCII "SASPAIR"
00 01                       u16be version 1
20                          type 0x20 (Bootstrap record)
u32be(len) applicationIdentity   1..1024 bytes   (DovahLink: 50)
u32be(len) keyAlgorithm          1..64 ASCII [a-z0-9][a-z0-9.-]*   (DovahLink: 32)
u32be(len) publicKey             1..4096 bytes   (DovahLink: 91)
u32be(len) sharedContext         0..8192 bytes   (DovahLink: 42)
no trailing bytes; complete frame <= 16384 bytes   (DovahLink: exactly 241)
```

The verifier reproduces the core-generated Initiator and Responder frames of the frozen [P3 vector](../../vectors/p3-remote-vodozemac-draft-01.json) byte for byte with this encoder before checking any DovahLink vector. Building a frame is encoding, not parsing; no Bootstrap decoder exists in P10.

## 10. Peer Bootstrap consumption (E-13, P10-OD-13)

**Decision: Option A, exact expected-frame comparison.** After a local result, each side builds the canonical frame the peer must have supplied, from values it already holds, and requires `authenticatedPeerBootstrap == expectedFrame` byte for byte over the whole frame. Only after equality does it use those candidate values, now as authenticated evidence.

| Needed value | Host has it (verifying the Client frame) | Client has it (verifying the Host frame) |
|---|---|---|
| Peer UUID | Candidate `clientId` from the provisional session (`hello`) | Candidate `hostId` from the provisional session (`hello_ack`) |
| Peer role byte | Known: the peer is the Client (`02`) | Known: the peer is the Host (`01`) |
| `keyAlgorithm` | Constant | Constant |
| Peer `publicKey` | Candidate Client SPKI sent by the client on the provisional session **before the ceremony** (a P10.6 DovahLink message) | From P10.5A: the provisional TLS certificate's SPKI (which TLS also proves possession of); before P10.5A, an explicit candidate field |
| `sharedContext` | Own constant | Own constant |

Both sides therefore hold every candidate value before trust is committed, and before the ceremony starts; no side learns an authenticated field only from the result. Rules:

- compare the **entire** frame; never accept on `clientId`, `hostId`, or any subset (a one-byte change anywhere is rejected, vectors V07–V10b);
- the candidate `publicKey` must pass §6 validation before the expected frame is built;
- also require `peerRole` to be the expected peer role, `authenticatedSharedContext` to equal the own constant, and `profileIdentifier` / `profileVersion` to equal `sas-pairing-vodozemac-profile-draft-01` / 1;
- with several live candidates, exactly one distinct expected frame may match; otherwise the evidence is discarded (DovahLink's one-active-pairing rule normally leaves one);
- a mismatch discards the result as evidence (no pending authorization) and is reported as a pairing failure, never as a trust verdict.

**Why not Option B (a consumer decoder):** unnecessary, since every value is held before trust; it would add a second parser. **Why not Option C (a wrapper helper):** it would change P8 / P9 with no gap to close. The consumer needs a ~15-line canonical **encoder** in each adapter (C# and Dart), vector-tested; P8-D-005 J and P9-D-005 (wrappers never parse the frame) are untouched. **ABI classification:** no ABI gap and no wrapper gap; ABI v1 already returns the exact authenticated bytes.

Real-consumer regression (not an open experiment): P10.3 and P10.4 test that a real result's `authenticatedPeerBootstrap` equals the locally built expected frame, and that a one-field change of the candidate fails.

## 11. Proof-of-possession boundary (E-07)

`sas-pairing` authenticates, for the human-approved ceremony peer, the exact `applicationIdentity`, `keyAlgorithm`, `publicKey`, and `sharedContext` bytes. It does **not** prove private-key possession (P3 §1, §4, §8). DovahLink proves possession, on the provisional DovahLink session, before any pending authorization:

- **Host.** TLS 1.3 server authentication on the provisional session with the Host's certificate key: the certificate SPKI must be byte-equal to the authenticated Host `publicKey`, and CertificateVerify proves possession. The client checks this before it sends its own PoP and before it writes a Known Host pin. Provisional TLS alone authenticates nothing; equality with the ceremony-authenticated SPKI is what makes it the Host's proof (DovahLink's S6 guard). Transport: P10.5A; the equality check: P10.6.
- **Client.** An ECDSA P-256 signature with the Client's long-term key, verified by the Host against the authenticated Client `publicKey`, over a DovahLink-owned pairing-PoP statement that is domain-separated from the S7 reconnect statement and contains at least: its own domain and version, the exact `ceremony_identity`, a fresh Host-generated challenge issued on that TLS session, and the Host and Client identities and keys (for example both canonical Bootstrap frames). Statement bytes, challenge size and lifetime, single use, signature encoding, and C#↔Dart vectors are frozen by P10.6; the reconnect statement remains S7, in P10.7.
- **Ordering.** Local result → exact peer-frame check → Host TLS-key check (client) → Client PoP verified (Host) → pending authorization → Pair / Reject / Block → durable trust. PoP precedes the pending authorization so that DovahLink's candidate "unknown-client Block by proven key" principal and its "no permanent trust before client PoP" rule both hold.

Proof of possession stays entirely DovahLink-owned (**E-07: yes**). Nothing moves into `sas-pairing`, and nothing in it is needed: the result supplies `ceremony_identity` and the authenticated keys.

## 12. Cross-channel binding

| Value | Generated by | Known by the Host how | Known by the Client how | Authenticated where | Security role |
|---|---|---|---|---|---|
| `hostId` | Host (installation file) | Own state | Candidate from `hello_ack` | Inside the Host `applicationIdentity`, by the ceremony; then exact-frame equality | Host logical identity |
| `clientId` | Client SDK (persisted) | Candidate from `hello` | Own state | Inside the Client `applicationIdentity`; then exact-frame equality | Client logical identity |
| Host public key | Host key (P10.3) | Own state | Candidate: provisional TLS certificate SPKI (P10.5A) | Ceremony (Host Bootstrap); possession by TLS CertificateVerify on the provisional session | Host verification key; Known Host pin; TLS identity |
| Client public key | Client key (P10.4) | Candidate sent before the ceremony (P10.6) | Own state | Ceremony (Client Bootstrap); possession by the P10.6 PoP signature | Client verification key; KnownDevice binding; reconnect PoP key |
| Host nonce | — (not used) | — | — | — | Rejected (§8) |
| Client nonce | — (not used) | — | — | — | Rejected (§8) |
| `sharedContext` | P10-D-002 constant | Own constant | Own constant | Compared by both before exposure; returned in the result | Application domain, purpose, mapping version |
| `request_id` | Client's `sas-pairing` core (CSPRNG) | From the START it received | From its run | Inside the transcript only | Routing and diagnostics; never authority |
| `ceremony_identity` | Both cores, from the transcript | Its own result | Its own result | Transcript digest; bound by both Bootstrap MACs and the completion MACs | Authoritative attempt identity; keys the pending authorization; signed in the Client PoP |
| Fresh Host PoP challenge (P10.6) | Host CSPRNG | Own state | Received on the provisional TLS session | Inside the Client's signed statement | Freshness and session binding of the Client PoP |
| Provisional TLS session | TLS 1.3 handshake | Own session | Own session | Server authentication by the Host key whose SPKI the ceremony authenticated | The one session on which both proofs happen (DovahLink invariant 10) |

No source or destination port, socket, address, or timing participates. The `sas-pairing` socket (through the client relay) only carries the ceremony; it is linked to the provisional session solely by the authenticated keys and `ceremony_identity` above (**AF**).

## 13. Local completion versus pending Pair (P10-OD-06, model only)

Two distinct states, never collapsed:

- **`SasCeremonyCompletedLocally`**: this endpoint holds a `PairingResult` for one exact `ceremony_identity`. Evidence held: `ceremony_identity`, `peerRole`, the authenticated peer frame, the authenticated context, the profile identifier and version (request ID for diagnostics only). It means nothing about the peer's result, the peer's key possession, authorization, or trust ([P10-D-001](decisions.md#p10-d-001--consumer-boundary-platform-boundary-and-portability-discipline) item 8).
- **`PendingPairingAuthorization`** (Host): reachable only after the exact peer-frame check and the Client PoP succeeded for that same `ceremony_identity`, within the same unchanged administrative fence. It awaits Pair / Reject / Block in Skyrim.

Between them sit two verification states (`PeerBootstrapVerified`, `ProofOfPossessionVerified`). Durable trust is written only on Pair. The client mirrors this with "waiting for the Host's decision" and writes its Known Host pin only after the Host's Pair outcome arrives on the verified provisional session. Class names are P10.6's; the invariant is that a result never becomes `Trusted`, KnownHost, or KnownDevice by itself. The executable model is in the vector file (`model.state_model`).

## 14. Pending authorization model (conceptual)

A Host pending authorization stores only what the decision needs:

| Field | Why |
|---|---|
| `ceremony_identity` (key) | The exact attempt; Pair / Reject / Block name it |
| Peer role (Initiator) and the authenticated Client frame | Exact evidence: `clientId`, key, algorithm, context |
| Own Host frame | What was authenticated to the peer |
| PoP verified (and when) | Required before the record exists |
| Security fence generation and Known Device incarnation (or absent) captured at attempt start | Administrative fence (§16) |
| Provisional session reference | Delivers the outcome; routing only, never authority |
| Display metadata (unauthenticated label) | Shown in Skyrim beside the SAS evidence, marked as a claim |
| Created / expires | Bounded lifetime (exact value in P10.6) |

Never the key or authority: `request_id`, `clientId` alone, `hostId` alone, the SAS string, the shared context, or any network location. A new ceremony for the same `clientId` supersedes the old attempt, and an approval naming the old `ceremony_identity` cannot authorize the new one (E-10).

## 15. Asymmetric local completion

Either side may hold the only result ([P6-D-005](../p6-remediation/decisions.md#p6-d-005--local-completion-and-final-ack-deadline-boundary)):

- **Host has a result, client does not.** The client never sends a PoP naming that `ceremony_identity` (it has no result and no authenticated Host key), so no pending authorization is created; the evidence expires. No trust.
- **Client has a result, Host does not.** The client's PoP names a `ceremony_identity` the Host does not hold; the Host rejects it; the client writes no Known Host (no Pair outcome). No trust.
- **Both have results.** The flow proceeds. If the Host commits Pair but the outcome is lost before the client records its pin, the Host holds a key-bound KnownDevice the client cannot yet use; P10.6 owns the recovery (a durable client-side pending-attempt record naming `hostId`, the verified Host SPKI, and `ceremony_identity`, completed by a later Host confirmation), never a bilateral-commit assumption.

## 16. Administrative mutation fence

DovahLink's existing fences map onto the new flow unchanged in kind:

| Point | Fence |
|---|---|
| Attempt start (candidate accepted on the provisional session) | One coherent `GetSecuritySnapshot`: refuse a `Blocked` record; capture the security fence generation and the Known Device incarnation (or absence) |
| Ceremony in flight | Revoke, Block, Reset Trust, and Factory Reset cancel the DovahLink attempt, as `Cancel` / `CancelAll` do today; the `sas-pairing` run may still complete locally, but its result no longer has an attempt to attach to (the adapter may also cancel the run by its exact identity) |
| PoP verification and pending creation | The captured generation must still be current |
| Pair commit | Conditional write against the captured generation that also refuses a `Blocked` record (today's `TryUpsertIfGenerationAsync` semantics) |
| Factory Reset | Additionally drops every pending authorization |

Stale evidence can therefore never commit later trust, even when the ceremony itself succeeded.

## 17. Initial pairing and normal reconnect

```text
INITIAL PAIRING                                   NORMAL RECONNECT (no SAS)
provisional DovahLink session (TLS from P10.5A)   pinned Host verification (TLS, Known Host SPKI)
  → candidate exchange                              → fresh Host challenge
  → sas-pairing ceremony (separate socket)          → fresh Client proof of possession (S7)
  → local PairingResult                             → Host current trust-state check
  → exact peer-frame check                          → fresh DovahLink session
  → Host key proof (TLS) / Client pairing PoP
  → PendingPairingAuthorization
  → Pair / Reject / Block
  → durable trust (KnownDevice key, Known Host pin)
```

An already trusted peer never runs SAS to reconnect; no `sas-pairing` runtime, authority, or listener takes part in reconnect (E-09, P10.7). SAS runs again only for a deliberate re-pair (after revoke, reset, key loss, or a DovahLink-defined condition).

## 18. Authority scope (P10-OD-14)

```text
Host scope   = ASCII "dovahlink.pairing-authority.v1" || 0x01 || hostId (16 bytes, RFC 9562)
Client scope = ASCII "dovahlink.pairing-authority.v1" || 0x02 || clientId (16 bytes, RFC 9562)
               domain hex 646f7661686c696e6b2e70616972696e672d617574686f726974792e7631 (30 bytes); scope 47 bytes
```

Both come only from stable local installation state, never from the network. `hostId` is stored per Windows user (`%LOCALAPPDATA%\DovahLink\host\host-id.dat`), so every Host process of one user shares one `hostId`, one trust store, and (from P10.3) one Host key; one pairing authority per Host installation is therefore intended, and a second concurrent Host process of the same user gets `OWNERSHIP_UNAVAILABLE` for pairing instead of running a second authority over the same trust store. The client scope likewise allows one pairing authority per client installation, matching DovahLink's "at most one pairing recovery per Client installation". The Host and client scopes never collide on one machine (role byte, different UUIDs). The scope uses its own domain, distinct from `applicationIdentity`. Runtime behaviour and UX remain experiment E-11 in P10.3.

## 19. E-05 and E-06

**E-05 — resolved.** The four fields bind: Host logical identity (`applicationIdentity`, role `01`, `hostId`), Host public identity (`publicKey`, Host Bootstrap), Client logical identity (role `02`, `clientId`), Client public identity (`publicKey`, Client Bootstrap), and the DovahLink pairing domain and context (`sharedContext`, plus the versioned `applicationIdentity` domain and `keyAlgorithm`). They do not prove possession (§11).

**E-06 — resolved.** After a local result each side has everything a pending authorization needs, by category:

| Needed | Category |
|---|---|
| `ceremony_identity`, `peerRole`, authenticated context, profile identifier and version | In the result |
| Peer `clientId` / `hostId`, peer key, peer algorithm | Recoverable by exact comparison (§10) |
| Own identity, key, frame, context | Already locally known |
| Fence generation, incarnation, provisional session, display label | Already locally known (DovahLink state) |
| Proof of possession | DovahLink protocol after the result (§11) |
| Anything requiring parsing | None |
| Wrapper gap | None |
| ABI gap | None |

## 20. Vectors

[`vectors/dovahlink-bootstrap-v1.json`](vectors/dovahlink-bootstrap-v1.json) (DovahLink consumer mapping vectors; every key is a published test key):

| ID | Content |
|---|---|
| V01 | Host Bootstrap: UUID `00112233-4455-6677-8899-aabbccddeeff`, Host test key; frame 241 bytes, SHA-256 `232a56f2392a3dd83ee3847663af9b13ca4e4deeb9ea018746b4c681a0f2d4af` |
| V02 | Client Bootstrap: UUID `0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0`, Client test key; frame 241 bytes, SHA-256 `2391656c6384a54177d9442c4cd57667208ab6c045f2c916901e88094331fa6c` |
| V03 | Same UUID in both roles → different `applicationIdentity` |
| V04 | UUID byte-order trap (RFC 9562 versus .NET `ToByteArray()`), with .NET 10 evidence |
| V05 | Two different keys |
| V06 | Independently built shared contexts are byte-equal |
| V07–V10b | Negatives: one changed byte of `sharedContext`; wrong `keyAlgorithm`; substitute `publicKey`; changed UUID bit; swapped role byte |
| V11 | Attempt-context contribution: not applicable (no fresh contribution selected); a context with appended attempt bytes is rejected |
| V12, V13 | E-13 exact comparison: candidate values rebuild the authenticated Client frame (Host side) and Host frame (Client side) |
| V14 | Authority scopes (`…0100112233445566778899aabbccddeeff` Host, `…020f1e2d3c4b5a69788796a5b4c3d2e1f0` Client) |
| V15 | Compressed-point SPKI is not a canonical `publicKey` |

Test-key fingerprints (`SHA-256(SPKI)`, unpadded base64url; display only): Host `_lEke2AL0V0gIvTYMZHejeeS60o7OIf5X-njMIR9X9Q`, Client `PDHvBJn32NNvAgEbJ9T_8np0awd4y_LIp40mmyM02kw`.

## 21. Portability

Every byte above is platform-neutral (PN): constant ASCII, a role byte, RFC 9562 UUID bytes, a standard DER SPKI, and the frozen `sas-pairing` record. The same bytes apply to a future Android client; producing a P-256 SPKI from a platform key store is DovahLink's own Stage 5A concern. P10.2 found no new Android evidence and changes no Android register entry.

## 22. Nonclaims

The mapping is specified and vector-tested, not implemented. It does not prove private-key possession, external identity truth, or authorization; it does not make a SAS mismatch deterministic or a human MATCH proof that no mediation occurred (§8; P3 §7 bounds the exact full-SAS match conditionally); it is not production-ready, hostile-LAN approved, professionally audited, or formally verified.
