# P10 Consumer Boundary

> **Pre-alpha. Analysis and design only.** This document is P10.1 evidence for [P10-D-001](decisions.md#p10-d-001--consumer-boundary-platform-boundary-and-portability-discipline). It changes no implementation, freezes no Bootstrap encoding, and issues no verdict on DovahLink's current authentication: that verdict belongs to P10.2 ([§14](#14-p102-authentication-audit-contract)). Nothing here is production-security approval.

Sources: this repository at `main` `b938016d1de53d3e269fe0840485fbd3dc715fd7`, and the DovahLink repository read only at `main` `9f4e925cc8dcba0db37d1bd7d38b39f0927b9387` (links to DovahLink below are pinned to that commit). P10.1 read `main` `4a69ee5057029878200b6e16614f67a136e3e032`; P10.1.1 reconciled the baseline to the live `main` above, and no DovahLink file cited here changed between the two commits ([README, P10.1.1 evidence](README.md#p1011-evidence)). DovahLink is a separate repository with its own workflow; P10.1 and P10.1.1 changed nothing in it.

## 1. Purpose

P10 integrates `sas-pairing` into its original consumer, DovahLink, on Windows. Before that integration starts, this document fixes who owns what, records the `sas-pairing` facts the integration depends on with their evidence, maps every DovahLink concept that pairing touches to its owner, and lists what P10.2 must audit in DovahLink's current authentication. The platform side of the same analysis (Windows encapsulation, threads and isolates, ABI v1 sufficiency, Android) is in the [portability assessment](portability-assessment.md).

## 2. Responsibility boundary

**`sas-pairing` owns** (the reusable library, application-neutral):

- the pairing protocol (`sas-pairing-vodozemac-profile-draft-01`, version 1) and its cryptography, implemented once in the native Rust core;
- SAS generation and the decimal display;
- the ceremony transcript and `ceremony_identity`;
- authentication and binding of the selected Bootstrap records and shared context, and the authenticated result data;
- protocol attempt and accounting controls (the exposure guard, the ten-opportunity process-session budget, START and pending limits, deadlines);
- result lifetime (runtime-owned results, delivered once);
- protocol-level failure semantics (statuses, `FATAL`, fail-closed ownership).

**`sas-pairing` does not own:** DovahLink Host or Client identity policy, KnownHost, KnownDevice, Pair, Reject, Block, revoke, durable trust, reconnect authentication, normal session authentication, discovery, UI, or application session lifecycle.

**DovahLink owns:** application identities (`hostId`, `clientId`) and their long-term keys or credentials; proof-of-possession policy; pending application authorization; Pair / Reject / Block; KnownHost and KnownDevice persistence; reconnect credentials and normal trusted reconnect; session establishment; discovery; UX and user authorization.

This split already exists on both sides. In `sas-pairing`: the [threat model](../threat-model.md#pairing-result-contract) ("the consumer decides whether and when to persist trust"), [architecture](../architecture.md#consumer-application), and [ABI contract §21](../p7-native-abi/abi-contract.md#21-wrapper-handoff-p8-p9) item 11. In DovahLink: its identity and transport contract says DovahLink "owns application identity, durable trust, authorization, Pair/Reject/Block decisions, reconnect behavior, and product integration" and that generic SAS work belongs to `sas-pairing` ([DovahLink `identity-and-transport.md` status](https://github.com/Soneka96/DovahLink/blob/9f4e925cc8dcba0db37d1bd7d38b39f0927b9387/ai/context/security/identity-and-transport.md)). P10 adds no policy to the library to make integration easier.

## 3. Verified `sas-pairing` facts

Each fact the task asked P10.1 to verify, with its evidence. All hold.

| | Fact | Evidence |
|---|---|---|
| A | ABI v1 is frozen | [P7-D-013](../p7-native-abi/decisions.md#p7-d-013--abi-v1-final-freeze-and-wrapper-handoff); [manifest](../p7-native-abi/abi-v1-manifest.md) "State: FROZEN"; `abi::tests::freeze` and `tooling/check_abi_exports.py` in CI; `git diff b938016 -- core/include/sas_pairing.h` empty |
| B | The Rust core is the only protocol and cryptography implementation | [P8 closure §15](../p8-dart-package/final-closure.md#15-security-invariants), [P9 closure §17](../p9-dotnet-package/final-closure.md#17-security-boundaries) (source-scanned in both packages) |
| C | P8 Dart and P9 .NET wrap the same ABI v1 | [P8-D-001](../p8-dart-package/decisions.md#p8-d-001--dart-native-binding-and-loader-architecture) B (generated from the frozen header), [P9-D-001](../p9-dotnet-package/decisions.md#p9-d-001--net-abi-v1-binding-and-loader-architecture) (exact 25-export table); both require `sas_pairing_abi_version() == 1` |
| D | Windows x64 is the only supported pairing platform | [Manifest §10](../p7-native-abi/abi-v1-manifest.md#10-platform-scope); [P8 closure §13–§14](../p8-dart-package/final-closure.md#13-windows-x64-support-scope); [P9 closure §16](../p9-dotnet-package/final-closure.md#16-supported-and-unsupported-platforms) |
| E | Non-Windows fails closed | `core/src/lib.rs` `#[cfg(not(windows))] mod os_lock`: `Lease::acquire` returns `Err(Error::UnsupportedPlatform)`; `windows_owner_loop` and `windows_tcp` are `#[cfg(windows)]` modules; every Windows-only export returns `SAS_PAIRING_UNSUPPORTED_PLATFORM` off Windows ([ABI contract §17.10](../p7-native-abi/abi-contract.md#1710-platform-behavior-and-scope), [§18.8](../p7-native-abi/abi-contract.md#188-fatal-state-platforms-and-concurrency)); .NET `SasPairingWindowsListenerSocket.FromSocket` throws `PlatformNotSupportedException`; the CI job `unsupported-platform-fails-closed` |
| F | Listener and network ownership are Windows-specific | `sas_pairing_host_attach_windows_listener` takes a Windows `SOCKET` (`sas_pairing_socket_t`, invalid `UINTPTR_MAX`); the owner loop is a bounded `WSAPoll` loop ([P7-D-006](../p7-native-abi/decisions.md#p7-d-006--windows-listener-ownership-and-responder-configuration), [P7-D-008](../p7-native-abi/decisions.md#p7-d-008--bounded-drive-and-foreign-event-model)) |
| G | The Dart package already exposes most of the high-level API an Android client would want, but native platform support prevents claiming Android | Public surface in [P8 closure §6](../p8-dart-package/final-closure.md#6-final-public-dart-surface): Bootstrap, Runtime / Authority / Host, Connection, Run, SAS presentation, `SasPairingCeremonyIdentity`, `SasPairingResult`; no `dart/lib` file tests the platform (no `Platform.is*`): the native core fails closed instead; Android is explicitly unclaimed ([P8 closure §14](../p8-dart-package/final-closure.md#14-unsupported-platform-scope)) |
| H | `PairingResult` is local completion only | [P6-D-005](../p6-remediation/decisions.md#p6-d-005--local-completion-and-final-ack-deadline-boundary), [P7-D-010](../p7-native-abi/decisions.md#p7-d-010--pairingresult-ownership-and-foreign-access) item 6, [ABI contract §19](../p7-native-abi/abi-contract.md#19-results), [P8-D-005](../p8-dart-package/decisions.md#p8-d-005--dart-pairingresult-ownership-data-access-and-local-completion) A, [P9 closure §12](../p9-dotnet-package/final-closure.md#12-pairingresult-model) |
| I | `CeremonyIdentity` identifies the exact ceremony, not the peer | [P3 profile §4](../p3-vodozemac-ceremony-profile-draft.md#4-request-id-and-bootstrap-record) (the transcript-derived SHA-256 `ceremony_identity` is the authoritative ceremony identifier); [ABI contract §19.2](../p7-native-abi/abi-contract.md#192-info) ("not the request ID, a connection or run handle, or peer identity"); neither wrapper has a public constructor for it (P8-D-004 rule 1; .NET `SasPairingCeremonyIdentity` constructor is `internal`) |
| J | No wrapper owns application trust policy | [ABI contract §21](../p7-native-abi/abi-contract.md#21-wrapper-handoff-p8-p9) item 11; P8-D-005 O; [P9 closure §17](../p9-dotnet-package/final-closure.md#17-security-boundaries) ("No automatic approval … trust persistence, enrollment, or trust verdict") |

Further facts found while verifying, which shape the integration:

| | Fact | Evidence |
|---|---|---|
| K | **ABI v1 is listen-only.** A connection handle is issued only by `CONNECTION_ACCEPTED` from a caller-bound listener; no export connects out or adopts an already-connected socket. Every two-sided proof joined two listeners through an external byte-transparent relay | [P7-D-006](../p7-native-abi/decisions.md#p7-d-006--windows-listener-ownership-and-responder-configuration) item 1 (the ABI never configures "an outgoing connection"); [ABI contract §18.5](../p7-native-abi/abi-contract.md#185-connection-handles); [P7 closure §7](../p7-native-abi/final-closure.md#7-two-sided-public-abi-evidence); [P8 closure §17](../p8-dart-package/final-closure.md#17-real-two-endpoint-evidence) ("a test-only byte-transparent relay") |
| L | A Responder's Bootstrap is fixed per listener at attach and used for every accepted connection; an Initiator's Bootstrap is supplied per run at start | [ABI contract §17.5](../p7-native-abi/abi-contract.md#175-attach) ("`local` is the Responder configuration the loop gives accepted connections for new STARTs"), [§20.4](../p7-native-abi/abi-contract.md#204-local-initiator-start) |
| M | The result returns the peer Bootstrap as its exact canonical frame; neither wrapper decodes it | [ABI contract §19.3](../p7-native-abi/abi-contract.md#193-field-copy); [P8-D-005](../p8-dart-package/decisions.md#p8-d-005--dart-pairingresult-ownership-data-access-and-local-completion) J ("never parsed … which would be Bootstrap frame parsing in Dart") |
| N | The application creates, binds, and listens on the socket; the Dart package needs a raw WinSock `SOCKET` value, the .NET package a `System.Net.Sockets.Socket` | [P8-D-003](../p8-dart-package/decisions.md#p8-d-003--dart-windows-listener-cooperative-drive-and-connection-lifetime) D ("obtaining the bound socket is an advanced integration boundary"); [P9-D-003](../p9-dotnet-package/decisions.md#p9-d-003--net-windows-listener-cooperative-drive-event-and-connection-ownership) C |
| O | The native library is an unsigned, exact-commit CI artifact (90-day retention) loaded from an explicit absolute path, one image per process for its lifetime | [P8-D-006](../p8-dart-package/decisions.md#p8-d-006--dart-native-artifact-distribution-and-p8-final-closure), [P9-D-006](../p9-dotnet-package/decisions.md#p9-d-006--net-managed-package-native-artifact-distribution-and-p9-closure), [P7-D-002](../p7-native-abi/decisions.md#p7-d-002--native-library-residency-and-loader-lifetime) |

## 4. PairingResult boundary

A `PairingResult` (Dart `SasPairingResult`, .NET `SasPairingResult`) is **this endpoint's locally verified completion of one `sas-pairing` ceremony**: the native core verified every required peer authentication and confirmation for that exact ceremony after this endpoint's own local MATCH. It carries the ceremony's `ceremony_identity`, the peer's role, the peer's exact authenticated Bootstrap frame, the authenticated shared context, the request ID, and the profile identifier and version.

It does **not** mean: bilateral completion; that the peer also holds a result (either side may be the only holder, P6-D-005); that the peer persisted trust or authorized us; that long-term authentication or proof of possession succeeded; that a DovahLink Pair happened; that reconnect is configured; or that durable trust exists.

P10 rule: DovahLink represents a result as *pairing evidence for one attempt*, the input to its own authorization step, and never as a trust state. No DovahLink type that holds a result is named or documented as "paired", "trusted", or "known", and no result is written to KnownHost or KnownDevice storage directly. P10.5 and P10.6 test this.

## 5. CeremonyIdentity boundary

`ceremony_identity` is the 32-byte transcript-derived identity of one exact ceremony attempt. The same Host and Client identities can take part in many attempts (a retry is a new ceremony, threat model "Pairing ceremony and identity"); each attempt has its own `ceremony_identity`, and a value from one attempt never matches another.

- **Binds decisions.** MATCH, MISMATCH, and CANCEL already take the exact presented identity in both wrappers, and the native core rejects any other (`CEREMONY_IDENTITY_MISMATCH`, nothing changes). P10 extends the same binding upward: DovahLink's pending authorization for an attempt, and the Pair / Reject / Block decision that answers it, are keyed by that attempt (conceptually DovahLink's `pendingPairingId`), never by `clientId` or `hostId` alone. A stale decision for an earlier attempt cannot authorize a later one. DovahLink's own architecture requires the same ("a future pending approval must identify the exact active attempt … rather than authorize by `clientId` alone", [DovahLink `identity-and-transport.md` §10](https://github.com/Soneka96/DovahLink/blob/9f4e925cc8dcba0db37d1bd7d38b39f0927b9387/ai/context/security/identity-and-transport.md#selected-dovahlink-pairing-authorization-architecture)).
- **Is not identity.** It is not a durable peer identity, a reconnect credential, a trust record, a `clientId`, a `hostId`, a request ID, or a handle. It is not secret, and knowing it grants nothing.
- **Crosses process and isolate boundaries only as a reference.** It is safe to carry the 32 bytes as correlation data to UI code and back, because the native core re-checks every decision against the live ceremony. The decision call itself stays with the `sas-pairing` owner (P10.4, P10.5).

## 6. Proof-of-possession boundary

**What `sas-pairing` proves.** After a successful ceremony with a correct human comparison, each result holder knows that the peer of this exact ceremony supplied exactly the Bootstrap bytes in the result (application identity, key algorithm, public key, shared context), bound to the roles and the transcript, under the conditional security argument of the frozen profile.

**What it does not prove.** That the peer possesses the private key for `public_key`, or that `application_identity` is true. P3 profile §4: "A successful ceremony authenticates the exact supplied algorithm and key bytes but does not prove possession of the private key"; the threat model's result contract says the same.

**Where possession is proved.** In DovahLink's subsequent authentication or session layer, where required: for example a fresh challenge signed with the long-term key whose public half the ceremony authenticated, verified against those exact authenticated bytes. DovahLink has already selected an application-level fresh ECDSA P-256 proof of possession for normal reconnect (its slice S7, protocol not yet specified) and requires "client proof-of-possession, user authorization, cryptographic confirmation, and durable finalization" before permanent trust ([DovahLink `identity-and-transport.md` §10–§11](https://github.com/Soneka96/DovahLink/blob/9f4e925cc8dcba0db37d1bd7d38b39f0927b9387/ai/context/security/identity-and-transport.md#11-trusted-reconnect-and-hello)). P10.1 does not choose the proof flow; P10.2 audits whether DovahLink's current system provides it ([§14](#14-p102-authentication-audit-contract)).

## 7. Pair / Reject / Block boundary

Two different human decisions, kept apart:

```text
SAS comparison (sas-pairing)                    Application authorization (DovahLink)
  MATCH / MISMATCH / CANCEL                       Pair / Reject / Block
  bound to ceremony_identity                      bound to the same exact attempt
  → local verified completion (PairingResult)     → durable trust only after Pair
```

MATCH approves one exact SAS comparison. It is not Pair, does not persist KnownDevice or KnownHost, and does not mean "trust forever". Pair, Reject, and Block are DovahLink application policy on a pending authorization that names the exact attempt; their persistence semantics stay DovahLink's (DovahLink records that "the application meaning and persistence semantics of Block before completed trust remain for a focused design", [§10](https://github.com/Soneka96/DovahLink/blob/9f4e925cc8dcba0db37d1bd7d38b39f0927b9387/ai/context/security/identity-and-transport.md#selected-dovahlink-pairing-authorization-architecture)). Whether a consumer may later present both decisions on one screen is a UX choice for P10.5, but the two remain separate state transitions with separate meanings, and the exact DovahLink states that represent "local completion" and "pending Pair" are an owner decision ([P10-OD-06](decisions.md#pending-owner-decisions)).

## 8. Durable trust boundary

KnownHost (client side: "this Client previously established a relationship with this Host identity", not live trust) and KnownDevice (Host side: the Host-authoritative trusted, revoked, blocked, or unpaired record) are DovahLink's, as are their storage (DPAPI on Windows today), revoke, block, unblock, forget, Reset Trust, and Factory Reset. `sas-pairing` persists nothing and offers no trust store. A DovahLink KnownDevice or KnownHost record may be created or bound to a key only after DovahLink's own authorization (Pair) and whatever proof of possession P10.2 requires; a `PairingResult` alone never writes one (P10.6).

## 9. Normal reconnect boundary

```text
unknown peer
  → SAS pairing (sas-pairing)                         ← once, or a deliberate re-pairing
  → DovahLink application authorization (Pair)
  → durable trust (KnownHost / KnownDevice)
  → future connection
  → normal DovahLink authentication / proof of possession
  → fresh runtime session
```

An already-trusted peer never runs SAS to reconnect. SAS establishes trust, or deliberately re-establishes it after reset, revocation, key loss, or another DovahLink-defined re-pair condition. Reconnect is DovahLink's normal authentication (today a bearer credential in `hello.auth`; target an application-level proof of possession on a pinned-Host TLS session), and every reconnect creates a fresh session. The `sas-pairing` runtime, authority, and listener are not needed for reconnect at all. P10.7 proves this.

## 10. Network identity boundary

An IP address, port, socket, `sas-pairing` connection handle, network interface, or listener address is never a peer identity or trust material, on either side. This already holds in both repositories: the ABI says a socket, its address, and its port "are not protocol identity, authenticated identity, or security identity" ([ABI contract §17](../p7-native-abi/abi-contract.md#17-windows-listener-ownership)), handles "must not be persisted, sent to peers, or used as trust material" ([§4](../p7-native-abi/abi-contract.md#4-handles)); DovahLink says "transport location is not identity" and an endpoint is "never identity or trust" ([DovahLink `ARCHITECTURE.md`](https://github.com/Soneka96/DovahLink/blob/9f4e925cc8dcba0db37d1bd7d38b39f0927b9387/ARCHITECTURE.md#runtime-and-identity-model), [`identity-and-transport.md` §7](https://github.com/Soneka96/DovahLink/blob/9f4e925cc8dcba0db37d1bd7d38b39f0927b9387/ai/context/security/identity-and-transport.md#7-endpoint-semantics-and-discovery)). A changed endpoint never redefines an identity. In particular, P10 must link a completed ceremony to a DovahLink session or pending attempt through authenticated material (the authenticated Bootstrap contents and `ceremony_identity`), never through matching addresses or ports of the two sockets ([§14](#14-p102-authentication-audit-contract) question X).

Note for P10.2: DovahLink's current public listener admits loopback peers only and rejects others by remote address (`PublicWebSocketListener.cs`). That is an exposure restriction, not an identity decision; P10.2 confirms it does not act as trust (question P).

## 11. Bootstrap pre-assessment (not frozen)

P10.1 does not freeze any encoding; P10.2 chooses deterministic canonical bytes ([P10-OD-04](decisions.md#pending-owner-decisions)). JSON is not chosen for convenience, and no protobuf, CBOR, or MessagePack is assumed. What each field must carry, with the DovahLink data that exists today:

| Field (bound) | Must carry | Candidate DovahLink data (source) | Open points for P10.2 |
|---|---|---|---|
| `applicationIdentity` (1–1,024 bytes, opaque) | The endpoint's logical DovahLink identity and its role in DovahLink terms | Host: `hostId`, a UUID persisted per installation ([`HostIdentityStore.cs`](https://github.com/Soneka96/DovahLink/blob/9f4e925cc8dcba0db37d1bd7d38b39f0927b9387/host/DovahLink.Host/Identity/HostIdentityStore.cs)); Client: `clientId`, a UUID generated and persisted by the SDK ([`ClientId.cs`](https://github.com/Soneka96/DovahLink/blob/9f4e925cc8dcba0db37d1bd7d38b39f0927b9387/host/DovahLink.Host/Identity/ClientId.cs), SDK `PersistedClientState.clientId`) | Exact layout; whether a DovahLink role or domain tag is included; `hostName` and display names are presentation metadata and stay out of identity |
| `keyAlgorithm` (1–64 ASCII, `[a-z0-9][a-z0-9.-]*`) | The identifier of the long-term key representation | DovahLink selected DER SubjectPublicKeyInfo with a `SHA-256(SPKI DER)` fingerprint, and ECDSA P-256 for the Client's reconnect key ([`identity-and-transport.md` §5, §6, §11](https://github.com/Soneka96/DovahLink/blob/9f4e925cc8dcba0db37d1bd7d38b39f0927b9387/ai/context/security/identity-and-transport.md)) | Exact identifier string; Host key algorithm (not fixed by DovahLink beyond SPKI) |
| `publicKey` (1–4,096 bytes) | The exact long-term public key whose possession DovahLink later proves | None exists: no Host or Client asymmetric key in DovahLink code today (its S3/S4 slices are unimplemented; no `ECDsa`, `X509Certificate`, `SslStream`, or SPKI use under `host/`, `sdk/`, or `app/lib`) | Who creates the keys, when, and where they are stored ([P10-OD-05](decisions.md#pending-owner-decisions)); a P-256 SPKI is 91 bytes, inside the bound |
| `sharedContext` (0–8,192 bytes, opaque, non-secret, byte-equal on both sides) | The DovahLink application security domain and purpose, independently supplied by each side | A fixed DovahLink pairing domain and context version (both sides know it without the peer) | Each side must supply it independently (P3 §4: never copied from the peer); a Responder's value is fixed per listener for every accepted connection (fact L), so it cannot vary per client or attempt when the Host is the Responder; no secrets, tokens, or credentials |

Also for P10.2: the complete canonical frame is at most 16,384 bytes; fields are authenticated as exact bytes and never normalized; the peer's fields reach DovahLink only as the canonical frame (fact M), so P10.2 decides how DovahLink reads them ([P10-OD-13](decisions.md#pending-owner-decisions)); and the role assignment changes which side's Bootstrap is per-listener ([P10-OD-10](decisions.md#pending-owner-decisions)).

## 12. DovahLink current-state evidence

Read only, at `9f4e925` (P10.1 read `4a69ee5`; P10.1.1 verified that no file behind any row changed). These are facts about the current implementation that P10 planning depends on; they are **not** an authentication verdict (P10.2 issues that).

| Area | Current state | Evidence |
|---|---|---|
| Process model | The Host is a standalone .NET process, started and supervised by the native SKSE adapter, never inside Skyrim; it does no game-thread work | [`ARCHITECTURE.md` "Host and native adapter"](https://github.com/Soneka96/DovahLink/blob/9f4e925cc8dcba0db37d1bd7d38b39f0927b9387/ARCHITECTURE.md#host-and-native-adapter); [`host/architecture.md`](https://github.com/Soneka96/DovahLink/blob/9f4e925cc8dcba0db37d1bd7d38b39f0927b9387/ai/context/host/architecture.md); `Program.cs` (async `Main`, DI composition) |
| Public transport | Loopback-only WebSocket listener (IPv4 and IPv6 loopback); non-loopback remote peers rejected | [`PublicWebSocketListener.cs`](https://github.com/Soneka96/DovahLink/blob/9f4e925cc8dcba0db37d1bd7d38b39f0927b9387/host/DovahLink.Host/Client/Transport/PublicWebSocketListener.cs); [`protocol/security.md` "Phase 1 exposure"](https://github.com/Soneka96/DovahLink/blob/9f4e925cc8dcba0db37d1bd7d38b39f0927b9387/ai/context/protocol/security.md#phase-1-exposure) |
| Pairing | Host-generated six-digit code shown in Skyrim and typed on the client; one global challenge; a valid code issues a 128-bit bearer credential, held pending until the client acknowledges, then committed as trusted. The challenge is keyed by `clientId` | [`PairingCoordinator.cs`](https://github.com/Soneka96/DovahLink/blob/9f4e925cc8dcba0db37d1bd7d38b39f0927b9387/host/DovahLink.Host/Pairing/PairingCoordinator.cs) (`BeginPairing(ClientId)`, `ConfirmCode`, `CommitPendingAsync`); [`protocol/security.md` "Persistent local trust"](https://github.com/Soneka96/DovahLink/blob/9f4e925cc8dcba0db37d1bd7d38b39f0927b9387/ai/context/protocol/security.md#persistent-local-trust) |
| KnownDevice | `TrustRecord`: `clientId`, short ID, display name, state (Trusted / Revoked / Blocked / Unpaired), SHA-256 verifier of the bearer credential, paired and blocked times, incarnation; DPAPI-protected per-user file | [`TrustRecord.cs`](https://github.com/Soneka96/DovahLink/blob/9f4e925cc8dcba0db37d1bd7d38b39f0927b9387/host/DovahLink.Host/Trust/TrustRecord.cs), [`CredentialHasher.cs`](https://github.com/Soneka96/DovahLink/blob/9f4e925cc8dcba0db37d1bd7d38b39f0927b9387/host/DovahLink.Host/Trust/CredentialHasher.cs), `WindowsDpapiTrustStorePersistence.cs` |
| KnownHost | SDK `PersistedKnownHost`: Host metadata (`hostId`, `hostName`, endpoint), the bearer credential, a `pairingRequired` hint; keyed by `hostId`; one Host-scoped pending recovery; DPAPI storage through the SDK's Windows entry point | [`persisted_known_host.dart`](https://github.com/Soneka96/DovahLink/blob/9f4e925cc8dcba0db37d1bd7d38b39f0927b9387/sdk/dart/dovahlink_client/lib/src/persistence/persisted_known_host.dart), [`persisted_client_state.dart`](https://github.com/Soneka96/DovahLink/blob/9f4e925cc8dcba0db37d1bd7d38b39f0927b9387/sdk/dart/dovahlink_client/lib/src/persistence/persisted_client_state.dart), [`dovahlink_client_windows.dart`](https://github.com/Soneka96/DovahLink/blob/9f4e925cc8dcba0db37d1bd7d38b39f0927b9387/sdk/dart/dovahlink_client/lib/dovahlink_client_windows.dart) |
| Reconnect | `hello.auth` with `trusted_device_credential` (the persisted bearer credential) | [`protocol/security.md` "Hello authentication and session trust tiers"](https://github.com/Soneka96/DovahLink/blob/9f4e925cc8dcba0db37d1bd7d38b39f0927b9387/ai/context/protocol/security.md#hello-authentication-and-session-trust-tiers) |
| Long-term keys | None in code; target architecture selects Host and Client key pairs, SPKI identities, TLS 1.3 with Host pinning, and Client PoP; slices S3–S11 blocked by DovahLink's S2.2 STOP | [`identity-and-transport.md` §4, §19](https://github.com/Soneka96/DovahLink/blob/9f4e925cc8dcba0db37d1bd7d38b39f0927b9387/ai/context/security/identity-and-transport.md#4-current-implementation-and-target-architecture) |
| Authorization architecture | Selected, not implemented: evidence → pending approval for one exact attempt → Pair / Reject / Block in Skyrim → durable trust only after Pair | [`identity-and-transport.md` §10](https://github.com/Soneka96/DovahLink/blob/9f4e925cc8dcba0db37d1bd7d38b39f0927b9387/ai/context/security/identity-and-transport.md#selected-dovahlink-pairing-authorization-architecture); [`roadmap/deviations/current-execution-flow.md`](https://github.com/Soneka96/DovahLink/blob/9f4e925cc8dcba0db37d1bd7d38b39f0927b9387/roadmap/deviations/current-execution-flow.md) |
| Skyrim-side decision path | The private IPC carries pairing display, display acknowledgement, and attempts-exhausted messages to Skyrim, and trust-administration requests from Skyrim (console, optional ConsoleUtil Extended); no pairing decision message exists | `host/DovahLink.Host/Adapter/Ipc/`, `adapter/ipc/`; [`protocol/security.md` "Trust administration surface"](https://github.com/Soneka96/DovahLink/blob/9f4e925cc8dcba0db37d1bd7d38b39f0927b9387/ai/context/protocol/security.md#trust-administration-surface) |
| Client architecture | Flutter app: Redux with middleware calling the SDK; the SDK owns pairing, authentication, reconnect, and Known Hosts behind platform ports; the app never handles keys or security policy | [`flutter/architecture.md`](https://github.com/Soneka96/DovahLink/blob/9f4e925cc8dcba0db37d1bd7d38b39f0927b9387/ai/context/flutter/architecture.md), [`sdk/architecture.md` "Platform ports"](https://github.com/Soneka96/DovahLink/blob/9f4e925cc8dcba0db37d1bd7d38b39f0927b9387/ai/context/sdk/architecture.md#platform-ports), `identity-and-transport.md` §18 |

## 13. DovahLink boundary matrix

| DovahLink concept | Owner | `sas-pairing` input / output | Platform-neutral? | P10 increment |
|---|---|---|---|---|
| `hostId` | DovahLink Host | Input: encoded in the Host's `applicationIdentity` (P10.2); output: inside the Client's authenticated peer Bootstrap | Yes | P10.2 map; P10.3 Host |
| `clientId` | DovahLink SDK (Client) | Input: in the Client's `applicationIdentity`; output: inside the Host's authenticated peer Bootstrap | Yes | P10.2; P10.4 |
| Host long-term key | DovahLink Host (storage: DovahLink) | Input: public half in the Host's `publicKey`; private half never touches `sas-pairing` | Concept yes; key storage is a DovahLink platform port | P10.2 (OD-05); P10.6 |
| Client long-term key | DovahLink SDK and its platform layer | Input: public half in the Client's `publicKey`; private half never touches `sas-pairing` | Concept yes; key storage is a DovahLink platform port | P10.2 (OD-05); P10.6 |
| Key algorithm | DovahLink | Input: `keyAlgorithm`; `sas-pairing` authenticates the exact identifier, interprets nothing | Yes | P10.2 |
| Bootstrap | DovahLink chooses the content; `sas-pairing` validates bounds and authenticates bytes | Input: four byte fields (`SasPairingBootstrap`); output: the peer's canonical frame in the result | Yes | P10.2 encoding; P10.3/P10.4 use |
| Shared context | DovahLink chooses the bytes; `sas-pairing` compares and authenticates them | Input: `sharedContext` on both sides; output: authenticated shared context | Yes | P10.2 |
| SAS display | `sas-pairing` produces it; DovahLink presents it | Output: `SasPairingSasPresentation` decimal `NNNN NNNN NNNN` plus identity | Yes (a plain string) | P10.5 |
| Ceremony identity | `sas-pairing` | Output: 32 bytes in presentation and result; input: MATCH / MISMATCH / CANCEL | Yes | P10.5 |
| `PairingResult` | `sas-pairing` (runtime-owned) | Output: local verified completion; read once into DovahLink pairing evidence | Yes | P10.3/P10.4 translate; P10.6 consume |
| Pending authorization | DovahLink Host (and Client pending state) | Input to DovahLink: pairing evidence keyed by the exact attempt; nothing back into `sas-pairing` | Yes | P10.6 (model in P10.2) |
| Proof of possession | DovahLink | None: `sas-pairing` only authenticated the public key bytes | Yes | P10.2 audit; P10.6/P10.7 |
| Pair | DovahLink Host (Skyrim user) | None | Yes | P10.6 |
| Reject | DovahLink Host | None (a SAS MISMATCH is a separate, earlier `sas-pairing` decision) | Yes | P10.6 |
| Block | DovahLink Host | None | Yes | P10.6 |
| KnownHost | DovahLink SDK | None; may be created only after authorization, never from a result alone | Yes (storage behind an SDK port) | P10.6 |
| KnownDevice | DovahLink Host | None; same rule | Yes (storage behind a Host port) | P10.6 |
| Normal reconnect | DovahLink | None: no `sas-pairing` object is used | Yes | P10.7 |
| Runtime session (`sessionId`) | DovahLink Host | None | Yes | P10.7 |
| Listener / transport for the ceremony | `sas-pairing` owns the carrier inside its owner loop; DovahLink's Windows adapter binds and hands over the listener and schedules drives | Input: a bound listening socket (Windows-specific); output: connections and events | **No**: Windows infrastructure only, below the adapter | P10.3, P10.4 |
| Discovery | DovahLink | None; discovery yields candidates, never identity or trust | Yes | Unchanged in P10 (endpoint question OD-11) |
| UI | DovahLink (Flutter app; Skyrim through the adapter) | Presentation data in, decisions out, through the integration owner | Yes (no native types in UI) | P10.4, P10.5 |

## 14. P10.2 authentication audit contract

P10.2 must audit DovahLink's **current** authentication and trust, from source and tests, before any major integration. It answers every question below with evidence:

| | Question |
|---|---|
| A | What currently authenticates the Host? |
| B | What currently authenticates the Client? |
| C | Is `clientId` merely an identifier, or cryptographic proof? |
| D | Is `hostId` merely an identifier, or cryptographic proof? |
| E | What long-term secret or private key does each side possess? |
| F | How does the peer prove possession of it? |
| G | Is that proof bound to the current connection or session? |
| H | Can identifiers be copied or spoofed? |
| I | Can credentials be copied to another machine? |
| J | Can authentication material be replayed? |
| K | What does KnownHost actually store? |
| L | What does KnownDevice actually store? |
| M | What happens after revoke? |
| N | What happens after block? |
| O | Can stale credentials reconnect? |
| P | Does an IP address, address, or port participate in trust incorrectly? |
| Q | What survives application restart? |
| R | What survives game restart? |
| S | What exact long-term identity material should `sas-pairing` authenticate? |
| T | Does `sas-pairing` authenticate enough information for the later DovahLink proof-of-possession step? |
| U | Can the current authentication remain unchanged? |
| V | Can it survive with targeted changes? |
| W | Or must it be replaced? |

Added by P10.1 from this assessment:

| | Question |
|---|---|
| X | How is a completed ceremony (its `ceremony_identity` and authenticated Bootstrap) linked to the DovahLink session and pending attempt it authorizes, without using network location, given that the ceremony runs on a separate `sas-pairing` socket? |
| Y | Do the Host and Client long-term keys that the Bootstrap must carry exist; if not, what must be created, by whom, and in which slice ([P10-OD-05](decisions.md#pending-owner-decisions))? |
| Z | Does DovahLink's invariant that Host verification and Client proof of possession happen on one cryptographically bound transport hold for the composition of a separate-socket SAS ceremony and a later DovahLink session? |
| AA | Does any current path (developer token, loopback restriction, pending-credential recovery) let something other than the new evidence and authorization create trust? |
| AB | What do revoke, block, Reset Trust, and Factory Reset do to an in-flight ceremony and to a pending authorization (DovahLink's mutation fence)? |

**Required verdict.** P10.2 ends with exactly one of:

- ✅ **WORKS AS-IS**
- 🟡 **WORKS WITH TARGETED CHANGES**
- 🔴 **DOES NOT PROVIDE ADEQUATE AUTHENTICATION — REPLACEMENT REQUIRED**

P10.1 chooses none of them. The facts in [§12](#12-dovahlink-current-state-evidence) (bearer credential, no long-term keys in code, six-digit code) are inputs to that audit, not its conclusion. No P10 integration implementation starts before the verdict is recorded.
