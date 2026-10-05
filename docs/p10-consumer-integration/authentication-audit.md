# P10.2 DovahLink Authentication and Trust Audit

> **Pre-alpha. Audit and design evidence only.** This document is the P10.2 audit of DovahLink's **current** authentication, trust, and reconnect system, recorded under [P10-D-003](decisions.md#p10-d-003--dovahlink-authentication-disposition-and-pop-boundary). It changes no DovahLink or `sas-pairing` code. It is not a professional audit, formal verification, hostile-network approval, or production-security approval; DovahLink's own security gate remains DovahLink's decision.

Baseline: DovahLink `main` `9f4e925cc8dcba0db37d1bd7d38b39f0927b9387`, fetched live from GitHub at the start of P10.2 (unchanged since the P10.1.1 reconciliation, so no reconciliation was needed), read only. DovahLink links below are pinned to that commit. `sas-pairing` baseline: `feature/p10-consumer-integration` at `2869089` over `main` `b938016`. The Bootstrap mapping that this audit feeds is in [bootstrap-mapping.md](bootstrap-mapping.md).

## 1. What the verdict judges

The P10 target already replaces DovahLink's **initial** six-digit pairing ceremony with `sas-pairing` ([P10-D-001](decisions.md#p10-d-001--consumer-boundary-platform-boundary-and-portability-discipline)). The verdict below is therefore **not** about the six-digit ceremony. It answers one question:

> Can DovahLink's current durable trust and normal-reconnect authentication mechanism safely remain after the initial ceremony becomes `sas-pairing`?

It judges long-term Host authentication, long-term Client authentication, credential possession, replay resistance, session freshness and binding, key / identity binding, KnownHost and KnownDevice state, revoke / block / reset semantics, and restart persistence. The six-digit flow appears below only where its mechanics (it issues the bearer credential) explain the durable state.

## 2. Labels

Every claim is labelled:

- **CURRENT**: behaviour of DovahLink code at `9f4e925`, read from source and tests.
- **TARGET-DESIGN**: selected DovahLink architecture in its documents that is **not implemented** (or not yet specified).
- **P10-DECISION**: a decision recorded by P10 ([P10-D-002](decisions.md#p10-d-002--canonical-dovahlink-bootstrap-v1-mapping), [P10-D-003](decisions.md#p10-d-003--dovahlink-authentication-disposition-and-pop-boundary)).

A target document is never treated as implemented code.

## 3. Sources reviewed

DovahLink (read only, at `9f4e925`), complete reads unless marked:

- Host: [`Pairing/PairingCoordinator.cs`](https://github.com/Soneka96/DovahLink/blob/9f4e925cc8dcba0db37d1bd7d38b39f0927b9387/host/DovahLink.Host/Pairing/PairingCoordinator.cs), `Pairing/PairingChallenge.cs`, [`Trust/TrustRecord.cs`](https://github.com/Soneka96/DovahLink/blob/9f4e925cc8dcba0db37d1bd7d38b39f0927b9387/host/DovahLink.Host/Trust/TrustRecord.cs), [`Trust/TrustStore.cs`](https://github.com/Soneka96/DovahLink/blob/9f4e925cc8dcba0db37d1bd7d38b39f0927b9387/host/DovahLink.Host/Trust/TrustStore.cs), [`Trust/CredentialHasher.cs`](https://github.com/Soneka96/DovahLink/blob/9f4e925cc8dcba0db37d1bd7d38b39f0927b9387/host/DovahLink.Host/Trust/CredentialHasher.cs), `Trust/KnownDeviceIncarnationId.cs`, `Trust/TrustSecuritySnapshot.cs`, [`Trust/TrustAdminService.cs`](https://github.com/Soneka96/DovahLink/blob/9f4e925cc8dcba0db37d1bd7d38b39f0927b9387/host/DovahLink.Host/Trust/TrustAdminService.cs), [`Trust/TrustResetService.cs`](https://github.com/Soneka96/DovahLink/blob/9f4e925cc8dcba0db37d1bd7d38b39f0927b9387/host/DovahLink.Host/Trust/TrustResetService.cs), `Trust/WindowsDpapiTrustStorePersistence.cs` (load / save / corruption paths), `Enums.cs` (`KnownDeviceState`), [`Identity/HostIdentityStore.cs`](https://github.com/Soneka96/DovahLink/blob/9f4e925cc8dcba0db37d1bd7d38b39f0927b9387/host/DovahLink.Host/Identity/HostIdentityStore.cs), `Identity/HostId.cs`, `Identity/HostIdentity.cs`, `Identity/HostIdentityProvider.cs`, `Identity/ClientId.cs`, [`Client/Authentication/PublicHelloAdmissionHandler.cs`](https://github.com/Soneka96/DovahLink/blob/9f4e925cc8dcba0db37d1bd7d38b39f0927b9387/host/DovahLink.Host/Client/Authentication/PublicHelloAdmissionHandler.cs), `Client/Authentication/TrustedCredentialFailureThrottle.cs` (structure), [`Authentication/LocalConnectionTokenAuthenticator.cs`](https://github.com/Soneka96/DovahLink/blob/9f4e925cc8dcba0db37d1bd7d38b39f0927b9387/host/DovahLink.Host/Authentication/LocalConnectionTokenAuthenticator.cs), `Client/Protocol/{HelloPayload,HelloAuthPayload,HelloAckPayload}.cs`, `Security/SecurityStateGate.cs`, `Sessions/ClientSessionInvalidator.cs`, `Sessions/SessionRegistry.cs` (developer-session exemption), [`Client/Transport/PublicWebSocketListener.cs`](https://github.com/Soneka96/DovahLink/blob/9f4e925cc8dcba0db37d1bd7d38b39f0927b9387/host/DovahLink.Host/Client/Transport/PublicWebSocketListener.cs) (bind and loopback check), `Client/Transport/PublicListenerOptions.cs`, `Composition/TrustServiceExtensions.cs`, [`Program.cs`](https://github.com/Soneka96/DovahLink/blob/9f4e925cc8dcba0db37d1bd7d38b39f0927b9387/host/DovahLink.Host/Program.cs), `Constants.cs` (identity and trust paths, credential and token lengths and lifetimes, throttles, public port).
- SDK: [`lib/src/dovahlink_pairing.dart`](https://github.com/Soneka96/DovahLink/blob/9f4e925cc8dcba0db37d1bd7d38b39f0927b9387/sdk/dart/dovahlink_client/lib/src/dovahlink_pairing.dart), [`internal/authentication/authentication_service.dart`](https://github.com/Soneka96/DovahLink/blob/9f4e925cc8dcba0db37d1bd7d38b39f0927b9387/sdk/dart/dovahlink_client/lib/src/internal/authentication/authentication_service.dart), `internal/authentication/{client_id_resolver,client_id_cache}.dart`, [`internal/pairing/pairing_service.dart`](https://github.com/Soneka96/DovahLink/blob/9f4e925cc8dcba0db37d1bd7d38b39f0927b9387/sdk/dart/dovahlink_client/lib/src/internal/pairing/pairing_service.dart), `internal/reconnect/{reconnect_service,reconnect_rejection_classifier}.dart` (reconnect entry points), `internal/session/{session_admission_service,session_trust_service}.dart`, `internal/random_id_generator.dart`, [`persistence/persisted_client_state.dart`](https://github.com/Soneka96/DovahLink/blob/9f4e925cc8dcba0db37d1bd7d38b39f0927b9387/sdk/dart/dovahlink_client/lib/src/persistence/persisted_client_state.dart), [`persistence/persisted_known_host.dart`](https://github.com/Soneka96/DovahLink/blob/9f4e925cc8dcba0db37d1bd7d38b39f0927b9387/sdk/dart/dovahlink_client/lib/src/persistence/persisted_known_host.dart), `persistence/pending_pairing_recovery.dart`, `persistence/persisted_client_state_decoder.dart` (persisted keys), `persistence/windows/{dpapi,dpapi_client_storage}.dart` (scope and path), `protocol/host_identity_validator.dart`, `dovahlink_host.dart`, `dovahlink_host_id.dart`, [`lib/dovahlink_client_windows.dart`](https://github.com/Soneka96/DovahLink/blob/9f4e925cc8dcba0db37d1bd7d38b39f0927b9387/sdk/dart/dovahlink_client/lib/dovahlink_client_windows.dart).
- App: the pairing feature (`app/lib/features/pairing/`: datasource, repository, use cases, Redux state, phases in `app/lib/shared/constants/enums.dart` `PairingPhase`, the code-entry widgets).
- Protocol and security: [`protocol/schema/README.md`](https://github.com/Soneka96/DovahLink/blob/9f4e925cc8dcba0db37d1bd7d38b39f0927b9387/protocol/schema/README.md) (envelope, `hello`, `hello_ack`, every `pairing_*` message, `error`, `session_invalidated`, session rules), [`ai/context/protocol/security.md`](https://github.com/Soneka96/DovahLink/blob/9f4e925cc8dcba0db37d1bd7d38b39f0927b9387/ai/context/protocol/security.md), [`ai/context/security/identity-and-transport.md`](https://github.com/Soneka96/DovahLink/blob/9f4e925cc8dcba0db37d1bd7d38b39f0927b9387/ai/context/security/identity-and-transport.md), [`ai/context/security/crypto-stack-selection.md`](https://github.com/Soneka96/DovahLink/blob/9f4e925cc8dcba0db37d1bd7d38b39f0927b9387/ai/context/security/crypto-stack-selection.md), the deviation records `roadmap/deviations/initial-pairing-security/README.md` and `roadmap/deviations/current-execution-flow.md`, [`tooling/security_feasibility/README.md`](https://github.com/Soneka96/DovahLink/blob/9f4e925cc8dcba0db37d1bd7d38b39f0927b9387/tooling/security_feasibility/README.md) (the S2 TLS and key POCs), `ARCHITECTURE.md` (runtime, identity, Host supervision), `ROADMAP.md` (current position and security gate).
- Tests cited as evidence: `host/DovahLink.Host.Tests/Client/Authentication/PublicHelloAdmissionTests.cs`, `…/Pairing/PairingCoordinatorTests.cs`, `…/Trust/{TrustStoreTests,TrustAdminServiceTests,TrustResetServiceTests,CredentialHasherTests}.cs`, `…/Identity/HostIdentityStoreTests.cs`, `…/Authentication/LocalConnectionTokenAuthenticatorTests.cs`, `…/Client/Transport/PublicWebSocketListenerTests.cs`; SDK tests under `sdk/dart/dovahlink_client/test/` (authentication, pairing, persistence, Known Host).

`sas-pairing` (this repository): the four P10.1 documents, the [P10 roadmap](../../roadmap/P10-consumer-integration.md), [P3 profile](../p3-vodozemac-ceremony-profile-draft.md) §2–§4 and §8–§10 and §11.1.2–§11.1.3, [P6 closure](../p6-remediation/final-closure.md), [ABI contract](../p7-native-abi/abi-contract.md) §17, §19, §20, the [ABI v1 manifest](../p7-native-abi/abi-v1-manifest.md), [P7](../p7-native-abi/decisions.md), [P8](../p8-dart-package/decisions.md), and [P9](../p9-dotnet-package/decisions.md) decisions and closures, the public `SasPairingBootstrap` / `SasPairingResult(Data)` types of both wrappers, `core/src/protocol.rs` (`Bootstrap::new`, `encode_frame`) and `core/src/ceremony.rs` (`validate_bootstraps`).

## 4. Current authentication architecture (CURRENT)

- **Transport.** One plain (no TLS) WebSocket listener bound to `127.0.0.1` and `::1` on port 58231; accepted sockets whose remote address is not loopback are rejected (`PublicWebSocketListener.IsLoopbackRemote`). The S2 feasibility README records the same: the listener "upgrades WebSocket traffic without TLS".
- **First message.** The client always sends `hello` first with `endpoint`, its `clientId`, and `auth`: `unpaired` (no token), `trusted_device_credential` (the persisted credential), or `one_time_local_token` (developer).
- **Host identity.** `hello_ack` returns `hostId` (a UUID read from the non-secret per-Windows-user file `%LOCALAPPDATA%\DovahLink\host\host-id.dat`), `hostName`, `hostVersion`, and `clientIdentityKind`. Nothing is signed; no Host key or certificate exists.
- **Initial pairing.** On an `unpaired` (Restricted) session: a Host-generated six-digit code shown in Skyrim and typed on the client; a correct code mints a 128-bit credential (32 lowercase hex characters, `RandomNumberGenerator.GetHexString`) held in Host memory and returned in `pairing_outcome credential_issued`; the client persists it with a Host-scoped `confirming` recovery record, then echoes it in `pairing_ack`; the Host writes a `Trusted` `TrustRecord` with `SHA-256(credential)` and upgrades that same session to Full in place.
- **Trusted reconnect.** `hello` with `trusted_device_credential`: the Host looks up the `TrustRecord` by the presented `clientId`, rejects `Blocked` (`blocked`) and `Revoked` (`revoked`), and compares `SHA-256(UTF-8(token))` with the stored verifier in fixed time through a global failure throttle (5 per 60 s); it re-checks after reserving the session slot; success admits a fresh Full session bound to that socket.
- **Sessions.** A fresh random `sessionId` per admitted socket; per-session `messageId` uniqueness (replay protection for messages, not for authentication); `session_invalidated` plus force-close on administrative mutation.
- **Persistence.** Host: `TrustRecord` list, JSON, DPAPI current-user, `%LOCALAPPDATA%\DovahLink\host\trust-store.dat`, atomic replace, fail closed on corruption. Client: `PersistedClientState` format 4, DPAPI current-user, `%LOCALAPPDATA%\DovahLink\`.

## 5. Target authentication architecture (TARGET-DESIGN, selected but not implemented)

From `identity-and-transport.md` (§1, §4–§6, §8–§11, §13–§21) and `crypto-stack-selection.md`:

| Element | Selected direction | State |
|---|---|---|
| Host logical identity | `hostId` UUID, unchanged | CURRENT (exists) |
| Host cryptographic identity | Persistent asymmetric key pair; private key never leaves the Host; DPAPI or Windows CNG storage | Selected (S3); **algorithm not selected by DovahLink** (P10-DECISION: ECDSA P-256, [P10-D-002](decisions.md#p10-d-002--canonical-dovahlink-bootstrap-v1-mapping)); unimplemented |
| Client logical identity | `clientId` UUID, unchanged | CURRENT (exists) |
| Client cryptographic identity | Persistent non-exportable ECDSA P-256 key; platform key storage behind an SDK port | Selected (S4, §10/§11); unimplemented |
| Public identity representation | DER SubjectPublicKeyInfo; fingerprint `SHA-256(SPKI DER)` unpadded base64url | Selected (§5, §6, S2.1); unimplemented |
| Transport | WSS over TLS 1.3, self-generated Host certificate, Host-key pinning by SPKI, no resumption, no 0-RTT | Selected (S5, S6); unimplemented |
| Host verification | TLS proves the pinned Host key before any application data | Selected (§11); unimplemented |
| Normal reconnect | Host fresh random challenge → Client domain-separated ECDSA P-256 signature → verify against the KnownDevice key → consume challenge → apply trust state; not mTLS | Selected (S7); **underspecified**: transcript bytes, domain, challenge size / entropy / lifetime / single use, signature encoding, replay behaviour, vectors are S7 work |
| Initial pairing | Evidence → pending approval for one exact attempt → Pair / Reject / Block → trust | Selected application architecture (§10); construction unselected by DovahLink (S2.2 STOP); `sas-pairing` is the intended construction |
| Provisional TLS for pairing | Accept the candidate certificate only during user-started pairing; trust only if the selected construction binds the exact SPKI and `hostId` (S6 guard) | Selected guard; unimplemented |

The S2 POCs (`tooling/security_feasibility/`: a non-exportable CNG ECDSA P-256 Host TLS key, Dart SPKI pinning, a Client challenge-signature flow) are feasibility evidence for separate primitives, not implementation.

## 6. Host authentication audit (CURRENT)

**What lets the Client believe it reached the intended Host today?** Only that something answered on the configured loopback endpoint with a `hello_ack` whose `hostId` matches the Known Host it asked for (`AuthenticationService._hello`: `normalizedKnownHostId != currentHost.hostId` → `DovahLinkHostIdentityMismatchException`). That is a claim, not authentication.

| Question | Answer | Evidence |
|---|---|---|
| Is `hostId` cryptographic proof? | **No.** A non-secret UUID in a per-user file, returned unsigned in `hello_ack` and from the unauthenticated `GET /.well-known/dovahlink` | `HostIdentityStore.cs`; `PublicHelloAdmissionHandler.Admit`; `protocol/security.md` "Phase 1 exposure" and "Hello authentication …" ("`hostId` is … not an authentication secret or proof of trust") |
| Is loopback Host authentication? | **No.** Loopback is an exposure restriction applied by the Host to its peers. It says nothing to the client about which local process owns the port | `PublicWebSocketListener.cs`; `protocol/security.md` "Local-OS-user threat boundary" ("loopback TCP itself is not proof of Windows-user identity") |
| Does the client pin a Host cryptographic identity? | **No.** `PersistedKnownHost` has no key or pin field | `persisted_known_host.dart`; `identity-and-transport.md` §4 ("no cryptographic pin or peer authentication is implemented") |
| Can a different process claim the same `hostId`? | **Yes.** Any process able to bind the endpoint (for example while the Host is not running) can return any `hostId` it has read | No Host key, no TLS (`Program.cs`, `PublicWebSocketListener.cs`) |
| What survives Client restart? | `clientId`, every Known Host (`hostId`, `hostName`, endpoint, bearer credential, `pairingRequired`), the Host-scoped pending recovery | `persisted_client_state.dart`, `dpapi_client_storage.dart` |
| Order of disclosure | The client sends its bearer credential in `hello` **before** it receives the `hostId` claim it later checks | `authentication_service.dart` `_hello` (payload built and sent, then `hello_ack` decoded and `hostId` compared) |

Routing (endpoint, loopback, port) and authentication are different things; today there is routing and an identity claim, and no Host authentication. DovahLink's own §17 already rejects a sequence that checks `hostId` on one connection and sends the bearer on another for the same reason.

## 7. Client authentication audit (CURRENT)

| | Answer | Evidence |
|---|---|---|
| What the Client presents | `clientId` (UUID string) and `auth.token` = the 32-hex-character credential issued at pairing | `HelloPayload`, `HelloAuthPayload`; `pairing_service.dart` (persisted from `credential_issued`) |
| What the Host stores | `TrustRecord.CredentialVerifier` = lowercase hex `SHA-256(UTF-8(credential))`; never the credential | `TrustRecord.cs`, `CredentialHasher.Hash`, `PairingCoordinator.CommitPendingAsync` |
| What the Host compares | `SHA-256(UTF-8(token))` against the verifier, fixed time, only when the record is `Trusted` (else against a dummy verifier); throttled 5 / 60 s globally; re-checked after slot reservation | `PublicHelloAdmissionHandler.HandleTrustBackedHello`; tests `HandleMessageAsync_MatchingTrustedDeviceCredentialHello_AdmitsPairedSession`, `…_MismatchedTrustedDeviceCredential_…`, `…_RevokedByAdminBetweenInitialCheckAndRecheck_RollsBackAndRejects` |
| Reusable? | **Yes**, for the life of the record: the same value authenticates every reconnect until revoke, block, Reset Trust, or Factory Reset | No rotation path in `PairingCoordinator` or the admission handler |
| Replayable? | **Yes.** No nonce, challenge, timestamp, or session input enters the comparison | `HandleTrustBackedHello` |
| Possession proven by challenge / signature? | **No.** Knowledge of the value is the whole proof | Same |
| Bound to this session? | **No.** The fresh `sessionId` is issued after authentication and is not part of what is proven | `Admit`; `protocol/security.md` "Session and replay protection" |

## 8. Bearer credential analysis (CURRENT)

| | Question | Answer |
|---|---|---|
| A | Is possession of the bearer sufficient to impersonate the stored Client? | **Yes.** `clientId` (sent in clear, not secret) plus the token is everything `HandleTrustBackedHello` checks |
| B | Does authentication require a fresh Host challenge? | **No.** `hello` is the first message; the Host sends nothing before it |
| C | Is there a signature over a fresh transcript? | **No.** No asymmetric key exists on either side |
| D | Is authentication bound to the connection / session? | **No.** Only the resulting session is bound to the socket; the proof is not |
| E | Can the same bearer be replayed? | **Yes**, on any later connection, until an administrative mutation clears the verifier |
| F | If raw credential and `clientId` are copied to another installation, what stops it authenticating as the original device? | **Nothing cryptographic.** Only reachability: the Host accepts loopback peers only, so the copy must run on the Host's machine (any local process qualifies) |
| G | Does DPAPI at rest change the wire semantics? | **No.** DPAPI (current-user scope) protects the file against other Windows users and offline reading; the value on the wire is the same reusable secret, and any process of the same user can call `CryptUnprotectData` |
| H | Does hashing the credential on the Host change the client-side semantics? | **No.** The verifier protects the Host's store against disclosure of usable secrets; the client still presents the raw reusable secret, and whoever holds it authenticates |

Storage encryption is not proof of possession, and a hashed verifier is not asymmetric proof of possession. The credential also crosses the wire in clear: in `pairing_outcome` (`credential_issued`, `trusted`, `already_trusted`), in `pairing_ack`, and in every trusted `hello`, over unencrypted loopback WebSocket.

## 9. KnownHost audit (CURRENT, client side)

`PersistedClientState` format 4, DPAPI current-user, `%LOCALAPPDATA%\DovahLink\`:

| Current Client trust field | Security meaning | Future disposition |
|---|---|---|
| `clientId` (UUID string, generated once by `RandomIdGenerator`, lowercase) | Logical installation identity; a public claim | **Keep**; encoded into the Client `applicationIdentity` ([P10-D-002](decisions.md#p10-d-002--canonical-dovahlink-bootstrap-v1-mapping)); bound to the Client key by the Host only after PoP and Pair |
| `knownHosts` keyed by lowercase `hostId` | Relationship index; one entry per Host | **Keep** the keying; a key-pinned entry is written only after verified Host possession and the Host's Pair (P10.6) |
| `host.hostId` | Claimed Host identity | **Keep**; from P10.6 trusted only together with the pinned key |
| `host.hostName` | Display metadata | **Keep** as display only |
| `host.endpoint` (`ws` / `wss` URI) | Last known route | **Keep** as routing only; never identity |
| `credential` (raw bearer) | The reusable secret that authenticates the client | **Remove** at the atomic P10.7 cutover (DovahLink S9 / S10; no dual mode) |
| `pairingRequired` | UX hint after a rejected credential | **Revisit** in P10.7 (meaning changes once rejection is key-based) |
| `pendingPairingRecovery {hostId, state: confirming}` | Crash recovery for the bearer `pairing_ack` | **Replace** in P10.6 by a pending-attempt record keyed to the exact ceremony and Host (no bearer to recover) |
| Host public key / pin | — | **Absent today.** Added in P10.6: the exact Host SPKI authenticated by the ceremony and verified by TLS possession |

## 10. KnownDevice audit (CURRENT, Host side)

`TrustRecord` (JSON, DPAPI current-user, `%LOCALAPPDATA%\DovahLink\host\trust-store.dat`):

| Current Host trust field | Security meaning | Future disposition |
|---|---|---|
| `ClientId` (Guid) | Logical identity the record is keyed by | **Keep** |
| `ShortId` (five digits, unique among retained records) | Human administration handle; never authentication | **Keep** unchanged |
| `DisplayName` | Presentation only | **Keep** unchanged |
| `State` (`Unpaired`, `Trusted`, `Revoked`, `Blocked`; no record = unknown) | Host-authoritative trust truth | **Keep** unchanged (typed outcomes preserved) |
| `CredentialVerifier` (hex SHA-256 of the bearer; emptied on revoke and block) | What reconnect authenticates against today | **Replace** by the exact Client SPKI and `keyAlgorithm` authenticated by the ceremony and proved by PoP (P10.6); verifier removed at the P10.7 cutover |
| `PairedAtUtc`, `BlockedAtUtc` | Administrative timestamps | **Keep** |
| `Incarnation` (Guid, stable across ordinary transitions, new after Forget or Factory Reset) | Stale-administration fence for one record | **Keep** unchanged; captured by pending authorization (§13 AB) |
| Public key | — | **Absent today** |
| Store-wide `SecurityFenceGeneration` (in memory, incremented by every mutation, not persisted) | Invalidates in-flight pairing across any administrative mutation | **Keep** unchanged; captured by the future pending authorization |

## 11. Revoke, block, and reset audit (CURRENT)

| Operation | Durable state change | Old credentials | Active sessions | Future reconnect returns | In-progress pairing | Can stale pending pairing commit? |
|---|---|---|---|---|---|---|
| Revoke | `Trusted` → `Revoked`; verifier emptied; record, `ShortId`, incarnation kept | Unusable (state checked first; verifier empty) | Invalidated with `session_invalidated revoked`, force-closed | `revoked` | That client's challenge / pending credential cancelled (`Cancel`) unless a commit already claimed it | No: fence advanced, so `ConfirmCode` / `CommitPendingAsync` return `pairing_invalidated`; re-pairing is allowed afterwards |
| Block | `Trusted` / `Revoked` → `Blocked`; verifier emptied; `BlockedAtUtc` set. Unpaired or unknown `clientId`s are not eligible | Unusable | Invalidated `blocked`, closed (developer-token sessions exempt from client-scoped invalidation) | `blocked` (also for `unpaired` hello) | Cancelled; `BeginPairing` returns `Blocked` | No: fence advanced, and `TryUpsertIfGenerationAsync` refuses a `Blocked` record |
| Unblock | `Blocked` → `Unpaired` (no credential) | Remain unusable | None affected | `unauthenticated` for the old credential; pairing allowed | Not affected | Not applicable |
| Forget | `Revoked` / `Unpaired` record deleted (`Trusted` and `Blocked` not eligible); `ShortId` freed | Already unusable | None (no Full session can exist for such a record) | `unauthenticated` | That client's pairing cancelled | No |
| Reset Trust | Every `Trusted` → `Revoked`; records, identities, metadata kept; fence advanced even when nothing changed | Unusable | Affected sessions invalidated `trust_reset`; developer-token sessions unaffected | `revoked` | `CancelAll` | No |
| Factory Reset (six-digit Skyrim / admin confirmation, 60 s, one wrong attempt invalidates) | Every record deleted, including `Blocked` and `Revoked`; `hostId` file untouched | Unusable | Every session invalidated `factory_reset`, including developer-token sessions | `unauthenticated` (no record); a previously blocked client may pair again | `CancelAll` | No |

Evidence: `TrustStore.{RevokeAsync,BlockAsync,UnblockAsync,ForgetAsync,ResetTrustAsync,ClearAsync,TryUpsertIfGenerationAsync,MutateAsync}`, `TrustAdminService`, `TrustResetService.ConfirmResetAsync`, `PairingCoordinator.{ConfirmCode,CommitPendingAsync,BeginPairing}`, `protocol/security.md` "Administrative session invalidation"; tests `ConfirmCode_TrustStoreMutatedAfterChallengeBegan_ReportsPairingInvalidatedWithoutIssuingCredential`, `CommitPending_AfterTrustMutation_ReturnsInvalidated`, `HandleMessageAsync_BlockedIdentity_RejectsAsBlocked`, `HandleMessageAsync_RevokedIdentityTrustedDeviceCredential_RejectsAsRevoked`, `HandleMessageAsync_BlockedByAdminBetweenInitialCheckAndRecheck_RollsBackAndRejects`.

**Restart persistence.** Persistent: trust records and `hostId` (Host); `clientId`, Known Hosts with credentials, pending recovery (client). Lost on Host restart: the pairing challenge, the pending credential (a client's recovery `pairing_ack` then gets `pending_not_found` and discards it), every session, the fence generation counter, the throttles. The Host runs as long as Skyrim (the adapter starts it and requests shutdown when Skyrim closes), so a game restart is a Host restart.

These administrative fences are sound and independent of the authentication primitive; §16 keeps them.

## 12. Developer authentication (CURRENT, classified separately)

`one_time_local_token`: an in-memory 32-hex-character token, five-minute lifetime, single use, validated and consumed atomically, 5 failures per 60 s; it admits a Full session reported as `unpaired`, never enrolls a Known Device, is exempt from client-scoped Revoke / Block, and is ended by Factory Reset. At `9f4e925`, `LocalConnectionTokenAuthenticator.IssueToken` has no production caller and no Host code reads `DOVAHLINK_DEV_TOKEN`, so the path cannot currently succeed in a production Host; `protocol/security.md` "Developer authentication" describes a configured token. This documentation / code drift is a DovahLink observation, not a P10 finding.

Developer authentication is not paired-device trust and creates none. **P10 does not change it**; no conflict with the P10 design was found (it never writes a KnownDevice, never receives a Client key, and never satisfies a pending authorization).

## 13. Audit questions A–AB

Contract: [consumer boundary §14](consumer-boundary.md#14-p102-authentication-audit-contract). Confidence: **High** = read directly in source and tests; **Medium** = read in source, behaviour inferred across components.

| | Question | Answer | Confidence | Sources / tests | Current vs target |
|---|---|---|---|---|---|
| A | What currently authenticates the Host? | Nothing cryptographic. The client accepts whatever answers on the loopback endpoint and checks an unsigned `hostId` claim after sending its credential | High | `authentication_service.dart` `_hello`; `PublicHelloAdmissionHandler.Admit` | TARGET-DESIGN: TLS 1.3 with a pinned Host SPKI (S5 / S6) |
| B | What currently authenticates the Client? | Knowledge of the reusable bearer credential matching the stored SHA-256 verifier for the claimed `clientId` | High | `HandleTrustBackedHello`; `CredentialHasher`; admission tests | TARGET-DESIGN: fresh-challenge ECDSA P-256 PoP (S7) |
| C | Is `clientId` an identifier or proof? | Identifier only; client-chosen, sent in clear | High | `HelloPayload` ("not itself a trust credential"); schema `hello` | Unchanged as logical identity; target binds it to a key |
| D | Is `hostId` an identifier or proof? | Identifier only | High | `HostIdentityStore`; `protocol/security.md` | Same |
| E | What long-term secret or private key does each side possess? | Client: the bearer credential. Host: only the verifier. **No private key on either side** | High | `TrustRecord`; `PersistedKnownHost`; repository search: no `ECDsa`, `X509Certificate`, `SslStream`, or SPKI under `host/`, `sdk/`, `app/lib` | TARGET-DESIGN: Host and Client key pairs (S3 / S4) |
| F | How does the peer prove possession? | Client: by presenting the secret itself. Host: it does not | High | Same | Target: TLS CertificateVerify (Host), application signature (Client) |
| G | Is the proof bound to the connection / session? | No | High | `HandleTrustBackedHello` | Target: same TLS session, fresh Host challenge |
| H | Can identifiers be copied or spoofed? | Yes: both are public UUIDs; any local process can send any `clientId` or answer with any `hostId` | High | Schema `hello` / `hello_ack`; `/.well-known/dovahlink` | Unchanged; keys make them non-sufficient |
| I | Can credentials be copied to another machine? | Yes; copied values work from any process that can reach the Host's loopback listener | High | §8 F, G | Target: non-exportable keys |
| J | Can authentication material be replayed? | Yes | High | §8 E | Target: single-use fresh challenge |
| K | What does KnownHost store? | §9: `hostId`, `hostName`, endpoint, raw bearer credential, `pairingRequired`; pending recovery; no Host key | High | `persisted_client_state.dart`, decoder | Target adds the pinned SPKI and removes the bearer |
| L | What does KnownDevice store? | §10: `ClientId`, `ShortId`, `DisplayName`, `State`, SHA-256 verifier, timestamps, incarnation; no public key | High | `TrustRecord.cs` | Target binds the Client SPKI |
| M | What happens after revoke? | §11: `Revoked`, verifier emptied, sessions closed, credential rejected `revoked`, re-pair allowed | High | `TrustStore.RevokeAsync`; tests | Semantics preserved |
| N | What happens after block? | §11: `Blocked`, sessions closed, `blocked` for hello and pairing, unblock → `Unpaired` | High | `TrustStore.BlockAsync`; tests | Preserved; Block before completed trust is open DovahLink design ([P10-OD-16](decisions.md#pending-owner-decisions)) |
| O | Can stale credentials reconnect? | No after any administrative mutation (state and verifier checked twice). A credential that was never revoked stays valid indefinitely, including a copied one | High | `HandleTrustBackedHello` recheck | Target: key possession plus current Host state |
| P | Does an address or port participate in trust incorrectly? | No. Loopback is an exposure filter; `endpoint` is routing metadata; no trust record or decision uses an address | High | `PublicWebSocketListener`; `PersistedKnownHost` | Preserved ([P10-D-001](decisions.md#p10-d-001--consumer-boundary-platform-boundary-and-portability-discipline) item 14) |
| Q | What survives application restart? | §11 "Restart persistence" | High | Persistence code | Unchanged in kind |
| R | What survives game restart? | Game restart = Host restart: trust store and `hostId` persist; challenge, pending credential, sessions, fence counter, throttles do not | Medium | `ARCHITECTURE.md` "Host and native adapter"; in-memory fields of `PairingCoordinator` / `TrustStore` | `sas-pairing` adds: in-flight ceremonies end and the process-session budget restarts with the Host (P6-D-002) |
| S | What exact long-term identity material should `sas-pairing` authenticate? | Per role: logical UUID with role and domain (`applicationIdentity`), `keyAlgorithm`, the full DER SPKI of the ECDSA P-256 long-term key (`publicKey`), and a fixed DovahLink pairing context (`sharedContext`) | High (P10-DECISION) | [bootstrap-mapping.md](bootstrap-mapping.md) | P10-DECISION |
| T | Does `sas-pairing` authenticate enough for the later PoP step? | Yes: the full verification key (not a fingerprint) and its algorithm identifier, bound to the logical identity and role | High | P3 §4, §8; mapping §7 | P10-DECISION |
| U | Can the current authentication remain unchanged? | **No** | High | §15 matrix | — |
| V | Can it survive with targeted changes? | **No**: the primitive (a reusable secret, no Host proof) is what fails | High | §15, §16 | — |
| W | Must it be replaced? | **Yes**: verdict §16 | High | §16 | P10-DECISION ([P10-D-003](decisions.md#p10-d-003--dovahlink-authentication-disposition-and-pop-boundary)) |
| X | How is a completed ceremony linked to the DovahLink session and pending attempt without network location? | By authenticated content, never sockets: the Host's and Client's candidate values are rebuilt into expected frames and compared exactly with the authenticated peer frame; Host possession of the authenticated Host key is proved by TLS on the provisional DovahLink session; the Client signs a statement containing the exact `ceremony_identity` and a fresh Host challenge on that session with the authenticated Client key | High (P10-DECISION; bytes in P10.6) | Mapping §10–§12 | P10-DECISION |
| Y | Do the Host and Client long-term keys exist; what must be created, by whom, where? | **DESIGN EXISTS — IMPLEMENTATION DOES NOT** for both. Host key: P10.3 (DovahLink S3, Host-owned storage); Client key: P10.4 (DovahLink S4, SDK key-operations port with a Windows implementation) | High | §17 | P10-DECISION ([P10-OD-05](decisions.md#pending-owner-decisions) resolved) |
| Z | Does "Host verification and Client PoP on one cryptographically bound transport" hold with a separate-socket ceremony? | **Yes, under P10-D-003**: the ceremony only authenticates bytes; both proofs (TLS CertificateVerify by the key whose SPKI the ceremony authenticated, and the Client signature) happen on the one provisional TLS session, which is linked to the ceremony by the exact `ceremony_identity` and the authenticated keys inside the signed statement | High (design) | `identity-and-transport.md` invariant 10, S6 guard; mapping §11, §12 | Not applicable to CURRENT (no TLS) |
| AA | Does any current path let something other than evidence plus authorization create trust? | Yes, today: typing the correct six-digit code is both the proof and the authorization (`ConfirmCode` → pending → `CommitPendingAsync` → `Trusted`). The developer token creates Full sessions but no trust record; loopback creates nothing; pending recovery only commits the Host's in-memory credential. The six-digit path is removed at the P10.5 cutover ([P10-OD-07](decisions.md#pending-owner-decisions)) and the bearer at P10.7 | High | `PairingCoordinator`; `LocalConnectionTokenAuthenticator`; `pairing_service.dart` | P10 target: only Pair after verified evidence and PoP |
| AB | What do revoke, block, Reset Trust, and Factory Reset do to an in-flight ceremony and a pending authorization? | Today they cancel the challenge / pending credential and advance the fence, so stale pairing cannot commit (§11). Future: an in-flight `sas-pairing` ceremony is not cancelled by DovahLink state (the library knows nothing of it), so the pending authorization captures the fence generation and Known Device incarnation at attempt start, and Pair commits only through a conditional write against the same generation; any mutation in between invalidates the attempt even if the ceremony completes | High (current) / design (future) | `PairingChallenge.SecurityFenceGeneration`; `TryUpsertIfGenerationAsync`; mapping §16 | P10-DECISION |

## 14. Additional audit questions AC–AF

| | Question | Answer (CURRENT unless marked) | Confidence | Sources |
|---|---|---|---|---|
| AC | If an attacker obtains the trusted-device credential and its `clientId`, what cryptographic fact prevents use from another process or machine? | **None.** The Host compares a hash of a presented value; there is no key, signature, device binding, or channel binding. Only the loopback exposure limit and the wrong-guess throttle (irrelevant to a correct value) remain | High | `HandleTrustBackedHello`; `CredentialHasher` |
| AD | What current cryptographic fact prevents a malicious process reachable at the candidate endpoint from claiming the expected `hostId`? | **None.** No certificate, key, or signature; and the client discloses its credential in `hello` before it sees the claimed `hostId` | High | `authentication_service.dart` `_hello`; `PublicWebSocketListener` (plain WebSocket) |
| AE | What current fresh value makes one trusted reconnect authentication unique to the current connection / session? | **None.** `sessionId` is fresh but issued after authentication and not part of it; `messageId` uniqueness protects messages within a session, not authentication | High | `Admit`; schema "Session and recovery rules" |
| AF | What exact application data will prove that this DovahLink provisional session and this `sas-pairing` ceremony are the intended pair, without ports, sockets, or timing? | P10-DECISION: (1) the exact `ceremony_identity` of the local result; (2) exact equality of the authenticated peer Bootstrap frame with the frame built from the candidate values exchanged on that provisional session; (3) on that same TLS session, Host possession of the private key for the authenticated Host SPKI (TLS CertificateVerify, certificate SPKI byte-equal to the authenticated `publicKey`); (4) on that same session, a Client ECDSA P-256 signature under the authenticated Client SPKI over a DovahLink pairing-PoP statement containing `ceremony_identity` and a fresh Host challenge. No experiment is left open; the statement bytes and vectors are frozen by P10.6 | High (design) | [bootstrap-mapping.md §11, §12](bootstrap-mapping.md#12-cross-channel-binding) |

## 15. Authentication property matrix

Current mechanism column: CURRENT only.

| Property | Current mechanism | Evidence | Meets P10 target? | Required change |
|---|---|---|---|---|
| Host authentication | Unsigned `hostId` claim in `hello_ack`, checked after the client already sent its credential | `authentication_service.dart` `_hello`; `PublicHelloAdmissionHandler.Admit` | No | Host key (P10.3) and TLS 1.3 with the Host key, verified against the authenticated or pinned SPKI (P10.5A) |
| Client authentication | Reusable 128-bit bearer `trusted_device_credential` compared by SHA-256 verifier | `HandleTrustBackedHello`; `CredentialHasher` | No | Client key (P10.4); pairing PoP (P10.6); fresh-challenge reconnect PoP (P10.7) |
| Private-key possession | None; no private key exists on either side | Repository search; `TrustRecord`; `PersistedKnownHost` | No | Keys (P10.3, P10.4) and their proofs (P10.5A, P10.6, P10.7) |
| Replay resistance | None for authentication; the same bearer works on every hello | `HandleTrustBackedHello` | No | Single-use fresh Host challenge (P10.7, S7) |
| Session freshness | None in authentication; `sessionId` is issued afterwards | `Admit` | No | Fresh challenge bound to the TLS session (P10.6, P10.7) |
| Session binding | The admitted session is bound to its socket, but the authentication is not bound to anything | `SessionRegistry`; `protocol/security.md` | No | Proofs on one TLS session (P10.5A, P10.6, P10.7) |
| Trust-key binding | None; trust binds a bearer verifier to a `clientId` | `TrustRecord` | No | KnownDevice stores the exact authenticated Client SPKI (P10.6) |
| Known-host pinning | None; Known Host stores an unauthenticated `hostId` and a route | `PersistedKnownHost` | No | Pin the exact authenticated, possession-verified Host SPKI (P10.6) and verify it on reconnect (P10.7) |
| Known-device key binding | Bearer verifier only | `TrustRecord.CredentialVerifier` | No | Client SPKI plus `keyAlgorithm`, written only after PoP and Pair (P10.6) |
| Revoke | `Revoked` state, verifier cleared, sessions closed, typed `revoked` | `TrustStore.RevokeAsync`; tests | Yes (semantics) | Keep; apply to key-bound records (P10.6, P10.7) |
| Block | `Blocked` state, sessions closed, typed `blocked`, pairing refused | `TrustStore.BlockAsync`; tests | Yes (semantics) | Keep; decide Block before completed trust ([P10-OD-16](decisions.md#pending-owner-decisions), P10.6) |
| Reset | Reset Trust and confirmed Factory Reset, with session invalidation and pairing cancellation | `TrustAdminService`; `TrustResetService` | Yes (semantics) | Keep; extend Factory Reset to pinned keys and pending attempts (P10.6) |
| Credential cloning resistance | None; copying the bearer and `clientId` is enough | §8 F, G | No | Non-exportable platform keys (P10.3, P10.4) |
| Endpoint independence | Endpoint is routing only; loopback is an exposure filter; identity keyed by `hostId` / `clientId` | `PublicWebSocketListener`; `PersistedKnownHost` | Yes | Keep |

## 16. Verdict

**Verdict: 🔴 DOES NOT PROVIDE ADEQUATE AUTHENTICATION — REPLACEMENT REQUIRED**

This verdict concerns durable trust, trusted reconnect, and normal-session authentication after initial pairing becomes `sas-pairing`. It does **not** count the replacement of the six-digit ceremony, which happens regardless.

**Deciding criteria.** `WORKS AS-IS` fails on every core property of §15 (Host authentication, Client authentication, private-key possession, replay resistance, session freshness, cloning resistance). `WORKS WITH TARGETED CHANGES` would need the current primitive to be sound with local repairs; it is not:

- The long-term Client primitive is a reusable secret. Rotating it per reconnect, hashing it, or encrypting it at rest still leaves a secret whose disclosure is impersonation, with no proof bound to a fresh challenge.
- There is no long-term Host primitive at all, and the client discloses its secret before any Host claim. Adding TLS without keys changes nothing; adding keys is replacing the primitive.
- `sas-pairing` authenticates public keys and nothing secret, so a bearer credential cannot be the thing it authenticates; keeping the bearer would leave the authenticated keys unused.

**What current authentication can remain:** nothing of the bearer path. **What must change:** Host and Client long-term keys, Host verification, Client PoP, key-bound trust records, Known Host pinning, fresh-challenge reconnect (§19). **What must be preserved:** §18.

## 17. Long-term identity state

| | Logical identity | Private / public key today | Design |
|---|---|---|---|
| Host | `hostId`: exists (CURRENT) | **DESIGN EXISTS — IMPLEMENTATION DOES NOT.** No asymmetric key, certificate, `SslStream`, or SPKI in `host/` | Persistent Host key, private key never leaves the Host, DER SPKI; ECDSA P-256 by P10-DECISION; also the TLS certificate key (forced by DovahLink's S6 guard) |
| Client | `clientId`: exists (CURRENT) | **DESIGN EXISTS — IMPLEMENTATION DOES NOT.** No key in `sdk/` or `app/lib`; no key-operations port | Persistent non-exportable ECDSA P-256 key behind an SDK port, DER SPKI; the pairing key is the reconnect PoP key (forced: one Client cryptographic identity, `identity-and-transport.md` §6, §9, §11) |

P10.2 generates no key. Its vectors use published test keys only.

## 18. Current controls that survive replacement

Kept unchanged where compatible: typed `Trusted` / `Revoked` / `Blocked` / `Unpaired` / unknown outcomes and their wire codes; immediate session invalidation (`session_invalidated` then force-close, ordered after the authoritative state change); idempotent administration and `TrustMutationOutcome`; the store-wide security fence generation and per-record incarnation; the conditional write that refuses a stale generation or a `Blocked` record; DPAPI current-user persistence with atomic replace and fail-closed corruption handling; Host-scoped client recovery (a pairing for Host AAA never resumes on BBB); cancellation of in-flight pairing on every mutation; the separate developer-authentication provider; loopback exposure until DovahLink's LAN gate; `ShortId` administration; the protocol-violation and admission limits.

## 19. Minimum replacement components and owners

Approved by the owner on 2026-10-05 ([P10-D-003](decisions.md#p10-d-003--dovahlink-authentication-disposition-and-pop-boundary)): accepted into P10, with transport in its own increment. Each DovahLink part follows DovahLink's own branch and pull-request workflow, opens the named DovahLink slice as pre-alpha P10 work, and leaves DovahLink's production gate closed.

| Component | Increment | DovahLink slice |
|---|---|---|
| Host long-term key foundation (persistent non-exportable P-256 key, SPKI export) | P10.3 | S3 |
| Client long-term key foundation (SDK key-operations port, Windows implementation) | P10.4 | S4 |
| Authenticated transport: WSS / TLS 1.3 with the Host key, provisional acceptance for pairing, pinned verification for Known Hosts, no resumption or 0-RTT | **P10.5A** (new) | S6 (S5 pin plumbing) |
| Host verification at pairing (TLS SPKI equals the authenticated Host `publicKey`) | P10.6 | S6 guard |
| Client pairing PoP bound to `ceremony_identity` | P10.6 | (initial-pairing composition) |
| Trust-record key binding (KnownDevice SPKI) and Known Host pin | P10.6 | S5 |
| Fresh-challenge reconnect PoP, replay resistance, session binding | P10.7 | S7 |
| Atomic removal of the bearer credential and the six-digit flow | P10.7 (six-digit policy decided at P10.5, [P10-OD-07](decisions.md#pending-owner-decisions)) | S9, S10 |

## 20. Nonclaims

No component of this audit is implemented. No claim is made that the P10 design is production-ready, hostile-LAN approved, professionally audited, or formally verified. `sas-pairing` remains experimental and pre-alpha; DovahLink's security gate remains an explicit later DovahLink decision.
