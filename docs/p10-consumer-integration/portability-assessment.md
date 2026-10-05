# P10 Portability and ABI-v1 Assessment

> **Pre-alpha. Analysis only.** P10.1 evidence for [P10-D-001](decisions.md#p10-d-001--consumer-boundary-platform-boundary-and-portability-discipline). P10 implements Windows only. Nothing here implements, designs, or approves Android support, a platform abstraction, or an ABI change. Unknowns are recorded as unknowns.

Baseline: this repository at `main` `b938016d1de53d3e269fe0840485fbd3dc715fd7`; DovahLink read only at `main` `9f4e925cc8dcba0db37d1bd7d38b39f0927b9387` (P10.1 read `4a69ee5057029878200b6e16614f67a136e3e032`; P10.1.1 found no pairing, authentication, trust, transport, or identity change between the two, [README, P10.1.1 evidence](README.md#p1011-evidence)). The ownership boundary these findings rely on is in the [consumer boundary](consumer-boundary.md).

## 1. Scope and method

The question is not "is ABI v1 ready for Android?" but two narrower ones: can the real DovahLink P10 integration be built on Windows with ABI v1 and the P8/P9 wrappers without breaking the consumer boundary, and which parts of that integration are consumer concepts, which are Windows mechanics that can stay below an adapter, and which are concrete Android blockers today. Every claim below cites source, a frozen document, or a DovahLink file at the pinned commit. Three categories are used, exactly:

- **PN**: platform-neutral consumer concept.
- **WE**: Windows-specific, properly encapsulated (it can stay below a DovahLink infrastructure adapter).
- **AB**: concrete future Android blocker, backed by current implementation evidence.

"Not implemented on Android yet" is not by itself proof that the consumer boundary is wrong, and neither is proof that ABI evolution is required. Those distinctions are kept apart in [§14](#14-concrete-android-blocker-register) and decided only by P10.8 ([§13](#13-p10-closure-portability-questions-p108)).

## 2. Portability classification (PN / WE / AB)

| Requirement / API | Evidence | Class | Why | P10 action | P11 implication |
|---|---|---|---|---|---|
| DovahLink Host / Client identity semantics (`hostId`, `clientId`) | DovahLink `ARCHITECTURE.md`, `identity-and-transport.md` §5–§6 | PN | UUIDs owned by DovahLink, independent of transport and OS | Encode in `applicationIdentity` (P10.2) | None |
| Canonical Bootstrap bytes (DovahLink's encoding of the four fields) | P3 profile §3.1, §4 | PN | Deterministic bytes; no platform serializer | Freeze in P10.2 | Same bytes on Android |
| Key algorithm identity | P3 §4 (`[a-z0-9][a-z0-9.-]*`) | PN | An opaque identifier both sides agree on | Choose in P10.2 | Android key store must produce the same representation (DovahLink's concern) |
| Public-key and fingerprint semantics (DER SPKI, `SHA-256(SPKI DER)`) | DovahLink `identity-and-transport.md` §5–§6 | PN | Standard encodings, independent of platform | Use in P10.2 / P10.6 | Android Keystore export of SPKI (DovahLink 5A) |
| Authenticated shared context | P3 §4 | PN | Opaque bytes compared exactly on both sides | Choose in P10.2 | None |
| `PairingResult` interpretation (local completion only) | P6-D-005, ABI §19 | PN | Semantics come from the profile, not the platform | Enforce in DovahLink types (P10.5/P10.6) | None |
| `ceremony_identity` | P3 §4, ABI §19.2, §20.7 | PN | 32 transcript-derived bytes | Bind every decision (P10.5) | None |
| Human SAS comparison (decimal `NNNN NNNN NNNN`) | ABI §20.6 | PN | Plain display string | Present in Flutter and Skyrim (P10.5) | Android UI presents the same string |
| Pending application authorization | DovahLink `identity-and-transport.md` §10 | PN | DovahLink domain state | Model (P10.2), implement (P10.6) | None |
| Pair / Reject / Block policy | Same | PN | DovahLink domain policy | P10.6 | None |
| Durable KnownHost / KnownDevice trust | DovahLink `identity-and-transport.md` §8–§9 | PN | Domain records; storage sits behind DovahLink ports | P10.6 | Android storage port is DovahLink 5A work |
| Proof-of-possession policy | P3 §4 nonclaim; DovahLink §11 | PN | Application protocol over DovahLink's session | Audit (P10.2), implement where required (P10.6/P10.7) | Android Keystore signing (DovahLink) |
| Reconnect authentication semantics | DovahLink `protocol/security.md` hello tiers; §11 | PN | DovahLink protocol | P10.7 | None |
| Result-to-application data mapping | ABI §19.2–§19.3 | PN | Fields are bytes; decoding is deterministic | P10.2 decides decode or exact compare (P10-OD-13) | Same code path |
| Runtime / Authority / Host lifecycle API (P8, P9) | P8-D-002, P9-D-002 | PN | No Windows type in the lifecycle API | Wrap in the adapter | Reusable if native support exists |
| Authority registration semantics (scope, one owner, process session, budget) | P3 §11.1.2, P6-D-002, ABI §15 | PN | Defined by the profile; API takes scope bytes only | Choose scope (P10-OD-14) | Same semantics required |
| Authority OS lease on Windows (`LockFileEx` on a per-account lock file) | `core/src/lib.rs` `mod os_lock` (`#[cfg(windows)]`) | WE | Invisible through the API: no path, SID, or lock name is exposed | None (handle `OWNERSHIP_*` statuses) | Replaced on Android, see next row |
| No non-Windows authority lease | `core/src/lib.rs` `#[cfg(not(windows))] mod os_lock`: `acquire` → `Err(UnsupportedPlatform)` | AB | Registration cannot succeed off Windows today | None | Android ownership primitive and account scoping ([§3](#3-authority-portability-assessment)) |
| Cooperative drive / recheck concept | ABI §18.3; P8-D-003 I; P9-D-003 J | PN | `drive()` / `Drive()` take and return no Windows type | Schedule from one owner (P10.3, P10.4) | Survives if a native carrier keeps the bounded semantics |
| Windows owner loop (`WSAPoll`, at most 250 ms, 1 + 16 sockets) | `core/src/windows_owner_loop.rs` (`#[cfg(windows)]`), P7-D-008 | WE | Below the drive API | None | Replaced by an Android carrier |
| No non-Windows carrier in the core | `core/src/lib.rs` lines 24–27 (`windows_owner_loop`, `windows_tcp` are `#[cfg(windows)]`) | AB | No connection can exist off Windows | None | Android carrier (P11) |
| ABI listener entry `sas_pairing_host_attach_windows_listener` with `sas_pairing_socket_t` (Windows `SOCKET`) | ABI §17, P7-D-006 | WE | Called only by the infrastructure adapter | Hide in the adapter (P10.3, P10.4) | Counterpart needed, see next row |
| No platform-neutral listener or connection handoff in ABI v1 | Manifest §2 (the only carrier entry is Windows-named) | AB | Android pairing cannot hand any carrier to the core today | Record only | Whether this needs ABI evolution is decided by P10.8 evidence, not here |
| Dart `SasPairingWindowsListenerSocket.fromNativeSocket(int)` | P8-D-003 D | WE | Raw `SOCKET` value; adapter-only | Keep out of SDK/app domain | Android counterpart needed |
| .NET `SasPairingWindowsListenerSocket.FromSocket(Socket)` with `DuplicateAndClose` | P9-D-003 W/X; `SasPairingWindowsListenerSocket.cs` | WE | Adapter-only; throws `PlatformNotSupportedException` off Windows | Keep out of Host domain | None (the Host is Windows-only) |
| WinSock `SOCKET` creation in the DovahLink client (bind and listen through WinSock FFI) | P8-D-003 D (no bind helper; P8 tests use a test-only WinSock harness) | WE | `dart:io` exposes no native listener handle | Implement in the client adapter (P10.4) | Android needs a different socket source |
| Client outbound reachability through an in-process loopback relay (proposed P10 adapter) | Fact K, [consumer boundary §3](consumer-boundary.md#3-verified-sas-pairing-facts); P7 closure §7 | WE | Byte-transparent; adapter-only | Experiment E-02 before major P10.4 work | Same question on Android ([§14](#14-concrete-android-blocker-register)) |
| Windows TCP readiness model (`POLLHUP` drained, `POLLERR`/`POLLNVAL` hard) | P6-D-003 | WE | Inside the owner loop | None | Carrier-specific on Android |
| Windows x64 native DLL distribution (unsigned exact-commit CI artifact) | P8-D-006, P9-D-006 | WE | Packaging, consumed by the adapter only | Pin and consume (P10-OD-12) | — |
| No Android `.so` build or artifact | P8-D-006 B ("no … Android … support") | AB | Nothing to load on Android | None | Android ABI targets, packaging, loading |
| Explicit absolute-path loader (P8 `SasPairingRuntime.create(nativeLibraryPath:)`, P9 `Create(path)`) | `dart/lib/src/native/native_library_loader.dart` (absolute, existing file, canonicalized); P9 closure §8 | PN | Generic code; no Windows API | Supply the path from the adapter | Android library location unknown ([§14](#14-concrete-android-blocker-register)) |
| One native image per process; `FATAL` → OS process restart | P7-D-001, P7-D-002 | PN | Process model, not Windows-specific | Host: process restart through its supervisor; Client: application restart | Must be re-verified under Android process lifecycle |
| Process-session accounting (ten exposures per authority per process session) | P6-D-002 | PN | Profile semantics | Surface `EXHAUSTED` / `BUSY` in UX (P10.5) | Android process death starts a fresh session, as on Windows restart |
| .NET runtime-tree lock serialization | P9-D-002 P, P9-D-003 V | PN | Plain managed lock, no thread affinity | Design the Host owner around it (P10.3) | n/a |
| Dart one-owner-isolate rule | P8-D-001 N | PN | Dart concurrency rule, not Windows-specific | Choose owner isolate (P10-OD-03) | Same rule on Android |
| Skyrim-side SAS display and decision path (adapter IPC) | DovahLink `host/DovahLink.Host/Adapter/Ipc/`, `adapter/ipc/` | WE | Host-side and Skyrim-specific; never reaches the client | Add a decision path (P10.5, P10-OD-08) | None (the Host stays on Windows) |
| DPAPI storage of DovahLink trust and Known Hosts | DovahLink `WindowsDpapiTrustStorePersistence.cs`, SDK `dpapi_client_storage.dart` | WE | Behind DovahLink storage ports | Unchanged by P10 except new fields (P10.6) | DovahLink Android storage (its 5A) |
| Flutter pairing presentation (SAS string, phases, decisions) | DovahLink `flutter/architecture.md` | PN | UI receives domain data only | P10.4, P10.5 | Reused on Android |

## 3. Authority portability assessment

**Generic semantics (PN).** An authority is one stable local scope registered with the core (`registerAuthority(Uint8List)` / `RegisterAuthority(ReadOnlySpan<byte>)`). The core builds the canonical identity (`sas-pairing-authority-v1` plus the length-prefixed scope), allows one active registration per canonical identity per process, excludes other processes through an OS lease, and keeps the ten-opportunity budget and START limiter for the whole process session, across release and re-registration (P3 §11.1.2, P6-D-002, [ABI contract §15](../p7-native-abi/abi-contract.md#15-authorities)). The scope must come from local configuration, be stable across restarts, and never come from the network.

**Windows mechanism (WE).** `core/src/lib.rs` `mod os_lock` (`#[cfg(windows)]`): the process token's user SID (`OpenProcessToken`, `GetTokenInformation`) and profile directory (`GetUserProfileDirectoryW`) locate `AppData\Local\sas-pairing\authority-locks`, whose directories must be plain (no reparse points); the lock file is named by `SHA-256(u32be(sid_len) || sid || canonical identity)`, opened without delete sharing, and held with an exclusive, fail-immediately `LockFileEx` byte-range lock. `ERROR_LOCK_VIOLATION` is `OWNERSHIP_UNAVAILABLE`; every other failure is `OWNERSHIP_UNCERTAIN`. This is account-scoped ownership (decision 0003). It is a lock file, not a named mutex: P3 §11.1.2 discussed a mutex as one candidate, and P4 selected the lock file.

**Non-Windows today.** `#[cfg(not(windows))] mod os_lock`: `Lease::acquire` returns `Err(UnsupportedPlatform)`, so `registerAuthority` fails with `SAS_PAIRING_UNSUPPORTED_PLATFORM` (proven by the Linux CI jobs of the core, P8, and P9). Nothing is faked.

**What DovahLink needs to know.** Nothing about the mechanism: no mutex name, lock path, SID, or kernel detail crosses the API, so DovahLink already just "asks for an authority scope". DovahLink does need to own three things: the stable scope bytes ([P10-OD-14](decisions.md#pending-owner-decisions)); the behaviour when another process of the same Windows account holds that scope (`OWNERSHIP_UNAVAILABLE`), which matters because DovahLink allows several adapter/Host pairs on one machine and its `hostId` is per installation; and the restart-only outcomes (`OWNERSHIP_UNCERTAIN`, `FATAL`, and `EXHAUSTED` until the next process session).

**Android.** The public API needs no change for authority ownership: the gap is a native implementation (an exclusive cross-process primitive in app-private storage) plus a definition of what "account-scoped" means for an Android app. Recorded as AB with P11 questions ([§14](#14-concrete-android-blocker-register)).

## 4. Network / listener portability assessment

**Windows-specific evidence.** The only carrier entry is `sas_pairing_host_attach_windows_listener(…, sas_pairing_socket_t *inout_listener, …)`; `sas_pairing_socket_t` is a Windows `SOCKET` with `INVALID_SOCKET` as its invalid value ([ABI contract §17.1](../p7-native-abi/abi-contract.md#171-types)). The owner loop and the TCP adapter are `#[cfg(windows)]` (`core/src/lib.rs` lines 24–27) and wait with `WSAPoll` (P7-D-008). In .NET the token moves the caller's socket into a package-owned descriptor with `Socket.DuplicateAndClose` because invalidating the caller's own `SafeSocketHandle` makes `Socket.Dispose` hang in .NET 10 (P9-D-003 W/X). In Dart the token wraps a raw `SOCKET` integer; `dart:io` cannot supply one, so the application needs WinSock FFI to create, bind, and listen (P8-D-003 D; the P8 tests use a test-only harness, `dart/test/support/winsock.dart`).

**Listen-only (fact K).** The ABI never binds, chooses an address, or makes an outgoing connection (P7-D-006 item 1); connection handles come only from accepts. For DovahLink:

- The **Host** binding a pairing listener is natural (it already binds a loopback WebSocket listener).
- The **Client** today connects out to the Host. Under ABI v1 its own `sas-pairing` host can only obtain a connection by accepting one. A plausible public-API adapter path, requiring experiment E-02 and not yet a proven solution, is an in-process, byte-transparent loopback relay in the client adapter: bind a loopback listener and attach it to the client's own `sas-pairing` host, connect to it, connect to the Host's pairing endpoint, and copy bytes unchanged in both directions. This is exactly the pattern every two-sided proof used (P7.7, P8.4, P9.4), but only in test code so far.
- **Security of the relay.** The threat model already gives the network attacker full control of the transport; the ceremony's commitment, transcript, and human SAS comparison defend against a man in the middle, so a relay that never parses, builds, or alters a frame is expected to add no new trust; that expectation is an assumption E-02's security review must confirm, not an established property. The risks are availability and confusion: another local process can connect to the client's loopback listener, and because no address crosses the ABI, the client cannot tell its own relay connection from another. Starting the Initiator on a foreign connection can only produce a ceremony whose SAS will not match what the Host shows (it fails safely), but it can disrupt pairing and consume resources inside the authority-wide caps (16 live connections, 4 queued accepts). Experiment E-02 ([§12](#12-experimental-assumptions)) must measure and accept or reject this before P10.4 builds on it.
- **Alternative.** The core's TCP adapter already takes an already-connected stream (`WindowsTcpConnection::from_accepted`), but no export reaches it. Exposing one would be an ABI change, which needs an owner decision on ABI version and compatibility (P7-D-013 item 14). P10.1 does not propose it ([§9](#9-abi-v1-p10-assessment)).

**Below the adapter.** All of this can stay below a DovahLink infrastructure adapter: the domain needs only "start pairing with this candidate", a SAS presentation, a decision, and pairing evidence. No Windows type needs to appear in DovahLink domain or trust services ([§5](#5-net-host-integration-boundary), [§7](#7-dart--flutter-integration-boundary)). Experiment E-08 checks this with architecture tests.

## 5. .NET Host integration boundary

**DovahLink Host domain and application services may see** consumer-level concepts only, for example: a pairing session request; a SAS presentation (decimal string plus an opaque reference to the exact ceremony); a decision command (MATCH / MISMATCH / CANCEL) naming that reference; pairing evidence (`ceremony_identity`, the peer's role, the decoded or exactly matched peer Bootstrap fields, the authenticated shared context); a pending authorization; a pairing outcome (typed: completed locally, rejected, cancelled, timed out, unavailable, failed); and operational states such as "pairing unavailable until Host restart" (from `EXHAUSTED`, `OWNERSHIP_UNCERTAIN`, or `FATAL`). Exact type names are P10.3's ([P10-OD-01](decisions.md#pending-owner-decisions)).

**Only the Windows infrastructure adapter may see:** `SasPairingRuntime`, `SasPairingAuthority`, `SasPairingHost`, `SasPairingConnection`, `SasPairingRun`, `SasPairingResult`, `SasPairingWindowsListenerSocket`, `System.Net.Sockets.Socket` used for the pairing listener, `SafeSocketHandle`, the native library path, `SasPairingHostNetworkState`, `SasPairingDriveBatch` and `SasPairingEvent`, and `SasPairingStatus` / `SasPairingNativeException` before translation. Statuses are translated into operational outcomes and never into trust verdicts (ABI §20.11). The adapter reads each result once into DovahLink evidence and disposes it; `FATAL` becomes a Host process-restart request through DovahLink's existing supervision, never a library reload.

**Fit with the DovahLink Host.** The Host is already layered (Pairing, Trust, Identity, Sessions, Client/Transport, Adapter/Ipc folders, DI composition in `Program.cs`), so an infrastructure adapter has a natural home, but DovahLink's `AGENTS.md` requires a maintainer instruction for new layers and dependencies; P10.3 brings that decision to the owner.

## 6. .NET thread and execution assessment

| Question | Answer (current behaviour) | Evidence |
|---|---|---|
| Can `Drive()` block? | Yes: one native drive, including at most one readiness wait of up to 250 ms, plus bounded work | [ABI contract §11](../p7-native-abi/abi-contract.md#11-threading), §18.3; `SasPairingHost.Drive` remarks |
| Documented bound | `OWNER_LOOP_MAX_WAIT` 250 ms; other calls on the same runtime wait at most that long plus bounded work, because every call takes the runtime tree's one lock and `Drive` holds it for the native call | ABI §11; P9-D-002 P; P9-D-003 V; `SasPairingHost.cs` `DriveOnce` (lock held around `Network.Drive`) |
| Busy loop risk | A persistently ready socket can make `Drive` return at once; calling it in a tight loop is a documented misuse | P9-D-003 J; `SasPairingHost.Drive` remarks |
| Should it run on the game / main thread? | The Skyrim game thread is never involved: the DovahLink Host is a separate process and does no game-thread work. Inside the Host, `Drive` should not run on a thread whose 250 ms stall delays other Host work (WebSocket I/O, IPC, trust administration) | DovahLink `ARCHITECTURE.md` "Host and native adapter"; `host/architecture.md` |
| Thread identity | None needed: the wrapper uses a plain `System.Threading.Lock` per call, the native ABI is safe from any thread, and the wrapper has no thread affinity, so domain code needs no thread identity | ABI §11; `SasPairingRuntime.Gate` |

**Required shape.** One logical `sas-pairing` owner service in the Host: it owns the runtime tree, schedules drives, performs ceremony actions, and translates events. Domain services send it commands (start, decision, cancel) and receive translated events. The thread model behind it (dedicated worker thread, hosted loop on the thread pool, or another scheduler) is **not chosen here** ([P10-OD-02](decisions.md#pending-owner-decisions)).

**P10.3 must validate experimentally (E-03):** drive cadence and latency against the protocol deadlines (10 s first frame, 2 s write progress, 60 s inactivity, 5 min absolute); lock contention between the drive loop and decisions arriving from Skyrim; no thread-pool starvation from repeated 250 ms blocking calls; shutdown ordering (cancellation, a final drive, disposal while a drive is in flight, Host process exit); `FATAL` turning into a supervised Host restart; exceptions from the owner never crashing the Host silently; `RUN_UNTRACKED` connections disposed after the batch; and that no wrapper object is used after its disposal.

## 7. Dart / Flutter integration boundary

**Flutter UI and Redux may receive** application data only: the SAS decimal string; an opaque reference to the exact ceremony (or its 32 bytes as correlation data); the pairing UX phase (for example connecting, waiting for the peer, comparing, waiting for the Host's decision, completed locally, pending Pair, paired, failed with a typed reason); and typed failure categories. They never receive a WinSock `SOCKET`, a `SasPairingWindowsListenerSocket`, any `SasPairing*` object, a native handle, an FFI pointer, the DLL path, a drive batch, or a status presented as a trust verdict.

**Owner.** DovahLink's SDK already owns pairing, authentication, reconnect, and Known Hosts, and its app "never handles private keys … unselected pairing internals, or protocol security policy" (DovahLink `identity-and-transport.md` §18, invariant 16); Windows facilities already live behind SDK ports and a Windows-specific entry library. The `sas-pairing` client owner therefore belongs at that SDK / platform boundary, not in widgets, ViewModels, or Redux middleware. Exact placement is [P10-OD-01](decisions.md#pending-owner-decisions). Experiment E-08 adds DovahLink architecture tests: no domain, Redux, ViewModel, or widget file imports `package:sas_pairing`.

## 8. Dart isolate assessment

| Question | Answer (current P8 behaviour) | Evidence |
|---|---|---|
| Owner-isolate semantics today | One Dart owner isolate per OS process holds all direct native access; other isolates must not load the library or create runtimes; every call is synchronous; there is no isolate façade | [P8-D-001](../p8-dart-package/decisions.md#p8-d-001--dart-native-binding-and-loader-architecture) N; `dart/README.md` "One owner isolate" |
| What is enforced | Natively: one runtime per image (`ALREADY_INITIALIZED`), the process-wide fatal state, and handle validation (handles are never public, so another isolate cannot reach this isolate's objects) | ABI §5, §6; P8-D-002 B |
| What is only documented | The isolate rule itself. The Dart loader state, the FATAL and contract latches, closed and ended states, and the result store are per isolate (Dart statics are isolate-local). A second isolate could initialize its own loader with a different path and load a second native image, which breaks the P7-D-002 one-image invariant; the package cannot prevent it | P8-D-001 N ("the loader is not claimed to be process-global") |
| Blocking | `drive()` blocks its isolate for up to about 250 ms; the package says not to call it blindly on a Flutter UI isolate | P8-D-003 I; `dart/README.md` "Network" |
| What must remain on the owner isolate | Every `SasPairing*` object (runtime, authority, host, connection, run, result), the listener token transfer, drive scheduling, every ceremony action including `presentation()`, and result reads and closes | P8-D-001 N (all direct native access) |
| How P10.4 should pass presentation state to Flutter | The owner sends immutable plain messages (decimal string, ceremony reference, phase, typed outcome) to the SDK side, which maps them to SDK public types for Redux middleware; decisions come back as commands naming the exact ceremony, and the owner calls `approveSas` / `rejectSas` / `cancelSas` with the `SasPairingCeremonyIdentity` it holds (no public constructor exists, so UI code cannot fabricate one) | P8-D-004 rule 1; DovahLink `flutter/architecture.md` |
| Not enforced, so P10.4 must test | Isolate confinement; that UI and Redux never see FFI types; that only one isolate ever initializes the loader | — |

No Android isolate, platform channel, or platform code is designed or created here. If the client relay of E-02 is used, its socket pumping and the blocking drive share or split isolates; that is part of [P10-OD-03](decisions.md#pending-owner-decisions) and E-02.

## 9. ABI-v1 P10 assessment

| Area | Real P10 need | ABI v1 capability (public Dart / .NET) | Assessment |
|---|---|---|---|
| Lifecycle | One runtime per Host process and per client process | Runtime create/destroy, one per process; one image resident | Sufficient |
| Authority | Stable local scope per Host installation and per client | Register / release / status by scope bytes | Sufficient; scope choice and multi-Host behaviour are owner decisions (P10-OD-14) |
| Host | One pairing host per authority | Host create/destroy | Sufficient |
| Listener handoff | Host binds a pairing listener; the client adapter binds a loopback listener | `AttachWindowsListener` / `attachWindowsListener` (in/out slot) | Sufficient on Windows; the Dart client needs WinSock FFI to create the socket (documented application boundary, P8-D-003 D) |
| Outbound connection | The client reaches the Host | **None** (listen-only, fact K) | Not natively expressible; the in-process byte relay is a plausible public-API adapter path, requiring E-02 and unproven until it passes |
| Drive / recheck | Bounded progress from one owner | One bounded drive / recheck per call | Sufficient; scheduling is E-03 / E-04 |
| Bootstrap | Four fields with DovahLink identity, key, and context | `SasPairingBootstrap` (bounds 1,024 / 64 / 4,096 / 8,192; frame 16,384) | Sufficient for a DER SPKI key; a Responder's Bootstrap is per listener (fact L), which constrains role choice (P10-OD-10) |
| Initiator / Responder | Either side may start | `startInitiator` on an accepted connection; Responder runs appear through drive events | Sufficient |
| Run | Exact ceremony steps | Nine explicit actions, exact run handles | Sufficient |
| SAS presentation | Decimal string for both screens | `presentation()` / `Presentation()` | Sufficient |
| Ceremony identity | Bind decisions to the attempt | Exact 32 bytes, decisions take only the presented identity | Sufficient |
| `PairingResult` | Evidence for pending authorization | Runtime-owned result, read once | Sufficient |
| Result data | `clientId` / `hostId` and the peer key | Peer Bootstrap as the exact canonical frame; neither wrapper decodes it (fact M) | The data is complete but frame-encoded; a consumer-side decode of the frozen, vector-backed record or an exact re-encode-and-compare is a plausible public-API adapter path, requiring E-13 and unproven until it passes (P10-OD-13) |
| Cleanup / fatal | Deterministic teardown; restart on `FATAL` | Consuming cleanup cascades; `FATAL` → process restart | Sufficient; the Host restarts under its supervisor, the client application restarts |

**Verdict: ABI-V1-P10-B — ABI v1 appears sufficient for P10 Windows integration, but one or more assumptions require an explicit P10 experiment before major integration.**

- **Why not A:** two real gaps have only plausible adapter paths, still unproven in a real consumer: the client's outbound reachability (E-02) and access to the peer's Bootstrap fields (E-13), and the Host and client owner-scheduling models (E-03, E-04) have no evidence yet outside tests.
- **Why not C:** no concrete DovahLink requirement has been shown to be inexpressible safely. The outbound gap has a plausible public-API adapter path: a byte-transparent relay over normal sockets, designed never to parse a frame or add trust, exercised against the real DLL only in test code; whether it is safe in the real consumer is what E-02 must establish. The result data is complete, only frame-encoded, in a frozen deterministic format; whether DovahLink can read it safely is what E-13 must establish. Neither is an Android-only concern, and neither needs private FFI.
- **Escalation rule.** If E-02 or E-13 fails (no safe adapter exists), the affected P10 work STOPs and P10 reports an ABI-V1-P10-C candidate with the exact missing capability, the exact DovahLink requirement, why the public Dart and .NET APIs cannot express it, why it is not merely an Android concern, and why no adapter can solve it safely. No ABI v2 or new export is designed automatically; the owner decides on ABI version and compatibility (P7-D-013 item 14).

### P10.2 re-evaluation

**Still ABI-V1-P10-B (unchanged).** P10.2 resolved the assumptions in its scope: E-13 by exact expected-frame comparison over the bytes ABI v1 already returns, with no decoder, wrapper helper, or export ([bootstrap mapping §10](bootstrap-mapping.md#10-peer-bootstrap-consumption-e-13-p10-od-13)); E-05 and E-06 by the frozen mapping ([§19](bootstrap-mapping.md#19-e-05-and-e-06)); E-07 by keeping proof of possession in DovahLink ([§11](bootstrap-mapping.md#11-proof-of-possession-boundary-e-07)). It is not promoted to A, because E-02 (client relay), E-03, and E-04 (owner scheduling) are still unproven and E-13 still needs its real-result regression in P10.3 / P10.4. It is not demoted to C: needing a consumer-side frame encoder, needing DovahLink long-term keys, and replacing bearer authentication are consumer work, not ABI gaps; the 241-byte DovahLink Bootstrap is far inside the ABI bounds, and every value a pending authorization needs is in the result, locally known, or recoverable by exact comparison.

## 10. Cooperative drive assessment

**Public orchestration concept (PN).** "Advance the pairing transport once, within a bound; receive every event it produced, in order; consume all of them (including results) even when the loop failed; then act." Dart `SasPairingHost.drive()` and .NET `SasPairingHost.Drive()` expose exactly that, and neither signature mentions a socket, WinSock, `DuplicateAndClose`, or a listener token. `recheckAfterResume()` is the same shape for a deadline sweep after an OS resume.

**Current Windows carrier beneath it (WE).** One `WSAPoll` over the listener and at most 16 connections, at most one accept and one socket operation per connection per call, adapter-owned frames, `POLLHUP` draining (P6-D-003, P7-D-008).

**Answer.** Yes: DovahLink application code can depend on a generic "progress pairing transport once, process the returned events" concept without depending on WinSock, `DuplicateAndClose`, or Windows listener tokens, because only listener attachment takes Windows types. Two properties of the concept matter for scheduling on any platform: the readiness wait is inside the call (no external readiness handle or callback is offered, so an owner must call it on a cadence), and the call blocks its thread or isolate for its bounded wait. P10 does not build an abstraction framework for this: the adapter owns one loop that calls `Drive()` / `drive()` and translates events. Whether the same concept survives a different native carrier is P10.8 question J.

## 11. Dart future-reuse matrix

| Dart public concept | Platform-neutral semantics? | Windows-specific implementation or API? | Future Android expectation |
|---|---|---|---|
| `SasPairingRuntime` | Yes (one runtime per process, consuming close, latches) | No; the loader takes an explicit absolute path to an existing file | Likely reusable but blocked by native platform support; the explicit-path rule is unknown on Android ([§14](#14-concrete-android-blocker-register)) |
| `SasPairingAuthority` | Yes (scope bytes, status, process session) | Natively: the Windows lease | Likely reusable but blocked by native platform support |
| `SasPairingHost` | Yes for lifecycle, `drive`, `recheckAfterResume`, `detachListener`, `networkState` | `attachWindowsListener` takes the Windows listener token | Lifecycle and drive likely reusable but blocked natively; attachment is a Windows-specific API that will need a future counterpart |
| `SasPairingBootstrap` | Yes (four byte fields, validated natively) | No | Reusable as-is semantically |
| `SasPairingWindowsListenerSocket` | No | Yes (raw Windows `SOCKET`) | Windows-specific API that will need a future counterpart |
| Drive (`drive()`, `SasPairingDriveBatch`, `SasPairingEvent`) | Yes | Carrier is native `WSAPoll` | Likely reusable but blocked by native platform support |
| `recheckAfterResume()` | Yes | No | Likely reusable but blocked natively; the Android resume trigger is unknown until P11 |
| `SasPairingConnection` | Yes (opaque connection, close) | Connections exist only through the Windows carrier | Likely reusable but blocked by native platform support |
| `SasPairingRun` and `SasPairingLocalAction` | Yes (nine explicit steps) | No | Reusable as-is semantically (blocked natively) |
| `SasPairingSasPresentation` | Yes | No | Reusable as-is semantically |
| `SasPairingCeremonyIdentity` | Yes | No | Reusable as-is semantically |
| `SasPairingResult` and `SasPairingResultData` | Yes (local completion only) | No | Reusable as-is semantically |

This is a statement about API shape, not Android compatibility: no Android build, artifact, or test exists, and none is claimed.

## 12. Experimental assumptions

None of these is proven yet. *P10.2 status:* E-05, E-06, E-07, and E-13 are **resolved** by [P10-D-002](decisions.md#p10-d-002--canonical-dovahlink-bootstrap-v1-mapping) and [P10-D-003](decisions.md#p10-d-003--dovahlink-authentication-disposition-and-pop-boundary) (E-13 keeps a real-result regression test in P10.3 / P10.4); E-11's scope bytes are decided and its runtime check stays in P10.3; the others are unchanged.

| ID | Assumption | Why it matters | Current evidence | P10 experiment | Decision deadline |
|---|---|---|---|---|---|
| E-01 | ABI v1 is sufficient for the real DovahLink Windows flow | Verdict B rests on it | Two-sided public-ABI ceremonies through a relay in P7.7, P8.4, P9.4; no real consumer yet | One end-to-end ceremony between the real DovahLink Host process and the real Windows Flutter client, through the P10 adapters | P10.5 exit |
| E-02 | The client can reach the Host through an in-process byte-transparent loopback relay | ABI v1 has no outbound connection (fact K) | Test-only relays against the real DLL | P10.4 spike before major client work: real client and Host processes; foreign local connections; latency against the 10 s / 2 s / 60 s deadlines; relay failure handling; security review that the relay parses and changes nothing | Before P10.4 major implementation; failure is a STOP ([§9](#9-abi-v1-p10-assessment)) |
| E-03 | `Drive()` can be owned by one Host service off any latency-sensitive thread | `Drive` blocks up to 250 ms under the runtime lock | P9-D-003 J/V; DovahLink Host is async and out of process | P10.3 owner service under a real ceremony: lock contention, cadence, shutdown, `FATAL` restart path | P10.3 exit |
| E-04 | Dart `sas_pairing` ownership can be isolated from the Flutter UI | `drive()` blocks its isolate; the one-isolate rule is unenforced | P8-D-001 N, P8-D-003 I | P10.4 owner isolate with a message façade; UI frame timing during drives; single-loader check | P10.4 exit |
| E-05 | The authenticated Bootstrap can carry enough identity material | Pending authorization and PoP depend on it | Four bounded fields; no DovahLink long-term key exists yet | P10.2 mapping with deterministic vectors; used for real in P10.6 | P10.2 exit |
| E-06 | The result contains enough data for pending application authorization | Pending authorization needs `clientId` / `hostId` and the peer key bound to the attempt | Result fields (ABI §19.2–§19.3) | P10.2 defines the evidence record; P10.3 / P10.4 build it from real results | P10.2 exit |
| E-07 | Proof of possession can remain DovahLink-owned | P10-D-001 item 10 | P3 §4 nonclaim; DovahLink selected application-level PoP (S7, unspecified) | P10.2 audit verdict; implemented where required in P10.6 / P10.7 | P10.2 verdict |
| E-08 | Listener and socket mechanics stay below the adapter | P10-D-001 item 3 | Only the listener token types and attach methods are Windows-specific in either wrapper | DovahLink architecture / source-scan tests: no domain, trust, Redux, or UI code references `SasPairing*` or socket types | P10.3 and P10.4 exits |
| E-09 | Normal reconnect stays fully separate from SAS | P10-D-001 item 13 | DovahLink reconnect uses `hello.auth` today | P10.7: reconnect with no `sas-pairing` runtime, authority, or listener involved | P10.7 exit |
| E-10 | Ceremony-bound approval works across the Host and the client | P10-D-001 items 9 and 11 | Native MATCH binding proven; DovahLink pending model not implemented | P10.5 / P10.6 stale-approval tests (approval of attempt 1 cannot authorize attempt 2 for the same `clientId`) | P10.6 exit |
| E-11 | The authority scope works with DovahLink's process model | Account-scoped exclusive lease; several Hosts per machine are allowed | `os_lock`; DovahLink `ARCHITECTURE.md` | P10.3: a second Host process with the same scope gets the documented outcome; scope chosen in P10.2 | P10.3 exit |
| E-12 | The ten-exposure process-session budget is acceptable in DovahLink UX | The Host process lives for one Skyrim run; `EXHAUSTED` lasts until restart | P6-D-002 | P10.5 surfaces `BUSY` and `EXHAUSTED` truthfully | P10.5 exit |
| E-13 | Peer Bootstrap fields can be read safely outside the core | Fact M | Frozen P3 §3.1, §4; `vectors/p3-remote-vodozemac-draft-01.json` | P10.2 chooses decode or exact compare and tests it against the frozen vector, including malformed and oversized frames | P10.2 exit |
| E-14 | Skyrim can present the SAS and carry MATCH / MISMATCH and Pair / Reject / Block decisions back | The Host user decides in Skyrim | IPC has display and acknowledgement only | P10.5 decision path through the adapter (P10-OD-08) | P10.5 exit |

## 13. P10 closure portability questions (P10.8)

Frozen now; P10.8 must answer each with evidence:

| | Question |
|---|---|
| A | Did DovahLink domain and application code remain free of Windows socket and handle types? |
| B | Is the canonical Bootstrap mapping platform-independent? |
| C | Is proof of possession application-level and platform-neutral? |
| D | Are Pair / Reject / Block platform-neutral application policy? |
| E | Is durable trust storage independent of the `sas-pairing` transport? |
| F | Is normal reconnect independent of the SAS transport? |
| G | Can the Dart consumer semantics be reused on a future Android client? |
| H | Which P8 APIs are already reusable unchanged? |
| I | Which P8 APIs are Windows-specific? |
| J | Can the cooperative-drive concept survive a different native carrier? |
| K | Does authority semantics require only a platform-native implementation, or a public API change? |
| L | Does Android require only native implementation plus packaging? |
| M | Does Android require an additional transport or platform API? |
| N | Did any real DovahLink integration need expose an ABI-v1 limitation? |

P10.8 then selects exactly one:

- **A.** ABI v1 reusable directly with native platform implementation work.
- **B.** ABI v1 survives, but additional native or platform transport or ownership work is required.
- **C.** Concrete P10 evidence demonstrates that ABI evolution is required.

P10.1 does not choose.

## 14. Concrete Android blocker register

"YES" requires current implementation evidence; absence of an Android implementation alone is not a blocker. *P10.2 produced no new Android evidence and changes no row; its canonical Bootstrap bytes are platform-neutral.*

| Potential Android issue | Current evidence | Concrete blocker? | P10 action | P11 question |
|---|---|---|---|---|
| Authority OS ownership | `core/src/lib.rs` non-Windows `os_lock::Lease::acquire` → `UnsupportedPlatform` | **YES** | None | Which cross-process exclusive primitive in app-private storage gives equivalent ownership, and what does account scoping mean for an Android app? |
| Native network carrier | `windows_owner_loop` / `windows_tcp` are `#[cfg(windows)]` | **YES** | None | Which bounded readiness model and socket adapter does Android need inside the core? |
| ABI carrier entry | The only listener entry is `sas_pairing_host_attach_windows_listener` with a Windows `SOCKET` type | **YES** (no carrier can be handed over on Android today) | Record | Can an Android carrier be reached through the existing export's documented semantics, or does it need an addition? Decided from P10.8 evidence, not here |
| Native packaging | No Android `.so` build or artifact (P8-D-006 B) | **YES** | None | Android ABIs (arm64-v8a, others?), packaging into the app, `panic = "unwind"` artifact checks |
| Dart loader: explicit absolute path to an existing file | `native_library_loader.dart` rejects relative or missing paths | NOT YET KNOWN | None | Can a Flutter Android app give an absolute path to the packaged `.so`, or does loading by name need a different (owner-decided) loader rule? |
| Dart 64-bit pointer gate | Loader refuses non-8-byte pointers | NO for 64-bit devices | None | Is 32-bit Android (armeabi-v7a) in scope at all? |
| Dart listener token | `SasPairingWindowsListenerSocket.fromNativeSocket(int)` wraps a Windows `SOCKET` | **YES** (Windows-specific API) | Keep below the adapter | What Android counterpart token is needed? |
| Client outbound connection | ABI v1 is listen-only (fact K) | NOT YET KNOWN | E-02 on Windows | If the relay works on Windows, does the same pattern work with an Android carrier? |
| One-image residency and `FATAL` → process restart | P7-D-002; P8 loader | NOT YET KNOWN | None | Does the Android process lifecycle (background kill, restart, multiple engines) keep one image per process and allow a clean restart? |
| Isolate and process model under Flutter Android | P8-D-001 N (unenforced) | NOT YET KNOWN | E-04 on Windows | Which isolate owns `sas_pairing` on Android, and does the owner survive backgrounding? |
| Suspend and resume | P5-F-011 (suspend behaviour unverified); `recheckAfterResume` exists | NOT YET KNOWN | None | Which Android lifecycle signal triggers the recheck, and is the monotonic clock behaviour acceptable? |
| Cooperative drive concept | Public API has no Windows type | NO | Use as-is | — |
| Ceremony, presentation, identity, result APIs | Public API has no Windows type | NO | Use as-is | — |
| DovahLink client key storage (Android Keystore) | DovahLink-owned (its Stage 5A) | NO (not a `sas-pairing` blocker) | None | DovahLink's own 5A work |
| WinSock FFI listener creation in the DovahLink client adapter | Windows-only by construction (P8-D-003 D) | **YES** for that adapter only | Implement Windows-only in P10.4 | Android socket source for the counterpart token |

## 15. Android questions recorded for P11

The nine questions the P10.1 task requires, with where the evidence stands. They are questions, not answers.

1. **Authority ownership.** The Windows primitive is an exclusive `LockFileEx` byte-range lock on a per-account lock file under the user profile; off Windows the lease returns `UnsupportedPlatform` ([§3](#3-authority-portability-assessment)). Android needs an equivalent native primitive and a scoping definition.
2. **Network carrier.** The Windows listener handoff is frozen. Android would need, at the native boundary, a carrier the core can own and poll with the same bounded semantics, and some way for the application to hand it over ([§14](#14-concrete-android-blocker-register) rows 2–3).
3. **Cooperative drive.** The high-level drive and event model is reusable in shape even if the carrier changes ([§10](#10-cooperative-drive-assessment)); whether its bounds and blocking behaviour suit Android scheduling is unknown.
4. **Native library lifecycle.** The one-image and `FATAL` → restart model is conceptually platform-neutral; whether Android's process lifecycle preserves it is unknown.
5. **Dart wrapper.** Platform-neutral today: lifecycle, Bootstrap, drive, connection, run, presentation, identity, result ([§11](#11-dart-future-reuse-matrix)).
6. **Dart Windows listener.** `SasPairingWindowsListenerSocket` and `SasPairingHost.attachWindowsListener` need an Android counterpart.
7. **Packaging.** The current artifact is a Windows DLL; Android needs `.so` builds, packaging, and loading (and an answer to the absolute-path loader question).
8. **Process and isolate.** One owner isolate, backgrounding, and process death under Flutter Android are unverified.
9. **ABI.** No P10 evidence of a missing generic operation exists yet; the only candidate is the outbound connection, which E-02 tests on Windows first.

## 16. Contradictions and gaps

Only items supported by repository evidence.

**Actual contradictions**

- `roadmap/README.md` (before this increment) went straight from P10 to "1.0 only after explicit security-readiness criteria", and `roadmap/P10-consumer-integration.md` said P10 "unlocks" a 1.0 readiness assessment, while the owner's direction now makes Android (P11) the next major platform phase. Corrected in this increment (P11 milestone added; P10's "what this unlocks" updated).
- DovahLink's current six-digit flow makes typing the code both the proof and the authorization that creates trust (`PairingCoordinator.ConfirmCode` → pending credential → committed trust), which conflicts with the compare-only SAS model (the SAS is not a secret and is never typed) and with the separation of P10-D-001 item 11. DovahLink's own target architecture already separates them; P10.5 / P10.6 replace the flow (cutover policy: P10-OD-07).

**Stale documentation**

- `docs/architecture.md` still says the API boundary, native interface, and transport responsibilities "remain open" and lists network transport among consumer responsibilities "unless a future protocol specification explicitly requires otherwise". The frozen ABI now fixes the boundary, and the core owns the TCP carrier inside its owner loop while the consumer binds the listener. Not changed in P10.1 (outside its listed current-state files); recommended for a later documentation pass.
- DovahLink (not changed by P10.1): `roadmap/deviations/current-execution-flow.md` and `roadmap/deviations/initial-pairing-security/README.md` say `sas-pairing` "remains research" and that no construction is "claimed selected"; `sas-pairing` has since selected and implemented an experimental construction with Dart and .NET packages (still not production-approved, so "not production-ready" remains true). DovahLink's identity contract also predates the Bootstrap / result model. DovahLink owns those updates.

**Missing planning detail**

- The P10 roadmap had no increments, no portability assessment, and no DovahLink authentication audit. Replaced by the [revised roadmap](../../roadmap/P10-consumer-integration.md).
- No plan existed for the client's outbound reachability under the listen-only ABI (E-02), the Skyrim-side decision path (P10-OD-08), artifact consumption by DovahLink (P10-OD-12), or reading the peer's Bootstrap fields (P10-OD-13).
- The original P10 goal included generic "integration examples"; the revised plan centres on DovahLink, so whether a generic example remains a deliverable is open (P10-OD-15).

**Future questions (not contradictions today)**

- The wrappers expose Windows-specific listener types in their public API. This is by design and documented (P8-D-003 D, P9-D-003); P10 keeps them below the adapter (E-08).
- Non-Windows fail-closed behaviour is documented everywhere as "not platform support" (manifest §10, P8 closure §14, P9 closure §16); no document mistakes it for portable pairing. Kept that way.
- The Dart API's platform-neutral shape is not presented anywhere as Android support (P8 closure §14). Kept that way ([§11](#11-dart-future-reuse-matrix)).
- DovahLink's invariant that Host verification and Client proof of possession happen on one bound transport must be reconciled with a SAS ceremony on a separate socket (P10.2 question Z), and DovahLink has not decided whether first pairing continues on a provisional connection or a new one (its `identity-and-transport.md` §10).
- Several DovahLink Host processes per machine versus account-scoped authority exclusivity (E-11, P10-OD-14).

## 17. STOP conditions review

| STOP | Hit? | Evidence |
|---|---|---|
| A. A real DovahLink P10 Windows requirement cannot be represented by ABI v1 | **No** | No need in [§9](#9-abi-v1-p10-assessment) has been shown inexpressible; the outbound connection has a plausible public-API adapter path, requiring experiment E-02 and unproven until it passes, with a STOP-and-report rule if it fails |
| B. The responsibility boundary cannot be defined without moving DovahLink policy into `sas-pairing` | **No** | [Consumer boundary §2](consumer-boundary.md#2-responsibility-boundary); DovahLink's own architecture already keeps that policy |
| C. Authenticated result data is insufficient for P10.2's application authorization | **No** | The result carries the peer's exact Bootstrap (identity, algorithm, key, context) and `ceremony_identity`; safe consumer access to the canonical-frame form is a plausible public-API adapter path, requiring experiment E-13 and unproven until it passes |
| D. `CeremonyIdentity` cannot bind application authorization to the exact attempt | **No** | 32 transcript-derived bytes, natively checked on every decision ([consumer boundary §5](consumer-boundary.md#5-ceremonyidentity-boundary)) |
| E. A wrapper lacks a capability P10 needs and the only workaround is private or raw FFI | **No** | The Dart client's WinSock FFI only creates the application's own listening socket, which P8-D-003 D assigns to the application; the proposed relay (E-02) would use only public APIs and ordinary sockets; nothing bypasses either wrapper's private interop |
| F. DovahLink's architecture inherently needs Windows socket or native objects inside its domain or trust layer | **No** | DovahLink already confines Windows facilities behind SDK ports and Host infrastructure folders ([§5](#5-net-host-integration-boundary), [§7](#7-dart--flutter-integration-boundary)) |
| G. Repository state differs materially from assumptions | **No** | `main` = `b938016`; the local `feature/p10-consumer-integration` already existed at exactly that commit and was used as-is; no remote P10 branch or P10 pull request existed. Untracked leftover build output under `examples/` (empty `bin` / `obj` folders and two MSBuild task DLLs, no sources) was present before P10.1 and is not part of it |
