# P8 — Dart Package

> **Pre-alpha, experimental.** P8 builds the Dart binding of the frozen sas-pairing native ABI v1. It is not production-security approved, not audited, and not formally verified. The protocol is implemented only by the native Rust core; Dart binds C.

**Status: P8 IN PROGRESS — P8.5 COMPLETE; P8.6 next.** Roadmap: [P8 — Dart Package](../../roadmap/P8-dart-package.md). Decisions: [decisions.md](decisions.md). Package: [`dart/`](../../dart/README.md).

## Baseline

| Item | Value |
|---|---|
| Branch | `feature/p8-dart-package`, the one long-lived P8 branch; one pull request at P8 closure |
| Baseline | `main` at `80ecbb1931b556f18000de70a37cac8c6b47aaa6` (merge of the P7 pull request #13) |
| Native boundary | [native ABI v1](../p7-native-abi/abi-v1-manifest.md), frozen by [P7-D-013](../p7-native-abi/decisions.md#p7-d-013--abi-v1-final-freeze-and-wrapper-handoff); declarations in [`sas_pairing.h`](../../core/include/sas_pairing.h); unchanged by P8 |

## Increments

| Increment | Scope | Decisions | State |
|---|---|---|---|
| P8.1 | Dart package foundation: pure-Dart package `sas_pairing`, generated private raw FFI of ABI v1 (25 functions, constants, records), the process-lifetime native-library loader (explicit path, 64-bit gate, symbol preflight, ABI version 1), layout and manifest consistency tests, Windows and Linux CI | [P8-D-001](decisions.md#p8-d-001--dart-native-binding-and-loader-architecture) | **Complete** ([evidence](#p81-evidence)) |
| P8.2 | Runtime / Authority / Host lifecycle wrapper: public lifecycle objects, status and exception model, explicit consuming `close()`, native-cascade mirroring, FATAL and contract-violation latches; P8.2.1: public initialization errors and the `READY` 1–10 bound | [P8-D-002](decisions.md#p8-d-002--dart-lifecycle-ownership-and-fail-closed-state) | **Complete** ([evidence](#p82-evidence), [P8.2.1](#p821-evidence)) |
| P8.3 | Windows listener ownership and cooperative network driver: Bootstrap value model, listening-socket ownership handoff, attach and detach, bounded host drive and resume recheck, event mapping, connection wrappers, `RUN_UNTRACKED` close guidance | [P8-D-003](decisions.md#p8-d-003--dart-windows-listener-cooperative-drive-and-connection-lifetime) | **Complete** ([evidence](#p83-evidence)) |
| P8.4 | Run + ceremony control + SAS presentation: public runs from drive events and local starts, the nine trusted-local ceremony actions, SAS presentation and ceremony-identity binding | [P8-D-004](decisions.md#p8-d-004--dart-run-identity-explicit-ceremony-control-and-sas-binding) | **Complete** ([evidence](#p84-evidence)) |
| P8.5 | PairingResult API + result ownership: public runtime-owned results from drive events, explicit synchronous snapshot reads, explicit and runtime-cascade destruction, result data access after native FATAL | [P8-D-005](decisions.md#p8-d-005--dart-pairingresult-ownership-data-access-and-local-completion) | **Complete** ([evidence](#p85-evidence)) |
| P8.6 | Native artifact distribution + final P8 closure | — | Next |

## P7 wrapper handoff

The mandatory obligations of [ABI contract §21](../p7-native-abi/abi-contract.md#21-wrapper-handoff-p8-p9) and where P8 meets them.

| # | Obligation | P8 state |
|---:|---|---|
| 1 | Bind exactly ABI v1; check `sas_pairing_abi_version() == 1` before any other call | P8.1: the loader preflights all 25 exports and requires version `1` before publishing the library; `0` and any other value fail permanently |
| 2 | One native image, retained for the process lifetime; no close, unload, reload, reset, or alternate copy | P8.1: one `DynamicLibrary.open` from an explicit path, retained strongly; no such API exists; a second initialization opens nothing |
| 3 | Tell consumers that `SAS_PAIRING_FATAL` needs an OS process restart | P8.2: `SasPairingNativeException.processRestartRequired` (true exactly for 900); the process FATAL latch refuses every later normal operation without a native call, cleanup stays allowed, no reset API; documented ([package README](../../dart/README.md)) |
| 4 | Caller-memory contract | P8.2 (lifecycle): the private lifecycle service allocates aligned, typed, distinct output slots and an exact scope copy for each call and frees them before returning; P8.3 (network): the private network service does the same for the socket slot, the Bootstrap views and their byte copies, the 17 event records, `out_count`, and `out_failure`, copying every produced record before the memory is freed; P8.5 (results): the private result service allocates one zeroed info record per info call and, per copy, one `size_t` slot and a buffer of exactly the reported length (a null buffer for 0), copying out only on `OK` and never past the capacity; no pointer outlives a call |
| 5 | Listener handoff through the in/out slot | P8.3: `SasPairingWindowsListenerSocket` is offered through one typed `sas_pairing_socket_t` slot; the slot is read before any status is processed; `isTransferred` becomes true exactly when it reads `SAS_PAIRING_SOCKET_INVALID`, and a transferred token never reaches native code again |
| 6 | Cooperative bounded drive; consume every event, also when `out_failure` is not OK | P8.3: `drive()` / `recheckAfterResume()` make exactly one native call with capacity 17; with `SAS_PAIRING_OK` every event is delivered in a `SasPairingDriveBatch` and the owner-loop failure is `batch.failure` (never thrown); no loop, timer, stream, isolate, or callback exists |
| 7 | SHOULD close a connection after `RUN_UNTRACKED` | P8.3: exposed as `event.runUntracked` with `event.shouldCloseConnection`; the consumer closes the connection after the batch (documented); the drive never closes it itself |
| 8 | Explicit ceremony steps, `WRITE_PENDING` handling, decisions bound to the exact `ceremony_identity` | P8.4: one public method per native action (`startInitiator`, `authorizeExposure`, `exposeKey`, `approveSas`, `emitBootstrapMac`, `rejectSas`, `cancelSas`, `emitInitiatorFinish`), each exactly one native call that chains nothing and drives nothing; status `writePending` (205) is thrown and means the action did not run, the action flag is `SasPairingLocalAction.writePending` and means it ran; `approveSas`, `rejectSas`, and `cancelSas` take only a `SasPairingCeremonyIdentity`, which only a presentation produces |
| 9 | Never construct, parse, or send frames; never confirm a final ACK | P8.1: no protocol code exists in Dart (guarded by a scope test); permanent. P8.4: no final-ACK confirmation API exists (scope-guarded); the Initiator's result appears on a later drive after the native adapter confirmed its final ACK |
| 10 | A result is local verified completion only | P8.3: a delivered result handle is retained package-privately at runtime lifetime. P8.4: a local action never returns a result. P8.5: `SasPairingResult` is one runtime-owned local verified completion, documented (class, entrypoint, and package README) as never peer completion, a bilateral commit, or persisted trust; it has no trust, bilateral, or persistence member (scope- and member-guarded), and the package never persists, enrolls, or trusts from it |
| 11 | Own the comparison UX and trust policy; no status is a trust verdict | P8.2: `SasPairingStatus` mirrors the 48 frozen values; exceptions carry the exact code (unknown codes preserved); no trust, malice, or authorization property exists. P8.4: `SasPairingSasPresentation.decimal` is display data; the package never compares displays or decides MATCH, and the application calls the decision; no action, run, or presentation carries a trust property |

## Package layout (P8.5)

```text
dart/
  pubspec.yaml                 sas_pairing 0.1.0-dev.1, publish_to: none, runtime dep ffi
  analysis_options.yaml        package:lints/recommended + strict analyzer modes
  ffigen.yaml                  explicit ABI v1 generation filter
  lib/
    sas_pairing.dart           public entrypoint: exports the P8.2 lifecycle, status, and
                               exception types, the P8.3 network types, the P8.4 run and
                               ceremony types, and the P8.5 result types by explicit show lists
    src/
      lifecycle.dart           SasPairingRuntime / Authority / Host (with the host's network
                               methods), AuthorityState / Status
      bootstrap.dart           SasPairingBootstrap (P8.3)
      network.dart             listener token, network state, connection (with startInitiator),
                               drive batch and failure, event and event enums; the
                               package-private HostNetwork and event mapper (P8.3)
      ceremony.dart            part of network.dart: SasPairingRun, SasPairingLocalAction,
                               SasPairingLocalEvent, SasPairingSasPresentation,
                               SasPairingCeremonyIdentity; action and presentation validation
                               and the one ceremony status handler (P8.4)
      result.dart              part of network.dart: SasPairingResult, SasPairingResultData,
                               SasPairingPeerRole; the runtime-owned NativeResultStore (P8.5)
      network_refs.dart        private: exact native run references (P8.3; run request IDs
                               may start unknown since P8.4; results moved to result.dart, P8.5)
      status.dart              SasPairingStatus (48 frozen values)
      exceptions.dart          Initialization / Native / Closed / Contract / RunEnded exceptions
      native/                  private: never exported
        abi_v1.dart            frozen ABI v1 tables (exports, values, record sizes)
        native_library_loader.dart   process-lifetime loader (P8.1, unchanged)
        native_lifecycle_api.dart    NativeLifecycleApi: the seven lifecycle exports, all FFI memory
        native_network_api.dart      NativeNetworkApi: the five network exports, all FFI memory (P8.3)
        native_ceremony_api.dart     NativeCeremonyApi: the nine ceremony exports, all FFI memory (P8.4)
        native_result_api.dart       NativeResultApi: the three result exports, all FFI memory (P8.5)
        native_bootstrap.dart        the one shared Bootstrap view marshaller (attach and start)
        native_process_context.dart  per-image process context: the four services, FATAL and
                                     contract latches, normal and data admission
        generated/
          sas_pairing_bindings.g.dart  generated raw FFI (SasPairingNativeBindings)
  test/                        manifest, binding, layout, loader, initialization, lifecycle
                               (fake), network (fake), ceremony (fake), result (fake), Bootstrap, FFI
                               marshalling, status, public API, real-artifact, scope tests;
                               support/winsock.dart is the test-only loopback listener harness
                               and support/ceremony_child.dart holds the test-only relay
```

## Lifecycle contract (P8-D-002)

```text
SasPairingRuntime                 runtime_create / runtime_destroy (close)
  └── SasPairingAuthority         authority_register / authority_status / authority_release (close)
        └── SasPairingHost        host_create / host_destroy (close)
```

- **Normal** operations (`SasPairingRuntime.create`, `registerAuthority`, `queryStatus`, `createHost`) check the wrapper is open (else `SasPairingClosedException`), then the process latches, then make one native call; success needs `SAS_PAIRING_OK` and, for creations, a nonzero handle.
- **Cleanup** (`close()` on each wrapper) is locally idempotent and consuming: the first call marks the wrapper closed, makes exactly one native cleanup call, then invalidates children locally, whatever the result; a failure is thrown once and never retried. Cleanup is never refused by a latch.
- **Cascade.** Native authority release and runtime destroy already clean up their children, so Dart issues no child cleanup call: closing an authority makes one `authority_release`; closing a runtime makes one `runtime_destroy`; every child wrapper is then closed.

| First `close()` of | Native calls | Local effect |
|---|---|---|
| Host | 1 × `sas_pairing_host_destroy` | host closed and removed from its authority; authority stays open |
| Authority | 1 × `sas_pairing_authority_release`, 0 × host destroy | authority and all of its hosts closed; removed from its runtime; runtime stays open |
| Runtime | 1 × `sas_pairing_runtime_destroy`, 0 × authority release, 0 × host destroy | runtime, all authorities, and all hosts closed |

- **Latches** (in the package-private process context of the loaded image, below every runtime, never cleared): status 900 from any lifecycle call sets the FATAL latch; an `OK` output that breaks a frozen success invariant (zero handle, authority state `INVALID` or unknown, `READY` with a remaining count outside 1–10, `BUSY`/`EXHAUSTED` with nonzero remaining) sets the contract latch. The bound validates one returned snapshot; Dart keeps no budget, decrement, or expected next value. Either refuses every later normal operation, including `SasPairingRuntime.create`, without a native call; recovery is an OS process restart.
- **Initialization failures** (P8.2.1). A loader failure inside `SasPairingRuntime.create` is translated at one package-private boundary into the public `SasPairingInitializationException` (category `SasPairingInitializationFailure`, message preserved, no native status). Pre-load failures (pointer width, invalid path, OS load failure) have `processRestartRequired == false` and may be retried after correcting the cause; post-load failures (missing export, version query 0, version mismatch, verification failure) have `processRestartRequired == true` and fail every later `create` in the process. The private loader types are never exported.
- **Runtime recreation** reuses the same loaded image (the loader opens nothing once ready) and resets nothing: not the latches, the authority opportunity budget, the START limiter, or any process-session state.

## Network contract (P8-D-003)

```text
SasPairingRuntime                 + runtime-owned results (public since P8.5)
  └── SasPairingAuthority
        └── SasPairingHost        networkState; attachWindowsListener / detachListener /
              │                   drive / recheckAfterResume
              ├── optional native network context (one listener + owner loop)
              └── SasPairingConnection wrappers (+ private exact run references)
```

- **Attach** (normal): one `sas_pairing_host_attach_windows_listener` over a typed in/out socket slot. The slot is read first: `SAS_PAIRING_SOCKET_INVALID` marks the token transferred (also for `LISTENER_SETUP_FAILED` and a late `FATAL`), the offered value leaves it with the caller, anything else is a contract violation, and `OK` without `INVALID` is a contract violation. `OK` sets `attached`; nothing is driven.
- **Detach** (cleanup, idempotent): one `sas_pairing_host_detach_listener`; then `detached`, every connection closed locally, no `sas_pairing_connection_close`.
- **Drive / recheck** (normal): one native call, capacity 17. A nonzero return value is a `SasPairingNativeException` with no batch; with `OK`, every event is delivered in native order and a nonzero `out_failure` is `batch.failure`, after which (and only after mapping every event) FATAL is latched for 900 and every connection is closed with the state `failedClosed`.
- **Events**: every frozen namespace value maps to one named enum value; an impossible record (unknown value or flag, `reserved != 0`, `request_id_len > 64`, missing or unknown connection, duplicate accept, more than 17 events, and the other record-local invariants of P8-D-003 K) is a contract violation.
- **Connections**: one wrapper per native handle, reused by every later event; closed by `close()` (one `sas_pairing_connection_close`, consuming; `OWNERSHIP_UNCERTAIN` fails the loop closed), by its closed event, by detach, by an owner-loop failure, and by host or parent close (no native call). `LISTENER_DISABLED` closes none.
- **Private references**: exact run handles per connection, never public; invalidated only by the native visibility rules and teardowns of P8-D-003 N. Result handles are kept by the runtime and wrapped as public results since P8.5 (see the result contract below).

| Operation | Native calls | Local effect |
|---|---|---|
| `SasPairingConnection.close()` (first) | 1 × `sas_pairing_connection_close` | that connection closed, its run references invalid; on `OWNERSHIP_UNCERTAIN` every connection closed and `failedClosed` |
| `detachListener()` | 1 × `sas_pairing_host_detach_listener`, 0 × connection close | `detached`, every connection closed |
| `SasPairingHost.close()` | 1 × `sas_pairing_host_destroy`, 0 × detach, 0 × connection close | host closed, `detached`, every connection closed |
| `SasPairingAuthority.close()` | 1 × `sas_pairing_authority_release`, 0 × host destroy, detach, or connection close | authority, hosts, and connections closed |
| `SasPairingRuntime.close()` | 1 × `sas_pairing_runtime_destroy`, no child cleanup export | every descendant closed, every open result closed |

## Ceremony contract (P8-D-004)

```text
SasPairingConnection              startInitiator(local, expected)  → a new SasPairingRun
  └── SasPairingRun               one exact native run handle (never a request ID); isEnded;
                                  authorizeExposure / exposeKey / presentation / approveSas /
                                  emitBootstrapMac / rejectSas / cancelSas / emitInitiatorFinish
```

- **Runs.** A drive event's `run` and a local action's `run` are the one `SasPairingRun` of their exact native handle; a new handle under a reused request ID is a new run and the earlier one ends. A locally started run has an unknown request ID until an event names its handle; it is never invented, and the same handle under a different request ID is a contract violation.
- **One call per step.** Every method makes exactly one native call; nothing chains, drives, retries, or closes. Each is a normal operation: a known-ended run throws `SasPairingRunEndedException` first, then the FATAL and contract latches refuse, then the native call.
- **Outcomes per method** (anything else on `OK` is a contract violation; every run action may also report `deadline`, run ended, deadline kind not `none`):

| Method | Native export | Success (`run`; `writePending`) |
|---|---|---|
| `SasPairingConnection.startInitiator` | `sas_pairing_connection_start_initiator` | `initiatorStarted` (new run; true) |
| `authorizeExposure` | `sas_pairing_run_authorize_exposure` | `exposureAuthorized` (same run; false); spends nothing |
| `exposeKey` | `sas_pairing_run_expose_key` | `keyExposed` (same run; true); **the security-spending step** |
| `presentation` | `sas_pairing_run_presentation` | `null` (no live SAS) or a presentation; read-only, also while a write is pending |
| `approveSas` | `sas_pairing_run_approve_sas` | `sasApproved` / `sasAlreadyApproved` (same run; false) |
| `emitBootstrapMac` | `sas_pairing_run_emit_bootstrap_mac` | `bootstrapMacEmitted` (same run; true) / `bootstrapMacAlreadyEmitted` (same run; false) |
| `rejectSas` | `sas_pairing_run_reject_sas` | `sasRejected` (run ended; either) |
| `cancelSas` | `sas_pairing_run_cancel_sas` | `sasCancelled` (run ended; either) |
| `emitInitiatorFinish` | `sas_pairing_run_emit_initiator_finish` | `initiatorFinishEmitted` (same run; true) / `initiatorFinishAlreadyEmitted` (same run; false) |

- **`WRITE_PENDING`, two facts.** Status `writePending` (205) is thrown: the requested action did not run (drive, then retry if still appropriate). `SasPairingLocalAction.writePending` is set on success: the action ran and its frame waits for a drive. Dart keeps no write-pending state of its own.
- **Presentation.** `available` 0 (every other byte 0) is `null`; `available` 1 needs exactly `NNNN NNNN NNNN` in ASCII and zero reserved bytes; the 32-byte `SasPairingCeremonyIdentity` is copied, unmodifiable, compared by value, and has no public constructor. The package never compares displays or decides MATCH.
- **Status side effects** (one package-private handler; nothing else is inferred):

| Nonzero status from a ceremony call | Local effect before it is thrown |
|---|---|
| `runEnded` (204) | that run ended and forgotten; later calls are local `SasPairingRunEndedException`s |
| `connectionEnded` (405) | the connection closed and removed, every run of it ended; no `sas_pairing_connection_close` |
| `ownershipUncertain`, `ownerLoopClosed` | every connection of the host closed, every run ended, network state `failedClosed`; no cleanup call |
| `fatal` (900) | process FATAL latch; no ending inferred; cleanup still allowed |
| `writePending` and every ceremony or core refusal | none |

- **Results.** A local action never returns a result. Results arrive only on drive events (`event.result`; see the result contract below).

## Result contract (P8-D-005)

```text
SasPairingRuntime                 owns every SasPairingResult (NativeResultStore: live results +
  │                               every delivered handle, never public)
  └── SasPairingResult            one native result handle = ONE local verified completion;
                                  isClosed / read() / close()
        read() ──► SasPairingResultData   immutable snapshot: ceremonyIdentity, peerRole (the
                                          PEER's role), profileVersion, requestId,
                                          authenticatedPeerBootstrap, authenticatedSharedContext,
                                          profileIdentifier
```

- **Local completion only.** A result is this endpoint's locally verified completion. It never says that the peer completed, holds a result, received the final message, or committed, and it is not persisted or established trust; either side may be the only holder. The package persists, enrolls, and trusts nothing.
- **Delivery.** A drive event with a result carries `event.result` (`hasResult == (result != null)`): the handle is checked, kept in the runtime's store, and wrapped. Nothing is read while the event is mapped, so a batch with several events and an `out_failure` is still delivered whole.
- **One object per handle, never reused.** The store keeps every delivered handle until runtime close. A second delivery of a handle, whether its result is open or already closed, is a contract violation; no second wrapper is ever made.
- **Ownership and survival.** Run endings, connection close, a `connectionClosed` event, detach, an owner-loop failure (also in the same batch as the result), host close, authority close, and native FATAL leave a result open and make no `sas_pairing_result_destroy` call. Only `SasPairingResult.close()` and `SasPairingRuntime.close()` end it.
- **Read.** `read()` checks that the result is open, then the data admission, then makes one `sas_pairing_result_info` and exactly one `sas_pairing_result_copy` per field (request ID, authenticated peer Bootstrap, authenticated shared context, profile identifier) at exactly the length the info reported (a null buffer with capacity 0 for an empty field). Every read reads native again (no cache); a failure returns nothing partial and leaves the result open.
- **Data admission.** Native FATAL does not block `read()` (ABI v1 keeps existing results readable because reading never enters the core); a Dart-observed contract violation does (no native call). `close()` is allowed after both.
- **Contract checks on a successful read.** Exactly 32 identity bytes (all-zero is valid); peer role `INITIATOR` or `RESPONDER` (`INVALID` or unknown is a violation); `request_id_len` ≤ 64, `peer_bootstrap_len` ≤ 16,384, `shared_context_len` ≤ 8,192 (the frozen bounds); a copy whose `OK` reports another length, or `BUFFER_TOO_SMALL` at the exact reported capacity, is a violation, never a resize and retry. Any other nonzero status is thrown exactly (`FATAL` latched). `profile_version` and `profile_identifier_len` are preserved, not validated.
- **Exact bytes.** The four byte fields are defensive copies behind unmodifiable views. The peer Bootstrap is the exact canonical frame native returned and is never parsed; the request ID, shared context, and profile identifier are never decoded. The ceremony identity reuses `SasPairingCeremonyIdentity`, equal to the presentation identity of the same ceremony.
- **Close.** The first `close()` marks the result closed and makes one `sas_pairing_result_destroy`; a failure (`INVALID_HANDLE`, `FATAL`, unknown) is thrown once and never retried. Runtime close makes its one `sas_pairing_runtime_destroy` and closes every remaining result, with no result destroy. A data snapshot already read stays usable after both.

| Operation | Native calls | Local effect on results |
|---|---|---|
| Drive event with a result | the drive only | one new open `SasPairingResult`; nothing read |
| `SasPairingResult.read()` | 1 × `sas_pairing_result_info`, 4 × `sas_pairing_result_copy` | none; a new immutable `SasPairingResultData` |
| `SasPairingResult.close()` (first) | 1 × `sas_pairing_result_destroy` | that result closed (also on failure); later calls nothing |
| Connection close, detach, host close, authority close, owner-loop failure, FATAL | their own calls only | none |
| `SasPairingRuntime.close()` | 1 × `sas_pairing_runtime_destroy`, 0 × result destroy | every open result closed |

## Real-native test topology

`dart test` runs each test file in its own isolate of one VM process. To keep the one-owner-isolate rule (P8-D-001 N), only `test/native_artifact_test.dart` loads the real library into the test process, and it calls only the version query there. The P8.2 real lifecycle scenarios the P8.3 real network scenarios, and the P8.4 real two-endpoint ceremony (extended in P8.5 with both results' reads, lifetimes, and destruction) run in child OS processes (`dart run test/support/lifecycle_child.dart <scenario> <artifact>`, `dart run test/support/network_child.dart <scenario> <artifact>`, `dart run test/support/ceremony_child.dart windows-happy-path <artifact>`), each with a single isolate that is its native owner; the test process never registers an authority. The ceremony child joins its two accepted loopback connections with a test-only byte-transparent relay (two Dart client sockets that copy every byte unchanged and only count them). The network scenarios bind loopback listening sockets with the test-only WinSock harness `test/support/winsock.dart`, which closes a socket only while its token is untransferred. Every Windows scenario uses unique, non-text scopes (a literal, the child's process ID, and the bytes `00 80 FF`). All other lifecycle tests use a deterministic fake of the private lifecycle service and load nothing; the production loader has no test reset.

Regenerating the raw bindings (requires libclang; on Windows the default LLVM install, on Linux `libclang-dev`):

```bash
cd dart && dart run ffigen --config ffigen.yaml
```

After regeneration `git diff` must be empty; CI regenerates on Windows and Linux and fails on any difference.

## Loader contract (P8-D-001)

- **Explicit path.** `NativeLibraryLoader.initialize(libraryPath: ...)` takes an absolute path to an existing file; nothing is discovered.
- **Order.** Pointer width 8 → path validation and canonicalization → one `DynamicLibrary.open` → retain → preflight the 25 exports → build the generated bindings → `sas_pairing_abi_version()` → require `1` → ready.
- **States.** *Uninitialized* (also after a failure before an image was loaded: pointer width, path, OS load error; a retry is allowed). *Ready* (the one retained library; every later `initialize` returns the identical object without reading its path argument). *Permanently failed* (an image was loaded but lacks an export, reports version `0`, reports another version, or failed to bind: the image stays referenced, nothing else is ever opened, and the error says to restart the OS process).
- **No escape hatch.** No close, unload, reload, reset, replace, or fatal-recovery API, in production or tests.

## Isolate contract

Dart statics are isolate-local, so the loader is a singleton per isolate, not per OS process. The supported model: **one Dart owner isolate per OS process holds all direct sas-pairing native access.** Other isolates do not open the library or call the bindings; they communicate with the owner at a higher layer, or do not use the native package. `DynamicLibrary.open` of the same file shares one image within the VM process, but a second isolate opening a different copy would break the P7-D-002 one-image invariant, and nothing in Dart can prevent that. P8.1 builds no cross-isolate façade.

## Platform scope

| Platform | Native ABI v1 in Dart | Pairing |
|---|---|---|
| Windows (x64) | The real `sas_pairing_core.dll` loads, binds, and reports ABI version 1; the P8.2 lifecycle, the P8.3 listener attach, drive, events, and connections, and the P8.4 runs, ceremony control, and SAS presentation work against it | Supported by P7 (Windows TCP carrier); a complete two-endpoint ceremony through the public Dart API is proven, and both endpoints' results are read after every networking object is gone and destroyed explicitly or by the runtime |
| Linux (x64) | The real `libsas_pairing_core.so` loads, binds, and reports ABI version 1; a runtime can be created and closed | Not supported: authority registration fails closed with `SasPairingStatus.unsupportedPlatform` (`SAS_PAIRING_UNSUPPORTED_PLATFORM`) as P7 defines, so no host or listener exists; the P8.3 network, P8.4 ceremony, and P8.5 result wrappers are verified there against the deterministic fake only (no result can be produced there) |
| 32-bit processes | Refused before any library is opened | Not supported |

## Evidence

### P8.1 evidence

Commits on `feature/p8-dart-package`: `36222c8` (`docs: define p8 dart binding foundation`), `799fab8` (`feat: add dart native abi v1 bindings`), `67139a7` (`test: verify dart abi v1 foundation`; CI green on that exact head), then the closure commit `docs: close p8.1 dart binding foundation`.

| Item | Result |
|---|---|
| Toolchain | Dart SDK 3.13.4 (stable), locally and pinned in CI; package constraint `^3.11.0`; `ffi` ^2.2.0; dev `ffigen` 22.0.0 (exact), `lints` ^6.1.0, `test` ^1.32.0; no Flutter |
| Generation | `dart run ffigen --config ffigen.yaml` from `dart/`, header `../core/include/sas_pairing.h`, output `lib/src/native/generated/sas_pairing_bindings.g.dart` (1,259 lines, LF); local regeneration byte-identical (Windows, libclang 19.1.5); CI regeneration with `git diff --exit-code` passes on Linux (Ubuntu `libclang-dev`) and Windows |
| Bound exports | Exactly the 25 frozen functions; every generated native signature equals the header declaration (C `const` has no FFI counterpart) |
| Type mapping | `int32_t` → `Int32`, `uint32_t` → `Uint32`, `uint64_t` → `Uint64` (all six handle types), `uint8_t` → `Uint8`, `uintptr_t` → `UintPtr` (`sas_pairing_socket_t`), `size_t` → `Size`, pointers → `Pointer<T>`; 21 ABI typedefs checked against manifest §6 |
| Constants | 145 generated constants (2 version, 48 statuses, 84 namespace values, 11 handle-invalid and scalar values), each mirrored by name and value in `abi_v1.dart` and compared with the manifest row by row; `SAS_PAIRING_SOCKET_INVALID` (`UINTPTR_MAX`) is `-1` as a 64-bit Dart `int` |
| Records | `sas_pairing_bytes_view_t` 16, `sas_pairing_bootstrap_view_t` 64, `sas_pairing_event_t` 128, `sas_pairing_result_info_t` 56, `sas_pairing_action_t` 24, `sas_pairing_sas_presentation_t` 56 (`sizeOf` equals the frozen size); all 37 manifest field offsets and sizes measured from memory; fixed arrays 64 / 32 / 14 / 2; no padding |
| Real artifact | Windows `sas_pairing_core.dll` (local and CI) and Linux `libsas_pairing_core.so` (CI): the production loader opens it from the explicit path, all 25 symbols resolve by exact name, `sas_pairing_abi_version()` = 1; a second initialization returns the identical retained object |
| Fresh-process states | Child processes with the real loader: a missing path then the artifact → pre-load failure, then ready (version 1); a foreign real library (kernel32.dll / libc.so.6) then the artifact → permanent `missingSymbol` failure naming all 25 exports, and the artifact is never opened |
| Dart tests | 48 passed (manifest 7, generated bindings 6, record layout 4, loader state machine 19, real artifact 5, scope 7); `dart format` clean; `dart analyze --fatal-infos` clean, generated file included |
| Mutations (temporary, reverted) | Each made its test fail: status `SAS_PAIRING_FATAL` 900 → 901; an export removed from the ffigen filter; a fake export added to the ffigen filter; a fake export added to the Dart export list; required ABI version 1 → 2 (real-artifact smoke fails); event size expectation 128 → 120; generated `request_id` length 64 → 63; a `close()` call in the loader (scope test) |
| Native regression | `git diff 80ecbb1 -- core` is empty; `abi::tests::freeze` 3 passed locally and in the Dart workflow; the unchanged `Rust security core` and `Repository consistency` workflows are green on the same head |

### P8.2 evidence

Commits on `feature/p8-dart-package`: `dd2054e` (`docs: define p8 dart lifecycle contract`), `8547e1b` (`feat: add dart runtime authority host lifecycle`), `2363592` (`test: verify dart lifecycle ownership`), `67445f7` (`test: allow freed lifecycle output slots to be reused`; CI green on that exact head), then the closure commit `docs: close p8.2 dart lifecycle`. CI on `2363592` failed in both `dart test` jobs: an FFI marshalling test wrongly required two consecutive calls to receive distinct output-slot addresses, although each call frees its slot and the allocator may reuse it. Reproduced in a fresh clone, the assertion was narrowed to slots of one call (plus a scope/output non-overlap check); no library code changed.

| Item | Result |
|---|---|
| Public surface | `package:sas_pairing/sas_pairing.dart` exports, by explicit `show` lists, exactly `SasPairingRuntime`, `SasPairingAuthority`, `SasPairingHost`, `SasPairingAuthorityState`, `SasPairingAuthorityStatus`, `SasPairingStatus`, `SasPairingNativeException`, `SasPairingClosedException`, `SasPairingContractException`; nothing from `lib/src/native/`; no public handle, pointer, binding, or loader |
| Native boundary | Exactly the seven lifecycle exports, called only from `NativeLifecycleApi` (source-scanned); `git diff 37c986a -- core` is empty |
| Fake lifecycle tests | 40 (`lifecycle_test.dart`): runtime 9, authority 12, host 7, parent cascade 4, FATAL latch 5, unknown status 2, no handle or scope in text 1 |
| Cascade call counts | Host close: 1 `host_destroy`. Authority close: 1 `authority_release`, 0 `host_destroy`, all hosts closed. Runtime close: 1 `runtime_destroy`, 0 `authority_release`, 0 `host_destroy`, every authority and host closed. Second `close()`: 0 calls |
| Cleanup errors | `authority_release` → `OWNERSHIP_UNCERTAIN`: exception, authority and hosts closed, 1 call, no retry; `host_destroy` → `OWNERSHIP_UNCERTAIN`: exception, host closed, authority open, 1 call; `runtime_destroy` → `INVALID_HANDLE`: exception, runtime and children closed |
| FATAL latch | A normal call returning 900 latches; the four normal operations then throw status 900 with no native call; host, authority, and runtime close still make their one cleanup call (also when it returns 900); `SasPairingRuntime.create` over a fake loader after FATAL: no second `DynamicLibrary.open` (`opened` stays 1) and no `runtime_create`; only 900 latches (901, 999, 899, −900, 777 do not) |
| Contract latch | `OK` with handle 0 (runtime, authority, host), state `INVALID`, unknown states 4 and `0xFFFFFFFF`, `READY` with 0, `BUSY`/`EXHAUSTED` with nonzero remaining: `SasPairingContractException`, later normal work refused without a native call, explicit cleanup still allowed |
| Unknown status | 777 (normal) and 31337 (cleanup): `SasPairingNativeException` with the exact integer, `knownStatus == null`, `processRestartRequired == false`, no latch |
| FFI marshalling | 7 tests (`native_lifecycle_api_test.dart`) over the real generated bindings with Dart callbacks as the C exports: scope bytes `00 80 FF 00 41 00` and a 1,024-byte non-text scope arrive exactly with their full length; an empty scope is a null pointer with length 0; aligned, typed, nonzero output slots; two distinct status slots; 64-bit handle bit patterns preserved |
| Status model | 5 tests (`status_test.dart`): 48 enum values equal the private ABI table by name and code (no duplicates); `fromCode` round-trips and returns null for unknown codes; only `fatal` requires a restart; the observed normal/cleanup split of the seven exports equals manifest §2 fatal classes |
| Public API and scope | `public_api_test.dart` 5 tests; `package_scope_test.dart` 10 tests (updated, not removed: entrypoint exports only the lifecycle surface; no unload/reload/reset or recovery, finalizer, timer, isolate, stream, socket, listener, drive, Bootstrap, connection, run, result, presentation, crypto, randomness, or text conversion; only three `close()` declarations and no child-by-child call; FFI memory only in the lifecycle service) |
| Real Windows lifecycle | Child process over the real `sas_pairing_core.dll` (local and CI): runtime created; a second `create` → `alreadyInitialized` (3); authority with a binary scope (literal + PID + `00 80 FF`) → `ready`, 10; same scope again → `alreadyRegistered` (101); empty scope → `invalidScope` (100); hosts A and B; close A → authority open, `ready`, 10; close authority → host B closed by the cascade, `queryStatus` → `SasPairingClosedException`; re-registration → `ready`, 10; runtime close with two live authorities and three hosts → all closed; recreated runtime → same loaded image, re-registration `ready`, 10 |
| Real Linux lifecycle | Child process over the real `libsas_pairing_core.so` (CI only; no local Linux): runtime created and closed; registration → `unsupportedPlatform` (103); empty scope → `invalidScope` (100); recreated runtime → `unsupportedPlatform` again. No Linux pairing support is claimed |
| Dart tests | 110 (Windows: 109 passed, 1 Linux-only skipped; Linux: the Windows-only test skipped): manifest 7, generated bindings 6, record layout 4, loader 19, real artifact 7, scope 10, lifecycle 40, FFI marshalling 7, status 5, public API 5; `dart format` clean; `dart analyze --fatal-infos` clean |
| Mutations (temporary, reverted) | Each made its test fail: a `Finalizer` in the lifecycle (scope test); a public `int get nativeHandle` (public API test); host invalidation removed from authority close; child invalidation removed from runtime close; a second runtime close and a second host close calling native; runtime close calling `authority.close()` first; authority close calling `host.close()` first; a normal call entering native after FATAL; `busy` 105 → 115 (status consistency); scope length cut at the first NUL; scope round-tripped through a `String` (marshalling tests) |
| Native regression | `abi::tests::freeze` 3 passed locally and in the Dart workflow; the unchanged `Rust security core` and `Repository consistency` workflows green on the same head |

### P8.2.1 evidence

Corrective increment after independent review of P8.2, on the same branch from `ea3ce92`: `45cf6d4` (`fix: harden p8.2 public initialization and status bounds`), then the closure commit `docs: close p8.2.1 lifecycle correction`. No native file changed.

| Item | Result |
|---|---|
| Findings | (1) `SasPairingRuntime.create` could throw the private P8.1 `NativeLibraryInitializationException`, which a consumer of the public entrypoint cannot name or catch by type; (2) `queryStatus()` accepted `READY` with any remaining count above 0, although a successful `READY` reports 1–10 |
| Public surface | The entrypoint now also exports `SasPairingInitializationException` and `SasPairingInitializationFailure` (explicit `show` list); still nothing from `lib/src/native/`; `NativeLibraryInitializationException` and `NativeLoadFailure` added to the prohibited public names |
| Mapping | Exhaustive switch, private → public, same seven names: `unsupportedPointerWidth`, `invalidLibraryPath`, `openFailed` (restart false); `missingSymbol`, `abiVersionQueryFailed`, `abiVersionMismatch`, `verificationFailed` (restart true) |
| Initialization tests | 12 (`initialization_test.dart`, fake loader seam): the category and restart table against every private value; each of the seven failures reaching the `create` boundary is the public type (never the private one) with the right category, restart class, and loader message, no lifecycle service, and an image retained exactly when restart is required; invalid path then a valid path → runtime created, one open; ABI mismatch then another path → the same public failure, one open only; a non-loader error passes untranslated |
| Public API tests | 11 (`public_api_test.dart`, +6): consumer-visible types; the restart table; the real `SasPairingRuntime.create` (this isolate's process loader, nothing loaded) with an empty, relative, missing absolute, and non-library path → `SasPairingInitializationException` (`invalidLibraryPath` ×3, `openFailed`), restart false; an architecture check that `exceptions.dart` knows nothing of the loader, the public exception holds only `failure` and `message`, no doc comment in `lifecycle.dart` names a private loader type, and in code they appear only in the import and the one translation boundary used by `create` |
| `READY` bound | `READY` 1 and 10 → `ready`; `READY` 0, 11, 500, and `0xFFFFFFFF` → `SasPairingContractException`, contract latch set, later `queryStatus`, `createHost`, `registerAuthority`, and runtime create refused with no native call, host/authority/runtime cleanup still one native call each; `BUSY` and `EXHAUSTED` still require 0; a sequence 1, 10, 4 is accepted (no snapshot is compared with an earlier one) |
| Lifecycle regression | `lifecycle_test.dart` 41 (40 unchanged + 1 bounds test; the impossible-state table gained three `READY` rows); real Windows and Linux lifecycle children unchanged |
| Mutations (temporary, reverted) | Each made its tests fail: (A) `create` without the translation boundary → the four public `create` tests and the architecture test; (B) `abiVersionMismatch` with restart false → initialization and public restart tests; (C) `READY` accepted for `remaining > 0` → the impossible-state test at `READY` 11; (D) upper bound `< 10` → the bounds test and every test whose default fake answers `READY` 10; (E) `NativeLibraryInitializationException` exported from the entrypoint → public API and scope export tests |
| Native boundary | `git diff ea3ce92 -- core` and `git diff 80ecbb1 -- core` empty |
| Dart tests | 128 (Windows with the real DLL: 127 passed, 1 Linux-only skipped): manifest 7, generated bindings 6, record layout 4, loader 19, initialization 12, real artifact 7, scope 10, lifecycle 41, FFI marshalling 7, status 5, public API 11; `dart format` clean; `dart analyze --fatal-infos` clean |

### P8.3 evidence

Commits on `feature/p8-dart-package`, from `c74d607`: `914e07d` (`docs: define p8 dart network driver contract`), `f24e147` (`feat: add dart listener drive and connection wrappers`), `6f65051` (`test: verify dart network ownership and events`; all five CI jobs green on that exact head), then the closure commit `docs: close p8.3 dart network driver`. No native file changed.

| Item | Result |
|---|---|
| Public surface | The entrypoint adds, by explicit `show` lists, `SasPairingBootstrap`, `SasPairingWindowsListenerSocket`, `SasPairingHostNetworkState`, `SasPairingConnection`, `SasPairingDriveBatch`, `SasPairingDriveFailure`, `SasPairingEvent`, `SasPairingEventKind`, `SasPairingStepKind`, `SasPairingProtocolEvent`, `SasPairingEventReason`, `SasPairingDeadlineKind`, `SasPairingCancelState`, `SasPairingCancelReason`; `SasPairingHost` gains `attachWindowsListener`, `detachListener`, `drive`, `recheckAfterResume`, `networkState`; `SasPairingConnection` has only `isClosed` and `close()`. No raw socket, connection, run, or result handle, generated record, `Pointer`, native event array, or raw enum or flag integer is public (source-checked) |
| Native boundary | Exactly the five network exports, called only from `NativeNetworkApi` (source-scanned); no ceremony action, presentation, or result export is called anywhere; `git diff c74d607 -- core` and `git diff 80ecbb1 -- core` empty |
| Attach ownership matrix (fake) | A `OK` + slot `INVALID` → transferred, `attached`, no drive; B `INVALID_BOOTSTRAP` + original → not transferred, `detached`; C `LISTENER_ALREADY_ATTACHED` + original → not transferred, existing network and connection untouched; D `LISTENER_SETUP_FAILED` + `INVALID` → transferred, `detached`, not fatal; E `FATAL` + original → not transferred, FATAL latched; F `FATAL` + `INVALID` → transferred, FATAL latched; G `OK` + original → contract violation; H another slot value (with `OK`, `FATAL`, `INVALID_HANDLE`) → contract violation (FATAL also latched for 900); `UNSUPPORTED_PLATFORM`, `INVALID_HANDLE`, `INVALID_ARGUMENT` → not transferred; a transferred token → `StateError`, no native call; attach on a closed host or after FATAL → refused, no native call |
| Bootstrap | 4 tests: bytes `00 80 FF` kept exactly; caller changes after construction do not reach it; writes through a getter, its buffer, a view of its buffer, or its byte data throw; Dart refuses no semantic value (uppercase algorithm, empty fields, 20,000-byte field); attach hands the exact bytes and lengths to the service and a null `expected` stays null |
| FFI marshalling | 10 tests (`native_network_api_test.dart`) over the generated bindings with Dart callbacks as the C exports: the offered socket in one aligned typed slot, read back raw (`-1` for `INVALID`, unchanged, or another value); Bootstrap bytes exact with exact lengths (including `00 80 FF` and a 16,385-byte non-text field); empty fields as null pointer + length 0; no `expected` as a null pointer; capacity always 17; zeroed record memory; every produced record copied field by field with 64-bit bit patterns preserved; nothing past `out_count` read; at most 17 copied; no events on a nonzero return |
| Network wrapper (fake) | 95 tests (`network_test.dart`): token 2, attach matrix 14, detach 5, drive 17, out_failure FATAL 1, event mapping 3, record invariants 28, connections 6, `LISTENER_DISABLED` 1, `RUN_UNTRACKED`/`WRITE_PENDING` 2, private runs 8, private results 3, parent cascade 4, recheck 1 |
| Drive | One public call = one native call (`drive` or `recheckAfterResume`, never the other); `OK` + 0 events → empty unmodifiable batch, `failure == null`; top-level `LISTENER_NOT_ATTACHED`, `HANDLES_EXHAUSTED`, `INVALID_HANDLE`, `UNSUPPORTED_PLATFORM`, `BUFFER_TOO_SMALL` → exception, no state change, connections open; top-level `FATAL` → exception, latched; `OK` + events + `NETWORK_POLL_FAILED` / `OWNERSHIP_UNCERTAIN` / `FATAL` → both events delivered in order, then the connections closed and `failedClosed`; `OK` + 0 events + `OWNER_LOOP_CLOSED` → `failedClosed`; unknown `out_failure` 777 preserved, not FATAL; after `failedClosed` the next drive still calls native; more than 17 events → contract violation; native order kept across interleaved connections |
| out_failure FATAL | Batch with its event and `failure.statusCode == 900`, `processRestartRequired`; FATAL latched; then drive, recheck, attach, `createHost`, `registerAuthority` refused with no native call; `detachListener`, host close, runtime close each still make their one native call |
| Event mapping | Every frozen value of the step (8), protocol event (13), reason (16), deadline (5), cancel state (4), and cancel reason (5) namespaces maps to the enum value named after it, with no extra member; the five produced event kinds map exactly and `INVALID` is no public kind |
| Contract checks | Event kind 0 and 6; step 8; protocol 13; reason 16; deadline 5; cancel state 4; cancel reason 5; flags `0x4` and `0x80000001`; `request_id_len` 65; `reserved` 1; a nonzero request-ID byte past its length; a missing connection on accepted, step, or closed; a connection on accept-refused or listener-disabled; a run, result, or flags on a non-step event; a run with a result; `RUN_UNTRACKED` with a run; a duplicate accept; a step or closed event for connection 777; a result handle delivered twice: each a `SasPairingContractException`, later normal work refused with no native call, host close still one native call. Request-ID lengths 0 and 64 are valid and copied exactly (unmodifiable); a bad record later in a batch changes no state before it |
| Connections | Accepted / step / closed for handle 100 → the identical object, closed after its closed event, no `100` in its text; a closed event makes no native call and forgets the handle; manual close → 1 `connection_close` with the exact handles, second close 0 calls; a native error → closed, thrown once, no retry, sibling open; `OWNERSHIP_UNCERTAIN` → both of two connections closed, `failedClosed`, 1 call; close after FATAL and a FATAL close → still one call each, latched, closed |
| `LISTENER_DISABLED` / `RUN_UNTRACKED` | Listener disabled → `listenerDisabled`, the connection stays open and later steps still map to it; detach closes it. `RUN_UNTRACKED` → `runUntracked`, `shouldCloseConnection`, `hasTrackedRun == false`, connection open, 0 close calls, no other run reference evicted; the consumer's close after the batch makes 1 call. `WRITE_PENDING` → `writePending` only |
| Private runs and results | Exact handle 5000 kept privately; the same handle → the identical reference; a new handle under a reused request ID → a new reference, the old one invalid and never retargeted; endings invalidate only under their request ID (`START_DUPLICATE` does not; peer cancel, a deadline with a request ID, and a result do; refused, unconfirmed, discarded, and written do not); connection close, closed event, detach, owner-loop failure, host, authority, and runtime close invalidate. Results 9000 / 9001 (Responder and Initiator paths) retained in the runtime store through connection close, detach, owner-loop failure, host close, and authority close; no result export called; runtime close invalidates them; a result with an owner-loop failure is retained |
| Parent cascade | Host close with two live connections: exactly `[hostDestroy]`; authority close with connections on two hosts: exactly `[authorityRelease]`; runtime close with two authorities, hosts, and connections: exactly `[runtimeDestroy]`; every descendant connection closed and every host `detached`; a failing host destroy still closes its connections |
| Fatal classes | The observed normal/cleanup split of the five network exports equals manifest §2 (`attach`, `drive`, `recheck` normal; `detach`, `connection_close` cleanup), in the extended `status_test.dart` |
| Real Windows attach / detach | Child process over the real `sas_pairing_core.dll` (local and CI) with the core's own ABI test Bootstrap fixture (`core/src/abi/tests/listener.rs` `local_view`: `p7-listener-application`, `x25519`, 32 × `07`, empty shared context): drive before attach → `listenerNotAttached` (402); attach with the fixture's uppercase-algorithm variant → `invalidBootstrap` (203), not transferred, the harness closed the socket; attach → transferred, `attached`; a second attach while attached → `listenerAlreadyAttached` (400), not transferred, harness closed it; one drive with no client → 0 events, no failure, about 259 ms locally (bounded); recheck → 0 events; detach → `detached`, host and authority open, authority `ready` with 10; drive after detach → 402; host close → `detached` |
| Real Windows connection | Loopback client → exactly one `connectionAccepted`, connection open; client closed → `connectionClosed` (reason `peerClosed`) with the identical object, already closed; a second `close()` makes no call; detach |
| Real listener replacement | Attach L1, accept C1; detach → `detached`, C1 closed; attach L2 (new token) → `attached`; a new client → C2, a different object, C1 still closed; manual `C2.close()` → closed, `attached`; authority `ready` with 10 before and after (no accounting change); both tokens transferred once; the harness closed neither |
| Linux | Ubuntu CI: package analysis, the 109 fake network, FFI marshalling, and Bootstrap tests (nothing skipped), the frozen-binding checks, and the real native smoke and lifecycle; no Linux networking is claimed (no host can exist there) |
| Mutations (temporary, reverted) | Each made its tests fail: (A) drive throws on `out_failure` → 6 drive tests; (B) transfer not recorded for `LISTENER_SETUP_FAILED` + `INVALID` → matrix D; (C) a new wrapper per event → identity, listener-disabled, untracked, and events-plus-failure tests; (D) `LISTENER_DISABLED` closes connections → listener-disabled test; (E) drive auto-closes `RUN_UNTRACKED` → untracked test; (F) runs looked up by request ID → exact-run test; (G) result handle dropped → 3 result tests; (H1) host close detaches first and (H2) host close closes connections first → cascade tests; (I) unknown flag bits accepted → both flag tests; (J) an automatic `while` drive loop → scope test |
| Dart tests | 243 (Windows with the real DLL: 242 passed, 1 Linux-only skipped): manifest 7, generated bindings 6, record layout 4, loader 19, initialization 11, lifecycle 41, FFI lifecycle 7, FFI network 10, network 95, Bootstrap 4, status 5, public API 13, scope 11, real artifact 10 (3 new real network); `dart format` clean; `dart analyze --fatal-infos` clean |
| Native regression | `abi::tests::freeze` 3 passed (1 ignored) locally and in the Dart workflow; `Rust security core` (`windows-core`, `unsupported-platform-fails-closed`) and `Repository consistency` green on the same head |

### P8.4 evidence

Commits on `feature/p8-dart-package`, from `da2d02d`: `cf4490d` (`docs: define p8 dart ceremony control contract`), `331c4b2` (`feat: add dart run ceremony and sas api`), `cf65336` (`test: verify dart ceremony control and sas binding`; all five CI jobs green on that exact head), then the closure commit `docs: close p8.4 dart ceremony control`. No native file changed.

| Item | Result |
|---|---|
| Public surface | The entrypoint adds, by explicit `show` lists, `SasPairingRun`, `SasPairingLocalAction`, `SasPairingLocalEvent`, `SasPairingSasPresentation`, `SasPairingCeremonyIdentity`, and `SasPairingRunEndedException`; `SasPairingConnection` gains `startInitiator`; `SasPairingEvent` gains `run` (`hasTrackedRun == (run != null)`). No run handle, action or presentation record, raw flag or local-event value, `Pointer`, or generated binding is public; no public constructor exists for a run, action, presentation, or identity (source-checked) |
| Native boundary | Exactly the nine ceremony exports, called only from `NativeCeremonyApi` (source-scanned, with the seven lifecycle and five network exports in their services); no result export is called anywhere; `git diff da2d02d -- core` and `git diff 80ecbb1 -- core` empty |
| Shared Bootstrap marshaller | The P8.3 view builder moved unchanged into `native/native_bootstrap.dart`, used by attach and start; the P8.3 FFI tests (exact bytes, `00 80 FF`, 16,385-byte field, empty field as null pointer + length 0, null `expected`) pass unchanged |
| Ceremony FFI marshalling | 20 tests (`native_ceremony_api_test.dart`) over the generated bindings with Dart callbacks as the C exports: exact handles; one zeroed, 8-aligned `sas_pairing_action_t` per call; every field copied on `OK` with 64-bit run bit patterns preserved; no record returned on a failing status even when the export wrote one; Bootstrap views exact (null `expected` is a null pointer); exactly 32 identity bytes (including `00`) disjoint from the record, and another length never reaches native; one zeroed, 4-aligned presentation record copied byte for byte (raw, uninterpreted) on `OK` only |
| Ceremony wrapper (fake) | 193 tests (`ceremony_test.dart`): local events 5, start 24, run identity 8, run actions 84 (each of the seven methods: one call on the exact handles, every ordinary success, every known wrong event, wrong flag or run handle, `DEADLINE` with each of the four kinds with and without `WRITE_PENDING`, `DEADLINE` invariants, first `RUN_ENDED`, status `WRITE_PENDING`; plus the successful flag, flags `0x2` / `0x80000000` / `0x80000001`, valid flags, reserved, missing record), explicit steps 6, refusals 18, lifecycle side effects 19, presentation 26, identity binding 2, results 1 |
| Start | One `startInitiator` call with the exact Bootstrap bytes (null and non-null `expected`), a new live run 7000 with an unknown request ID, `writePending`, no drive or other action; zero run, the handle of a live run (same or another connection), another event, no or an unknown flag, a deadline kind, or `reserved` → contract violation with no run; closed connection → `SasPairingClosedException`, no call; `FATAL` → latched, no run; `WRITE_PENDING`, `INVALID_BOOTSTRAP`, `RESOURCE_LIMITED`, `HANDLES_EXHAUSTED`, and four more → exact status, no run, no drive; `CONNECTION_ENDED` → connection closed locally, no close call; `OWNERSHIP_UNCERTAIN` / `OWNER_LOOP_CLOSED` → `failedClosed` |
| Run identity | Start → run 7000 (request ID unknown, usable); an `ACCEPT` naming 7000 under `A1 A2` → the identical object, request ID learned; the same ID again changes nothing; a different ID for the same handle → contract violation (also for a run first reported by a drive); learning an ID ends a stale run under it, mirroring the native start; request-ID endings (peer cancel, deadline, result) never end a run whose ID is unknown; handle 100 then 101 under the same request ID → two objects, 100 ended and never retargeted, 101 reaches native as 101; event, later event, and action carry the identical run; a started run and the later event naming it are identical |
| Lifetime and statuses | Terminal successes, `DEADLINE`, first `RUN_ENDED` (exact 204 thrown, then local `SasPairingRunEndedException` with no native call, also for presentation), visible ending, result, and deadline events, connection close, closed event, detach, owner-loop failure, host, authority, and runtime close all end the public run; refused, unconfirmed, discarded, a deadline without a request ID, and `START_DUPLICATE` do not; 17 ceremony and core refusals and an unknown status 777 change nothing; `CONNECTION_ENDED` ends that connection and its three runs only, without a close call; `OWNERSHIP_UNCERTAIN` and `OWNER_LOOP_CLOSED` (from an action or from presentation) close both connections, end both runs, and set `failedClosed` with no cleanup call; `FATAL` (also from presentation) latches, ends nothing, refuses every later run method and start with no native call, while connection close, detach, and runtime close still make their calls; a known-ended run is refused before the latch |
| `WRITE_PENDING` | Status 205 from each of the seven methods and from start: exception, no action, exactly one call (no drive, no retry), run live, the next call still reaches native. Flag on `keyExposed`: action returned with `writePending`, run live, and `presentation()` still reaches native; no automatic drive |
| Presentation | `available` 0 → `null`, run live; `available` 0 with a nonzero reserved, identity, decimal, or tail byte → contract violation (4); `available` 2 or `0xFFFFFFFF`, nonzero reserved or tail, 13- or 15-byte display, 31-byte identity, tab, misplaced or missing spaces, letter, NUL, UTF-8 Arabic-Indic digit, a byte above ASCII, `/`, `:` → contract violation (16); valid displays (`0000 0000 0000`, `9999 9999 9999`, `1000 9191 4567`) exact; identity bytes exact, unaffected by later changes to the native copy, unmodifiable through the getter, its buffer, and `setAll`, value equality and hash code |
| Identity binding | A decision passes exactly the presented 32 bytes; run A approving identity B reaches native unblocked, which answers `CEREMONY_IDENTITY_MISMATCH`; run A stays live and approves its own identity |
| Explicit steps | `authorizeExposure` → only `authorizeExposure` (no key output); `approveSas` → only `approveSas`; `emitBootstrapMac` → only `emitBootstrapMac`; reject and cancel call different exports with distinct events and end their runs without closing the connection; a Responder finish gets `NOT_INITIATOR` and the run stays usable; a scope test checks that each of the seven run methods names exactly its own one service call and that `ceremony.dart` drives, rechecks, and closes nothing |
| Fatal classes | The observed normal/cleanup split of all 21 stateful exports equals manifest §2, now including the nine ceremony exports (all normal), in `status_test.dart` |
| Scope and public API | `package_scope_test.dart` 12 (updated, not removed: the later-increment rule now forbids the result API; new rules forbid automatic approval and action chaining, final-ACK confirmation names, Dart-side accounting or write-pending state, and trust verdicts; SAS logic stays forbidden apart from the frozen `sas*` local-event names; `emitBootstrapMac` is the one allowed `emit…Mac` name; one validated `String.fromCharCodes(decimal)` for the display; FFI memory only in the three services and the shared Bootstrap marshaller); `public_api_test.dart` 15 (+2: a consumer type-checks the whole P8.4 API from the entrypoint alone; the P8.4 types carry exactly their payload fields and no public constructor; `ceremony.dart` scanned for raw values and handles) |
| Real Windows ceremony | One child process over the real `sas_pairing_core.dll` (local and CI): one runtime, authorities A and B, hosts A and B with loopback listeners (local / expected Bootstraps of the opposite endpoint), joined by the test-only byte-transparent relay; both connections accepted; A `startInitiator` → `initiatorStarted`, `writePending`; a second start before the drive → `writePending` (205), and B sees exactly one START; B's `startAccepted` event carries a new run, `writePending`, a 16-byte request ID; A's `accept` event carries the identical run with the same request ID; A authorize → `exposureAuthorized`, no output, authority `ready` 10; A expose → `keyExposed`, `writePending`, authority `busy` 0; A presentation while its key waits → reaches native, `null`; B gets `initiatorKey` on its run, authorizes, exposes (`busy` 0), and presents its SAS while its key is still retained; A presents after `responderKey`; both decimals equal (for example `7676 2446 5640`), both 32-byte identities equal; MATCH chosen explicitly on A → `sasApproved`, then one drive of each host produces no event and A's presentation is withdrawn; A `emitBootstrapMac` → `writePending`; a second MAC before the drive → 205; after the drive the retry → `bootstrapMacAlreadyEmitted`; B MATCH, B MAC; both MACs authenticated on the identical runs; B `emitInitiatorFinish` → `notInitiator` (217), run live; A `emitInitiatorFinish` → `initiatorFinishEmitted`, `writePending`; driving on gives exactly one local result per endpoint (A `connectionStep/confirmed`, B `connectionStep/inbound/initiatorFinishAck`), result fields never read; both runs ended, a later action refused locally; both authorities `ready` 9; relay 721 bytes A→B and 613 B→A; detach; both listener tokens transferred and never closed by the harness. About 5 s locally |
| Linux | Ubuntu CI: package analysis, the 193 fake ceremony, 20 ceremony FFI, scope, public-API, and status tests (nothing skipped in the `P8.4 ceremony control (fake native services)` step), and the existing real native smoke and lifecycle; no Linux pairing is claimed |
| Mutations (temporary, reverted) | Each made its tests fail: (A) `authorizeExposure` also calls `exposeKey` → 3 ceremony tests and the scope test; (B) `approveSas` also emits BOOTSTRAP_MAC → 4 ceremony tests and the scope test; (C) `emitBootstrapMac` also emits INITIATOR_FINISH → 5 ceremony tests and the scope test; (D) status `WRITE_PENDING` turned into a successful action → 7 tests; (E) unknown action flag bits accepted → 4 tests; (F) terminal actions keep the run live → 34 tests; (G) `RUN_ENDED` does not end the run → 8 tests; (H1) malformed decimal accepted → 9 tests, (H2) `available` 2 accepted → 1, (H3) nonzero reserved tail accepted → 2; (I) public `int get nativeHandle` on `SasPairingRun` → 3 public API tests; (J) runs keyed by request ID → 2 ceremony tests and the P8.3 exact-run test; and a public `confirmFinalAck()` → the scope test |
| Dart tests | 460 (Windows with the real DLL: 459 passed, 1 Linux-only skipped): manifest 7, generated bindings 6, record layout 4, loader 19, initialization 11, lifecycle 41, FFI lifecycle 7, FFI network 10, FFI ceremony 20, network 95, ceremony 193, Bootstrap 4, status 5, public API 15, scope 12, real artifact 11 (1 new real ceremony); `dart format` clean; `dart analyze --fatal-infos` clean |
| Native regression | `abi::tests::freeze` 3 passed (1 ignored) locally and in the Dart workflow; `Rust security core` (`windows-core`, `unsupported-platform-fails-closed`) and `Repository consistency` green on the same head |

### P8.5 evidence

Commits on `feature/p8-dart-package`, from `4877db4`: `b259c16` (`docs: define p8 dart result ownership contract`), `d178f94` (`feat: add dart pairing result api`), `4c07053` (`test: verify dart result ownership and data access`; all five CI jobs green on that exact head), then the closure commit `docs: close p8.5 dart pairing results`. No native file changed.

| Item | Result |
|---|---|
| Public surface | The entrypoint adds, by explicit `show` lists, `SasPairingResult` (`isClosed`, `read()`, `close()`), `SasPairingResultData` (exactly `ceremonyIdentity`, `peerRole`, `profileVersion`, `requestId`, `authenticatedPeerBootstrap`, `authenticatedSharedContext`, `profileIdentifier`), and `SasPairingPeerRole` (`initiator`, `responder`); `SasPairingEvent` gains `result` (`hasResult == (result != null)`). No result handle, field number, info record, copy primitive, required length, `Pointer`, or generated record is public; no public constructor exists for a result or its data; the ceremony identity is the one P8.4 type (source-checked) |
| Native boundary | Exactly the three result exports, called only from `NativeResultApi` (source-scanned, with the 7 lifecycle, 5 network, and 9 ceremony exports in their services); `git diff 4877db4 -- core` and `git diff 80ecbb1 -- core` empty |
| Source-proven bounds | `request_id_len` ≤ 64 (`SAS_PAIRING_MAX_REQUEST_ID_LEN`, ABI contract §18.1); `peer_bootstrap_len` ≤ 16,384 (the canonical Bootstrap frame bound of the frozen profile §3.1/§4, `MAX_BOOTSTRAP_FRAME`); `shared_context_len` ≤ 8,192 (profile §4); no narrower bound for `profile_identifier_len`; `profile_version` not validated |
| Result FFI marshalling | 15 tests (`native_result_api_test.dart`) over the generated bindings with Dart callbacks as the C exports: one zeroed, 4-aligned 56-byte info record; every field copied on `OK` (64-bit handles and `0xFFFFFFFF` values preserved), the identity a copy that outlives the record; no record on `INVALID_HANDLE`, `FATAL`, or 777 even when the export wrote one; each of the four field constants unchanged; a zero length as a null buffer with capacity 0 and empty bytes; a nonzero length as an exact-capacity zeroed buffer, bytes exact with no terminator (a 16,384-byte non-text field included); `BUFFER_TOO_SMALL` reports `required` and no bytes; never a read past the capacity; destroy statuses raw |
| Result wrapper (fake) | 70 tests (`result_test.dart`): delivery 8, read 15, source-proven bounds 8, copy length consistency 6, native failures 5, data admission 5, explicit close 6, survival 10, result with `out_failure` 2, runtime close 4, no handle in text 1 |
| Delivery and handles | A result event carries an open result and only the drive crosses the boundary (no info, copy, or destroy); `hasResult` mirrors `result` on every event kind; Responder (`INITIATOR_FINISH_ACK`) and Initiator (`CONFIRMED`) paths; one object per handle in the runtime store; a live duplicate (later batch or same batch) and a handle reused after its result was closed are contract violations with no new object and nothing read |
| Read | One info then four copies, in field order, at exactly the reported lengths and the exact handles; data equal to the source bytes; repeated reads go to native each time and agree; the identity equals a P8.4 presentation identity of the same bytes (same type, equality, hash); `INITIATOR` → `initiator`, `RESPONDER` → `responder`; `INVALID`, 3, `0xFFFFFFFF`, a 31-byte identity, or `OK` without a record → contract violation (later reads refused locally, close still destroys); all-zero identity accepted; profile versions 0, 1, 2, `0xFFFF`, `0xFFFFFFFF` preserved; non-text bytes (`00 FF 80 00`, `FF 00 C3 28 00`, ...) exact; empty shared context and profile identifier empty; request ID 64, Bootstrap 16,384, shared context 8,192 accepted and one more → violation before any copy; a 70,000-byte profile identifier preserved; a negative length → violation |
| Length consistency | `OK` with required 15 or 17 for a 16-byte request ID, or with the right required length but other bytes → violation, nothing copied after it, result open; `BUFFER_TOO_SMALL` at the exact capacity (required 7, 8, 1,000) → violation (never a `SasPairingNativeException`), the Bootstrap asked for once only |
| Native failures | Copy `INVALID_HANDLE` on the shared context → exact exception after three copies, no data, result open, the next read succeeds; copy or info `FATAL` → FATAL latched, result still closeable; unknown 777 preserved; info `INVALID_HANDLE` → no copy |
| Data admission | After native FATAL from an unrelated drive, a pre-existing result is read (info + four copies) and destroyed natively while normal operations stay refused; after an unrelated contract violation a read is refused locally (no info, no copy) and close still makes one destroy; a closed result is refused before any latch |
| Close | One destroy with the exact handles, second close 0 calls; `INVALID_HANDLE`, `FATAL` (latched), and 31337 from the first destroy → closed, thrown once, later close silent, read local; a FATAL destroy blocks no read of another result; data read before close stays usable |
| Survival | The run's ending, connection close (no destroy), a `connectionClosed` event, detach, a later `NETWORK_POLL_FAILED` or `OWNERSHIP_UNCERTAIN` loop failure, a ceremony call's `OWNERSHIP_UNCERTAIN`, host close (exactly `[hostDestroy]`), authority close (exactly `[authorityRelease]`), and all of them plus native FATAL together leave the result open and readable |
| Result + `out_failure` | One drive with a result and `NETWORK_POLL_FAILED`: the result delivered, open, readable, while the host is `failedClosed` and the connection closed. With `out_failure = FATAL`: the batch returned, FATAL latched, `failedClosed`, connection closed, then `read()` makes info + four copies and succeeds, and `close()` reaches native |
| Runtime cascade | Three results: runtime close makes exactly `[runtimeDestroy]`, every result closed, later read local and close silent with no call; an explicitly closed result is not destroyed again; a failing runtime destroy still closes every result; snapshots stay usable |
| Fatal classes | `status_test.dart`: the three result exports are `data` in manifest §2, and after a FATAL latch a pre-existing result's info, copy, and destroy still reach native |
| Scope and public API | `package_scope_test.dart` 14 (updated, not removed: the later-increment result ban replaced by bans on a generic field API (`copyField`, `readRawField`, `nativeResultInfo`, `requiredLength`, `SasPairingResultField`, `nativeHandle`, ...) and on trust automation or bilateral names (`persist…`, `enroll…`, `bilateral…`, `peerSucceeded`, `committed`, `isTrusted`, `trustPeer`, ...); the result file has exactly one `close()`; runtime close names no result destroy or close; the result service is the only caller of the three exports and holds FFI memory; new: `read()` uses `admitData` exactly once and never `admitNormal`, `close()` no admission, one info and one copy call site, each field once, no loop, and no other file reads or destroys a result; new: `authenticatedPeerBootstrap` appears only in its declaration and constructor, and the result file uses no Bootstrap model or byte-parsing primitive); `public_api_test.dart` 17 (+2: a consumer type-checks the whole P8.5 API from the entrypoint alone; the result types carry exactly their reviewed members, no public constructor, no second identity type, and a two-member peer role) |
| Real Windows ceremony | The P8.4 child, unchanged up to its local results, now continues through the public API only: exactly one result object per endpoint, from its own event, both open; detach (connections closed), then both hosts and both authorities closed while the runtime stays open; then both results read: identity A equals presentation A, identity B equals presentation B, and both are equal; peer role A (the Initiator) `responder`, B `initiator`; both request IDs equal, 16 bytes, and equal to the `startAccepted` request ID; profile version 1 and identifier `sas-pairing-vodozemac-profile-draft-01` on both (the frozen `PROFILE_ID` / `VERSION`); shared context exactly the fixture's bytes on both; peer Bootstraps 136 bytes each, distinct, A's containing B's configured identity and key and not A's own identity, and back (test-only byte search, no parsing); a repeat read equal; result A closed explicitly (twice), its read refused; runtime close then closes result B (read refused); both snapshots unchanged. About 6 s locally |
| Linux | Ubuntu CI: package analysis, the 70 fake result, 15 result FFI, scope, public-API, status, and network tests (nothing skipped in the `P8.5 results (fake native services)` step), and the existing real native smoke and lifecycle; no Linux pairing is claimed (no result can be produced there) |
| Mutations (temporary, reverted) | Each made its tests fail: (A) connection close invalidates results → 1 survival test; (B) authority close invalidates results → 2 tests; (C) `read()` uses `admitNormal` → 4 FATAL-read tests; (D) `BUFFER_TOO_SMALL` resized and retried → 3 tests; (E) copy length mismatch accepted → 3 tests; (F) a second `close()` calls native → 5 tests; (G) runtime close closes each result first → 2 cascade tests and 2 scope tests; (H) peer roles reversed → 3 fake tests and the real Windows ceremony; (I) public `int get nativeHandle` → 3 public-API tests and the scope test; (J) a Dart decoder of `authenticatedPeerBootstrap` into `SasPairingBootstrap` → the Bootstrap-bytes scope test and the members test; (K) `bool get peerSucceeded => true` → the scope trust rule and the members test; (L) only live handles checked, so a destroyed handle is accepted again → the never-reused-handle test |
| Dart tests | 549 (Windows with the real DLL: 548 passed, 1 Linux-only skipped): manifest 7, generated bindings 6, record layout 4, loader 19, initialization 11, lifecycle 41, FFI lifecycle 7, FFI network 10, FFI ceremony 20, FFI result 15, network 95, ceremony 193, result 70, Bootstrap 4, status 5, public API 17, scope 14, real artifact 11 (the real ceremony extended); `dart format` clean; `dart analyze --fatal-infos` clean |
| Native regression | `abi::tests::freeze` 3 passed (1 ignored) locally and in the Dart workflow; `Rust security core` (`windows-core`, `unsupported-platform-fails-closed`) and `Repository consistency` green on the same head |

## Nonclaims

P8 does not claim production readiness, bilateral completion or persisted trust from a result, security approval, an audit, formal verification, Linux or other non-Windows pairing support, cross-isolate enforcement of the one-image rule, protection against hostile in-process code, or recovery from `SAS_PAIRING_FATAL` without a process restart.
