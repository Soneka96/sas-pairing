# .NET binding

> **Experimental, pre-alpha, not production-ready.** Not production-security approved, not audited, and not formally verified. Do not use it to protect production systems.

`SasPairing` (package ID, namespace, and assembly; version `0.1.0-dev.1`, `net10.0`) is the implemented experimental .NET wrapper over the shared native security core, built in P9 ([P9 final closure](../docs/p9-dotnet-package/final-closure.md), [P9 package](../docs/p9-dotnet-package/README.md), [decisions](../docs/p9-dotnet-package/decisions.md), [changelog](CHANGELOG.md)). It binds the frozen [native ABI v1](../docs/p7-native-abi/abi-v1-manifest.md) and implements no protocol or cryptography itself: the Rust core is the only protocol implementation.

## Current state (P9 complete)

**P9 is complete** (P9.1–P9.6): the wrapper below exists, and it is distributed as two experimental GitHub Actions artifacts of one exact commit ([installation](#installation-experimental-ci-artifacts)): the NuGet-format package `SasPairing.0.1.0-dev.1.nupkg`, which contains **no native library**, and the separate Windows x64 native bundle. Nothing is published to nuget.org or any other feed; there is no GitHub Release or tag.

- The P9.1 foundation exists: the solution [`SasPairing.sln`](SasPairing.sln), the library [`src/SasPairing`](src/SasPairing/SasPairing.csproj), and its tests [`tests/SasPairing.Tests`](tests/SasPairing.Tests/SasPairing.Tests.csproj). The ABI v1 binding and its loader stay **internal**: the exact constants, records, and 25-export function table, and a loader that opens one native library from an explicit absolute path, requires 64-bit pointers, all 25 exports, and ABI version 1, and keeps the library loaded until the process exits ([P9-D-001](../docs/p9-dotnet-package/decisions.md#p9-d-001--net-abi-v1-binding-and-loader-architecture)).
- **P9.2: the runtime, authority, and host lifecycle** and its status and error model ([P9-D-002](../docs/p9-dotnet-package/decisions.md#p9-d-002--net-lifecycle-ownership-public-errors-and-fail-closed-state)).
- **P9.3: the Windows listener handoff and the cooperative network driver** ([P9-D-003](../docs/p9-dotnet-package/decisions.md#p9-d-003--net-windows-listener-cooperative-drive-event-and-connection-ownership)): the binary `SasPairingBootstrap`, the one-use listener token, attach and detach, one bounded `Drive()` and one `RecheckAfterResume()`, drive events, and `IDisposable` connections. Nothing native is public: no handle, socket value, pointer, native record, or loader.
- **P9.4: runs, the trusted-local ceremony, and SAS presentation** ([P9-D-004](../docs/p9-dotnet-package/decisions.md#p9-d-004--net-run-identity-explicit-ceremony-control-and-sas-binding)): one `SasPairingRun` per exact native run, `StartInitiator`, the explicit exposure, SAS, BOOTSTRAP_MAC, and INITIATOR_FINISH steps, read-only SAS presentation, and decisions bound to the exact ceremony identity. A full ceremony can be completed through .NET on Windows.
- **P9.5: the PairingResult API** ([P9-D-005](../docs/p9-dotnet-package/decisions.md#p9-d-005--net-pairingresult-ownership-reads-and-immutable-snapshots)): each local result arrives as `SasPairingEvent.Result`, owned by the runtime, read with `Read()` into an immutable detached `SasPairingResultData`, and closed with `Dispose()`. A result is **local completion only**.
- **P9.6: distribution** ([P9-D-006](../docs/p9-dotnet-package/decisions.md#p9-d-006--net-managed-package-native-artifact-distribution-and-p9-closure)): the project is packable (`dotnet pack`) into the experimental package `SasPairing.0.1.0-dev.1.nupkg` (`net10.0`, license `MIT OR Apache-2.0`, this README, the exact repository commit, no package dependency, no native binary), and CI distributes it with the separately staged Windows x64 native bundle. No native binary is committed or embedded in the package, and nothing is published.

## API

| Type | Members |
|---|---|
| `SasPairingRuntime : IDisposable` | `static Create(string nativeLibraryPath)`, `RegisterAuthority(ReadOnlySpan<byte> scope)`, `IsDisposed`, `Dispose()` |
| `SasPairingAuthority : IDisposable` | `GetStatus()`, `CreateHost()`, `IsDisposed`, `Dispose()` |
| `SasPairingHost : IDisposable` | `AttachWindowsListener(listener, local, expected = null)`, `DetachListener()`, `Drive()`, `RecheckAfterResume()`, `NetworkState`, `IsDisposed`, `Dispose()` |
| `SasPairingBootstrap` | `new(applicationIdentity, keyAlgorithm, publicKey, sharedContext)` (four `ReadOnlySpan<byte>`, copied); the same four as read-only `ReadOnlySpan<byte>` properties |
| `SasPairingWindowsListenerSocket : IDisposable` | `static FromSocket(Socket listener)`, `IsTransferred`, `Dispose()` |
| `SasPairingHostNetworkState` | `Detached`, `Attached`, `ListenerDisabled`, `FailedClosed` |
| `SasPairingDriveBatch` | `Events` (read-only, native order), `Failure` (null or the owner loop's failure) |
| `SasPairingDriveFailure` | `StatusCode`, `KnownStatus`, `ProcessRestartRequired` |
| `SasPairingEvent` | `Kind`, `Connection`, `StepKind`, `ProtocolEvent`, `Reason`, `DeadlineKind`, `CancelState`, `CancelReason`, `WritePending`, `RunUntracked`, `RequestId` (exact bytes), `Run`, `HasTrackedRun` (exactly `Run is not null`), `Result`, `HasResult` (exactly `Result is not null`), `ShouldDisposeConnection` |
| `SasPairingConnection : IDisposable` | `StartInitiator(local, expected = null)`, `IsDisposed`, `Dispose()` |
| `SasPairingRun` (not disposable) | `IsEnded`, `AuthorizeExposure()`, `ExposeKey()`, `Presentation()`, `ApproveSas(identity)`, `EmitBootstrapMac()`, `RejectSas(identity)`, `CancelSas(identity)`, `EmitInitiatorFinish()` |
| `SasPairingLocalAction` | `Event`, `Run` (null once the run ended), `DeadlineKind`, `WritePending` |
| `SasPairingLocalEvent` | the twelve frozen successful local events (`InitiatorStarted = 1` … `Deadline = 12`) |
| `SasPairingSasPresentation` | `CeremonyIdentity`, `DecimalDisplay` (`NNNN NNNN NNNN`) |
| `SasPairingCeremonyIdentity` | `Bytes` (exactly 32, read-only); value equality (`Equals`, `==`, `!=`, `GetHashCode`); no public constructor |
| `SasPairingRunEndedException` | `Operation`: a method of a run already known to have ended (no native call) |
| `SasPairingResult : IDisposable` | `Read()`, `IsDisposed`, `Dispose()`: one runtime-owned local verified result; reference identity |
| `SasPairingResultData` | `CeremonyIdentity`, `PeerRole`, `ProfileVersion`, and the read-only byte fields `RequestId`, `AuthenticatedPeerBootstrap`, `AuthenticatedSharedContext`, `ProfileIdentifier`; no public constructor |
| `SasPairingPeerRole` | the PEER's role: `Initiator = 1`, `Responder = 2` |
| Event enums | `SasPairingEventKind`, `SasPairingStepKind`, `SasPairingProtocolEvent`, `SasPairingEventReason`, `SasPairingDeadlineKind`, `SasPairingCancelState`, `SasPairingCancelReason`, each with the frozen native values |
| `SasPairingAuthorityStatus` | immutable `readonly record struct` (`State`, `RemainingOpportunities`) |
| `SasPairingAuthorityState` | `Ready`, `Busy`, `Exhausted` |
| `SasPairingStatus` | the 48 frozen native statuses with their exact values (`Ok = 0` … `Fatal = 900`) |
| `SasPairingInitializationException`, `SasPairingInitializationFailure` | loading or ABI verification failed |
| `SasPairingNativeException` | a native operation returned a non-zero status |
| `SasPairingContractException` | the native library reported an output that native ABI v1 makes impossible |

## Lifecycle

```csharp
using SasPairing;

// The native library is loaded once per process from this explicit absolute path; nothing is searched for.
using SasPairingRuntime runtime = SasPairingRuntime.Create(nativeLibraryPath);

// The scope is arbitrary binary data, passed byte for byte (not text, no terminator).
using SasPairingAuthority authority = runtime.RegisterAuthority(scope);
SasPairingAuthorityStatus status = authority.GetStatus(); // e.g. Ready with 1 to 10 remaining

using SasPairingHost host = authority.CreateHost();
```

The **first `Dispose` can throw** `SasPairingNativeException` when native cleanup reports a failure (for example `OwnershipUncertain`); the object is disposed all the same, and a second `Dispose` does nothing. There is no finalizer: dispose deterministically.

### Ownership and disposal cascade

A runtime owns its authorities, an authority its hosts, and a host its listener and connections, exactly as in the native library. Native parent cleanup already ends the children, so every `Dispose` is one native call:

- `Runtime.Dispose()`: one native destroy; every authority, host, connection, and result of it becomes disposed locally;
- `Authority.Dispose()`: one native release; every host and connection of it becomes disposed locally;
- `Host.Dispose()`: one native destroy, which also closes the listener and every connection (no separate detach or close call); the authority and its other hosts stay valid;
- `Connection.Dispose()`: one native connection close;
- `Result.Dispose()`: one native result destroy. A result belongs to the runtime, so no connection, host, or authority disposal ends it.

Disposing a child after its parent was disposed does nothing. Any operation on a disposed object throws `ObjectDisposedException` without entering the native library.

## Windows listener and network drive

```csharp
using System.Net;
using System.Net.Sockets;
using SasPairing;

// The APPLICATION creates, binds, and starts listening on the socket; the package never binds or listens.
using Socket listener = new(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
listener.Bind(new IPEndPoint(IPAddress.Loopback, port));
listener.Listen(16);

// FromSocket takes the socket: the token now owns the listening socket, and `listener` is closed.
using SasPairingWindowsListenerSocket token = SasPairingWindowsListenerSocket.FromSocket(listener);

// Attach hands the socket to the native library (token.IsTransferred becomes true). It drives nothing.
SasPairingBootstrap localBootstrap = new(applicationIdentity, keyAlgorithm, publicKey, sharedContext);
host.AttachWindowsListener(token, localBootstrap);

// ONE bounded synchronous native drive (it may wait up to about 250 ms). No loop runs in the background.
SasPairingDriveBatch batch = host.Drive();
foreach (SasPairingEvent evt in batch.Events)
{
    // ... process every event first ...
}

foreach (SasPairingEvent evt in batch.Events)
{
    if (evt.ShouldDisposeConnection)
    {
        evt.Connection?.Dispose();
    }
}

// A non-null batch.Failure means the owner loop failed closed after producing the events above:
// every connection is disposed, and the listener should be detached (or the host disposed).

host.DetachListener(); // cleanup: one native detach; every connection becomes disposed locally
```

- **The application binds and listens.** The package never binds, listens, chooses an address, interface, port, or backlog, configures a firewall, or discovers peers. The socket's address and port are not peer identity, authenticated identity, or trust. Trusted precondition: a valid Windows socket, already bound and listening, owned exclusively by the caller, never used for asynchronous operations, and not used or closed concurrently.
- **`FromSocket` takes the socket.** It moves the listening socket into a package-owned descriptor (`Socket.DuplicateAndClose` for this process) and closes your `Socket` object, so disposing it later does nothing and it must not be used again. Until the transfer, the socket is yours through the token: `token.Dispose()` closes it, also after a failed attach.
- **Attach transfers ownership.** Once `token.IsTransferred` is true the native library owns the socket (or has already closed it). The package invalidates the managed `SafeSocketHandle` of its own descriptor **without closing** the native-owned socket, never disposes it, and `token.Dispose()` does nothing: no managed disposal or finalizer can close the socket the native library owns. A failure before adoption (`InvalidBootstrap`, `ListenerAlreadyAttached`, `UnsupportedPlatform`, …) leaves `IsTransferred` false. `ListenerSetupFailed` and `Fatal` can come after adoption, with `IsTransferred` true. A token is offered to one attach at a time.
- **The Bootstrap is binary and validated natively.** Its four fields are bytes, copied at construction; the native core alone decides validity (`InvalidBootstrap`). `expected` (optional) is the exact expected peer Bootstrap, not a trust configuration.
- **`Drive()` is one bounded synchronous call**, and `RecheckAfterResume()` one deadline sweep, to be called only after your trusted code observed an OS resume (the package subscribes to no power event). There is no async driver, task, timer, thread, channel, or callback. All calls of one runtime tree are serialized, so a drive also delays the other calls of that tree for its bounded wait. Do not call `Drive()` on a UI thread, and never in a loop without a pause, such as `while (true) { host.Drive(); }`: a persistently ready socket can make it return at once. Choose a scheduling strategy that suits your UI or server.
- **Detach is cleanup.** `DetachListener()` makes one native detach (allowed after `Fatal` and after a contract violation, and repeatable); every connection becomes disposed locally; the host, authority, and accounting stay, so you can attach a new listener (replacement is detach, then attach).

### Network states

| `NetworkState` | Meaning |
|---|---|
| `Detached` | No listener: before any attach, after `DetachListener()`, after an adopted attach that failed setup, after the host or a parent was disposed |
| `Attached` | A listener is attached and accepts when driven |
| `ListenerDisabled` | The listening socket is gone (a `ListenerDisabled` event): nothing new is accepted, but **existing connections continue** and may still be driven. To replace the listener, detach it and attach a new one |
| `FailedClosed` | The owner loop failed closed: the listener and **every connection are gone** and every `SasPairingConnection` of the host is disposed. Detach the listener or dispose the host |

### Events and failures

A successful `Drive()` can return useful `Events` **and** a `Failure` at the same time: process every event, then act on the failure, which means the owner loop failed closed after or beside those events (`NetworkPollFailed`, `OwnershipUncertain`, `OwnerLoopClosed`, or `Fatal`, which also requires a process restart). A non-zero status of the call itself (for example `ListenerNotAttached` or `HandlesExhausted`) is thrown as `SasPairingNativeException` and returns no batch.

Every event of one native connection carries the same `SasPairingConnection` object. A `ConnectionClosed` event carries it already disposed. Event kinds, step kinds, protocol events, reasons, deadline kinds, and cancel states and reasons are operational metadata copied from the native core, never trust verdicts. `RequestId` is the exact 0–64 routing bytes, never text or an identity. `WritePending` only says that the connection still holds one outbound frame, which the native library writes on a later drive. `Run` is the run the event names (the same `SasPairingRun` object for every event and local action of one native run). `Result` is the local result the event delivered (see [PairingResult](#pairingresult-local-completion-only)); `HasResult` says that this endpoint completed one ceremony locally.

**`RUN_UNTRACKED`.** When `evt.RunUntracked` is true, the native core has a live run for which no run handle exists, so no trusted local ceremony action can ever target it. `evt.ShouldDisposeConnection` is then true: after processing the whole batch you SHOULD call `evt.Connection?.Dispose()`. The package never disposes it automatically.

## Runs and the trusted-local ceremony

```csharp
// Endpoint A starts an Initiator on an accepted connection. ONE native call: nothing is driven,
// authorized, exposed, or spent. The request ID is generated natively and not returned.
SasPairingLocalAction started = connection.StartInitiator(local, expected);
SasPairingRun run = started.Run!;            // the same object every later event of this run carries

host.Drive();                                // explicit: started.WritePending is true (START is retained)

// ... later, once the run is ready for exposure (for example after its ACCEPT event):
run.AuthorizeExposure();                     // records consent only: exposes, spends, sends nothing
SasPairingLocalAction exposed = run.ExposeKey(); // THE security-spending step (native accounting)
host.Drive();                                // explicit: exposed.WritePending is true

SasPairingSasPresentation? presentation = run.Presentation(); // read-only; null while no SAS is live
if (presentation is not null)
{
    // The application shows presentation.DecimalDisplay ("NNNN NNNN NNNN") to the user, who compares it
    // with the other device. Only if the user (or trusted local policy) chooses MATCH:
    run.ApproveSas(presentation.CeremonyIdentity);  // records MATCH only: emits nothing
    // Otherwise: run.RejectSas(presentation.CeremonyIdentity) or run.CancelSas(presentation.CeremonyIdentity).
}

// Still explicit, and only after MATCH:
run.EmitBootstrapMac();                      // does NOT emit INITIATOR_FINISH
host.Drive();

// Initiator only, after both approvals were authenticated (BOOTSTRAP_MAC_AUTHENTICATED events):
run.EmitInitiatorFinish();
host.Drive();                                // the native library writes the frames and confirms the final ACK itself
```

A Responder run appears on the other endpoint as `evt.Run` of a `StartAccepted` drive event; it makes the same explicit `AuthorizeExposure`, `ExposeKey`, `Presentation`, `ApproveSas`, and `EmitBootstrapMac` steps, but never `EmitInitiatorFinish` (`NotInitiator`).

- **Every step is explicit and is exactly one native call.** `AuthorizeExposure` does not expose the key; `ApproveSas` does not emit BOOTSTRAP_MAC; `EmitBootstrapMac` does not emit INITIATOR_FINISH. No method chains another step, drives the host, or retries. There is no convenience "approve and continue" call.
- **Two kinds of "write pending".** A `SasPairingNativeException` with `SasPairingStatus.WritePending` (205) means the requested action **did NOT run**: the connection still retains an earlier frame. Drive, then retry only if the application still wants to. `SasPairingLocalAction.WritePending == true` on a returned action means the action **did run** and its frame is retained until a later `Drive()`. The package keeps no write-pending state of its own and retries nothing.
- **One run object per native run.** A run is identified by its exact native run, never by its request ID: `StartInitiator(...).Run`, every later action's `Run`, and every drive event's `Run` for that native run are the same object. A locally started run's request ID is unknown until a drive event names the run; a new native run under a reused request ID is a new object, and the old one ends. There is no run handle or request-ID property.
- **`IsEnded` means "ending observed".** It becomes true after a reject, cancel, or deadline action, a drive event that makes the end visible (including a result), native `RunEnded`, or the end of the connection, listener, owner loop, host, or a parent. A run can also end without anything visible: `IsEnded` then stays false and the next call throws a `SasPairingNativeException` with `RunEnded` (204), after which it is true. False never proves the native run is still live. Any method of a run known to have ended throws `SasPairingRunEndedException` without a native call. A run is not disposable (ABI v1 has no run destroy).
- **The SAS display is comparison data only.** `DecimalDisplay` is exactly 14 ASCII characters, `NNNN NNNN NNNN`. It authenticates, approves, and trusts nothing by itself; the application or user owns the comparison and decides MATCH, MISMATCH, or CANCEL. The package never compares displays and never approves. Presentation is read-only (no state change, no deadline refresh, nothing sent) and reaches the native library also while a frame is retained. The raw SAS bytes are never exposed.
- **The ceremony identity binds the decision.** Pass `presentation.CeremonyIdentity` back **unchanged** to `ApproveSas`, `RejectSas`, or `CancelSas`. It is exactly 32 bytes (`Bytes`, read-only), compares by value, and cannot be constructed by callers. It is **not** a peer identity, request ID, run or connection identity, secret, or trust key. The package does not check whether an identity belongs to the run: the native core does, and a stale or foreign identity is refused with `CeremonyIdentityMismatch` (208) and changes nothing.
- **Exposure spends.** `ExposeKey` makes the native core consume the run's fresh authorization and reserve the authority's guard and one opportunity (`GetStatus()` then reports `Busy` until the run ends); nothing ever refunds it. The package keeps no budget or accounting of its own.
- **Reject and cancel end the run.** Their action has no `Run`, the run reports `IsEnded`, and `WritePending` may report a retained best-effort authenticated CANCEL (drive to write it). The connection stays open. A successful action may also report `SasPairingLocalEvent.Deadline` (with a `DeadlineKind`): the run's own deadline ended it first and the requested step did not happen.
- **No final-ACK API.** The native library writes every frame and confirms the Initiator's final ACK itself after the complete local write; there is nothing to call after a socket write, and no such method exists.
- **A result is local only.** An event with `HasResult` means only that THIS endpoint completed the ceremony locally: not that the peer completed, not a bilateral commit, and not stored trust. The result is `evt.Result` (see [PairingResult](#pairingresult-local-completion-only)).

| Failure of a ceremony call | Effect, then the exact `SasPairingNativeException` |
|---|---|
| `RunEnded` (204) | that run ends (later calls: `SasPairingRunEndedException`) |
| `ConnectionEnded` (405) | the connection is disposed locally (no native close) and every run of it ends |
| `OwnershipUncertain` (104), `OwnerLoopClosed` (403) | the host becomes `FailedClosed`: every connection disposed, every run ended |
| `Fatal` (900) | process fatal latch; no run or connection is ended by it; cleanup still works |
| any other (`WritePending`, `MissingAuthorization`, `Busy`, `Exhausted`, `CeremonyIdentityMismatch`, `NotLocallyApproved`, `NotInitiator`, …) | nothing changes |

## PairingResult: local completion only

> **A result is THIS endpoint's local verified completion of one ceremony, and nothing more.** It does NOT prove that the peer completed, received the final message, holds a result of its own, or stored anything, and it is not an established session, a committed pair, bilateral success, or trust. Either endpoint may be the only one holding a result. The package trusts, persists, and enrolls nothing: what to do with the data is the application's policy.

```csharp
SasPairingDriveBatch batch = host.Drive();
foreach (SasPairingEvent evt in batch.Events)
{
    if (evt.Result is { } result)
    {
        SasPairingResultData data = result.Read();

        // Application policy may inspect the authenticated data here.
        // This is LOCAL completion only: it says nothing about the peer.

        result.Dispose();
    }
}
```

- **Delivered once, by its event.** `evt.Result` is the one `SasPairingResult` of that native result (`evt.HasResult` is exactly `evt.Result is not null`). It is never returned anywhere else: there is no polling, lookup, or list of results, so keep the object if you need it later. A native result handle delivered twice is a contract violation, also after the first result was disposed.
- **The runtime owns it.** A result does not belong to the connection, run, host, or authority that produced it. It stays open and readable after `Connection.Dispose()`, a `ConnectionClosed` event, `DetachListener()`, an owner-loop failure, `Host.Dispose()`, `Authority.Dispose()`, and `Fatal`. Only `result.Dispose()` or `runtime.Dispose()` ends it.
- **Close it explicitly.** `result.Dispose()` makes exactly one native destroy; the result is disposed whatever the native status (a failure is thrown once, never retried), and a second `Dispose` does nothing. `runtime.Dispose()` makes no destroy call per result: the runtime's one native destroy drops every result, and each open `SasPairingResult` becomes disposed locally. There is no finalizer.
- **Reading is a fresh, coherent snapshot.** `result.Read()` makes one native info read and exactly one copy of each byte field at the length that info reported; there is no size query, negotiation, or retry, and nothing is cached. A failed read returns nothing and leaves the result open (you can still dispose it). `Read()` on a disposed result throws `ObjectDisposedException` without a native call.
- **Snapshots are detached.** `SasPairingResultData` is plain managed data: it stays valid after `result.Dispose()` and after `runtime.Dispose()`. Every byte field is the snapshot's own copy, exposed as a read-only `ReadOnlySpan<byte>`; nothing is decoded, parsed, trimmed, or terminated.
- **After `Fatal`**, normal pairing work is refused, but existing results can still be read and disposed: the frozen native ABI allows that data access because it never enters the pairing core. This recovers nothing; new pairing work still needs an OS process restart.
- **After a contract violation**, `Read()` is refused locally (`SasPairingContractException`): the package no longer trusts successful native output. `Dispose()` still runs, so owned native resources can always be released.

| `SasPairingResultData` | Meaning |
|---|---|
| `CeremonyIdentity` | The 32-byte transcript-derived ceremony identity, the same `SasPairingCeremonyIdentity` value the SAS presentation of this ceremony carried. Not a peer identity, request ID, handle, or trust key |
| `PeerRole` | The PEER's role (`SasPairingPeerRole.Initiator = 1` or `Responder = 2`), never this endpoint's: an Initiator's result reports `Responder` |
| `ProfileVersion` | The protocol profile version (`uint`), exactly as reported: data, not a compatibility or trust decision |
| `RequestId` | The exact routing and correlation bytes (at most 64): never text, a GUID, or an identity |
| `AuthenticatedPeerBootstrap` | The exact canonical Bootstrap frame (at most 16,384 bytes) the peer supplied in this ceremony under the approved SAS flow. Not parsed, split, re-encoded, enrolled, or trusted by the package |
| `AuthenticatedSharedContext` | The authenticated opaque shared-context bytes (at most 8,192; possibly empty), never interpreted |
| `ProfileIdentifier` | The exact profile identifier bytes (the frozen profile's 38 bytes); not decoded, compared, or used to select anything |

A length the native library reports above these source-proven bounds is impossible output: the read fails with `SasPairingContractException` before any buffer is allocated.

## Errors

| Exception | Meaning |
|---|---|
| `SasPairingInitializationException` | Loading or ABI verification of the native library failed (`Failure`: one of seven categories). No native status exists. When `ProcessRestartRequired` is false (`UnsupportedPointerWidth`, `InvalidLibraryPath`, `OpenFailed`) nothing was loaded and a later `Create` may succeed once the cause is fixed. When it is true (`MissingSymbol`, `BindingFailed`, `AbiVersionQueryFailed`, `AbiVersionMismatch`) an image is loaded and never replaced: correct the library and restart the OS process |
| `SasPairingNativeException` | A native operation returned a non-zero status: `Operation`, the exact `StatusCode`, and `KnownStatus` (null for a status this version does not name; an unknown status is always a failure). A second live `Create` gives `AlreadyInitialized` |
| `ObjectDisposedException` | Local use of a disposed runtime, authority, host, connection, listener token, or result; no native call is made |
| `SasPairingRunEndedException` | A method of a run already known to have ended (`Operation`); no native call is made. The first native `RunEnded` is a `SasPairingNativeException` (204) instead |
| `InvalidOperationException` | A listener token that was already transferred, or that another attach is using, was offered again; no native call is made |
| `PlatformNotSupportedException` | `FromSocket` off Windows; the socket was not touched |
| `SasPairingContractException` | The native library reported an output that native ABI v1 makes impossible (for example a zero handle, an impossible authority status, an impossible socket slot, an impossible drive event, or a result field longer than its info reported). Normal operations and result reads are refused for the rest of the process; cleanup (including `Result.Dispose`) still runs; restart the OS process |

**Fatal.** When a native operation returns `SasPairingStatus.Fatal` (900), or a drive reports it as its `Failure`, the native state of the process is permanently fatal: the wrapper refuses every later normal operation (`Create`, `RegisterAuthority`, `GetStatus`, `CreateHost`, `AttachWindowsListener`, `Drive`, `RecheckAfterResume`, `StartInitiator`, and every run step including `Presentation`) without entering the native library, with `ProcessRestartRequired` true. Cleanup (`Dispose`, `DetachListener`, `Connection.Dispose`, `Result.Dispose`) still performs its native call, and existing results stay readable (`Result.Read`: data access, not pairing work). The only recovery is restarting the OS process: there is no reset, reload, or re-initialize, and disposing and re-creating the runtime does not clear it.

**Statuses are not trust verdicts.** A status describes the outcome of one operation. It never classifies a peer as trusted, malicious, attacking, or compromised.

### A runtime is not a security reset

Disposing a runtime and creating another reuses the same loaded native library and the same process state. It does **not** reset authority opportunity accounting, START limiting, or any other same-process security state, and it is not a fresh security session: only an OS process restart is. Likewise, releasing an authority and registering the same scope again continues its opportunity budget, and replacing a listener resets nothing.

### Platform scope

- **Windows (x64):** the lifecycle, the listener and network path, the trusted-local ceremony, and the result API work through the public API (the Windows TCP carrier the native core defines).
- **Linux (x64):** the package builds, the ABI v1 library loads, and a runtime can be created, but authority registration fails closed with `UnsupportedPlatform` and `SasPairingWindowsListenerSocket.FromSocket` throws `PlatformNotSupportedException`. The network, ceremony, and result wrappers' fake and FFI tests run there; no result can be produced, and Linux pairing is not supported.

## Installation (experimental CI artifacts)

> **Nothing is published to nuget.org** or any other package feed, and there is no GitHub Release or tag. These are experimental, pre-alpha, unsigned CI artifacts with finite retention (90 days); they are not a production release.

Each push of a commit that the `.NET package` workflow builds and tests on Windows uploads two GitHub Actions artifacts, named with the full 40-hex-digit commit SHA ([P9-D-006](../docs/p9-dotnet-package/decisions.md#p9-d-006--net-managed-package-native-artifact-distribution-and-p9-closure)):

| Artifact | Contents |
|---|---|
| `sas-pairing-dotnet-nuget-<commit>` | `SasPairing.0.1.0-dev.1.nupkg` (the managed `net10.0` assembly, its XML documentation, and this README; **no native library**), `ARTIFACT-MANIFEST.json`, `SHA256SUMS.txt`, `README.md` |
| `sas-pairing-dotnet-windows-x64-abi1-<commit>` | `sas_pairing_core.dll` (Windows x64, native ABI v1, 25 exports, **unsigned**), `ARTIFACT-MANIFEST.json`, `SHA256SUMS.txt`, `README.md`, `LICENSE-MIT`, `LICENSE-APACHE`, `THIRD-PARTY-NOTICES.md`, `sas_pairing.h`, `abi-v1-manifest.md` |

1. Download `sas-pairing-dotnet-nuget-<commit>` from the repository's Actions run of that commit (a GitHub sign-in is required).
2. Download `sas-pairing-dotnet-windows-x64-abi1-<same commit>` from the **same** run. Use both artifacts of the **same exact commit**; never mix a package and a native library of different commits.
3. Verify both: each `ARTIFACT-MANIFEST.json` names that commit, and `sha256sum -c SHA256SUMS.txt` (or PowerShell `Get-FileHash -Algorithm SHA256`) matches. From a checkout of that commit, `python tooling/package_dotnet_nuget.py verify --bundle <dir> --git-sha <commit>` and `python tooling/package_dotnet_native.py verify --bundle <dir> --git-sha <commit>` check everything. **A checksum is integrity metadata, not a signature**: it does not prove who built the files, and the package and the DLL are not signed.
4. Reference the local package: add the extracted `sas-pairing-dotnet-nuget-<commit>` directory as a local package source (for example in a `nuget.config`), then `<PackageReference Include="SasPairing" Version="0.1.0-dev.1" />`. Every commit packs a different file under the same version, and NuGet caches a restored version: clear the cached `saspairing/0.1.0-dev.1` (or use a project-local `globalPackagesFolder`) when you switch commits.
5. Extract the native bundle once, to a location your application controls.
6. Pass the **absolute path** of its `sas_pairing_core.dll` to `SasPairingRuntime.Create(nativeLibraryPath)`. The package never searches `PATH`, the application, current, or package directory, or `runtimes/`, and never downloads anything.
7. Keep that one image resident: one native image per process, never replaced or reloaded while the process runs; `SasPairingStatus.Fatal` requires an OS process restart.

Windows x64 is the only pairing distribution target. The package can be referenced on other platforms, but no Linux, macOS, mobile, ARM64, or 32-bit native artifact is distributed and pairing there is not supported.

## Build and test

Requires the .NET 10 SDK pinned in [`global.json`](global.json) (`10.0.401`, later 10.0.4xx patches accepted). CI builds, tests, and packs the **Release** configuration. From `dotnet/`:

```bash
dotnet restore --locked-mode
```

```bash
dotnet build -c Release --no-restore -warnaserror
```

```bash
dotnet test -c Release --no-build
```

```bash
dotnet format --verify-no-changes
```

```bash
dotnet pack src/SasPairing/SasPairing.csproj -c Release --no-build --no-restore -o ../dist/pack
```

The real-native tests need the native library built from the same commit (`cargo build --manifest-path core/Cargo.toml --release --features native-abi` from the repository root) and its **absolute** path in `SAS_PAIRING_NATIVE_LIBRARY` (`core/target/release/sas_pairing_core.dll` on Windows, `libsas_pairing_core.so` on Linux; in Windows CI, the staged distribution copy). Without it they are skipped locally; under CI (`CI=true`) a missing library fails the run. The package-consumer smoke [`tests/SasPairing.PackageSmoke`](tests/SasPairing.PackageSmoke/Program.cs) is not part of the solution: it restores the staged package from `dist/sas-pairing-dotnet-nuget` only (see the `.NET package` workflow).
