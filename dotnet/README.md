# .NET binding

> **Experimental, pre-alpha, not production-ready.** Not production-security approved, not audited, and not formally verified. Do not use it to protect production systems.

`SasPairing` (package ID, namespace, and assembly; version `0.1.0-dev.1`, `net10.0`) is the planned idiomatic .NET wrapper over the shared native security core, built in P9 ([P9 package](../docs/p9-dotnet-package/README.md), [decisions](../docs/p9-dotnet-package/decisions.md)). It binds the frozen [native ABI v1](../docs/p7-native-abi/abi-v1-manifest.md) and implements no protocol or cryptography itself: the Rust core is the only protocol implementation.

## Current state (P9.3)

- The P9.1 foundation exists: the solution [`SasPairing.sln`](SasPairing.sln), the library [`src/SasPairing`](src/SasPairing/SasPairing.csproj), and its tests [`tests/SasPairing.Tests`](tests/SasPairing.Tests/SasPairing.Tests.csproj). The ABI v1 binding and its loader stay **internal**: the exact constants, records, and 25-export function table, and a loader that opens one native library from an explicit absolute path, requires 64-bit pointers, all 25 exports, and ABI version 1, and keeps the library loaded until the process exits ([P9-D-001](../docs/p9-dotnet-package/decisions.md#p9-d-001--net-abi-v1-binding-and-loader-architecture)).
- **P9.2: the runtime, authority, and host lifecycle** and its status and error model ([P9-D-002](../docs/p9-dotnet-package/decisions.md#p9-d-002--net-lifecycle-ownership-public-errors-and-fail-closed-state)).
- **P9.3: the Windows listener handoff and the cooperative network driver** ([P9-D-003](../docs/p9-dotnet-package/decisions.md#p9-d-003--net-windows-listener-cooperative-drive-event-and-connection-ownership)): the binary `SasPairingBootstrap`, the one-use listener token, attach and detach, one bounded `Drive()` and one `RecheckAfterResume()`, drive events, and `IDisposable` connections. Nothing native is public: no handle, socket value, pointer, native record, or loader.
- **No ceremony or result API exists yet.** Runs, the trusted-local ceremony steps, and SAS presentation (P9.4) and results (P9.5) follow; until then an accepted connection can be driven and closed, but no pairing ceremony can be completed through .NET.
- **No NuGet package exists.** The project is not packable and nothing is published; P9.6 decides distribution. No native binary is committed or bundled.

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
| `SasPairingEvent` | `Kind`, `Connection`, `StepKind`, `ProtocolEvent`, `Reason`, `DeadlineKind`, `CancelState`, `CancelReason`, `WritePending`, `RunUntracked`, `RequestId` (exact bytes), `HasTrackedRun`, `HasResult`, `ShouldDisposeConnection` |
| `SasPairingConnection : IDisposable` | `IsDisposed`, `Dispose()` |
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

- `Runtime.Dispose()`: one native destroy; every authority, host, and connection of it becomes disposed locally;
- `Authority.Dispose()`: one native release; every host and connection of it becomes disposed locally;
- `Host.Dispose()`: one native destroy, which also closes the listener and every connection (no separate detach or close call); the authority and its other hosts stay valid;
- `Connection.Dispose()`: one native connection close.

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

Every event of one native connection carries the same `SasPairingConnection` object. A `ConnectionClosed` event carries it already disposed. Event kinds, step kinds, protocol events, reasons, deadline kinds, and cancel states and reasons are operational metadata copied from the native core, never trust verdicts. `RequestId` is the exact 0–64 routing bytes, never text or an identity. `WritePending` only says that the connection still holds one outbound frame, which the native library writes on a later drive. `HasResult` says that this endpoint completed one ceremony locally; the result itself is held by the runtime until P9.5 exposes it.

**`RUN_UNTRACKED`.** When `evt.RunUntracked` is true, the native core has a live run for which no run handle exists, so no trusted local ceremony action can ever target it. `evt.ShouldDisposeConnection` is then true: after processing the whole batch you SHOULD call `evt.Connection?.Dispose()`. The package never disposes it automatically.

## Errors

| Exception | Meaning |
|---|---|
| `SasPairingInitializationException` | Loading or ABI verification of the native library failed (`Failure`: one of seven categories). No native status exists. When `ProcessRestartRequired` is false (`UnsupportedPointerWidth`, `InvalidLibraryPath`, `OpenFailed`) nothing was loaded and a later `Create` may succeed once the cause is fixed. When it is true (`MissingSymbol`, `BindingFailed`, `AbiVersionQueryFailed`, `AbiVersionMismatch`) an image is loaded and never replaced: correct the library and restart the OS process |
| `SasPairingNativeException` | A native operation returned a non-zero status: `Operation`, the exact `StatusCode`, and `KnownStatus` (null for a status this version does not name; an unknown status is always a failure). A second live `Create` gives `AlreadyInitialized` |
| `ObjectDisposedException` | Local use of a disposed runtime, authority, host, or listener token; no native call is made |
| `InvalidOperationException` | A listener token that was already transferred, or that another attach is using, was offered again; no native call is made |
| `PlatformNotSupportedException` | `FromSocket` off Windows; the socket was not touched |
| `SasPairingContractException` | The native library reported an output that native ABI v1 makes impossible (for example a zero handle, an impossible authority status, an impossible socket slot, or an impossible drive event). Normal operations are refused for the rest of the process; cleanup still runs; restart the OS process |

**Fatal.** When a native operation returns `SasPairingStatus.Fatal` (900), or a drive reports it as its `Failure`, the native state of the process is permanently fatal: the wrapper refuses every later normal operation (`Create`, `RegisterAuthority`, `GetStatus`, `CreateHost`, `AttachWindowsListener`, `Drive`, `RecheckAfterResume`) without entering the native library, with `ProcessRestartRequired` true. Cleanup (`Dispose`, `DetachListener`, `Connection.Dispose`) still performs its native call. The only recovery is restarting the OS process: there is no reset, reload, or re-initialize, and disposing and re-creating the runtime does not clear it.

**Statuses are not trust verdicts.** A status describes the outcome of one operation. It never classifies a peer as trusted, malicious, attacking, or compromised.

### A runtime is not a security reset

Disposing a runtime and creating another reuses the same loaded native library and the same process state. It does **not** reset authority opportunity accounting, START limiting, or any other same-process security state, and it is not a fresh security session: only an OS process restart is. Likewise, releasing an authority and registering the same scope again continues its opportunity budget, and replacing a listener resets nothing.

### Platform scope

- **Windows (x64):** the lifecycle and the listener and network path work through the public API (the Windows TCP carrier the native core defines). Ceremony control and results follow in P9.4 and P9.5.
- **Linux (x64):** the package builds, the ABI v1 library loads, and a runtime can be created, but authority registration fails closed with `UnsupportedPlatform` and `SasPairingWindowsListenerSocket.FromSocket` throws `PlatformNotSupportedException`. The network wrapper's fake and FFI tests run there; Linux pairing is not supported.

## Build and test

Requires the .NET 10 SDK pinned in [`global.json`](global.json) (`10.0.401`, later 10.0.4xx patches accepted). From `dotnet/`:

```bash
dotnet restore --locked-mode
```

```bash
dotnet build --no-restore -warnaserror
```

```bash
dotnet test --no-build
```

```bash
dotnet format --verify-no-changes
```

The real-native tests need the native library built from the same commit (`cargo build --manifest-path core/Cargo.toml --release --features native-abi` from the repository root) and its **absolute** path in `SAS_PAIRING_NATIVE_LIBRARY` (`core/target/release/sas_pairing_core.dll` on Windows, `libsas_pairing_core.so` on Linux). Without it they are skipped locally; under CI (`CI=true`) a missing library fails the run.
