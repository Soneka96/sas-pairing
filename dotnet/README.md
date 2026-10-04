# .NET binding

> **Experimental, pre-alpha, not production-ready.** Not production-security approved, not audited, and not formally verified. Do not use it to protect production systems.

`SasPairing` (package ID, namespace, and assembly; version `0.1.0-dev.1`, `net10.0`) is the planned idiomatic .NET wrapper over the shared native security core, built in P9 ([P9 package](../docs/p9-dotnet-package/README.md), [decisions](../docs/p9-dotnet-package/decisions.md)). It binds the frozen [native ABI v1](../docs/p7-native-abi/abi-v1-manifest.md) and implements no protocol or cryptography itself: the Rust core is the only protocol implementation.

## Current state (P9.2)

- The P9.1 foundation exists: the solution [`SasPairing.sln`](SasPairing.sln), the library [`src/SasPairing`](src/SasPairing/SasPairing.csproj), and its tests [`tests/SasPairing.Tests`](tests/SasPairing.Tests/SasPairing.Tests.csproj). The ABI v1 binding and its loader stay **internal**: the exact constants, records, and 25-export function table, and a loader that opens one native library from an explicit absolute path, requires 64-bit pointers, all 25 exports, and ABI version 1, and keeps the library loaded until the process exits ([P9-D-001](../docs/p9-dotnet-package/decisions.md#p9-d-001--net-abi-v1-binding-and-loader-architecture)).
- **P9.2 adds the first public API: the runtime, authority, and host lifecycle** and its status and error model ([P9-D-002](../docs/p9-dotnet-package/decisions.md#p9-d-002--net-lifecycle-ownership-public-errors-and-fail-closed-state)). Nothing else is public: no handle, pointer, native record, or loader.
- **No pairing API exists yet.** Listener ownership and the network driver (P9.3), runs, ceremony control, and SAS presentation (P9.4), and results (P9.5) follow. There is no `Bootstrap`, connection, run, or result type yet.
- **No NuGet package exists.** The project is not packable and nothing is published; P9.6 decides distribution. No native binary is committed or bundled.

## Lifecycle API

| Type | Members |
|---|---|
| `SasPairingRuntime : IDisposable` | `static Create(string nativeLibraryPath)`, `RegisterAuthority(ReadOnlySpan<byte> scope)`, `IsDisposed`, `Dispose()` |
| `SasPairingAuthority : IDisposable` | `GetStatus()`, `CreateHost()`, `IsDisposed`, `Dispose()` |
| `SasPairingHost : IDisposable` | `IsDisposed`, `Dispose()` (P9.3 adds the listener and network operations) |
| `SasPairingAuthorityStatus` | immutable `readonly record struct` (`State`, `RemainingOpportunities`) |
| `SasPairingAuthorityState` | `Ready`, `Busy`, `Exhausted` |
| `SasPairingStatus` | the 48 frozen native statuses with their exact values (`Ok = 0` … `Fatal = 900`) |
| `SasPairingInitializationException`, `SasPairingInitializationFailure` | loading or ABI verification failed |
| `SasPairingNativeException` | a native operation returned a non-zero status |
| `SasPairingContractException` | the native library reported success with an impossible output |

```csharp
using SasPairing;

// The native library is loaded once per process from this explicit absolute path; nothing is searched for.
SasPairingRuntime runtime = SasPairingRuntime.Create(nativeLibraryPath);
try
{
    // The scope is arbitrary binary data, passed byte for byte (not text, no terminator).
    SasPairingAuthority authority = runtime.RegisterAuthority(scope);
    try
    {
        SasPairingAuthorityStatus status = authority.GetStatus(); // e.g. Ready with 1 to 10 remaining

        SasPairingHost host = authority.CreateHost();
        try
        {
            // P9.3 adds the listener and network APIs.
        }
        finally
        {
            host.Dispose();
        }
    }
    finally
    {
        authority.Dispose();
    }
}
finally
{
    runtime.Dispose();
}
```

`using` declarations are the idiomatic shorthand (`using SasPairingRuntime runtime = SasPairingRuntime.Create(path);`). Note that the **first `Dispose` can throw** `SasPairingNativeException` when native cleanup reports a failure (for example `OwnershipUncertain`); the object is disposed all the same, and a second `Dispose` does nothing. There is no finalizer: dispose deterministically.

### Ownership and disposal cascade

A runtime owns its authorities and an authority owns its hosts, exactly as in the native library. Native parent cleanup already destroys the children, so:

- `Runtime.Dispose()` makes one native destroy call; every authority and host of it becomes disposed locally, with no native call of its own;
- `Authority.Dispose()` makes one native release call; every host of it becomes disposed locally;
- `Host.Dispose()` makes one native destroy call; the authority and its other hosts stay valid.

Disposing a child after its parent was disposed does nothing. Any operation on a disposed object throws `ObjectDisposedException` without entering the native library.

### Errors

| Exception | Meaning |
|---|---|
| `SasPairingInitializationException` | Loading or ABI verification of the native library failed (`Failure`: one of seven categories). No native status exists. When `ProcessRestartRequired` is false (`UnsupportedPointerWidth`, `InvalidLibraryPath`, `OpenFailed`) nothing was loaded and a later `Create` may succeed once the cause is fixed. When it is true (`MissingSymbol`, `BindingFailed`, `AbiVersionQueryFailed`, `AbiVersionMismatch`) an image is loaded and never replaced: correct the library and restart the OS process |
| `SasPairingNativeException` | A native operation returned a non-zero status: `Operation`, the exact `StatusCode`, and `KnownStatus` (null for a status this version does not name; an unknown status is always a failure). A second live `Create` gives `AlreadyInitialized` |
| `ObjectDisposedException` | Local use of a disposed runtime, authority, or host; no native call is made |
| `SasPairingContractException` | The native library reported success with an output that native ABI v1 makes impossible (a zero handle, or a status other than `Ready` 1–10, `Busy` 0, `Exhausted` 0). Normal operations are refused for the rest of the process; cleanup still runs; restart the OS process |

**Fatal.** When a native operation returns `SasPairingStatus.Fatal` (900), the native state of the process is permanently fatal: the wrapper refuses every later normal operation (`Create`, `RegisterAuthority`, `GetStatus`, `CreateHost`) without entering the native library, with `ProcessRestartRequired` true. `Dispose` still performs its native cleanup. The only recovery is restarting the OS process: there is no reset, reload, or re-initialize, and disposing and re-creating the runtime does not clear it.

**Statuses are not trust verdicts.** A status describes the outcome of one operation. It never classifies a peer as trusted, malicious, attacking, or compromised.

### A runtime is not a security reset

Disposing a runtime and creating another reuses the same loaded native library and the same process state. It does **not** reset authority opportunity accounting, START limiting, or any other same-process security state, and it is not a fresh security session: only an OS process restart is. Likewise, releasing an authority and registering the same scope again continues its opportunity budget.

### Platform scope

- **Windows (x64):** the lifecycle works; pairing (P9.3–P9.5) will be Windows-only, as the native core defines (the Windows TCP carrier).
- **Linux (x64):** the ABI v1 library loads and a runtime can be created, but authority registration fails closed with `UnsupportedPlatform`. Linux pairing is not supported.

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
