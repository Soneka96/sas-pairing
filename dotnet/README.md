# .NET binding

> **Experimental, pre-alpha, not production-ready.** Not production-security approved, not audited, and not formally verified. Do not use it to protect production systems.

`SasPairing` (package ID, namespace, and assembly; version `0.1.0-dev.1`, `net10.0`) is the planned idiomatic .NET wrapper over the shared native security core, built in P9 ([P9 package](../docs/p9-dotnet-package/README.md), [decisions](../docs/p9-dotnet-package/decisions.md)). It binds the frozen [native ABI v1](../docs/p7-native-abi/abi-v1-manifest.md) and implements no protocol or cryptography itself: the Rust core is the only protocol implementation.

## Current state (P9.1)

- The P9.1 foundation exists: the solution [`SasPairing.sln`](SasPairing.sln), the library [`src/SasPairing`](src/SasPairing/SasPairing.csproj), and its tests [`tests/SasPairing.Tests`](tests/SasPairing.Tests/SasPairing.Tests.csproj).
- The ABI v1 binding and its loader exist **internally only**: the exact constants, records, and 25-export function table, and a loader that opens one native library from an explicit absolute path, requires 64-bit pointers, all 25 exports, and ABI version 1, and keeps the library loaded until the process exits ([P9-D-001](../docs/p9-dotnet-package/decisions.md#p9-d-001--net-abi-v1-binding-and-loader-architecture)).
- **No high-level pairing API exists yet.** The assembly exports no public type. The runtime, authority, and host lifecycle wrapper is P9.2; networking, ceremony control, and results follow in P9.3–P9.5.
- **No NuGet package exists.** The project is not packable and nothing is published; P9.6 decides distribution. No native binary is committed or bundled.
- **Windows is the only pairing-networking platform** (the Windows TCP carrier of the native core). Linux CI only verifies that the same ABI v1 library loads, exports its 25 symbols, and reports version 1, and that the loader fails closed; that is not Linux pairing support.

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
