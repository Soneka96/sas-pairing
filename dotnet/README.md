# .NET binding

The planned NuGet package and namespace are `SasPairing`, intended for .NET and C# applications. It will provide an idiomatic API over the shared native security core.

The package does not exist yet. No independent cryptographic implementation or P/Invoke binding will be added before the core exposes a reviewed stable native ABI.

The native boundary it will bind is now frozen as [native ABI v1](../docs/p7-native-abi/abi-v1-manifest.md) ([P7 final closure](../docs/p7-native-abi/final-closure.md)); the wrapper obligations are in [ABI contract §21](../docs/p7-native-abi/abi-contract.md#21-wrapper-handoff-p8-p9). The P/Invoke binding is P9 work and has not started. No independent cryptographic implementation will be added.
