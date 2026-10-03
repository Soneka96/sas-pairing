# Dart binding

The planned Dart package is `sas_pairing`, intended for Dart and Flutter applications. It will offer an idiomatic API over the shared native security core.

The package does not exist yet. No independent cryptographic implementation or FFI binding will be added before the core exposes a reviewed native API.

The native boundary it will bind is now frozen as [native ABI v1](../docs/p7-native-abi/abi-v1-manifest.md) ([P7 final closure](../docs/p7-native-abi/final-closure.md)); the wrapper obligations are in [ABI contract §21](../docs/p7-native-abi/abi-contract.md#21-wrapper-handoff-p8-p9). The FFI binding is P8 work and has not started. No independent cryptographic implementation will be added.
