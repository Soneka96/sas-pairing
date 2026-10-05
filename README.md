# sas-pairing

**Pre-alpha · experimental P4 native security core complete · P5 security review complete · P6 remediation complete, experimental protocol candidate frozen · P7 native ABI v1 frozen · P8 experimental Dart package complete · P9 experimental .NET package complete · P10 consumer integration in progress (P10.1 complete) · not production-ready**

`sas-pairing` is a language-neutral project for human-authenticated pairing between two devices. The intended experience is that each device displays the same short authentication string (SAS), and the user compares the values:

```text
Device A:  4442 5768 1708
Device B:  4442 5768 1708

If the values match, approve pairing.
```

The value is compared on both devices. It is not typed and is not a password. The owner selected the vodozemac-based remote profile for experimental implementation, and that profile now has an implemented experimental native Rust security core, including the pairing ceremony and its P4 resource and lifecycle controls. Its current conformance evidence is closed in [P4 conformance closure](docs/p4-conformance-closure.md). The internal, AI-assisted P5 implementation and protocol security review is complete ([final synthesis](docs/p5-security-review/final-synthesis.md)); P6 remediated or dispositioned its open findings and froze the experimental protocol candidate for the next phase, native ABI work ([P6 final closure](docs/p6-remediation/final-closure.md)). The freeze is not production approval, and nothing is approved for production. No qualified professional audit or formal verification is claimed. **Do not use this project to protect production systems.**

## Intended properties

The design aims to support active man-in-the-middle resistant initial pairing, human comparison instead of password entry, and authentication and binding of consumer-supplied application context by a successful ceremony. The selected experimental remote profile uses three decimal groups of 13 bits each (39 displayed bits); historical presentation research is not the selected format. Context values are input, not trusted facts merely because an application supplied them; the selected profile defines what it authenticates and binds. The protocol is language-neutral, with one security core, Dart and .NET bindings, deterministic test vectors, and an explicit threat model.

These are design goals, not current capabilities or security claims. The example shows the selected experimental representation; it does not indicate implementation status or production approval.

## Project status

This repository is in pre-alpha. The owner selected the vodozemac-based remote pairing profile for experimental Rust implementation. Its security argument remains conditional, review was AI-assisted, and no qualified professional audit or formal verification is claimed. This selection does not establish production security or approve production use. The P4 experimental native security core implementation is complete, the P5 review is complete, and P6 review remediation is complete with the experimental protocol candidate frozen; P7 (native ABI) is complete: native ABI v1, the language-neutral C boundary for the future Dart and .NET wrappers, is frozen ([P7 final closure](docs/p7-native-abi/final-closure.md)); P8 (Dart package) is complete ([P8 final closure](docs/p8-dart-package/final-closure.md)): the experimental Dart wrapper over the frozen ABI v1 provides the runtime / authority / host lifecycle, the Windows listener handoff and cooperative network driver, run and ceremony control with SAS presentation, and local `PairingResult` access, and the Windows x64 native library is distributed as an experimental, unsigned CI artifact per exact commit (not a release and not published to pub.dev); P9 (.NET package) is complete ([P9 final closure](docs/p9-dotnet-package/final-closure.md)): the experimental `net10.0` wrapper `SasPairing` provides the same lifecycle, Windows network driver, ceremony control with SAS presentation, and local `PairingResult` access, distributed as an experimental NuGet-format package (`SasPairing.0.1.0-dev.1.nupkg`, with no native library inside) and a separate Windows x64 native library, both unsigned CI artifacts per exact commit (not a release and not published to nuget.org). P4–P9 are complete as experimental development phases; P10 (consumer integration / DovahLink example) is in progress: P10.1, the consumer boundary and ABI-v1 / portability assessment, is complete ([P10 package](docs/p10-consumer-integration/README.md)), and P10.2 is next after independent review. P10 integrates on Windows only; Android is a later milestone (P11) and is not supported. The ABI freeze is an interface freeze, and completing P8 and P9 is a development milestone; neither is a security approval. Production-security approval is not granted. Production use and release are not approved. See [protocol status](docs/protocol-status.md) for current decisions and required gates.

## Architecture

The security-sensitive implementation lives once in a Rust core; the experimental P4 native core exists in [`core/`](core/README.md). The experimental Dart package ([`dart/`](dart/README.md), P8) is an idiomatic wrapper around that core, and the experimental .NET package ([`dotnet/`](dotnet/README.md), P9) is another; neither implements production cryptography independently. The core is intended to remain application-neutral. See [architecture](docs/architecture.md).

## Consumer packages

Both bindings sit on the frozen [native ABI v1](docs/p7-native-abi/abi-v1-manifest.md) (P7).

- **Dart / Flutter:** implemented experimentally in P8 as the pure-Dart package [`sas_pairing`](dart/README.md) (0.1.0-dev.1, not published), used from the repository at one exact commit together with that commit's Windows x64 native CI artifact. Pairing works on Windows x64 only.
- **.NET / C#:** implemented experimentally in P9 as [`SasPairing`](dotnet/README.md) (0.1.0-dev.1, `net10.0`): the native lifecycle, the Windows listener and cooperative network driver, runs with explicit trusted-local ceremony control and SAS presentation, and runtime-owned PairingResults presented as local completion only. It is distributed per exact commit as the experimental CI artifact `sas-pairing-dotnet-nuget-<commit>` (a NuGet-format package, not published to nuget.org, containing no native library) together with the separate Windows x64 native artifact `sas-pairing-dotnet-windows-x64-abi1-<commit>`, loaded from an explicit absolute path. Pairing works on Windows x64 only.

## Origin

`sas-pairing` was originally created to solve the first-device trust problem in [DovahLink](https://github.com/Soneka96/DovahLink), a Skyrim companion platform. It is developed as a standalone, reusable library so other applications with similar pairing requirements can use and review the same security core.

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution expectations and [SECURITY.md](SECURITY.md) for responsible disclosure guidance. Security design and protocol changes need clear rationale and careful review.

## License

SPDX license expression: `MIT OR Apache-2.0`.

Licensed under either the Apache License, Version 2.0 or the MIT license, at your option. See [LICENSE-APACHE](LICENSE-APACHE) and [LICENSE-MIT](LICENSE-MIT).
