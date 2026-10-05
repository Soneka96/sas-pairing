# Changelog

No production release has been made: there is no stable release, GitHub Release, tag, or published package. Changes are tracked in the repository history.

P8 defined an experimental distribution process for the Dart package's native library ([P8-D-006](docs/p8-dart-package/decisions.md#p8-d-006--dart-native-artifact-distribution-and-p8-final-closure)): each push of a commit that CI builds and tests produces the unsigned, pre-alpha GitHub Actions artifact `sas-pairing-dart-windows-x64-abi1-<commit>` (Windows x64, native ABI v1), kept for 90 days. It is a CI artifact, not a release; the Dart package itself has its own [changelog](dart/CHANGELOG.md) and is not published.

P9 defined the experimental distribution of the .NET package ([P9-D-006](docs/p9-dotnet-package/decisions.md#p9-d-006--net-managed-package-native-artifact-distribution-and-p9-closure)): each push of a commit that CI builds and tests produces two unsigned, pre-alpha GitHub Actions artifacts, kept for 90 days: `sas-pairing-dotnet-nuget-<commit>` (the NuGet-format package `SasPairing.0.1.0-dev.1.nupkg`, which contains no native library) and `sas-pairing-dotnet-windows-x64-abi1-<commit>` (Windows x64, native ABI v1). They are CI artifacts, not a release; nothing is published to nuget.org, and the .NET package has its own [changelog](dotnet/CHANGELOG.md).
