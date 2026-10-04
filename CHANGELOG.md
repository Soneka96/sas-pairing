# Changelog

No production release has been made: there is no stable release, GitHub Release, tag, or published package. Changes are tracked in the repository history.

P8 defined an experimental distribution process for the Dart package's native library ([P8-D-006](docs/p8-dart-package/decisions.md#p8-d-006--dart-native-artifact-distribution-and-p8-final-closure)): each push of a commit that CI builds and tests produces the unsigned, pre-alpha GitHub Actions artifact `sas-pairing-dart-windows-x64-abi1-<commit>` (Windows x64, native ABI v1), kept for 90 days. It is a CI artifact, not a release; the Dart package itself has its own [changelog](dart/CHANGELOG.md) and is not published.
