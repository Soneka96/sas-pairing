# Changelog

## 0.1.0-dev.1

First experimental, pre-alpha version of the Dart wrapper (phase P8). Not published to pub.dev and not a release; there is no stable API or semantic-versioning promise yet. Not production-security approved, not audited, and not formally verified.

- **Native ABI v1 loader.** Binds exactly the frozen native ABI v1 (25 exports, ABI version 1) through private generated bindings. The native library is loaded once per process from an explicit absolute path and stays loaded until the process exits; there is no search, download, unload, or reload.
- **Lifecycle.** `SasPairingRuntime`, `SasPairingAuthority`, and `SasPairingHost` with explicit, consuming `close()`, the native cleanup cascade, the 48 frozen statuses, and distinct initialization, native, closed, contract, and run-ended exceptions. `SAS_PAIRING_FATAL` requires an OS process restart.
- **Windows network driver.** Hand over an already-bound WinSock listening socket, then drive the host cooperatively, one bounded synchronous call at a time; every event of a batch is delivered, also when the owner loop failed; `RUN_UNTRACKED` close guidance.
- **Ceremony and SAS.** Runs identified by their exact native run, one explicit call per ceremony step (authorize, expose, approve, BOOTSTRAP_MAC, reject, cancel, INITIATOR_FINISH), and the decimal SAS presentation with its 32-byte ceremony identity. The application compares the SAS and decides; nothing is chained or approved automatically.
- **Pairing results.** Runtime-owned `SasPairingResult` objects delivered by drive events and read explicitly into immutable `SasPairingResultData`. A result is this endpoint's local verified completion only, never proof that the peer completed or persisted trust.
- **Windows x64 native artifact (pre-alpha distribution).** Each commit's CI stages, tests, and uploads the Windows x64 library as the experimental GitHub Actions artifact `sas-pairing-dart-windows-x64-abi1-<commit>`, with an artifact manifest, SHA-256 checksums, the project licenses, and a third-party dependency inventory. It is unsigned, expires after 90 days, and must be used with this package's source from the same commit.

Limitations: pairing works on Windows x64 only (Linux loads the library but pairing fails closed; no macOS, mobile, ARM64, or 32-bit support); the application creates the listening socket and schedules every drive; one Dart isolate owns all native access; nothing is persisted or trusted automatically.
