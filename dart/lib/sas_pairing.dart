/// `package:sas_pairing`: experimental, pre-alpha Dart binding of the sas-pairing native core.
///
/// P8.2 provides the native lifecycle only: [SasPairingRuntime], [SasPairingAuthority], and
/// [SasPairingHost], with the status and exception model. There is no listener, network,
/// connection, ceremony, or SAS API yet. Raw FFI types, pointers, native handles, the
/// `DynamicLibrary`, the generated bindings, and the loader stay private.
///
/// A native library that cannot be loaded or verified is a [SasPairingInitializationException];
/// its `processRestartRequired` says whether a corrected retry is possible in this process.
///
/// Close every object explicitly (`try`/`finally`); no finalizer does it. `close()` consumes
/// the object on its first call even when the native cleanup reports an error, and closing a
/// parent closes its children. If the native library reports `SAS_PAIRING_FATAL`, every new or
/// normal operation is refused for the rest of the process and only an OS process restart
/// recovers. Statuses are operation outcomes, never trust verdicts.
///
/// Not production-security approved, not audited, and not formally verified. The protocol is
/// implemented only by the native Rust core; this package implements no protocol or
/// cryptography. Pairing networking is supported on Windows only.
library;

export 'src/exceptions.dart'
    show
        SasPairingClosedException,
        SasPairingContractException,
        SasPairingInitializationException,
        SasPairingInitializationFailure,
        SasPairingNativeException;
export 'src/lifecycle.dart'
    show
        SasPairingAuthority,
        SasPairingAuthorityState,
        SasPairingAuthorityStatus,
        SasPairingHost,
        SasPairingRuntime;
export 'src/status.dart' show SasPairingStatus;
