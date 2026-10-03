/// `package:sas_pairing`: experimental, pre-alpha Dart binding of the sas-pairing native core.
///
/// It provides the native lifecycle ([SasPairingRuntime], [SasPairingAuthority], and
/// [SasPairingHost], with the status and exception model; P8.2) and the Windows listener
/// ownership transfer and cooperative network driver (a [SasPairingBootstrap] value, the
/// [SasPairingWindowsListenerSocket] transfer token, `attachWindowsListener`, `detachListener`,
/// one bounded `drive()` or `recheckAfterResume()` per call returning a [SasPairingDriveBatch]
/// of [SasPairingEvent] values, and [SasPairingConnection]; P8.3). There is no ceremony, SAS,
/// run, or result API yet. Raw FFI types, pointers, native handles, sockets, event records, the
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
/// Network calls are synchronous and bounded; the caller decides their cadence and nothing runs
/// in the background. Consume every event of a batch, also when its `failure` is set. When an
/// event's `shouldCloseConnection` is true, close that connection after consuming the batch.
///
/// Not production-security approved, not audited, and not formally verified. The protocol is
/// implemented only by the native Rust core; this package implements no protocol or
/// cryptography. Pairing networking is supported on Windows only.
library;

export 'src/bootstrap.dart' show SasPairingBootstrap;
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
export 'src/network.dart'
    show
        SasPairingCancelReason,
        SasPairingCancelState,
        SasPairingConnection,
        SasPairingDeadlineKind,
        SasPairingDriveBatch,
        SasPairingDriveFailure,
        SasPairingEvent,
        SasPairingEventKind,
        SasPairingEventReason,
        SasPairingHostNetworkState,
        SasPairingProtocolEvent,
        SasPairingStepKind,
        SasPairingWindowsListenerSocket;
export 'src/status.dart' show SasPairingStatus;
