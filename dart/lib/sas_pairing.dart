/// `package:sas_pairing`: experimental, pre-alpha Dart binding of the sas-pairing native core.
///
/// It provides the native lifecycle ([SasPairingRuntime], [SasPairingAuthority], and
/// [SasPairingHost], with the status and exception model; P8.2) and the Windows listener
/// ownership transfer and cooperative network driver (a [SasPairingBootstrap] value, the
/// [SasPairingWindowsListenerSocket] transfer token, `attachWindowsListener`, `detachListener`,
/// one bounded `drive()` or `recheckAfterResume()` per call returning a [SasPairingDriveBatch]
/// of [SasPairingEvent] values, and [SasPairingConnection]; P8.3), and trusted-local ceremony
/// control (a [SasPairingRun] from a drive event or `SasPairingConnection.startInitiator`, its
/// explicit steps returning a [SasPairingLocalAction], and the [SasPairingSasPresentation] with
/// its [SasPairingCeremonyIdentity]; P8.4). There is no result content API yet: a completed
/// ceremony shows only `SasPairingEvent.hasResult`. Raw FFI types, pointers, native handles,
/// sockets, event, action, and presentation records, the `DynamicLibrary`, the generated
/// bindings, and the loader stay private.
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
/// Every ceremony step is one explicit call, and nothing is chained or driven automatically.
/// The package never decides whether a SAS matches: the application displays
/// `SasPairingSasPresentation.decimal`, obtains a trusted-local user or policy choice, and calls
/// `approveSas`, `rejectSas`, or `cancelSas` with the presented identity. `exposeKey()` is the
/// security-spending step. A [SasPairingNativeException] with `SasPairingStatus.writePending`
/// means the requested action did not run (drive, then retry if still appropriate), while
/// `SasPairingLocalAction.writePending` means it ran and its output waits for a drive.
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
        SasPairingNativeException,
        SasPairingRunEndedException;
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
        SasPairingCeremonyIdentity,
        SasPairingConnection,
        SasPairingDeadlineKind,
        SasPairingDriveBatch,
        SasPairingDriveFailure,
        SasPairingEvent,
        SasPairingEventKind,
        SasPairingEventReason,
        SasPairingHostNetworkState,
        SasPairingLocalAction,
        SasPairingLocalEvent,
        SasPairingProtocolEvent,
        SasPairingRun,
        SasPairingSasPresentation,
        SasPairingStepKind,
        SasPairingWindowsListenerSocket;
export 'src/status.dart' show SasPairingStatus;
