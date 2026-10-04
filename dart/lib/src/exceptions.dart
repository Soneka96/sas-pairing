/// The exceptions of the public API (P8-D-002 F, H, I, M; P8-D-004 L).
///
/// None of them carries a native handle, pointer, or authority scope, and none is a trust
/// verdict.
library;

import 'status.dart';

/// Why the native library could not be initialized for [SasPairingInitializationException].
enum SasPairingInitializationFailure {
  /// The process pointer width is not the supported 64-bit width. Nothing was opened.
  unsupportedPointerWidth,

  /// The library path is empty, relative, or not an existing file. Nothing was opened.
  invalidLibraryPath,

  /// The operating system could not load the file. No native image was retained.
  openFailed,

  /// The loaded native library lacks one or more of the frozen ABI v1 exports.
  missingSymbol,

  /// The native ABI version query failed inside the native library (it reported version 0).
  abiVersionQueryFailed,

  /// The native library implements an ABI version other than 1.
  abiVersionMismatch,

  /// Verifying the loaded native library failed unexpectedly.
  verificationFailed,
}

/// The native library could not be initialized, so no runtime was created and no lifecycle
/// operation ran. There is no native status: the failure happened before any lifecycle export
/// was called.
///
/// When [processRestartRequired] is false (`unsupportedPointerWidth`, `invalidLibraryPath`,
/// `openFailed`), no native image was retained by the failed attempt: after correcting the
/// cause, `SasPairingRuntime.create` may be called again. When it is true (`missingSymbol`,
/// `abiVersionQueryFailed`, `abiVersionMismatch`, `verificationFailed`), a native image was
/// already loaded and cannot be unloaded or replaced: every later `SasPairingRuntime.create` in
/// this process fails with this same failure; correct the native library and restart the OS
/// process.
final class SasPairingInitializationException implements Exception {
  SasPairingInitializationException(this.failure, this.message);

  /// The failure category.
  final SasPairingInitializationFailure failure;

  /// What failed, including the library path where it is known.
  final String message;

  /// Whether a native image was already loaded, so only an OS process restart recovers.
  bool get processRestartRequired => switch (failure) {
    SasPairingInitializationFailure.unsupportedPointerWidth ||
    SasPairingInitializationFailure.invalidLibraryPath ||
    SasPairingInitializationFailure.openFailed => false,
    SasPairingInitializationFailure.missingSymbol ||
    SasPairingInitializationFailure.abiVersionQueryFailed ||
    SasPairingInitializationFailure.abiVersionMismatch ||
    SasPairingInitializationFailure.verificationFailed => true,
  };

  @override
  String toString() =>
      'SasPairingInitializationException(${failure.name}): $message'
      '${processRestartRequired ? ' Restart the OS process after correcting the native '
                'library; the loaded image cannot be unloaded or replaced.' : ''}';
}

/// A native operation returned a nonzero `sas_pairing_status_t`, or was refused locally because
/// `SAS_PAIRING_FATAL` was already observed in this process.
///
/// [statusCode] is the exact native value, including codes ABI v1 does not define
/// ([knownStatus] is then `null`). It describes the outcome of [operation] only: it is not a
/// trust verdict, a judgement about a peer, authentication policy, or authorization.
final class SasPairingNativeException implements Exception {
  SasPairingNativeException(this.operation, this.statusCode, {this.detail})
    : knownStatus = SasPairingStatus.fromCode(statusCode);

  /// The operation that failed, such as `SasPairingRuntime.registerAuthority`.
  final String operation;

  /// The native status value, preserved exactly.
  final int statusCode;

  /// The known status for [statusCode], or `null` when ABI v1 does not define it.
  final SasPairingStatus? knownStatus;

  /// Additional context, if any.
  final String? detail;

  /// True exactly for `SAS_PAIRING_FATAL`: the native state of this process is permanently
  /// fatal, every new or normal operation is refused, and only an OS process restart recovers.
  bool get processRestartRequired => statusCode == SasPairingStatus.fatal.code;

  @override
  String toString() {
    final name = knownStatus?.name ?? 'unknown status';
    final buffer = StringBuffer(
      'SasPairingNativeException: $operation failed with native status '
      '$statusCode ($name)',
    );
    if (detail != null) buffer.write(': $detail');
    if (processRestartRequired) {
      buffer.write(
        '. The native state of this process is permanently fatal; restart the OS process.',
      );
    }
    return buffer.toString();
  }
}

/// A normal operation was attempted on a wrapper that is already closed, by its own `close()`
/// or by its parent's. Raised locally; no native code was called. Not a native status.
final class SasPairingClosedException implements Exception {
  SasPairingClosedException(this.objectKind, this.operation);

  /// The closed object, such as `SasPairingAuthority`.
  final String objectKind;

  /// The operation that was attempted, such as `createHost`.
  final String operation;

  @override
  String toString() =>
      'SasPairingClosedException: $objectKind.$operation was called after the '
      '$objectKind was closed.';
}

/// An operation was attempted on a `SasPairingRun` that is already known to be ended: by a
/// visible terminal drive event, a terminal local action (reject, cancel, or a deadline), an
/// earlier `SasPairingStatus.runEnded`, or the end of its connection, host, or a parent.
/// Raised locally; no native code was called and there is no native status.
///
/// A run that ended without a visible event may still look live (`isEnded == false`); the next
/// native call then reports `SasPairingStatus.runEnded` as a [SasPairingNativeException], and
/// only later calls raise this exception.
final class SasPairingRunEndedException implements Exception {
  SasPairingRunEndedException(this.operation);

  /// The operation that was attempted, such as `SasPairingRun.exposeKey`.
  final String operation;

  @override
  String toString() =>
      'SasPairingRunEndedException: $operation was called on a run that is already known to '
      'have ended.';
}

/// The native library reported success but broke a frozen ABI v1 success invariant (for
/// example a zero handle, or an invalid authority state).
///
/// There is no native failure status to report. The package refuses every further normal
/// operation in this process; closing existing objects stays allowed. Restart the OS process
/// with a correct native library.
final class SasPairingContractException implements Exception {
  SasPairingContractException(this.operation, this.violation);

  /// The operation whose success output broke the contract.
  final String operation;

  /// What was wrong with the success output.
  final String violation;

  /// Always true: no recovery exists in the same process.
  bool get processRestartRequired => true;

  @override
  String toString() =>
      'SasPairingContractException: native ABI v1 contract was violated by $operation: '
      '$violation. Normal operations are refused for the rest of this process; restart '
      'the OS process.';
}
