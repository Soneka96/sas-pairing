/// The exceptions of the public lifecycle API (P8-D-002 F, H, I).
///
/// None of them carries a native handle, pointer, or authority scope, and none is a trust
/// verdict.
library;

import 'status.dart';

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
