// The public run, trusted-local ceremony control, and SAS presentation API (P8-D-004). A part of
// network.dart so that runs share the private connection and host state they belong to.
part of 'network.dart';

/// What one successful trusted-local ceremony action did, as reported by the native core.
///
/// Every value is a successful outcome; a refusal is a [SasPairingNativeException] instead. None
/// is a trust verdict.
enum SasPairingLocalEvent {
  /// A local Initiator was routed; its START is retained for a later drive. No opportunity was
  /// spent.
  initiatorStarted(raw.SAS_PAIRING_LOCAL_EVENT_INITIATOR_STARTED),

  /// Fresh ceremony-specific exposure consent was recorded on exactly this run. Nothing was
  /// exposed, reserved, spent, or sent.
  exposureAuthorized(raw.SAS_PAIRING_LOCAL_EVENT_EXPOSURE_AUTHORIZED),

  /// The authorization was consumed, the authority's guard and one opportunity were reserved
  /// (spent: never refunded), and this role's key is retained for a later drive.
  keyExposed(raw.SAS_PAIRING_LOCAL_EVENT_KEY_EXPOSED),

  /// Local MATCH was recorded for the exact ceremony identity. Nothing was sent; BOOTSTRAP_MAC
  /// was not emitted.
  sasApproved(raw.SAS_PAIRING_LOCAL_EVENT_SAS_APPROVED),

  /// Local MATCH was already recorded; nothing changed.
  sasAlreadyApproved(raw.SAS_PAIRING_LOCAL_EVENT_SAS_ALREADY_APPROVED),

  /// This run's own BOOTSTRAP_MAC was produced once and is retained for a later drive.
  bootstrapMacEmitted(raw.SAS_PAIRING_LOCAL_EVENT_BOOTSTRAP_MAC_EMITTED),

  /// BOOTSTRAP_MAC was already produced; nothing was recomputed or sent.
  bootstrapMacAlreadyEmitted(
    raw.SAS_PAIRING_LOCAL_EVENT_BOOTSTRAP_MAC_ALREADY_EMITTED,
  ),

  /// INITIATOR_FINISH was produced once and is retained for a later drive. There is no result
  /// yet: the native library confirms the final ACK itself on a later drive.
  initiatorFinishEmitted(raw.SAS_PAIRING_LOCAL_EVENT_INITIATOR_FINISH_EMITTED),

  /// INITIATOR_FINISH was already produced; nothing was recomputed or sent.
  initiatorFinishAlreadyEmitted(
    raw.SAS_PAIRING_LOCAL_EVENT_INITIATOR_FINISH_ALREADY_EMITTED,
  ),

  /// Local MISMATCH: the run is ended, with no result and its opportunity kept spent. A
  /// best-effort authenticated CANCEL may be retained ([SasPairingLocalAction.writePending]).
  sasRejected(raw.SAS_PAIRING_LOCAL_EVENT_SAS_REJECTED),

  /// Local CANCEL: as [sasRejected], with the distinct user-cancellation reason.
  sasCancelled(raw.SAS_PAIRING_LOCAL_EVENT_SAS_CANCELLED),

  /// The run's own deadline ended it first, and the requested action did NOT happen. See
  /// [SasPairingLocalAction.deadlineKind]; a timeout CANCEL may be retained.
  deadline(raw.SAS_PAIRING_LOCAL_EVENT_DEADLINE);

  const SasPairingLocalEvent(this._code);
  final int _code;
  static final Map<int, SasPairingLocalEvent> _byCode = _index(values, _codeOf);
  static int _codeOf(SasPairingLocalEvent value) => value._code;
}

/// The outcome of one successful trusted-local ceremony action. Immutable; made only by this
/// package. A local action never carries a protocol frame or a result.
final class SasPairingLocalAction {
  SasPairingLocalAction._(
    this.event,
    this.run,
    this.deadlineKind,
    this.writePending,
  );

  /// What the action did.
  final SasPairingLocalEvent event;

  /// The run that is still live after the action: the same object the action was called on, or
  /// the new run of [SasPairingConnection.startInitiator]. Null once the action ended the run
  /// ([SasPairingLocalEvent.sasRejected], [SasPairingLocalEvent.sasCancelled], or
  /// [SasPairingLocalEvent.deadline]); the old [SasPairingRun] then reports `isEnded`.
  final SasPairingRun? run;

  /// How the run's own deadline ended it: not [SasPairingDeadlineKind.none] exactly for
  /// [SasPairingLocalEvent.deadline].
  final SasPairingDeadlineKind deadlineKind;

  /// The action ran and the native library now retains its output (or a deadline's timeout
  /// CANCEL) for its connection, to write it on a later drive: call `SasPairingHost.drive()`.
  /// Nothing is driven automatically.
  ///
  /// Not the same as a [SasPairingNativeException] with `SasPairingStatus.writePending`, which
  /// means the requested action did NOT run because an earlier frame is still retained.
  final bool writePending;
}

/// The exact 32-byte ceremony identity of one presented SAS: the value a MATCH, MISMATCH, or
/// CANCEL decision must name.
///
/// It is obtained only from a [SasPairingSasPresentation]; there is no public constructor. It
/// is not a peer identity, an authority identity, a request ID, a secret, or a trust decision.
/// Two identities are equal when their bytes are equal.
final class SasPairingCeremonyIdentity {
  SasPairingCeremonyIdentity._(Uint8List bytes)
    : _bytes = Uint8List.fromList(bytes).asUnmodifiableView();

  final Uint8List _bytes;

  /// The 32 bytes, as an unmodifiable view of this object's own copy.
  Uint8List get bytes => _bytes;

  @override
  bool operator ==(Object other) {
    if (other is! SasPairingCeremonyIdentity) return false;
    for (var i = 0; i < _bytes.length; i++) {
      if (_bytes[i] != other._bytes[i]) return false;
    }
    return true;
  }

  @override
  int get hashCode => Object.hashAll(_bytes);
}

/// One live SAS of a run, presented for local comparison. Made only by
/// [SasPairingRun.presentation]; immutable.
///
/// Display data only: it authorizes, approves, and proves nothing, and equality of two
/// displays is not a decision. The application shows [decimal] to the user (or applies its
/// trusted-local policy) and then calls `approveSas`, `rejectSas`, or `cancelSas` with exactly
/// [ceremonyIdentity]. This package never compares displays and never decides MATCH.
final class SasPairingSasPresentation {
  SasPairingSasPresentation._(this.ceremonyIdentity, this.decimal);

  /// The exact identity of the presented ceremony; pass it to the decision.
  final SasPairingCeremonyIdentity ceremonyIdentity;

  /// The decimal SAS display, exactly `NNNN NNNN NNNN` (fourteen ASCII characters: three groups
  /// of four digits separated by single spaces). Comparison display data only.
  final String decimal;
}

/// One exact native ceremony run of one [SasPairingConnection]. Every drive event and local
/// action that names the same native run carries this same object; the run is identified by
/// its native run, never by its request ID.
///
/// **Every step is explicit.** Each method makes exactly one native call and chains nothing:
/// [authorizeExposure] does not expose, [approveSas] does not emit BOOTSTRAP_MAC,
/// [emitBootstrapMac] does not emit INITIATOR_FINISH, and nothing drives the host. A retained
/// frame ([SasPairingLocalAction.writePending]) is written by the native library on a later
/// `SasPairingHost.drive()`. The final ACK is confirmed by the native library itself; there is
/// no API for it here.
///
/// **Lifetime.** [isEnded] becomes true when the package KNOWS the run can no longer be used: a
/// drive event made its end visible, a local action ended it (reject, cancel, or a deadline),
/// native reported `SasPairingStatus.runEnded`, or its connection, host, or a parent closed.
/// A run can also end without any event; then `isEnded` is still false and the next native call
/// reports `SasPairingStatus.runEnded` as a [SasPairingNativeException] (expected, not an error
/// of the package), after which `isEnded` is true. `isEnded == false` therefore means only that
/// the end has not been observed. A method called on a known-ended run throws a
/// [SasPairingRunEndedException] without a native call.
///
/// Statuses are operation outcomes, never trust verdicts. A refusal such as `notInitiator` or
/// `ceremonyIdentityMismatch` leaves the run as it is (the native core alone knows whether it
/// ended).
final class SasPairingRun {
  SasPairingRun._(this._connection, this._ref);

  final SasPairingConnection _connection;
  final NativeRunRef _ref;

  /// Whether the package knows that this run has ended. See the class documentation: false does
  /// not guarantee the native run is still live.
  bool get isEnded => !_ref.isValid;

  /// Records fresh, ceremony-specific exposure authorization for exactly this run, from the
  /// host's own authority.
  ///
  /// It exposes, reserves, spends, and sends nothing: [exposeKey] is the separate,
  /// security-spending step. Success: [SasPairingLocalEvent.exposureAuthorized] (or
  /// [SasPairingLocalEvent.deadline]).
  SasPairingLocalAction authorizeExposure() => _act(
    'authorizeExposure',
    _authorizeOutcomes,
    (api, runtime, host, connection, run) =>
        api.authorizeExposure(runtime, host, connection, run),
  );

  /// **The security-spending step.** The native core consumes this run's fresh authorization,
  /// atomically reserves the authority's guard and spends one opportunity, then produces this
  /// role's key, retained for a later drive. No retry, reject, cancel, close, or teardown ever
  /// refunds the opportunity; this package keeps no budget of its own.
  ///
  /// Success: [SasPairingLocalEvent.keyExposed] with `writePending` (or
  /// [SasPairingLocalEvent.deadline]). Without a fresh authorization:
  /// `SasPairingStatus.missingAuthorization`; also `busy` or `exhausted`.
  SasPairingLocalAction exposeKey() => _act(
    'exposeKey',
    _exposeOutcomes,
    (api, runtime, host, connection, run) =>
        api.exposeKey(runtime, host, connection, run),
  );

  /// Reads this run's live SAS for local comparison, or null when the live run presents none
  /// (not established yet, already decided locally, or expiring).
  ///
  /// Read-only: it changes no state, refreshes no deadline, sends nothing, and also works while
  /// the connection retains a frame. Display the result's `decimal` to the user; the user's
  /// decision must name exactly its `ceremonyIdentity`.
  SasPairingSasPresentation? presentation() {
    const operation = 'SasPairingRun.presentation';
    _admit(operation);
    final network = _connection._network;
    final result = network._context.ceremony.presentation(
      network._runtime,
      network._host,
      _connection._handle,
      _ref.handle,
    );
    if (result.status != _ok) {
      network._ceremonyFailure(operation, result.status, _connection, this);
    }
    final record =
        result.presentation ??
        (throw network._context.violation(
          operation,
          'SAS_PAIRING_OK without a presentation record',
        ));
    return network._presentationOf(operation, record);
  }

  /// Local MATCH for exactly [identity], which must come from this run's presentation. Records
  /// the approval only: it sends nothing and does NOT emit BOOTSTRAP_MAC ([emitBootstrapMac] is
  /// separate).
  ///
  /// Call it only after the user (or trusted-local policy) chose MATCH for the displayed SAS.
  /// Success: [SasPairingLocalEvent.sasApproved] or [SasPairingLocalEvent.sasAlreadyApproved]
  /// (or [SasPairingLocalEvent.deadline]). Another identity:
  /// `SasPairingStatus.ceremonyIdentityMismatch`, decided by the native core, and nothing
  /// changes.
  SasPairingLocalAction approveSas(SasPairingCeremonyIdentity identity) => _act(
    'approveSas',
    _approveOutcomes,
    (api, runtime, host, connection, run) =>
        api.approveSas(runtime, host, connection, run, identity._bytes),
  );

  /// Produces this run's own BOOTSTRAP_MAC once, after its local MATCH
  /// (`SasPairingStatus.notLocallyApproved` before it), retained for a later drive. It does
  /// not approve and does NOT emit INITIATOR_FINISH.
  ///
  /// Success: [SasPairingLocalEvent.bootstrapMacEmitted] with `writePending`, or
  /// [SasPairingLocalEvent.bootstrapMacAlreadyEmitted] on a repeat (or
  /// [SasPairingLocalEvent.deadline]).
  SasPairingLocalAction emitBootstrapMac() => _act(
    'emitBootstrapMac',
    _bootstrapMacOutcomes,
    (api, runtime, host, connection, run) =>
        api.emitBootstrapMac(runtime, host, connection, run),
  );

  /// Local MISMATCH for exactly [identity]: the run ends at once with no result, and its spent
  /// opportunity is not refunded. A best-effort authenticated CANCEL may be retained
  /// (`writePending`); drive to write it. Not a judgement about the peer.
  ///
  /// Success: [SasPairingLocalEvent.sasRejected] (or [SasPairingLocalEvent.deadline]); the
  /// returned action has no run and this run reports `isEnded`.
  SasPairingLocalAction rejectSas(SasPairingCeremonyIdentity identity) => _act(
    'rejectSas',
    _rejectOutcomes,
    (api, runtime, host, connection, run) =>
        api.rejectSas(runtime, host, connection, run, identity._bytes),
  );

  /// Local CANCEL for exactly [identity]: as [rejectSas], with the distinct user-cancellation
  /// reason. Success: [SasPairingLocalEvent.sasCancelled] (or
  /// [SasPairingLocalEvent.deadline]).
  SasPairingLocalAction cancelSas(SasPairingCeremonyIdentity identity) => _act(
    'cancelSas',
    _cancelOutcomes,
    (api, runtime, host, connection, run) =>
        api.cancelSas(runtime, host, connection, run, identity._bytes),
  );

  /// Produces the Initiator's INITIATOR_FINISH once, after both approvals are authenticated
  /// (`SasPairingStatus.approvalsNotAuthenticated` before), retained for a later drive. A
  /// Responder run gets `SasPairingStatus.notInitiator` and continues.
  ///
  /// Success: [SasPairingLocalEvent.initiatorFinishEmitted] with `writePending`, or
  /// [SasPairingLocalEvent.initiatorFinishAlreadyEmitted] on a repeat (or
  /// [SasPairingLocalEvent.deadline]). There is no result yet: the native library writes the
  /// frames and confirms the final ACK itself, and the local result arrives on a later drive.
  SasPairingLocalAction emitInitiatorFinish() => _act(
    'emitInitiatorFinish',
    _finishOutcomes,
    (api, runtime, host, connection, run) =>
        api.emitInitiatorFinish(runtime, host, connection, run),
  );

  /// The local known-ended check first, then the process latches.
  void _admit(String operation) {
    if (isEnded) throw SasPairingRunEndedException(operation);
    _connection._network._context.admitNormal(operation);
  }

  SasPairingLocalAction _act(
    String method,
    List<_Outcome> allowed,
    _RunCall call,
  ) {
    final operation = 'SasPairingRun.$method';
    _admit(operation);
    final network = _connection._network;
    final result = call(
      network._context.ceremony,
      network._runtime,
      network._host,
      _connection._handle,
      _ref.handle,
    );
    if (result.status != _ok) {
      network._ceremonyFailure(operation, result.status, _connection, this);
    }
    return network._settleAction(operation, allowed, result.action, this);
  }
}

/// One native run action of the ceremony service, on exactly the given handles.
typedef _RunCall =
    NativeActionResult Function(
      NativeCeremonyApi api,
      int runtime,
      int host,
      int connection,
      int run,
    );

/// One success a method allows: the event, whether the run stays live, and the required
/// `WRITE_PENDING` flag (null: either).
typedef _Outcome = ({
  SasPairingLocalEvent event,
  bool live,
  bool? writePending,
});

const _Outcome _deadlineOutcome = (
  event: SasPairingLocalEvent.deadline,
  live: false,
  writePending: null,
);
const List<_Outcome> _startOutcomes = [
  (
    event: SasPairingLocalEvent.initiatorStarted,
    live: true,
    writePending: true,
  ),
];
const List<_Outcome> _authorizeOutcomes = [
  (
    event: SasPairingLocalEvent.exposureAuthorized,
    live: true,
    writePending: false,
  ),
  _deadlineOutcome,
];
const List<_Outcome> _exposeOutcomes = [
  (event: SasPairingLocalEvent.keyExposed, live: true, writePending: true),
  _deadlineOutcome,
];
const List<_Outcome> _approveOutcomes = [
  (event: SasPairingLocalEvent.sasApproved, live: true, writePending: false),
  (
    event: SasPairingLocalEvent.sasAlreadyApproved,
    live: true,
    writePending: false,
  ),
  _deadlineOutcome,
];
const List<_Outcome> _bootstrapMacOutcomes = [
  (
    event: SasPairingLocalEvent.bootstrapMacEmitted,
    live: true,
    writePending: true,
  ),
  (
    event: SasPairingLocalEvent.bootstrapMacAlreadyEmitted,
    live: true,
    writePending: false,
  ),
  _deadlineOutcome,
];
const List<_Outcome> _rejectOutcomes = [
  (event: SasPairingLocalEvent.sasRejected, live: false, writePending: null),
  _deadlineOutcome,
];
const List<_Outcome> _cancelOutcomes = [
  (event: SasPairingLocalEvent.sasCancelled, live: false, writePending: null),
  _deadlineOutcome,
];
const List<_Outcome> _finishOutcomes = [
  (
    event: SasPairingLocalEvent.initiatorFinishEmitted,
    live: true,
    writePending: true,
  ),
  (
    event: SasPairingLocalEvent.initiatorFinishAlreadyEmitted,
    live: true,
    writePending: false,
  ),
  _deadlineOutcome,
];

final int _runEnded = SasPairingStatus.runEnded.code;
final int _connectionEnded = SasPairingStatus.connectionEnded.code;
final int _ownerLoopClosed = SasPairingStatus.ownerLoopClosed.code;
const int _knownActionFlags = raw.SAS_PAIRING_ACTION_FLAG_WRITE_PENDING;
const int _asciiSpace = 0x20;
const int _asciiZero = 0x30;
const int _asciiNine = 0x39;

/// The ceremony operations of one host network (P8-D-004).
extension _HostCeremony on HostNetwork {
  SasPairingLocalAction _startInitiator(
    SasPairingConnection connection,
    SasPairingBootstrap local,
    SasPairingBootstrap? expected,
  ) {
    const operation = 'SasPairingConnection.startInitiator';
    _context.admitNormal(operation);
    final result = _context.ceremony.startInitiator(
      _runtime,
      _host,
      connection._handle,
      nativeBootstrapBytes(local),
      expected == null ? null : nativeBootstrapBytes(expected),
    );
    if (result.status != _ok) {
      _ceremonyFailure(operation, result.status, connection, null);
    }
    return _settleAction(
      operation,
      _startOutcomes,
      result.action,
      null,
      connection: connection,
    );
  }

  /// The one place that applies the frozen lifecycle effects of a nonzero ceremony status
  /// (P8-D-004 rule 6) and then throws it exactly. Nothing else is inferred: `WRITE_PENDING`
  /// and every ceremony or core refusal change no state.
  Never _ceremonyFailure(
    String operation,
    int status,
    SasPairingConnection connection,
    SasPairingRun? run,
  ) {
    if (status == _runEnded) {
      // The exact run is no longer routed; native removed its handle.
      if (run != null) connection._endRun(run);
    } else if (status == _connectionEnded) {
      // The connection and every run of it are invalid natively; no close call.
      _dropConnection(connection);
    } else if (status == _ownershipUncertain || status == _ownerLoopClosed) {
      // The owner loop failed closed: every connection and run of the host is invalid.
      _teardown(SasPairingHostNetworkState.failedClosed);
    }
    // Latches FATAL for 900 and throws every nonzero status.
    _context.check(operation, status);
    throw StateError('$operation: a nonzero status was not thrown');
  }

  /// Checks one successful action record against the frozen record invariants and the
  /// outcomes [allowed] for the called method, before any state changes; then applies it.
  /// [input] is the run acted on, or null for a start on [connection].
  SasPairingLocalAction _settleAction(
    String operation,
    List<_Outcome> allowed,
    NativeActionRecord? record,
    SasPairingRun? input, {
    SasPairingConnection? connection,
  }) {
    Never broken(String what) => throw _context.violation(operation, what);
    if (record == null) broken('SAS_PAIRING_OK without an action record');
    if (record.reserved != 0) broken('nonzero reserved field');
    if (record.flags & ~_knownActionFlags != 0) {
      broken('unknown action flag bits in ${record.flags}');
    }
    final event =
        SasPairingLocalEvent._byCode[record.event] ??
        broken('local event ${record.event}');
    final deadlineKind =
        SasPairingDeadlineKind._byCode[record.deadlineKind] ??
        broken('deadline kind ${record.deadlineKind}');
    if ((event == SasPairingLocalEvent.deadline) !=
        (deadlineKind != SasPairingDeadlineKind.none)) {
      broken('deadline kind ${deadlineKind.name} with ${event.name}');
    }
    final writePending =
        record.flags & raw.SAS_PAIRING_ACTION_FLAG_WRITE_PENDING != 0;
    _Outcome? outcome;
    for (final candidate in allowed) {
      if (candidate.event == event) outcome = candidate;
    }
    if (outcome == null) {
      broken('${event.name} is not an outcome of $operation');
    }
    final required = outcome.writePending;
    if (required != null && required != writePending) {
      broken(
        '${event.name} ${writePending ? 'with' : 'without'} WRITE_PENDING',
      );
    }
    if (!outcome.live) {
      if (record.run != 0) broken('${event.name} with a live run');
      // Terminal: the input run's handle is invalid natively from now on.
      input!._connection._endRun(input);
      return SasPairingLocalAction._(event, null, deadlineKind, writePending);
    }
    if (input != null) {
      if (record.run != input._ref.handle) {
        broken(
          record.run == 0
              ? '${event.name} without its live run'
              : '${event.name} with a different run handle',
        );
      }
      return SasPairingLocalAction._(event, input, deadlineKind, writePending);
    }
    if (record.run == 0) broken('${event.name} without a run handle');
    if (_holdsRun(record.run)) {
      broken('${event.name} with the handle of a live run');
    }
    return SasPairingLocalAction._(
      event,
      connection!._startRun(record.run),
      deadlineKind,
      writePending,
    );
  }

  /// Checks one successful presentation record (P8-D-004 rule 5) and returns its public value,
  /// or null when no SAS is presented.
  SasPairingSasPresentation? _presentationOf(
    String operation,
    NativePresentationRecord record,
  ) {
    Never broken(String what) => throw _context.violation(operation, what);
    final identity = record.ceremonyIdentity;
    final decimal = record.decimal;
    if (identity.length != NativePresentationRecord.identityLength ||
        decimal.length != NativePresentationRecord.decimalLength ||
        record.reservedTail.length !=
            NativePresentationRecord.reservedTailLength) {
      broken('presentation fields of the wrong length');
    }
    if (record.reserved != 0) broken('nonzero reserved field');
    if (record.reservedTail.any((byte) => byte != 0)) {
      broken('nonzero reserved tail');
    }
    switch (record.available) {
      case 0:
        if (identity.any((byte) => byte != 0) ||
            decimal.any((byte) => byte != 0)) {
          broken('available = 0 with a nonzero identity or decimal byte');
        }
        return null;
      case 1:
        for (var i = 0; i < decimal.length; i++) {
          final byte = decimal[i];
          final valid = i == 4 || i == 9
              ? byte == _asciiSpace
              : byte >= _asciiZero && byte <= _asciiNine;
          if (!valid) broken('the decimal SAS is not NNNN NNNN NNNN');
        }
        return SasPairingSasPresentation._(
          SasPairingCeremonyIdentity._(identity),
          // Validated above: exactly fourteen ASCII digits and spaces.
          String.fromCharCodes(decimal),
        );
      default:
        broken('available = ${record.available}');
    }
  }
}
