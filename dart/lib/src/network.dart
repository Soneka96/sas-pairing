/// The public Windows listener, cooperative drive, event, and connection API (P8-D-003), and,
/// in the `ceremony.dart` part, the run, trusted-local ceremony control, and SAS presentation API
/// (P8-D-004).
///
/// A host has zero or one native network context (a listener and its owner loop), which owns
/// zero or more connections, each of which owns its runs. A connection never outlives listener
/// detach, host close, authority close, runtime close, or an owner-loop failure, and a run never
/// outlives its connection. Network progress happens only inside one bounded synchronous call
/// made by the caller, and every ceremony step is one explicit synchronous call: there is no
/// background work or automatic step of any kind.
library;

import 'dart:typed_data';

import 'bootstrap.dart';
import 'exceptions.dart';
import 'native/generated/sas_pairing_bindings.g.dart' as raw;
import 'native/native_bootstrap.dart';
import 'native/native_ceremony_api.dart';
import 'native/native_network_api.dart';
import 'native/native_process_context.dart';
import 'network_refs.dart';
import 'status.dart';

part 'ceremony.dart';

/// One caller-owned, already-bound, already-listening Windows `SOCKET`, offered to a host for
/// ownership transfer by `SasPairingHost.attachWindowsListener`.
///
/// The package never binds or listens: the caller chooses the address, interface, port, and IP
/// version and creates the socket before wrapping it. **Trusted caller precondition** (the
/// package cannot check it): at attach the value is a valid Windows `SOCKET`, already bound,
/// already listening, owned exclusively by the caller, and not used or closed by anyone else
/// meanwhile. The socket, its address, and its port are not peer identity, protocol identity,
/// authenticated identity, or trust material.
///
/// While [isTransferred] is false the caller owns the socket, including after a failed attach,
/// and closes it when done. Once [isTransferred] is true the native library owns it (or has
/// already closed it): never close, use, change, or hand on the old socket value again. The raw
/// value cannot be read back from this object. Pairing networking exists on Windows only;
/// elsewhere attach fails with `SasPairingStatus.unsupportedPlatform` and the socket stays the
/// caller's.
final class SasPairingWindowsListenerSocket {
  /// Wraps the raw Windows `SOCKET` value [socket]. Windows `INVALID_SOCKET` is refused: it is
  /// never a socket.
  SasPairingWindowsListenerSocket.fromNativeSocket(int socket)
    : _socket = socket {
    if (socket == raw.SAS_PAIRING_SOCKET_INVALID) {
      throw ArgumentError(
        'INVALID_SOCKET is not a socket and cannot be offered for transfer',
        'socket',
      );
    }
  }

  final int _socket;
  bool _transferred = false;

  /// Whether the native library has taken ownership of the socket. Once true, never close or
  /// use the old socket value; a transferred object cannot be attached again.
  bool get isTransferred => _transferred;
}

/// The network state of one host.
enum SasPairingHostNetworkState {
  /// No network context: before any attach, after `detachListener`, and after the host or a
  /// parent was closed.
  detached,

  /// A listener is attached and its owner loop is running.
  attached,

  /// The listening socket was dropped (a `listenerDisabled` event): nothing new is accepted, but
  /// existing connections continue and may still be driven. To replace the listener, call
  /// `detachListener` and attach a new one.
  listenerDisabled,

  /// The owner loop failed closed: the listener and every connection are gone. Consume the
  /// batch that reported it, then call `detachListener` or close the host.
  failedClosed,
}

/// The kind of one drive event.
enum SasPairingEventKind {
  /// A new connection was accepted; the event carries its [SasPairingConnection].
  connectionAccepted(raw.SAS_PAIRING_EVENT_CONNECTION_ACCEPTED),

  /// An accepted socket was dropped without becoming a connection; see the event's reason.
  acceptRefused(raw.SAS_PAIRING_EVENT_ACCEPT_REFUSED),

  /// The listening socket was dropped; existing connections continue.
  listenerDisabled(raw.SAS_PAIRING_EVENT_LISTENER_DISABLED),

  /// One step of a connection; see the step kind and its fields.
  connectionStep(raw.SAS_PAIRING_EVENT_CONNECTION_STEP),

  /// The connection ended; its [SasPairingConnection] is already closed.
  connectionClosed(raw.SAS_PAIRING_EVENT_CONNECTION_CLOSED);

  const SasPairingEventKind(this._code);
  final int _code;
  static final Map<int, SasPairingEventKind> _byCode = _index(values, _codeOf);
  static int _codeOf(SasPairingEventKind value) => value._code;
}

/// What one connection step did.
enum SasPairingStepKind {
  /// Not a step event, or a step with nothing more to report.
  none(raw.SAS_PAIRING_STEP_NONE),

  /// One inbound frame was dispatched; see the protocol event.
  inbound(raw.SAS_PAIRING_STEP_INBOUND),

  /// A frame was refused by its START attempt or run; see the reason.
  refused(raw.SAS_PAIRING_STEP_REFUSED),

  /// A run ended by its own deadline processing; see the deadline kind and cancel state.
  deadline(raw.SAS_PAIRING_STEP_DEADLINE),

  /// The connection's retained frame was written locally (not proof that the peer received it).
  written(raw.SAS_PAIRING_STEP_WRITTEN),

  /// The Initiator's final ACK was written locally and confirmed.
  confirmed(raw.SAS_PAIRING_STEP_CONFIRMED),

  /// The final ACK was written but its run refused confirmation; see the reason.
  unconfirmed(raw.SAS_PAIRING_STEP_UNCONFIRMED),

  /// The retained frame's run ended before any byte was written; the frame was dropped.
  discarded(raw.SAS_PAIRING_STEP_DISCARDED);

  const SasPairingStepKind(this._code);
  final int _code;
  static final Map<int, SasPairingStepKind> _byCode = _index(values, _codeOf);
  static int _codeOf(SasPairingStepKind value) => value._code;
}

/// What one dispatched inbound frame did. Metadata reported by the native core: Dart parses no
/// frame and judges no protocol sequence.
enum SasPairingProtocolEvent {
  none(raw.SAS_PAIRING_PROTOCOL_EVENT_NONE),
  startAccepted(raw.SAS_PAIRING_PROTOCOL_EVENT_START_ACCEPTED),
  startDuplicate(raw.SAS_PAIRING_PROTOCOL_EVENT_START_DUPLICATE),
  accept(raw.SAS_PAIRING_PROTOCOL_EVENT_ACCEPT),
  initiatorKey(raw.SAS_PAIRING_PROTOCOL_EVENT_INITIATOR_KEY),
  responderKey(raw.SAS_PAIRING_PROTOCOL_EVENT_RESPONDER_KEY),
  bootstrapMacAuthenticated(
    raw.SAS_PAIRING_PROTOCOL_EVENT_BOOTSTRAP_MAC_AUTHENTICATED,
  ),
  bootstrapMacDuplicate(raw.SAS_PAIRING_PROTOCOL_EVENT_BOOTSTRAP_MAC_DUPLICATE),
  initiatorFinish(raw.SAS_PAIRING_PROTOCOL_EVENT_INITIATOR_FINISH),
  initiatorFinishDuplicate(
    raw.SAS_PAIRING_PROTOCOL_EVENT_INITIATOR_FINISH_DUPLICATE,
  ),
  responderFinishAck(raw.SAS_PAIRING_PROTOCOL_EVENT_RESPONDER_FINISH_ACK),
  initiatorFinishAck(raw.SAS_PAIRING_PROTOCOL_EVENT_INITIATOR_FINISH_ACK),
  peerCancel(raw.SAS_PAIRING_PROTOCOL_EVENT_PEER_CANCEL);

  const SasPairingProtocolEvent(this._code);
  final int _code;
  static final Map<int, SasPairingProtocolEvent> _byCode = _index(
    values,
    _codeOf,
  );
  static int _codeOf(SasPairingProtocolEvent value) => value._code;
}

/// The operational reason of a refusal or ending. Never evidence about the peer, authentication,
/// a SAS, or compromise: an I/O error is not an attack, and a peer close is not a rejection.
enum SasPairingEventReason {
  none(raw.SAS_PAIRING_EVENT_REASON_NONE),
  resourceLimited(raw.SAS_PAIRING_EVENT_REASON_RESOURCE_LIMITED),
  peerClosed(raw.SAS_PAIRING_EVENT_REASON_PEER_CLOSED),
  socketIo(raw.SAS_PAIRING_EVENT_REASON_SOCKET_IO),
  abandonedPartialFrame(raw.SAS_PAIRING_EVENT_REASON_ABANDONED_PARTIAL_FRAME),
  readinessFailure(raw.SAS_PAIRING_EVENT_REASON_READINESS_FAILURE),
  listenerIo(raw.SAS_PAIRING_EVENT_REASON_LISTENER_IO),
  listenerReadiness(raw.SAS_PAIRING_EVENT_REASON_LISTENER_READINESS),
  routeRefused(raw.SAS_PAIRING_EVENT_REASON_ROUTE_REFUSED),
  ownershipUncertain(raw.SAS_PAIRING_EVENT_REASON_OWNERSHIP_UNCERTAIN),
  otherHostFailure(raw.SAS_PAIRING_EVENT_REASON_OTHER_HOST_FAILURE),
  invalidFrame(raw.SAS_PAIRING_EVENT_REASON_INVALID_FRAME),
  transportDeadline(raw.SAS_PAIRING_EVENT_REASON_TRANSPORT_DEADLINE),
  clockUnavailable(raw.SAS_PAIRING_EVENT_REASON_CLOCK_UNAVAILABLE),
  sessionProtocolFailure(raw.SAS_PAIRING_EVENT_REASON_SESSION_PROTOCOL_FAILURE),
  alreadyClosed(raw.SAS_PAIRING_EVENT_REASON_ALREADY_CLOSED);

  const SasPairingEventReason(this._code);
  final int _code;
  static final Map<int, SasPairingEventReason> _byCode = _index(
    values,
    _codeOf,
  );
  static int _codeOf(SasPairingEventReason value) => value._code;
}

/// How a run ended by its own deadline processing. A timeout, the pending pre-exposure resource
/// expiry, and an unusable clock are different outcomes.
enum SasPairingDeadlineKind {
  none(raw.SAS_PAIRING_DEADLINE_NONE),
  absoluteTimeout(raw.SAS_PAIRING_DEADLINE_ABSOLUTE_TIMEOUT),
  inactivityTimeout(raw.SAS_PAIRING_DEADLINE_INACTIVITY_TIMEOUT),
  pendingExpired(raw.SAS_PAIRING_DEADLINE_PENDING_EXPIRED),
  clockUnavailable(raw.SAS_PAIRING_DEADLINE_CLOCK_UNAVAILABLE);

  const SasPairingDeadlineKind(this._code);
  final int _code;
  static final Map<int, SasPairingDeadlineKind> _byCode = _index(
    values,
    _codeOf,
  );
  static int _codeOf(SasPairingDeadlineKind value) => value._code;
}

/// What became of a deadline's best-effort authenticated CANCEL locally; never whether the peer
/// received it.
enum SasPairingCancelState {
  none(raw.SAS_PAIRING_CANCEL_STATE_NONE),
  notBuilt(raw.SAS_PAIRING_CANCEL_STATE_NOT_BUILT),
  pending(raw.SAS_PAIRING_CANCEL_STATE_PENDING),
  dropped(raw.SAS_PAIRING_CANCEL_STATE_DROPPED);

  const SasPairingCancelState(this._code);
  final int _code;
  static final Map<int, SasPairingCancelState> _byCode = _index(
    values,
    _codeOf,
  );
  static int _codeOf(SasPairingCancelState value) => value._code;
}

/// The reason a verified peer CANCEL carried (protocol event `peerCancel`).
enum SasPairingCancelReason {
  none(raw.SAS_PAIRING_CANCEL_REASON_NONE),
  userRejection(raw.SAS_PAIRING_CANCEL_REASON_USER_REJECTION),
  userCancellation(raw.SAS_PAIRING_CANCEL_REASON_USER_CANCELLATION),
  timeout(raw.SAS_PAIRING_CANCEL_REASON_TIMEOUT),
  localPolicyFailure(raw.SAS_PAIRING_CANCEL_REASON_LOCAL_POLICY_FAILURE);

  const SasPairingCancelReason(this._code);
  final int _code;
  static final Map<int, SasPairingCancelReason> _byCode = _index(
    values,
    _codeOf,
  );
  static int _codeOf(SasPairingCancelReason value) => value._code;
}

Map<int, T> _index<T>(List<T> values, int Function(T value) code) => {
  for (final value in values) code(value): value,
};

/// One live accepted connection of a host's owner loop: local and volatile, not a socket, peer
/// identity, authentication, or trust.
///
/// Every event of one native connection carries this same object. It is closed by [close], by a
/// `connectionClosed` event, by `detachListener`, by an owner-loop failure, by a ceremony call
/// that reports `SasPairingStatus.connectionEnded`, and by closing its host or a parent; a closed
/// connection stays closed and every [SasPairingRun] of it is ended.
final class SasPairingConnection {
  SasPairingConnection._(this._network, this._handle);

  final HostNetwork _network;
  final int _handle;

  /// The runs of this connection, keyed by their exact native run handle (never a request ID).
  final Map<int, SasPairingRun> _runs = {};
  bool _closed = false;

  /// Whether this connection was closed.
  bool get isClosed => _closed;

  /// Starts an honest local Initiator on this connection with exactly one native call
  /// (`sas_pairing_connection_start_initiator`), and returns the new run in
  /// [SasPairingLocalAction.run] (event [SasPairingLocalEvent.initiatorStarted], with
  /// [SasPairingLocalAction.writePending] true: native retains its START for a later drive).
  ///
  /// [local] is the explicit trusted-local Initiator configuration: not the listener's
  /// Responder Bootstrap and never peer input. [expected] is the exact expected peer Bootstrap,
  /// or null for none. Their bytes are passed exactly; the native core validates them
  /// (`SasPairingStatus.invalidBootstrap`). The native core generates the request ID, which
  /// this package learns only when a later drive event names the run; it is never invented.
  ///
  /// Nothing else happens: no drive, no exposure authorization, no exposure. A nonzero status
  /// (for example `writePending`: the connection still retains a frame, so nothing started)
  /// is thrown as a [SasPairingNativeException] and creates no run. Refused locally with a
  /// [SasPairingClosedException] when the connection is closed.
  SasPairingLocalAction startInitiator({
    required SasPairingBootstrap local,
    SasPairingBootstrap? expected,
  }) {
    if (_closed) {
      throw SasPairingClosedException('SasPairingConnection', 'startInitiator');
    }
    return _network._startInitiator(this, local, expected);
  }

  /// Closes this connection with exactly one native call (cleanup: allowed after
  /// `SAS_PAIRING_FATAL`). No CANCEL is sent and nothing is retried.
  ///
  /// The connection is closed after the first call whatever the native result, and a failure is
  /// thrown once as a [SasPairingNativeException]. When the native result is
  /// `ownershipUncertain`, the owner loop failed closed: every connection of the host is closed
  /// and the host's network state becomes `failedClosed`. Later calls do nothing.
  void close() {
    if (_closed) return;
    _network._closeConnection(this);
  }

  /// The run of the exact native run [handle] that a drive event named under [requestId]: the
  /// existing one, or a new one after the runs under the same request ID were ended (that run is
  /// the only live one under its request ID on this connection).
  ///
  /// A locally started run learns its request ID here. Native retired every other reference
  /// under that request ID when it bound the local run, and the exact run is still bound, so the
  /// connection's other runs under it are ended too. The same handle reported under a different
  /// known request ID breaks the frozen contract.
  SasPairingRun _runFor(String operation, int handle, Uint8List requestId) {
    final existing = _runs[handle];
    if (existing == null) {
      _retire(requestId);
      return _runs[handle] = SasPairingRun._(
        this,
        NativeRunRef(handle, requestId),
      );
    }
    final ref = existing._ref;
    if (ref.requestId == null) {
      _retire(requestId);
      ref.learnRequestId(requestId);
    } else if (!ref.learnRequestId(requestId)) {
      throw _network._context.violation(
        operation,
        'a run handle reported under a different request ID',
      );
    }
    return existing;
  }

  /// A new local Initiator run for the exact native run [handle]; its request ID is unknown.
  SasPairingRun _startRun(int handle) =>
      _runs[handle] = SasPairingRun._(this, NativeRunRef(handle, null));

  /// Ends every run known to be routed under [requestId]: an event made that run's end visible.
  /// A run whose request ID is still unknown is never matched.
  void _retire(Uint8List requestId) {
    _runs.removeWhere((_, run) {
      if (!run._ref.hasRequestId(requestId)) return false;
      run._ref.invalidate();
      return true;
    });
  }

  /// Ends exactly [run] (a terminal local action, or native `RUN_ENDED`). No native call.
  void _endRun(SasPairingRun run) {
    run._ref.invalidate();
    if (identical(_runs[run._ref.handle], run)) _runs.remove(run._ref.handle);
  }

  /// Marks the connection closed and ends every run. No native call.
  void _invalidate() {
    _closed = true;
    for (final run in _runs.values) {
      run._ref.invalidate();
    }
    _runs.clear();
  }
}

/// The owner loop's own failure reported by an otherwise successful drive: the loop failed
/// closed, and every event of the same batch is still valid and must be consumed.
///
/// Not an exception, and not a trust verdict.
final class SasPairingDriveFailure {
  SasPairingDriveFailure._(this.statusCode)
    : knownStatus = SasPairingStatus.fromCode(statusCode);

  /// The native `out_failure` value, preserved exactly (for example `networkPollFailed`,
  /// `ownershipUncertain`, `ownerLoopClosed`, or `fatal`).
  final int statusCode;

  /// The known status for [statusCode], or `null` when ABI v1 does not define it.
  final SasPairingStatus? knownStatus;

  /// True exactly for `SAS_PAIRING_FATAL`: after cleanup, only an OS process restart recovers.
  bool get processRestartRequired => statusCode == SasPairingStatus.fatal.code;

  @override
  String toString() =>
      'SasPairingDriveFailure: the owner loop failed closed with native status '
      '$statusCode (${knownStatus?.name ?? 'unknown status'})';
}

/// The result of one bounded drive or resume recheck: every event the native call produced, in
/// native order, and the owner loop's failure if it failed during the call.
final class SasPairingDriveBatch {
  SasPairingDriveBatch._(this.events, this.failure);

  /// The events, in exactly the order the native call reported them. Unmodifiable. Consume every
  /// one, also when [failure] is not null.
  final List<SasPairingEvent> events;

  /// Null when the owner loop did not fail; otherwise the loop failed closed after producing
  /// [events], and the host's network state is now `failedClosed`.
  final SasPairingDriveFailure? failure;
}

/// One drive event, as reported by the native core. Metadata only: no protocol frame, trust
/// verdict, or authentication result.
final class SasPairingEvent {
  SasPairingEvent._({
    required this.kind,
    required this.connection,
    required this.stepKind,
    required this.protocolEvent,
    required this.reason,
    required this.deadlineKind,
    required this.cancelState,
    required this.cancelReason,
    required this.writePending,
    required this.runUntracked,
    required this.requestId,
    required this.run,
    required NativeResultRef? result,
  }) : _result = result;

  final SasPairingEventKind kind;

  /// The connection the event names (the same object for every event of one connection), or
  /// null for `acceptRefused` and `listenerDisabled`.
  final SasPairingConnection? connection;

  final SasPairingStepKind stepKind;
  final SasPairingProtocolEvent protocolEvent;
  final SasPairingEventReason reason;
  final SasPairingDeadlineKind deadlineKind;
  final SasPairingCancelState cancelState;
  final SasPairingCancelReason cancelReason;

  /// The connection still holds one outbound frame, which the native library writes itself on a
  /// later drive. Not a failure, a trust signal, or a busy authority.
  final bool writePending;

  /// The event names a live run that got no run handle, so no trusted local ceremony action can
  /// target it. See [shouldCloseConnection].
  final bool runUntracked;

  /// The exact request ID bytes (0–64 of them; unmodifiable): routing and correlation data only,
  /// never a run, ceremony identity, peer identity, or authentication. Not text.
  final Uint8List requestId;

  /// The live run the event names, tracked by its exact native run (never by request ID), or
  /// null. Every event and local action that names the same native run carries this same
  /// object. Null for a run that ended (its end is reported with no run), for a run without a
  /// handle ([runUntracked]), and for an event that names no run.
  final SasPairingRun? run;

  final NativeResultRef? _result;

  /// Whether the event names a live run that the package tracks: exactly `run != null`.
  bool get hasTrackedRun => run != null;

  /// Whether the event delivered a new local verified result, which a later version of this
  /// package exposes. It means only that this endpoint completed locally: not that the peer
  /// succeeded or received the final message, not a bilateral commit, and not persisted trust.
  bool get hasResult => _result != null;

  /// True when [runUntracked] is set on a connection event: after consuming the whole batch, the
  /// consumer SHOULD call `event.connection?.close()`, because no exact run handle exists for
  /// trusted local ceremony actions on that run. The drive never closes it automatically.
  bool get shouldCloseConnection => runUntracked && connection != null;
}

/// The private run reference an event names, if any. Package-private (P8-D-003 N).
NativeRunRef? runReferenceOf(SasPairingEvent event) => event.run?._ref;

/// The private run reference behind [run]. Package-private (P8-D-004 A).
NativeRunRef runReferenceOfRun(SasPairingRun run) => run._ref;

/// The private result reference an event delivered, if any. Package-private (P8-D-003 N).
NativeResultRef? resultReferenceOf(SasPairingEvent event) => event._result;

/// The private run references [connection] holds. Package-private (P8-D-003 N).
List<NativeRunRef> runReferencesOf(SasPairingConnection connection) =>
    List.unmodifiable([for (final run in connection._runs.values) run._ref]);

final int _ok = SasPairingStatus.ok.code;
final int _ownershipUncertain = SasPairingStatus.ownershipUncertain.code;
const int _knownFlags =
    raw.SAS_PAIRING_EVENT_FLAG_WRITE_PENDING |
    raw.SAS_PAIRING_EVENT_FLAG_RUN_UNTRACKED;

/// One record checked against the frozen record invariants, before it changes any state.
typedef _Decoded = ({
  NativeEventRecord record,
  SasPairingEventKind kind,
  SasPairingStepKind stepKind,
  SasPairingProtocolEvent protocolEvent,
  SasPairingEventReason reason,
  SasPairingDeadlineKind deadlineKind,
  SasPairingCancelState cancelState,
  SasPairingCancelReason cancelReason,
  bool writePending,
  bool runUntracked,
  Uint8List requestId,
});

/// The package-private network context of one host: its network state, its live connection
/// wrappers, and the five network operations (P8-D-003). Owned by `SasPairingHost`.
final class HostNetwork {
  HostNetwork(this._context, this._runtime, this._host, this._results);

  final NativeProcessContext _context;
  final int _runtime;
  final int _host;
  final NativeResultStore _results;
  final Map<int, SasPairingConnection> _connections = {};
  SasPairingHostNetworkState _state = SasPairingHostNetworkState.detached;

  SasPairingHostNetworkState get state => _state;

  /// Attaches [listener] (normal). The host wrapper checked that the host is open.
  void attach(
    SasPairingWindowsListenerSocket listener,
    SasPairingBootstrap local,
    SasPairingBootstrap? expected,
  ) {
    const operation = 'SasPairingHost.attachWindowsListener';
    _context.admitNormal(operation);
    if (listener._transferred) {
      throw StateError(
        'This SasPairingWindowsListenerSocket was already transferred to the native library; '
        'never use the old socket value again.',
      );
    }
    final offered = listener._socket;
    final result = _context.network.attachWindowsListener(
      _runtime,
      _host,
      offered,
      nativeBootstrapBytes(local),
      expected == null ? null : nativeBootstrapBytes(expected),
    );
    // The slot is the only evidence of who owns the socket: record it before any status is
    // processed or anything is thrown.
    final after = result.socketAfterCall;
    if (after == raw.SAS_PAIRING_SOCKET_INVALID) {
      listener._transferred = true;
    } else if (after != offered) {
      _context.observe(result.status);
      throw _context.violation(
        operation,
        'the socket slot holds neither the offered socket nor SAS_PAIRING_SOCKET_INVALID',
      );
    }
    if (result.status == _ok && !listener._transferred) {
      throw _context.violation(
        operation,
        'SAS_PAIRING_OK left the offered socket in the slot',
      );
    }
    _context.check(operation, result.status);
    _state = SasPairingHostNetworkState.attached;
  }

  /// Detaches the listener (cleanup): one native call, then every connection is closed locally
  /// and the state is `detached`, whatever the result.
  void detach() {
    final int status;
    try {
      status = _context.network.detachListener(_runtime, _host);
    } finally {
      _teardown(SasPairingHostNetworkState.detached);
    }
    _context.check('SasPairingHost.detachListener', status);
  }

  /// One bounded native drive (normal).
  SasPairingDriveBatch drive() =>
      _driveOnce('SasPairingHost.drive', _context.network.drive);

  /// One native resume recheck (normal).
  SasPairingDriveBatch recheckAfterResume() => _driveOnce(
    'SasPairingHost.recheckAfterResume',
    _context.network.recheckAfterResume,
  );

  /// The host or a parent was closed: native cleanup already ended the network context.
  void invalidateLocally() => _teardown(SasPairingHostNetworkState.detached);

  void _closeConnection(SasPairingConnection connection) {
    _connections.remove(connection._handle);
    connection._invalidate();
    final status = _context.network.connectionClose(
      _runtime,
      _host,
      connection._handle,
    );
    if (status == _ownershipUncertain) {
      // The owner loop failed closed: every connection of the host is gone.
      _teardown(SasPairingHostNetworkState.failedClosed);
    }
    _context.check('SasPairingConnection.close', status);
  }

  void _teardown(SasPairingHostNetworkState state) {
    for (final connection in _connections.values) {
      connection._invalidate();
    }
    _connections.clear();
    _state = state;
  }

  SasPairingDriveBatch _driveOnce(
    String operation,
    NativeDriveResult Function(int runtime, int host) call,
  ) {
    _context.admitNormal(operation);
    final result = call(_runtime, _host);
    _context.check(operation, result.status);
    final failure = result.failure;
    final List<SasPairingEvent> events;
    try {
      if (result.count > raw.SAS_PAIRING_MAX_DRIVE_EVENTS ||
          result.count != result.events.length) {
        throw _context.violation(
          operation,
          'SAS_PAIRING_OK with ${result.count} events (at most '
          '${raw.SAS_PAIRING_MAX_DRIVE_EVENTS})',
        );
      }
      // Every record is checked before any of them changes host state; then they are applied in
      // native order.
      final decoded = [
        for (final record in result.events) _decode(operation, record),
      ];
      events = List.unmodifiable([
        for (final event in decoded) _apply(operation, event),
      ]);
    } finally {
      if (failure != _ok) {
        // The events above stay delivered; then the loop's failure takes effect.
        _context.observe(failure);
        _teardown(SasPairingHostNetworkState.failedClosed);
      }
    }
    return SasPairingDriveBatch._(
      events,
      failure == _ok ? null : SasPairingDriveFailure._(failure),
    );
  }

  _Decoded _decode(String operation, NativeEventRecord record) {
    Never broken(String what) => throw _context.violation(operation, what);
    final kind =
        SasPairingEventKind._byCode[record.kind] ??
        broken('event kind ${record.kind}');
    final stepKind =
        SasPairingStepKind._byCode[record.stepKind] ??
        broken('step kind ${record.stepKind}');
    final protocolEvent =
        SasPairingProtocolEvent._byCode[record.protocolEvent] ??
        broken('protocol event ${record.protocolEvent}');
    final reason =
        SasPairingEventReason._byCode[record.reason] ??
        broken('event reason ${record.reason}');
    final deadlineKind =
        SasPairingDeadlineKind._byCode[record.deadlineKind] ??
        broken('deadline kind ${record.deadlineKind}');
    final cancelState =
        SasPairingCancelState._byCode[record.cancelState] ??
        broken('cancel state ${record.cancelState}');
    final cancelReason =
        SasPairingCancelReason._byCode[record.cancelReason] ??
        broken('cancel reason ${record.cancelReason}');
    if (record.flags & ~_knownFlags != 0) {
      broken('unknown event flag bits in ${record.flags}');
    }
    if (record.reserved != 0) broken('nonzero reserved field');
    final length = record.requestIdLength;
    if (length > NativeEventRecord.requestIdCapacity) {
      broken('request ID length $length');
    }
    for (var i = length; i < record.requestIdBytes.length; i++) {
      if (record.requestIdBytes[i] != 0) {
        broken('nonzero request ID byte past its length');
      }
    }
    final runUntracked =
        record.flags & raw.SAS_PAIRING_EVENT_FLAG_RUN_UNTRACKED != 0;
    switch (kind) {
      case SasPairingEventKind.connectionAccepted ||
          SasPairingEventKind.connectionStep ||
          SasPairingEventKind.connectionClosed:
        if (record.connection == 0) broken('${kind.name} without a connection');
      case SasPairingEventKind.acceptRefused ||
          SasPairingEventKind.listenerDisabled:
        if (record.connection != 0) broken('${kind.name} with a connection');
    }
    if (kind != SasPairingEventKind.connectionStep &&
        (record.run != 0 || record.result != 0 || record.flags != 0)) {
      broken('${kind.name} with a run, a result, or flags');
    }
    if (record.run != 0 && record.result != 0) {
      broken('both a run and a result');
    }
    if (runUntracked && record.run != 0) broken('RUN_UNTRACKED with a run');
    return (
      record: record,
      kind: kind,
      stepKind: stepKind,
      protocolEvent: protocolEvent,
      reason: reason,
      deadlineKind: deadlineKind,
      cancelState: cancelState,
      cancelReason: cancelReason,
      writePending:
          record.flags & raw.SAS_PAIRING_EVENT_FLAG_WRITE_PENDING != 0,
      runUntracked: runUntracked,
      requestId: Uint8List.fromList(
        record.requestIdBytes.sublist(0, length),
      ).asUnmodifiableView(),
    );
  }

  SasPairingEvent _apply(String operation, _Decoded event) {
    Never broken(String what) => throw _context.violation(operation, what);
    final record = event.record;
    SasPairingConnection? connection;
    SasPairingRun? run;
    NativeResultRef? result;
    switch (event.kind) {
      case SasPairingEventKind.connectionAccepted:
        if (_connections.containsKey(record.connection)) {
          broken('a second connectionAccepted for a live connection');
        }
        connection = _connections[record.connection] = SasPairingConnection._(
          this,
          record.connection,
        );
      case SasPairingEventKind.acceptRefused:
        break;
      case SasPairingEventKind.listenerDisabled:
        // Existing connections continue: none is closed.
        _state = SasPairingHostNetworkState.listenerDisabled;
      case SasPairingEventKind.connectionStep:
        connection =
            _connections[record.connection] ??
            broken('connectionStep for a connection the host does not hold');
        (run, result) = _track(operation, connection, event);
      case SasPairingEventKind.connectionClosed:
        connection =
            _connections.remove(record.connection) ??
            broken('connectionClosed for a connection the host does not hold');
        connection._invalidate();
    }
    return SasPairingEvent._(
      kind: event.kind,
      connection: connection,
      stepKind: event.stepKind,
      protocolEvent: event.protocolEvent,
      reason: event.reason,
      deadlineKind: event.deadlineKind,
      cancelState: event.cancelState,
      cancelReason: event.cancelReason,
      writePending: event.writePending,
      runUntracked: event.runUntracked,
      requestId: event.requestId,
      run: run,
      result: result,
    );
  }

  /// Applies the frozen run-reference rules (ABI contract §18.6) of one step event.
  (SasPairingRun?, NativeResultRef?) _track(
    String operation,
    SasPairingConnection connection,
    _Decoded event,
  ) {
    final record = event.record;
    final requestId = event.requestId;
    if (record.result != 0) {
      // A local verified completion: the run is terminal, and the result is runtime-owned.
      if (_results.holds(record.result)) {
        throw _context.violation(operation, 'a result handle already held');
      }
      connection._retire(requestId);
      return (null, _results.retain(record.result));
    }
    if (record.run != 0) {
      return (connection._runFor(operation, record.run, requestId), null);
    }
    // Endings the event makes visible; RUN_UNTRACKED names a live run and ends nothing.
    final visibleEnd = switch (event.stepKind) {
      SasPairingStepKind.inbound =>
        event.protocolEvent != SasPairingProtocolEvent.startDuplicate &&
            !event.runUntracked,
      SasPairingStepKind.deadline => requestId.isNotEmpty,
      _ => false,
    };
    if (visibleEnd) connection._retire(requestId);
    return (null, null);
  }

  /// Removes [connection] after a ceremony call reported `CONNECTION_ENDED`: native already
  /// invalidated it and every run of it. No `sas_pairing_connection_close` call.
  void _dropConnection(SasPairingConnection connection) {
    _connections.remove(connection._handle);
    connection._invalidate();
  }

  /// Whether any connection of this host holds a run with the exact native [handle].
  bool _holdsRun(int handle) => _connections.values.any(
    (connection) => connection._runs.containsKey(handle),
  );
}
