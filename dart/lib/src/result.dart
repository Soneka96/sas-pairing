// The public PairingResult API (P8-D-005). A part of network.dart so that a result reuses the one
// SasPairingCeremonyIdentity type (whose constructor stays private) and the drive's event mapper
// can hand each delivered result to the runtime's store.
part of 'network.dart';

/// The PEER's role in the ceremony a result completed, as the native core reports it. Never this
/// endpoint's own role: an Initiator's result reports [responder].
enum SasPairingPeerRole {
  /// The peer was the ceremony's Initiator.
  initiator(raw.SAS_PAIRING_ROLE_INITIATOR),

  /// The peer was the ceremony's Responder.
  responder(raw.SAS_PAIRING_ROLE_RESPONDER);

  const SasPairingPeerRole(this._code);
  final int _code;
  static final Map<int, SasPairingPeerRole> _byCode = _index(values, _codeOf);
  static int _codeOf(SasPairingPeerRole value) => value._code;
}

/// An immutable snapshot of one local verified result, made only by [SasPairingResult.read].
///
/// Plain Dart data: it stays usable after the result and its runtime are closed. Every byte
/// field is this object's own copy, exposed as an unmodifiable view, and is exactly the bytes the
/// native core reported: nothing is decoded, parsed, trimmed, or terminated.
///
/// **Local completion only.** These values were authenticated inside THIS endpoint's locally
/// completed SAS ceremony. They are inputs to the application's own policy, not proof that the
/// peer also completed, not a bilateral commit, and not persisted or established trust; the
/// package persists, enrolls, and trusts nothing.
final class SasPairingResultData {
  SasPairingResultData._({
    required this.ceremonyIdentity,
    required this.peerRole,
    required this.profileVersion,
    required Uint8List requestId,
    required Uint8List authenticatedPeerBootstrap,
    required Uint8List authenticatedSharedContext,
    required Uint8List profileIdentifier,
  }) : requestId = _frozen(requestId),
       authenticatedPeerBootstrap = _frozen(authenticatedPeerBootstrap),
       authenticatedSharedContext = _frozen(authenticatedSharedContext),
       profileIdentifier = _frozen(profileIdentifier);

  /// The 32-byte transcript-derived ceremony identity: the same value the SAS presentation of
  /// this ceremony carried. Not a request ID, handle, peer identity, or trust key.
  final SasPairingCeremonyIdentity ceremonyIdentity;

  /// The PEER's role in the ceremony, never this endpoint's.
  final SasPairingPeerRole peerRole;

  /// The protocol profile version, exactly as reported (data, not a trust decision).
  final int profileVersion;

  /// The ceremony's request ID: routing and correlation bytes only, never text, a result
  /// identity, or a peer identity.
  final Uint8List requestId;

  /// The exact canonical Bootstrap frame the peer supplied in this ceremony under the approved
  /// SAS flow, as native returned it. Not parsed by this package; what to do with it is
  /// application policy.
  final Uint8List authenticatedPeerBootstrap;

  /// The authenticated shared context: exact opaque bytes, possibly empty.
  final Uint8List authenticatedSharedContext;

  /// The protocol profile identifier, as exact bytes (not decoded into text).
  final Uint8List profileIdentifier;
}

/// This value's own copy of [bytes], exposed only as an unmodifiable view.
Uint8List _frozen(Uint8List bytes) =>
    Uint8List.fromList(bytes).asUnmodifiableView();

/// One native PairingResult: ONE local verified completion of this endpoint's ceremony.
///
/// **Not bilateral success.** A result does not mean that the peer completed, holds a result
/// of its own, received the final message, or committed, and it is not persisted or established
/// trust. Either side may be the only one holding a result. The package trusts, persists, and
/// enrolls nothing; the application decides.
///
/// **Ownership.** A result belongs to its `SasPairingRuntime`, not to the connection, run, host,
/// or authority that produced it: it stays open across connection close, listener detach, an
/// owner-loop failure, host close, authority close, and `SAS_PAIRING_FATAL`. Only [close] and
/// `SasPairingRuntime.close()` end it. Close it explicitly; no finalizer does it.
///
/// **Reading.** [read] returns an immutable [SasPairingResultData] snapshot, reading the native
/// result on every call. It also works after `SAS_PAIRING_FATAL` (reading never enters the
/// pairing core), but not after the package observed a native contract violation.
final class SasPairingResult {
  SasPairingResult._(this._store, this._handle);

  final NativeResultStore _store;
  final int _handle;
  bool _closed = false;

  /// Whether this result was closed, by [close] or by closing its runtime.
  bool get isClosed => _closed;

  /// Reads one coherent snapshot of the result: its fixed fields, then each byte field exactly
  /// once at the length the native result reported. Synchronous.
  ///
  /// Throws [SasPairingClosedException] when the result is closed and
  /// [SasPairingContractException] (no native call) once a native contract violation was
  /// observed in this process. A nonzero native status (for example `invalidHandle`, or
  /// `fatal`, which this read records) is thrown as a [SasPairingNativeException]; a success
  /// output that breaks the frozen contract is a [SasPairingContractException]. Nothing partial
  /// is ever returned, and a failed read leaves the result open.
  SasPairingResultData read() {
    const operation = 'SasPairingResult.read';
    if (_closed) throw SasPairingClosedException('SasPairingResult', 'read');
    final context = _store._context;
    // Not the normal-operation admission: native FATAL does not block reading existing results.
    context.admitData(operation);
    final api = context.results;
    final runtime = _store._runtime;
    final answer = api.resultInfo(runtime, _handle);
    context.check(operation, answer.status);
    Never broken(String what) => throw context.violation(operation, what);
    final info = answer.info ?? broken('SAS_PAIRING_OK without a result info');
    if (info.ceremonyIdentity.length != NativeResultInfoRecord.identityLength) {
      broken('a ceremony identity of ${info.ceremonyIdentity.length} bytes');
    }
    final peerRole =
        SasPairingPeerRole._byCode[info.peerRole] ??
        broken('peer role ${info.peerRole}');
    final requestIdLength = _bounded(
      operation,
      'request ID',
      info.requestIdLength,
      _maxRequestIdLength,
    );
    final peerBootstrapLength = _bounded(
      operation,
      'peer Bootstrap',
      info.peerBootstrapLength,
      _maxBootstrapFrameLength,
    );
    final sharedContextLength = _bounded(
      operation,
      'shared context',
      info.sharedContextLength,
      _maxSharedContextLength,
    );
    final profileIdentifierLength = _bounded(
      operation,
      'profile identifier',
      info.profileIdentifierLength,
      null,
    );
    // Copy every field before anything is built: a failure returns nothing partial.
    final requestId = _copy(
      operation,
      'request ID',
      raw.SAS_PAIRING_RESULT_FIELD_REQUEST_ID,
      requestIdLength,
    );
    final peerBootstrap = _copy(
      operation,
      'peer Bootstrap',
      raw.SAS_PAIRING_RESULT_FIELD_AUTHENTICATED_PEER_BOOTSTRAP,
      peerBootstrapLength,
    );
    final sharedContext = _copy(
      operation,
      'shared context',
      raw.SAS_PAIRING_RESULT_FIELD_AUTHENTICATED_SHARED_CONTEXT,
      sharedContextLength,
    );
    final profileIdentifier = _copy(
      operation,
      'profile identifier',
      raw.SAS_PAIRING_RESULT_FIELD_PROFILE_IDENTIFIER,
      profileIdentifierLength,
    );
    return SasPairingResultData._(
      ceremonyIdentity: SasPairingCeremonyIdentity._(info.ceremonyIdentity),
      peerRole: peerRole,
      profileVersion: info.profileVersion,
      requestId: requestId,
      authenticatedPeerBootstrap: peerBootstrap,
      authenticatedSharedContext: sharedContext,
      profileIdentifier: profileIdentifier,
    );
  }

  /// Destroys the native result with exactly one native call (cleanup: allowed after
  /// `SAS_PAIRING_FATAL` and after a contract violation). Data already read stays usable.
  ///
  /// The result is closed after the first call whatever the native result, and a failure is
  /// thrown once as a [SasPairingNativeException]; it is never retried. Later calls do nothing.
  void close() {
    if (_closed) return;
    _closed = true;
    _store._live.remove(_handle);
    final status = _store._context.results.resultDestroy(
      _store._runtime,
      _handle,
    );
    _store._context.check('SasPairingResult.close', status);
  }

  /// [length] from a successful info, checked against its source-proven [max] (null: no bound
  /// narrower than `uint32_t`).
  int _bounded(String operation, String field, int length, int? max) {
    if (length < 0 || length > (max ?? _maxUint32)) {
      throw _store._context.violation(operation, 'a $field length of $length');
    }
    return length;
  }

  /// Exactly one copy of the raw [field] (named [name] in errors) at exactly [expected] bytes,
  /// the length the same immutable result reported in its info.
  Uint8List _copy(String operation, String name, int field, int expected) {
    final context = _store._context;
    final answer = context.results.resultCopy(
      _store._runtime,
      _handle,
      field,
      expected,
    );
    if (answer.status == _bufferTooSmall) {
      // Never a buffer negotiation: the capacity is the length this result reported.
      throw context.violation(
        operation,
        'SAS_PAIRING_BUFFER_TOO_SMALL for the $name at its reported length $expected '
        '(required ${answer.required})',
      );
    }
    context.check(operation, answer.status);
    final bytes = answer.bytes;
    if (answer.required != expected ||
        bytes == null ||
        bytes.length != expected) {
      throw context.violation(
        operation,
        'the $name copied with length ${answer.required}, but its info reported '
        '$expected',
      );
    }
    return bytes;
  }
}

/// `SAS_PAIRING_MAX_REQUEST_ID_LEN`: the frozen protocol request-ID bound (ABI contract §18.1).
const int _maxRequestIdLength = raw.SAS_PAIRING_MAX_REQUEST_ID_LEN;

/// The frozen profile's complete canonical Bootstrap frame bound (`MAX_BOOTSTRAP_FRAME`; profile
/// §3.1 and §4, ABI contract §17.2). Not an ABI v1 header constant.
const int _maxBootstrapFrameLength = 16384;

/// The frozen profile's `shared_context` bound (0–8,192 bytes; profile §4). Not an ABI v1 header
/// constant.
const int _maxSharedContextLength = 8192;

const int _maxUint32 = 0xFFFFFFFF;

final int _bufferTooSmall = SasPairingStatus.bufferTooSmall.code;

/// The results of one runtime (P8-D-005 B, E): the one public object of each live result handle,
/// and every result handle ever delivered under the runtime. Package-private.
///
/// The runtime owns it; connections, hosts, and authorities only hand it new results. Delivered
/// handles are remembered after their result is closed (handles are never reused natively), so a
/// second delivery of one is a contract violation rather than a new object.
final class NativeResultStore {
  NativeResultStore(this._context, this._runtime);

  final NativeProcessContext _context;
  final int _runtime;
  final Map<int, SasPairingResult> _live = {};
  final Set<int> _delivered = {};

  /// The open results, in delivery order.
  List<SasPairingResult> get live => List.unmodifiable(_live.values);

  /// Whether [handle] was ever delivered under this runtime.
  bool delivered(int handle) => _delivered.contains(handle);

  /// Wraps the newly delivered [handle]; the caller checked it was never delivered.
  SasPairingResult retain(int handle) {
    _delivered.add(handle);
    return _live[handle] = SasPairingResult._(this, handle);
  }

  /// Marks every open result closed: native runtime destruction dropped every result. No native
  /// call.
  void invalidateAll() {
    for (final result in _live.values) {
      result._closed = true;
    }
    _live.clear();
  }
}
