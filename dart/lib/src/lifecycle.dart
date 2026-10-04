/// The public runtime, authority, and host lifecycle (P8-D-002), with the host's network
/// operations (P8-D-003).
///
/// Ownership mirrors the native ABI: a runtime owns its authorities, an authority owns its
/// hosts, and a host owns its network context and connections. Native cleanup of a parent
/// already cascades to its children, so closing a parent makes exactly one native cleanup call
/// and then marks every child wrapper closed locally; no child cleanup call is made. Every `close()` consumes its wrapper on the first call, whatever the
/// native result, and later calls do nothing.
library;

import 'dart:typed_data';

import 'bootstrap.dart';
import 'exceptions.dart';
import 'native/generated/sas_pairing_bindings.g.dart' as raw;
import 'native/native_library_loader.dart'
    show NativeLibraryInitializationException, NativeLoadFailure;
import 'native/native_process_context.dart';
import 'network.dart';

/// The largest remaining-opportunity count a successful `READY` status can report (ABI contract
/// §15: 1–10). Used only to validate one native success output; Dart keeps no budget.
const int _maxAuthorityOpportunities = 10;

/// Returns the process context that [initialize] obtains from the native-library loader,
/// translating a loader failure into the public [SasPairingInitializationException]: the one
/// boundary where the private loader failure becomes public (P8-D-002 M). Package-private:
/// [SasPairingRuntime.create] uses it with the process loader, tests with a fake loader.
NativeProcessContext initializeProcessContext(
  NativeProcessContext Function() initialize,
) {
  try {
    return initialize();
  } on NativeLibraryInitializationException catch (error) {
    throw SasPairingInitializationException(
      _publicFailure(error.failure),
      error.message,
    );
  }
}

// Exhaustive by design: a new loader failure category does not compile until it is given a
// public meaning.
SasPairingInitializationFailure _publicFailure(NativeLoadFailure failure) =>
    switch (failure) {
      NativeLoadFailure.unsupportedPointerWidth =>
        SasPairingInitializationFailure.unsupportedPointerWidth,
      NativeLoadFailure.invalidLibraryPath =>
        SasPairingInitializationFailure.invalidLibraryPath,
      NativeLoadFailure.openFailed =>
        SasPairingInitializationFailure.openFailed,
      NativeLoadFailure.missingSymbol =>
        SasPairingInitializationFailure.missingSymbol,
      NativeLoadFailure.abiVersionQueryFailed =>
        SasPairingInitializationFailure.abiVersionQueryFailed,
      NativeLoadFailure.abiVersionMismatch =>
        SasPairingInitializationFailure.abiVersionMismatch,
      NativeLoadFailure.verificationFailed =>
        SasPairingInitializationFailure.verificationFailed,
    };

/// Creates a runtime over [context]. Package-private: [SasPairingRuntime.create] is the public
/// entry, and tests use this with a fake context.
SasPairingRuntime createRuntime(NativeProcessContext context) {
  const operation = 'SasPairingRuntime.create';
  context.admitNormal(operation);
  final result = context.api.runtimeCreate();
  context.check(operation, result.status);
  return SasPairingRuntime._(
    context,
    context.requireHandle(operation, result.handle),
  );
}

/// The runtime-owned result store of [runtime] (P8-D-005 B, E). Package-private.
NativeResultStore resultStoreOf(SasPairingRuntime runtime) => runtime._results;

/// The one native runtime of this process: the owning root of authorities and hosts.
///
/// A runtime is a native object lifetime, not a security session. Closing it and creating a new
/// one reuses the same loaded native library and resets nothing: authority opportunity
/// accounting, the START limiter, and every process-session security state continue, and a
/// recorded `SAS_PAIRING_FATAL` stays recorded. Close it explicitly, in a `finally` block; no
/// finalizer does it for you.
final class SasPairingRuntime {
  SasPairingRuntime._(NativeProcessContext context, int handle)
    : _context = context,
      _handle = handle,
      _results = NativeResultStore(context, handle);

  /// Creates the native runtime, loading the native library from the absolute
  /// [nativeLibraryPath] the first time (it is never loaded twice; later calls ignore the
  /// path).
  ///
  /// Three failure classes stay distinct:
  ///
  /// * [SasPairingInitializationException]: the native library could not be loaded or set up;
  ///   no native status exists. When its `processRestartRequired` is false (pointer width,
  ///   invalid path, OS load failure) no image was retained, and `create` may be called again
  ///   after correcting the cause. When it is true (missing export, failed or mismatched ABI
  ///   version query, failed verification) an image is already loaded: every later `create` in
  ///   this process fails the same way, and only an OS process restart recovers.
  /// * [SasPairingNativeException]: `runtime_create` returned a nonzero status, for example
  ///   `alreadyInitialized` while another runtime is open (the open runtime is never returned
  ///   again), or `fatal` (900) once `SAS_PAIRING_FATAL` was observed in this process, which
  ///   requires an OS process restart.
  /// * [SasPairingContractException]: the native library reported success but broke a frozen
  ///   ABI v1 invariant, now or earlier in this process; an OS process restart is required.
  static SasPairingRuntime create({required String nativeLibraryPath}) =>
      createRuntime(
        initializeProcessContext(
          () => NativeProcessContext.forLibrary(nativeLibraryPath),
        ),
      );

  final NativeProcessContext _context;
  final int _handle;
  final Set<SasPairingAuthority> _authorities = {};
  // Native results are runtime-owned: they outlive connections, listeners, hosts, authorities,
  // and the fatal state, and end only with result destruction or runtime destruction.
  final NativeResultStore _results;
  bool _closed = false;

  /// Whether this runtime was closed. A closed runtime stays closed.
  bool get isClosed => _closed;

  /// Registers the authority named by the exact bytes of [scope] and takes its OS ownership.
  ///
  /// The bytes are arbitrary (they are not text and may contain `0x00`); they are copied for
  /// the call and not kept. An empty scope is passed to the native core, which rejects it
  /// (`invalidScope`). Native failures such as `alreadyRegistered`, `ownershipUnavailable`,
  /// `ownershipUncertain`, or `unsupportedPlatform` are thrown as
  /// [SasPairingNativeException]; no authority object exists then.
  SasPairingAuthority registerAuthority(Uint8List scope) {
    const operation = 'SasPairingRuntime.registerAuthority';
    _requireOpen('registerAuthority');
    _context.admitNormal(operation);
    final result = _context.api.authorityRegister(_handle, scope);
    _context.check(operation, result.status);
    final authority = SasPairingAuthority._(
      this,
      _context.requireHandle(operation, result.handle),
    );
    _authorities.add(authority);
    return authority;
  }

  /// Destroys the native runtime with exactly one native call, which also releases every
  /// authority, destroys every host, closes every listener and connection, and drops every
  /// result it owns; all of those objects (every open `SasPairingResult` included) are then
  /// closed too, with no other native call. Result data already read stays usable.
  ///
  /// The runtime is closed after the first call whatever the native result, and a failure is
  /// thrown once as a [SasPairingNativeException]; it is never retried. Later calls do nothing.
  /// Allowed after `SAS_PAIRING_FATAL`.
  void close() {
    if (_closed) return;
    _closed = true;
    final int status;
    try {
      status = _context.api.runtimeDestroy(_handle);
    } finally {
      for (final authority in _authorities) {
        authority._invalidateByParent();
      }
      _authorities.clear();
      _results.invalidateAll();
    }
    _context.check('SasPairingRuntime.close', status);
  }

  void _requireOpen(String operation) {
    if (_closed) {
      throw SasPairingClosedException('SasPairingRuntime', operation);
    }
  }
}

/// One registered authority: one active registration holding the authority's OS ownership,
/// owned by its runtime.
///
/// Its opportunity budget and START limiter belong to the process, not to this object:
/// registering the same scope again after closing it continues them.
final class SasPairingAuthority {
  SasPairingAuthority._(this._runtime, this._handle);

  final SasPairingRuntime _runtime;
  final int _handle;
  final Set<SasPairingHost> _hosts = {};
  bool _closed = false;

  /// Whether this authority was closed, by [close] or by closing its runtime.
  bool get isClosed => _closed;

  /// The authority's current native state. Native failures are thrown as
  /// [SasPairingNativeException]. A success output outside the frozen invariant (`READY` with
  /// other than 1–10 remaining, `BUSY` or `EXHAUSTED` with nonzero remaining, or another state)
  /// is a [SasPairingContractException].
  SasPairingAuthorityStatus queryStatus() {
    const operation = 'SasPairingAuthority.queryStatus';
    _requireOpen('queryStatus');
    final context = _runtime._context;
    context.admitNormal(operation);
    final result = context.api.authorityStatus(_runtime._handle, _handle);
    context.check(operation, result.status);
    final (state, remaining) = (result.state, result.remaining);
    // Validates this one success output against the frozen invariant (READY: 1–10; BUSY and
    // EXHAUSTED: 0). Nothing is remembered or compared with an earlier answer.
    switch (state) {
      case raw.SAS_PAIRING_AUTHORITY_READY
          when remaining >= 1 && remaining <= _maxAuthorityOpportunities:
        return SasPairingAuthorityStatus._(
          SasPairingAuthorityState.ready,
          remaining,
        );
      case raw.SAS_PAIRING_AUTHORITY_BUSY when remaining == 0:
        return const SasPairingAuthorityStatus._(
          SasPairingAuthorityState.busy,
          0,
        );
      case raw.SAS_PAIRING_AUTHORITY_EXHAUSTED when remaining == 0:
        return const SasPairingAuthorityStatus._(
          SasPairingAuthorityState.exhausted,
          0,
        );
      default:
        throw context.violation(
          operation,
          'SAS_PAIRING_OK with authority state $state and $remaining remaining '
          'opportunities',
        );
    }
  }

  /// Creates a host (one native hosting context) for this authority. No networking happens and
  /// no accounting changes. Native failures are thrown as [SasPairingNativeException].
  SasPairingHost createHost() {
    const operation = 'SasPairingAuthority.createHost';
    _requireOpen('createHost');
    final context = _runtime._context;
    context.admitNormal(operation);
    final result = context.api.hostCreate(_runtime._handle, _handle);
    context.check(operation, result.status);
    final handle = context.requireHandle(operation, result.handle);
    final host = SasPairingHost._(
      this,
      handle,
      HostNetwork(context, _runtime._handle, handle, _runtime._results),
    );
    _hosts.add(host);
    return host;
  }

  /// Releases the registration with exactly one native call, which also destroys every host of
  /// this authority with its listener and connections; those objects are then closed too, with
  /// no other native call. The runtime and its results stay open.
  ///
  /// The authority is closed after the first call whatever the native result (for example
  /// `ownershipUncertain`), and a failure is thrown once as a [SasPairingNativeException]; it is
  /// never retried. Later calls do nothing. Allowed after `SAS_PAIRING_FATAL`. Process-session
  /// accounting is not reset.
  void close() {
    if (_closed) return;
    _closed = true;
    final int status;
    try {
      status = _runtime._context.api.authorityRelease(
        _runtime._handle,
        _handle,
      );
    } finally {
      _invalidateHosts();
      _runtime._authorities.remove(this);
    }
    _runtime._context.check('SasPairingAuthority.close', status);
  }

  void _invalidateByParent() {
    _closed = true;
    _invalidateHosts();
  }

  void _invalidateHosts() {
    for (final host in _hosts) {
      host._invalidateByParent();
    }
    _hosts.clear();
  }

  void _requireOpen(String operation) {
    if (_closed) {
      throw SasPairingClosedException('SasPairingAuthority', operation);
    }
  }
}

/// One hosting context of an authority, owned by that authority. It may hold one Windows
/// listener at a time ([attachWindowsListener]) and is driven cooperatively by the caller
/// ([drive]); it owns the [SasPairingConnection] objects its listener accepts.
///
/// Pairing networking is supported on Windows only. Nothing happens in the background: no
/// thread, timer, stream, isolate, or callback exists, and network progress happens only inside
/// [drive] and [recheckAfterResume].
final class SasPairingHost {
  SasPairingHost._(this._authority, this._handle, this._network);

  final SasPairingAuthority _authority;
  final int _handle;
  final HostNetwork _network;
  bool _closed = false;

  /// Whether this host was closed, by [close] or by closing its authority or runtime.
  bool get isClosed => _closed;

  /// The host's network state. `detached` once the host is closed.
  SasPairingHostNetworkState get networkState => _network.state;

  /// Attaches the caller's already-bound, already-listening Windows socket [listener] to this
  /// host, with [local] as the host's Responder Bootstrap and [expected] as the exact expected
  /// peer Bootstrap (null: none). One native call; nothing is driven or accepted, and no
  /// connection exists afterwards.
  ///
  /// Ownership of the socket follows the native in/out slot and is recorded on [listener] before
  /// any error is thrown: when `listener.isTransferred` is true afterwards (success, or
  /// `listenerSetupFailed` or `fatal` after the native library took the socket), never close or
  /// use the old socket value; when it is false (any earlier failure, such as
  /// `invalidBootstrap`, `listenerAlreadyAttached`, or `unsupportedPlatform`), the socket is
  /// still the caller's to close. On success the network state is `attached`. A host holds one
  /// listener: replace it with [detachListener] and a new attach. A transferred [listener]
  /// cannot be attached again (`StateError`).
  void attachWindowsListener({
    required SasPairingWindowsListenerSocket listener,
    required SasPairingBootstrap local,
    SasPairingBootstrap? expected,
  }) {
    _requireOpen('attachWindowsListener');
    _network.attach(listener, local, expected);
  }

  /// Detaches the listener with exactly one native call (cleanup: allowed after
  /// `SAS_PAIRING_FATAL`; native detach is idempotent). The native library closes the listener
  /// and every connection itself; afterwards the network state is `detached` and every
  /// [SasPairingConnection] of this host is closed, whatever the native result, and a failure
  /// (for example `ownershipUncertain`) is thrown once and never retried. The host, its
  /// authority, its runtime, and all accounting stay; a new listener may be attached. Does
  /// nothing on a closed host.
  void detachListener() {
    if (_closed) return;
    _network.detach();
  }

  /// Drives the host's owner loop once: exactly one bounded native call (deadline sweeps, at
  /// most one readiness wait of at most about 250 ms, at most one socket operation per
  /// connection, at most one accept), returning every event it produced.
  ///
  /// The call is synchronous and may block for up to about 250 ms, so blindly calling it on a
  /// Flutter UI isolate is not recommended; the caller decides the cadence. Do not spin
  /// `while (true) host.drive();` without a scheduling or yield policy: persistent readiness can
  /// make calls return at once.
  ///
  /// A nonzero native result (for example `listenerNotAttached`, `handlesExhausted`, or
  /// `fatal`) is thrown as a [SasPairingNativeException] and returns no batch. When the call ran
  /// but the owner loop failed during it, the batch still carries every event and reports the
  /// failure in `failure`; the network state is then `failedClosed` and every connection is
  /// closed. Consume every event, then call [detachListener] or [close].
  SasPairingDriveBatch drive() {
    _requireOpen('drive');
    return _network.drive();
  }

  /// One resume recheck of the owner loop: a single deadline sweep with no readiness wait,
  /// socket read or write, or accept, with exactly the batch, failure, and connection rules of
  /// [drive]. Only for trusted outer code that observed an OS resume notification; the package
  /// does not detect resume and never calls this by itself.
  SasPairingDriveBatch recheckAfterResume() {
    _requireOpen('recheckAfterResume');
    return _network.recheckAfterResume();
  }

  /// Destroys the host with exactly one native call, which also closes its listener and every
  /// connection; those connections are then closed too, with no other native call. Its
  /// authority stays registered and open, and results stay open.
  ///
  /// The host is closed after the first call whatever the native result, and a failure is
  /// thrown once as a [SasPairingNativeException]; it is never retried. Later calls do nothing.
  /// Allowed after `SAS_PAIRING_FATAL`.
  void close() {
    if (_closed) return;
    _closed = true;
    final runtime = _authority._runtime;
    final int status;
    try {
      status = runtime._context.api.hostDestroy(runtime._handle, _handle);
    } finally {
      _network.invalidateLocally();
      _authority._hosts.remove(this);
    }
    runtime._context.check('SasPairingHost.close', status);
  }

  void _invalidateByParent() {
    _closed = true;
    _network.invalidateLocally();
  }

  void _requireOpen(String operation) {
    if (_closed) {
      throw SasPairingClosedException('SasPairingHost', operation);
    }
  }
}

/// The successful state of an authority. Not a status code: the native failure status
/// `SasPairingStatus.busy` is a different thing.
enum SasPairingAuthorityState {
  /// The authority can host a ceremony; `remainingOpportunities` says how many remain.
  ready,

  /// An exposed ceremony currently holds the authority.
  busy,

  /// The authority's opportunity budget for this process session is spent.
  exhausted,
}

/// An immutable snapshot of an authority's native state. The native core stays authoritative:
/// this is a report, not an accounting copy.
final class SasPairingAuthorityStatus {
  const SasPairingAuthorityStatus._(this.state, this.remainingOpportunities);

  final SasPairingAuthorityState state;

  /// The remaining opportunities when [state] is `ready` (1–10); otherwise 0.
  final int remainingOpportunities;

  @override
  bool operator ==(Object other) =>
      other is SasPairingAuthorityStatus &&
      other.state == state &&
      other.remainingOpportunities == remainingOpportunities;

  @override
  int get hashCode => Object.hash(state, remainingOpportunities);

  @override
  String toString() =>
      'SasPairingAuthorityStatus(${state.name}, '
      'remainingOpportunities: $remainingOpportunities)';
}
