/// Package-private references to native run handles (P8-D-003 N, P8-D-004 A-D).
///
/// Private to the package and never exported. Drive events may name an exact native run, and a
/// local Initiator start returns a new exact run. A public `SasPairingRun` is backed by one run
/// reference. Nothing is reconstructed from request IDs, connections, or event order, and no
/// handle is ever re-targeted or interpreted here. Results are runtime-owned and live in the
/// runtime's `NativeResultStore` (P8-D-005).
library;

import 'dart:typed_data';

/// One exact native run handle of one connection.
///
/// The identity is the native handle, never the request ID: a replacement run under a reused
/// request ID gets its own reference. The request ID is known when a drive event reported the
/// run; a locally started Initiator's request ID is unknown (null) until an event names that
/// exact handle, and it is never fabricated. A reference may be stale (its run ended without a
/// visible event); it becomes invalid when an event or a local action makes its end visible, or
/// when its connection, the owner loop, the host, or a parent is torn down.
final class NativeRunRef {
  NativeRunRef(this.handle, Uint8List? requestId)
    : _requestId = requestId == null ? null : Uint8List.fromList(requestId);

  /// The exact native run handle.
  final int handle;

  Uint8List? _requestId;
  bool _valid = true;

  /// Whether the reference has not been invalidated by a visible ending or a teardown.
  bool get isValid => _valid;

  /// A copy of the request ID the run was routed under, or null while it is unknown.
  Uint8List? get requestId {
    final known = _requestId;
    return known == null ? null : Uint8List.fromList(known);
  }

  /// Whether this run is known to be routed under exactly [requestId]. Never true while the
  /// request ID is unknown.
  bool hasRequestId(Uint8List requestId) {
    final known = _requestId;
    if (known == null || requestId.length != known.length) return false;
    for (var i = 0; i < requestId.length; i++) {
      if (requestId[i] != known[i]) return false;
    }
    return true;
  }

  /// Records [requestId] reported for this exact handle: true when it was unknown (it is now
  /// known) or equal; false when a different request ID is already known, which the frozen ABI
  /// never produces for one run handle.
  bool learnRequestId(Uint8List requestId) {
    if (_requestId == null) {
      _requestId = Uint8List.fromList(requestId);
      return true;
    }
    return hasRequestId(requestId);
  }

  void invalidate() => _valid = false;
}
