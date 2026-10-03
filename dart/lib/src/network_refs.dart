/// Package-private references to native run and result handles (P8-D-003 N).
///
/// Private to the package and never exported. Drive events may name an exact native run or a new
/// native result. P8.3 exposes neither, but keeps the exact handles here so that later increments
/// can wrap them without reconstructing anything from request IDs, connections, or event order.
/// No handle is ever destroyed, re-targeted, or interpreted here.
library;

import 'dart:typed_data';

/// One exact native run handle of one connection.
///
/// The identity is the native handle, never the request ID: a replacement run under a reused
/// request ID gets its own reference. A reference may be stale (its run ended without a visible
/// event); it becomes invalid when an event makes its end visible, or when its connection, the
/// owner loop, the host, or a parent is torn down.
final class NativeRunRef {
  NativeRunRef(this.handle, Uint8List requestId)
    : _requestId = Uint8List.fromList(requestId);

  /// The exact native run handle.
  final int handle;

  final Uint8List _requestId;
  bool _valid = true;

  /// Whether the reference has not been invalidated by a visible ending or a teardown.
  bool get isValid => _valid;

  /// Whether this run was routed under exactly [requestId].
  bool hasRequestId(Uint8List requestId) {
    if (requestId.length != _requestId.length) return false;
    for (var i = 0; i < requestId.length; i++) {
      if (requestId[i] != _requestId[i]) return false;
    }
    return true;
  }

  void invalidate() => _valid = false;
}

/// One native result handle the runtime now owns: a local verified completion only, never
/// bilateral success. It outlives its connection, the listener, the owner loop, the host, and
/// the authority; only result destruction (a later increment) or runtime destruction ends it.
final class NativeResultRef {
  NativeResultRef(this.handle);

  /// The exact native result handle.
  final int handle;

  bool _valid = true;

  /// Whether the native result still exists (false once its runtime was destroyed).
  bool get isValid => _valid;

  void invalidate() => _valid = false;
}

/// The result references of one runtime, in delivery order.
final class NativeResultStore {
  final Map<int, NativeResultRef> _results = {};

  /// Every reference retained so far.
  List<NativeResultRef> get references => List.unmodifiable(_results.values);

  /// Whether [handle] is already retained.
  bool holds(int handle) => _results.containsKey(handle);

  /// Retains a new [handle]; the caller checked it is not already held.
  NativeResultRef retain(int handle) =>
      _results[handle] = NativeResultRef(handle);

  /// Invalidates every reference: native runtime destruction dropped every result.
  void invalidateAll() {
    for (final result in _results.values) {
      result.invalidate();
    }
    _results.clear();
  }
}
