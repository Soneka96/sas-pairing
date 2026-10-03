/// The private native network service (P8-D-003 Q): the five network exports of the frozen ABI
/// v1, with every piece of their FFI memory handled here.
///
/// Private to the package. This is not a second declaration layer: it calls only the generated
/// bindings. It returns raw status values, the raw socket slot, and plain copies of the produced
/// event records without interpreting them; the host network wrapper decides what they mean.
/// Every native allocation is made for one synchronous call and freed before it returns, and no
/// pointer or generated record leaves this file.
library;

import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import 'generated/sas_pairing_bindings.g.dart';

/// The four exact byte fields of one Bootstrap configuration, in ABI order.
typedef NativeBootstrapBytes = ({
  Uint8List applicationIdentity,
  Uint8List keyAlgorithm,
  Uint8List publicKey,
  Uint8List sharedContext,
});

/// An attach result: the raw status and the raw value of the in/out socket slot after the call.
typedef NativeAttachResult = ({int status, int socketAfterCall});

/// A drive or recheck result: the raw status, the raw `*out_count` and `*out_failure`, and a
/// copy of every produced record (only on `SAS_PAIRING_OK`, and never more than the capacity).
typedef NativeDriveResult = ({
  int status,
  int count,
  int failure,
  List<NativeEventRecord> events,
});

/// A plain Dart copy of one `sas_pairing_event_t`, every field raw and uninterpreted.
final class NativeEventRecord {
  NativeEventRecord({
    required this.kind,
    this.stepKind = 0,
    this.protocolEvent = 0,
    this.reason = 0,
    this.deadlineKind = 0,
    this.cancelState = 0,
    this.cancelReason = 0,
    this.flags = 0,
    this.connection = 0,
    this.run = 0,
    this.result = 0,
    this.requestIdLength = 0,
    this.reserved = 0,
    Uint8List? requestIdBytes,
  }) : requestIdBytes = requestIdBytes ?? Uint8List(requestIdCapacity);

  /// The fixed size of the record's `request_id` array (`SAS_PAIRING_MAX_REQUEST_ID_LEN`).
  static const int requestIdCapacity = SAS_PAIRING_MAX_REQUEST_ID_LEN;

  final int kind;
  final int stepKind;
  final int protocolEvent;
  final int reason;
  final int deadlineKind;
  final int cancelState;
  final int cancelReason;
  final int flags;
  final int connection;
  final int run;
  final int result;
  final int requestIdLength;
  final int reserved;

  /// All [requestIdCapacity] bytes of the record's `request_id` array.
  final Uint8List requestIdBytes;
}

/// The network exports the host wrapper uses. Production: [FfiNativeNetworkApi]; tests supply a
/// deterministic fake.
abstract interface class NativeNetworkApi {
  /// `sas_pairing_host_attach_windows_listener` with an in/out slot holding [socket] on entry.
  NativeAttachResult attachWindowsListener(
    int runtime,
    int host,
    int socket,
    NativeBootstrapBytes local,
    NativeBootstrapBytes? expected,
  );

  /// `sas_pairing_host_detach_listener` (cleanup).
  int detachListener(int runtime, int host);

  /// One `sas_pairing_host_drive` with capacity `SAS_PAIRING_MAX_DRIVE_EVENTS`.
  NativeDriveResult drive(int runtime, int host);

  /// One `sas_pairing_host_recheck_after_resume` with capacity `SAS_PAIRING_MAX_DRIVE_EVENTS`.
  NativeDriveResult recheckAfterResume(int runtime, int host);

  /// `sas_pairing_connection_close` (cleanup).
  int connectionClose(int runtime, int host, int connection);
}

typedef _DriveExport =
    int Function(
      int runtime,
      int host,
      Pointer<sas_pairing_event_t> events,
      int capacity,
      Pointer<Size> outCount,
      Pointer<sas_pairing_status_t> outFailure,
    );

/// The production service over the one generated binding object of the loaded image.
final class FfiNativeNetworkApi implements NativeNetworkApi {
  FfiNativeNetworkApi(this._bindings);

  final SasPairingNativeBindings _bindings;

  @override
  NativeAttachResult attachWindowsListener(
    int runtime,
    int host,
    int socket,
    NativeBootstrapBytes local,
    NativeBootstrapBytes? expected,
  ) => using((arena) {
    final slot = arena<sas_pairing_socket_t>()..value = socket;
    final localView = _bootstrap(arena, local);
    final expectedView = expected == null
        ? nullptr.cast<sas_pairing_bootstrap_view_t>()
        : _bootstrap(arena, expected);
    final status = _bindings.sas_pairing_host_attach_windows_listener(
      runtime,
      host,
      slot,
      localView,
      expectedView,
    );
    return (status: status, socketAfterCall: slot.value);
  });

  @override
  int detachListener(int runtime, int host) =>
      _bindings.sas_pairing_host_detach_listener(runtime, host);

  @override
  NativeDriveResult drive(int runtime, int host) =>
      _drive(_bindings.sas_pairing_host_drive, runtime, host);

  @override
  NativeDriveResult recheckAfterResume(int runtime, int host) =>
      _drive(_bindings.sas_pairing_host_recheck_after_resume, runtime, host);

  @override
  int connectionClose(int runtime, int host, int connection) =>
      _bindings.sas_pairing_connection_close(runtime, host, connection);

  NativeDriveResult _drive(
    _DriveExport export,
    int runtime,
    int host,
  ) => using((arena) {
    const capacity = SAS_PAIRING_MAX_DRIVE_EVENTS;
    final events = arena<sas_pairing_event_t>(capacity);
    final outCount = arena<Size>();
    final outFailure = arena<sas_pairing_status_t>();
    final status = export(
      runtime,
      host,
      events,
      capacity,
      outCount,
      outFailure,
    );
    final count = outCount.value;
    // Copy every produced record before the memory is freed; nothing past the capacity is
    // ever read (a larger count is reported raw and refused by the host wrapper).
    final copied = status == SAS_PAIRING_OK
        ? [for (var i = 0; i < count && i < capacity; i++) _copy(events[i])]
        : const <NativeEventRecord>[];
    return (
      status: status,
      count: count,
      failure: outFailure.value,
      events: copied,
    );
  });

  static NativeEventRecord _copy(sas_pairing_event_t record) {
    final requestId = Uint8List(NativeEventRecord.requestIdCapacity);
    for (var i = 0; i < requestId.length; i++) {
      requestId[i] = record.request_id[i];
    }
    return NativeEventRecord(
      kind: record.kind,
      stepKind: record.step_kind,
      protocolEvent: record.protocol_event,
      reason: record.reason,
      deadlineKind: record.deadline_kind,
      cancelState: record.cancel_state,
      cancelReason: record.cancel_reason,
      flags: record.flags,
      connection: record.connection,
      run: record.run,
      result: record.result,
      requestIdLength: record.request_id_len,
      reserved: record.reserved,
      requestIdBytes: requestId,
    );
  }

  /// One Bootstrap view over exact copies of the four fields, valid until [arena] is released.
  static Pointer<sas_pairing_bootstrap_view_t> _bootstrap(
    Arena arena,
    NativeBootstrapBytes bootstrap,
  ) {
    final view = arena<sas_pairing_bootstrap_view_t>();
    _bytes(arena, view.ref.application_identity, bootstrap.applicationIdentity);
    _bytes(arena, view.ref.key_algorithm, bootstrap.keyAlgorithm);
    _bytes(arena, view.ref.public_key, bootstrap.publicKey);
    _bytes(arena, view.ref.shared_context, bootstrap.sharedContext);
    return view;
  }

  /// Exact bytes, pointer plus length: an empty field is a null pointer with length 0, any other
  /// field an exact copy. No encoding, no terminator.
  static void _bytes(
    Arena arena,
    sas_pairing_bytes_view_t view,
    Uint8List bytes,
  ) {
    if (bytes.isEmpty) {
      view
        ..data = nullptr
        ..len = 0;
      return;
    }
    final copy = arena<Uint8>(bytes.length);
    copy.asTypedList(bytes.length).setAll(0, bytes);
    view
      ..data = copy
      ..len = bytes.length;
  }
}
