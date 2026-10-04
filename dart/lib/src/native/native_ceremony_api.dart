/// The private native ceremony service (P8-D-004 rule 8): the nine trusted-local ceremony exports
/// of the frozen ABI v1, with every piece of their FFI memory handled here.
///
/// Private to the package. This is not a second declaration layer: it calls only the generated
/// bindings. It returns raw status values and, only on `SAS_PAIRING_OK`, plain copies of the
/// action or presentation record, uninterpreted; the run wrapper decides what they mean. Every
/// native allocation (one zeroed output record, the 32 ceremony-identity bytes, the Bootstrap
/// views of a start) is made for one synchronous call and freed before it returns, and no
/// pointer or generated record leaves this file.
library;

import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import 'generated/sas_pairing_bindings.g.dart';
import 'native_bootstrap.dart';

/// A plain Dart copy of one `sas_pairing_action_t`, every field raw and uninterpreted.
final class NativeActionRecord {
  NativeActionRecord({
    required this.event,
    this.deadlineKind = 0,
    this.flags = 0,
    this.reserved = 0,
    this.run = 0,
  });

  final int event;
  final int deadlineKind;
  final int flags;
  final int reserved;
  final int run;
}

/// A plain Dart copy of one `sas_pairing_sas_presentation_t`, every field raw and uninterpreted.
/// The byte lists are copies owned by this value.
final class NativePresentationRecord {
  NativePresentationRecord({
    required this.available,
    this.reserved = 0,
    Uint8List? ceremonyIdentity,
    Uint8List? decimal,
    Uint8List? reservedTail,
  }) : ceremonyIdentity = ceremonyIdentity ?? Uint8List(identityLength),
       decimal = decimal ?? Uint8List(decimalLength),
       reservedTail = reservedTail ?? Uint8List(reservedTailLength);

  /// The fixed size of the record's `ceremony_identity` array.
  static const int identityLength = 32;

  /// The fixed size of the record's `decimal` array (`SAS_PAIRING_SAS_DECIMAL_LEN`).
  static const int decimalLength = SAS_PAIRING_SAS_DECIMAL_LEN;

  /// The fixed size of the record's `reserved_tail` array.
  static const int reservedTailLength = 2;

  final int available;
  final int reserved;
  final Uint8List ceremonyIdentity;
  final Uint8List decimal;
  final Uint8List reservedTail;
}

/// An action result: the raw status and, only for `SAS_PAIRING_OK`, the copied record.
typedef NativeActionResult = ({int status, NativeActionRecord? action});

/// A presentation result: the raw status and, only for `SAS_PAIRING_OK`, the copied record.
typedef NativePresentationResult = ({
  int status,
  NativePresentationRecord? presentation,
});

/// The ceremony exports the run wrapper uses. Production: [FfiNativeCeremonyApi]; tests supply a
/// deterministic fake.
abstract interface class NativeCeremonyApi {
  /// `sas_pairing_connection_start_initiator`.
  NativeActionResult startInitiator(
    int runtime,
    int host,
    int connection,
    NativeBootstrapBytes local,
    NativeBootstrapBytes? expected,
  );

  /// `sas_pairing_run_authorize_exposure`.
  NativeActionResult authorizeExposure(
    int runtime,
    int host,
    int connection,
    int run,
  );

  /// `sas_pairing_run_expose_key`.
  NativeActionResult exposeKey(int runtime, int host, int connection, int run);

  /// `sas_pairing_run_presentation`.
  NativePresentationResult presentation(
    int runtime,
    int host,
    int connection,
    int run,
  );

  /// `sas_pairing_run_approve_sas` for exactly the 32 [ceremonyIdentity] bytes.
  NativeActionResult approveSas(
    int runtime,
    int host,
    int connection,
    int run,
    Uint8List ceremonyIdentity,
  );

  /// `sas_pairing_run_emit_bootstrap_mac`.
  NativeActionResult emitBootstrapMac(
    int runtime,
    int host,
    int connection,
    int run,
  );

  /// `sas_pairing_run_reject_sas` for exactly the 32 [ceremonyIdentity] bytes.
  NativeActionResult rejectSas(
    int runtime,
    int host,
    int connection,
    int run,
    Uint8List ceremonyIdentity,
  );

  /// `sas_pairing_run_cancel_sas` for exactly the 32 [ceremonyIdentity] bytes.
  NativeActionResult cancelSas(
    int runtime,
    int host,
    int connection,
    int run,
    Uint8List ceremonyIdentity,
  );

  /// `sas_pairing_run_emit_initiator_finish`.
  NativeActionResult emitInitiatorFinish(
    int runtime,
    int host,
    int connection,
    int run,
  );
}

typedef _RunExport =
    int Function(
      int runtime,
      int host,
      int connection,
      int run,
      Pointer<sas_pairing_action_t> outAction,
    );

typedef _DecisionExport =
    int Function(
      int runtime,
      int host,
      int connection,
      int run,
      Pointer<Uint8> ceremonyIdentity,
      Pointer<sas_pairing_action_t> outAction,
    );

/// The production service over the one generated binding object of the loaded image.
final class FfiNativeCeremonyApi implements NativeCeremonyApi {
  FfiNativeCeremonyApi(this._bindings);

  final SasPairingNativeBindings _bindings;

  @override
  NativeActionResult startInitiator(
    int runtime,
    int host,
    int connection,
    NativeBootstrapBytes local,
    NativeBootstrapBytes? expected,
  ) => using((arena) {
    final out = arena<sas_pairing_action_t>();
    final localView = nativeBootstrapView(arena, local);
    final expectedView = expected == null
        ? nullptr.cast<sas_pairing_bootstrap_view_t>()
        : nativeBootstrapView(arena, expected);
    final status = _bindings.sas_pairing_connection_start_initiator(
      runtime,
      host,
      connection,
      localView,
      expectedView,
      out,
    );
    return _action(status, out);
  });

  @override
  NativeActionResult authorizeExposure(
    int runtime,
    int host,
    int connection,
    int run,
  ) => _run(
    _bindings.sas_pairing_run_authorize_exposure,
    runtime,
    host,
    connection,
    run,
  );

  @override
  NativeActionResult exposeKey(
    int runtime,
    int host,
    int connection,
    int run,
  ) => _run(
    _bindings.sas_pairing_run_expose_key,
    runtime,
    host,
    connection,
    run,
  );

  @override
  NativePresentationResult presentation(
    int runtime,
    int host,
    int connection,
    int run,
  ) => using((arena) {
    final out = arena<sas_pairing_sas_presentation_t>();
    final status = _bindings.sas_pairing_run_presentation(
      runtime,
      host,
      connection,
      run,
      out,
    );
    if (status != SAS_PAIRING_OK) return (status: status, presentation: null);
    final record = out.ref;
    // Copy every byte before the memory is freed.
    return (
      status: status,
      presentation: NativePresentationRecord(
        available: record.available,
        reserved: record.reserved,
        ceremonyIdentity: _copy(
          record.ceremony_identity,
          NativePresentationRecord.identityLength,
        ),
        decimal: _copy(record.decimal, NativePresentationRecord.decimalLength),
        reservedTail: _copy(
          record.reserved_tail,
          NativePresentationRecord.reservedTailLength,
        ),
      ),
    );
  });

  @override
  NativeActionResult approveSas(
    int runtime,
    int host,
    int connection,
    int run,
    Uint8List ceremonyIdentity,
  ) => _decide(
    _bindings.sas_pairing_run_approve_sas,
    runtime,
    host,
    connection,
    run,
    ceremonyIdentity,
  );

  @override
  NativeActionResult emitBootstrapMac(
    int runtime,
    int host,
    int connection,
    int run,
  ) => _run(
    _bindings.sas_pairing_run_emit_bootstrap_mac,
    runtime,
    host,
    connection,
    run,
  );

  @override
  NativeActionResult rejectSas(
    int runtime,
    int host,
    int connection,
    int run,
    Uint8List ceremonyIdentity,
  ) => _decide(
    _bindings.sas_pairing_run_reject_sas,
    runtime,
    host,
    connection,
    run,
    ceremonyIdentity,
  );

  @override
  NativeActionResult cancelSas(
    int runtime,
    int host,
    int connection,
    int run,
    Uint8List ceremonyIdentity,
  ) => _decide(
    _bindings.sas_pairing_run_cancel_sas,
    runtime,
    host,
    connection,
    run,
    ceremonyIdentity,
  );

  @override
  NativeActionResult emitInitiatorFinish(
    int runtime,
    int host,
    int connection,
    int run,
  ) => _run(
    _bindings.sas_pairing_run_emit_initiator_finish,
    runtime,
    host,
    connection,
    run,
  );

  NativeActionResult _run(
    _RunExport export,
    int runtime,
    int host,
    int connection,
    int run,
  ) => using((arena) {
    final out = arena<sas_pairing_action_t>();
    return _action(export(runtime, host, connection, run, out), out);
  });

  /// One SAS decision: exactly the 32 identity bytes in temporary native memory, no terminator.
  NativeActionResult _decide(
    _DecisionExport export,
    int runtime,
    int host,
    int connection,
    int run,
    Uint8List ceremonyIdentity,
  ) {
    if (ceremonyIdentity.length != NativePresentationRecord.identityLength) {
      throw ArgumentError.value(
        ceremonyIdentity.length,
        'ceremonyIdentity',
        'a ceremony identity is exactly 32 bytes',
      );
    }
    return using((arena) {
      final identity = arena<Uint8>(NativePresentationRecord.identityLength);
      identity
          .asTypedList(NativePresentationRecord.identityLength)
          .setAll(0, ceremonyIdentity);
      final out = arena<sas_pairing_action_t>();
      return _action(
        export(runtime, host, connection, run, identity, out),
        out,
      );
    });
  }

  /// The record only for `SAS_PAIRING_OK`: a refused call leaves it zeroed, and a zeroed record
  /// is never read as an action.
  static NativeActionResult _action(
    int status,
    Pointer<sas_pairing_action_t> out,
  ) {
    if (status != SAS_PAIRING_OK) return (status: status, action: null);
    final record = out.ref;
    return (
      status: status,
      action: NativeActionRecord(
        event: record.event,
        deadlineKind: record.deadline_kind,
        flags: record.flags,
        reserved: record.reserved,
        run: record.run,
      ),
    );
  }

  static Uint8List _copy(Array<Uint8> array, int length) {
    final copy = Uint8List(length);
    for (var i = 0; i < length; i++) {
      copy[i] = array[i];
    }
    return copy;
  }
}
