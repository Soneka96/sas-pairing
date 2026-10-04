/// The private native result service (P8-D-005 rule 1): the three result-data exports of the
/// frozen ABI v1, with every piece of their FFI memory handled here.
///
/// Private to the package. This is not a second declaration layer: it calls only the generated
/// bindings. It returns raw status values and, only on `SAS_PAIRING_OK`, plain copies of the info
/// record or of the copied field bytes, uninterpreted; the result wrapper decides what they mean.
/// Every native allocation (one zeroed info record, one `size_t` slot and the caller buffer of a
/// copy) is made for one synchronous call and freed before it returns, and no pointer or
/// generated record leaves this file.
library;

import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import 'generated/sas_pairing_bindings.g.dart';

/// A plain Dart copy of one `sas_pairing_result_info_t`, every field raw and uninterpreted. The
/// identity is a copy owned by this value.
final class NativeResultInfoRecord {
  NativeResultInfoRecord({
    required this.ceremonyIdentity,
    required this.peerRole,
    required this.profileVersion,
    required this.requestIdLength,
    required this.peerBootstrapLength,
    required this.sharedContextLength,
    required this.profileIdentifierLength,
  });

  /// The fixed size of the record's `ceremony_identity` array.
  static const int identityLength = 32;

  final Uint8List ceremonyIdentity;
  final int peerRole;
  final int profileVersion;
  final int requestIdLength;
  final int peerBootstrapLength;
  final int sharedContextLength;
  final int profileIdentifierLength;
}

/// An info result: the raw status and, only for `SAS_PAIRING_OK`, the copied record.
typedef NativeResultInfoResult = ({int status, NativeResultInfoRecord? info});

/// A field copy result: the raw status, the `*out_required` value the export wrote, and, only for
/// `SAS_PAIRING_OK`, a copy of the bytes the export wrote into the buffer (never more than the
/// capacity).
typedef NativeResultCopyResult = ({int status, int required, Uint8List? bytes});

/// The result exports the result wrapper uses. Production: [FfiNativeResultApi]; tests supply a
/// deterministic fake.
abstract interface class NativeResultApi {
  /// `sas_pairing_result_info`.
  NativeResultInfoResult resultInfo(int runtime, int result);

  /// `sas_pairing_result_copy` of the raw [field] into a buffer of exactly [capacity] bytes (a
  /// null buffer when [capacity] is 0).
  NativeResultCopyResult resultCopy(
    int runtime,
    int result,
    int field,
    int capacity,
  );

  /// `sas_pairing_result_destroy`.
  int resultDestroy(int runtime, int result);
}

/// The production service over the one generated binding object of the loaded image.
final class FfiNativeResultApi implements NativeResultApi {
  FfiNativeResultApi(this._bindings);

  final SasPairingNativeBindings _bindings;

  @override
  NativeResultInfoResult resultInfo(int runtime, int result) => using((arena) {
    final out = arena<sas_pairing_result_info_t>();
    final status = _bindings.sas_pairing_result_info(runtime, result, out);
    // A refused call leaves the record zeroed, and a zeroed record is never read as info.
    if (status != SAS_PAIRING_OK) return (status: status, info: null);
    final record = out.ref;
    final identity = Uint8List(NativeResultInfoRecord.identityLength);
    for (var i = 0; i < identity.length; i++) {
      identity[i] = record.ceremony_identity[i];
    }
    // Copy every field before the memory is freed.
    return (
      status: status,
      info: NativeResultInfoRecord(
        ceremonyIdentity: identity,
        peerRole: record.peer_role,
        profileVersion: record.profile_version,
        requestIdLength: record.request_id_len,
        peerBootstrapLength: record.peer_bootstrap_len,
        sharedContextLength: record.shared_context_len,
        profileIdentifierLength: record.profile_identifier_len,
      ),
    );
  });

  @override
  NativeResultCopyResult resultCopy(
    int runtime,
    int result,
    int field,
    int capacity,
  ) {
    if (capacity < 0) {
      throw ArgumentError.value(capacity, 'capacity', 'must not be negative');
    }
    return using((arena) {
      // Exactly the requested capacity: no terminator, no slack. A zero capacity passes a null
      // buffer, which the export accepts only with capacity 0.
      final buffer = capacity == 0
          ? nullptr.cast<Uint8>()
          : arena<Uint8>(capacity);
      final required = arena<Size>();
      final status = _bindings.sas_pairing_result_copy(
        runtime,
        result,
        field,
        buffer,
        capacity,
        required,
      );
      final length = required.value;
      if (status != SAS_PAIRING_OK) {
        return (status: status, required: length, bytes: null);
      }
      // Never read past the buffer, whatever the export reported (a `size_t` above the Dart
      // `int` range reads as negative).
      final written = length >= 0 && length < capacity ? length : capacity;
      return (
        status: status,
        required: length,
        bytes: written == 0
            ? Uint8List(0)
            : Uint8List.fromList(buffer.asTypedList(written)),
      );
    });
  }

  @override
  int resultDestroy(int runtime, int result) =>
      _bindings.sas_pairing_result_destroy(runtime, result);
}
