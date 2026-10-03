// Measures the generated FFI record layouts from memory: each field is written through its
// generated accessor into a zeroed record, and the bytes that changed give its offset and size.
import 'dart:ffi';

import 'package:ffi/ffi.dart';
import 'package:sas_pairing/src/native/generated/sas_pairing_bindings.g.dart';

/// `sizeOf` of each generated record, by C typedef name.
final Map<String, int> generatedRecordSizes = <String, int>{
  'sas_pairing_bytes_view_t': sizeOf<sas_pairing_bytes_view_t>(),
  'sas_pairing_bootstrap_view_t': sizeOf<sas_pairing_bootstrap_view_t>(),
  'sas_pairing_event_t': sizeOf<sas_pairing_event_t>(),
  'sas_pairing_result_info_t': sizeOf<sas_pairing_result_info_t>(),
  'sas_pairing_action_t': sizeOf<sas_pairing_action_t>(),
  'sas_pairing_sas_presentation_t': sizeOf<sas_pairing_sas_presentation_t>(),
};

typedef FieldWriter = void Function(Pointer<Uint8> record);

// Integer stores truncate to the field width, so -1 sets every byte of any integer field.
final Pointer<Uint8> _allOnes = Pointer<Uint8>.fromAddress(-1);

void _fill(Array<Uint8> array, int length) {
  for (var i = 0; i < length; i++) {
    array[i] = 0xff;
  }
}

void _fillView(sas_pairing_bytes_view_t view) => view
  ..data = _allOnes
  ..len = -1;

sas_pairing_bytes_view_t _bytes(Pointer<Uint8> p) =>
    p.cast<sas_pairing_bytes_view_t>().ref;
sas_pairing_bootstrap_view_t _boot(Pointer<Uint8> p) =>
    p.cast<sas_pairing_bootstrap_view_t>().ref;
sas_pairing_event_t _event(Pointer<Uint8> p) =>
    p.cast<sas_pairing_event_t>().ref;
sas_pairing_result_info_t _info(Pointer<Uint8> p) =>
    p.cast<sas_pairing_result_info_t>().ref;
sas_pairing_action_t _action(Pointer<Uint8> p) =>
    p.cast<sas_pairing_action_t>().ref;
sas_pairing_sas_presentation_t _sas(Pointer<Uint8> p) =>
    p.cast<sas_pairing_sas_presentation_t>().ref;

/// A writer for every field of every generated record, in declaration order. Fixed arrays are
/// filled exactly to their frozen length; an index past it throws (see the layout test).
final Map<String, Map<String, FieldWriter>> recordFieldWriters = {
  'sas_pairing_bytes_view_t': {
    'data': (p) => _bytes(p).data = _allOnes,
    'len': (p) => _bytes(p).len = -1,
  },
  'sas_pairing_bootstrap_view_t': {
    'application_identity': (p) => _fillView(_boot(p).application_identity),
    'key_algorithm': (p) => _fillView(_boot(p).key_algorithm),
    'public_key': (p) => _fillView(_boot(p).public_key),
    'shared_context': (p) => _fillView(_boot(p).shared_context),
  },
  'sas_pairing_event_t': {
    'kind': (p) => _event(p).kind = -1,
    'step_kind': (p) => _event(p).step_kind = -1,
    'protocol_event': (p) => _event(p).protocol_event = -1,
    'reason': (p) => _event(p).reason = -1,
    'deadline_kind': (p) => _event(p).deadline_kind = -1,
    'cancel_state': (p) => _event(p).cancel_state = -1,
    'cancel_reason': (p) => _event(p).cancel_reason = -1,
    'flags': (p) => _event(p).flags = -1,
    'connection': (p) => _event(p).connection = -1,
    'run': (p) => _event(p).run = -1,
    'result': (p) => _event(p).result = -1,
    'request_id_len': (p) => _event(p).request_id_len = -1,
    'reserved': (p) => _event(p).reserved = -1,
    'request_id': (p) => _fill(_event(p).request_id, 64),
  },
  'sas_pairing_result_info_t': {
    'ceremony_identity': (p) => _fill(_info(p).ceremony_identity, 32),
    'peer_role': (p) => _info(p).peer_role = -1,
    'profile_version': (p) => _info(p).profile_version = -1,
    'request_id_len': (p) => _info(p).request_id_len = -1,
    'peer_bootstrap_len': (p) => _info(p).peer_bootstrap_len = -1,
    'shared_context_len': (p) => _info(p).shared_context_len = -1,
    'profile_identifier_len': (p) => _info(p).profile_identifier_len = -1,
  },
  'sas_pairing_action_t': {
    'event': (p) => _action(p).event = -1,
    'deadline_kind': (p) => _action(p).deadline_kind = -1,
    'flags': (p) => _action(p).flags = -1,
    'reserved': (p) => _action(p).reserved = -1,
    'run': (p) => _action(p).run = -1,
  },
  'sas_pairing_sas_presentation_t': {
    'available': (p) => _sas(p).available = -1,
    'reserved': (p) => _sas(p).reserved = -1,
    'ceremony_identity': (p) => _fill(_sas(p).ceremony_identity, 32),
    'decimal': (p) => _fill(_sas(p).decimal, 14),
    'reserved_tail': (p) => _fill(_sas(p).reserved_tail, 2),
  },
};

/// The measured (offset, size) of [field] in [record]: the one contiguous run of bytes the
/// field's writer changes in a zeroed record.
({int offset, int size}) measureField(String record, String field) {
  final size = generatedRecordSizes[record]!;
  final memory = calloc<Uint8>(size);
  try {
    recordFieldWriters[record]![field]!(memory);
    final touched = [
      for (var i = 0; i < size; i++)
        if (memory[i] != 0) i,
    ];
    if (touched.isEmpty) throw StateError('$record.$field wrote nothing');
    final offset = touched.first;
    final length = touched.last - offset + 1;
    if (touched.length != length) {
      throw StateError('$record.$field wrote non-contiguous bytes $touched');
    }
    return (offset: offset, size: length);
  } finally {
    calloc.free(memory);
  }
}
