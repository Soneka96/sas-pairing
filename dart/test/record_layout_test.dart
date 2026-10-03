// The generated FFI records have exactly the frozen 64-bit ABI v1 sizes and fixed array
// capacities (manifest §7, P7-D-008, P7-D-010 to P7-D-012).
import 'dart:ffi';

import 'package:ffi/ffi.dart';
import 'package:sas_pairing/src/native/abi_v1.dart';
import 'package:sas_pairing/src/native/generated/sas_pairing_bindings.g.dart';
import 'package:test/test.dart';

import 'support/record_layout.dart';

/// The frozen sizes, written out independently of the package tables.
const Map<String, int> frozenSizes = {
  'sas_pairing_bytes_view_t': 16,
  'sas_pairing_bootstrap_view_t': 64,
  'sas_pairing_event_t': 128,
  'sas_pairing_result_info_t': 56,
  'sas_pairing_action_t': 24,
  'sas_pairing_sas_presentation_t': 56,
};

void main() {
  test('this test process is the supported 64-bit target', () {
    expect(sizeOf<IntPtr>(), supportedPointerSize);
    expect(sizeOf<Pointer<Uint8>>(), 8);
    expect(sizeOf<Size>(), 8);
    expect(sizeOf<UintPtr>(), 8);
  });

  test('every generated record has its frozen size', () {
    expect(abiV1RecordSizes, frozenSizes);
    for (final entry in frozenSizes.entries) {
      expect(generatedRecordSizes[entry.key], entry.value, reason: entry.key);
    }
  });

  test('fixed arrays hold exactly their frozen capacity', () {
    // Capacities: request ID 64, ceremony identity 32, SAS decimal 14, reserved tail 2.
    final event = calloc<sas_pairing_event_t>();
    final info = calloc<sas_pairing_result_info_t>();
    final sas = calloc<sas_pairing_sas_presentation_t>();
    addTearDown(() {
      calloc.free(event);
      calloc.free(info);
      calloc.free(sas);
    });
    void expectCapacity(Array<Uint8> array, int capacity) {
      array[capacity - 1] = 1;
      expect(array[capacity - 1], 1);
      expect(() => array[capacity], throwsRangeError);
    }

    expectCapacity(
      event.ref.request_id,
      abiV1Scalars['SAS_PAIRING_MAX_REQUEST_ID_LEN']!,
    );
    expectCapacity(event.ref.request_id, 64);
    expectCapacity(info.ref.ceremony_identity, 32);
    expectCapacity(sas.ref.ceremony_identity, 32);
    expectCapacity(
      sas.ref.decimal,
      abiV1Scalars['SAS_PAIRING_SAS_DECIMAL_LEN']!,
    );
    expectCapacity(sas.ref.decimal, 14);
    expectCapacity(sas.ref.reserved_tail, 2);
  });

  test('no record has padding: its measured fields tile it exactly', () {
    for (final record in recordFieldWriters.entries) {
      var next = 0;
      for (final field in record.value.keys) {
        final measured = measureField(record.key, field);
        expect(
          measured.offset,
          next,
          reason: '${record.key}.$field follows contiguously',
        );
        next = measured.offset + measured.size;
      }
      expect(
        next,
        frozenSizes[record.key],
        reason: '${record.key} has no tail padding',
      );
    }
  });
}
