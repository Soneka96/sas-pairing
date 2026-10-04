// P8.3 FFI marshalling of the private native network service (P8-D-003 C, Q): the production
// FfiNativeNetworkApi runs over the generated bindings, whose five network symbols resolve to Dart
// callbacks that observe exactly what crossed the C boundary. No native library is loaded.
import 'dart:ffi';
import 'dart:typed_data';

import 'package:sas_pairing/src/native/generated/sas_pairing_bindings.g.dart';
import 'package:sas_pairing/src/native/native_bootstrap.dart';
import 'package:sas_pairing/src/native/native_network_api.dart';
import 'package:test/test.dart';

/// What one bytes view held during the call: `[length, bytes]`, bytes null for a null pointer.
typedef SeenBytes = List<Object?>;

SeenBytes readView(sas_pairing_bytes_view_t view) => [
  view.len,
  view.data == nullptr ? null : List.of(view.data.asTypedList(view.len)),
];

List<SeenBytes>? readBootstrap(Pointer<sas_pairing_bootstrap_view_t> view) =>
    view == nullptr
    ? null
    : [
        readView(view.ref.application_identity),
        readView(view.ref.key_algorithm),
        readView(view.ref.public_key),
        readView(view.ref.shared_context),
      ];

typedef DriveNative =
    Int32 Function(
      Uint64,
      Uint64,
      Pointer<sas_pairing_event_t>,
      Size,
      Pointer<Size>,
      Pointer<Int32>,
    );

/// Fake C exports for the five network functions.
final class FakeNetworkExports {
  final List<String> seen = [];
  final List<NativeCallable<Function>> _callables = [];

  // Attach.
  int attachStatus = 0;
  int? slotWrite; // null: leave the slot unchanged
  final List<int> slotOnEntry = [];
  final List<List<SeenBytes>?> locals = [];
  final List<List<SeenBytes>?> expecteds = [];
  final List<int> slotAddresses = [];

  // Drive and recheck.
  int driveStatus = 0;
  int driveCount = 0;
  int driveFailure = 0;
  void Function(Pointer<sas_pairing_event_t> events)? fill;
  final List<int> capacities = [];
  final List<int> countOnEntryAddresses = [];

  int cleanupStatus = 0;
  final List<List<int>> cleanupArguments = [];

  late final SasPairingNativeBindings bindings =
      SasPairingNativeBindings.fromLookup(
        <T extends NativeType>(String symbol) => _lookup(symbol).cast<T>(),
      );

  Pointer<NativeFunction<Function>> _keep<F extends Function>(
    NativeCallable<F> callable,
  ) {
    _callables.add(callable);
    return callable.nativeFunction;
  }

  NativeCallable<DriveNative> _drive(String symbol) =>
      NativeCallable<DriveNative>.isolateLocal((
        int runtime,
        int host,
        Pointer<sas_pairing_event_t> events,
        int capacity,
        Pointer<Size> outCount,
        Pointer<Int32> outFailure,
      ) {
        seen.add('$symbol[$runtime, $host]');
        capacities.add(capacity);
        countOnEntryAddresses.add(outCount.address);
        fill?.call(events);
        outCount.value = driveCount;
        outFailure.value = driveFailure;
        return driveStatus;
      }, exceptionalReturn: -1);

  Pointer<NativeFunction<Function>> _lookup(String symbol) => switch (symbol) {
    'sas_pairing_host_attach_windows_listener' => _keep(
      NativeCallable<
        Int32 Function(
          Uint64,
          Uint64,
          Pointer<UintPtr>,
          Pointer<sas_pairing_bootstrap_view_t>,
          Pointer<sas_pairing_bootstrap_view_t>,
        )
      >.isolateLocal((
        int runtime,
        int host,
        Pointer<UintPtr> slot,
        Pointer<sas_pairing_bootstrap_view_t> local,
        Pointer<sas_pairing_bootstrap_view_t> expected,
      ) {
        seen.add('$symbol[$runtime, $host]');
        slotAddresses.add(slot.address);
        slotOnEntry.add(slot.value);
        locals.add(readBootstrap(local));
        expecteds.add(readBootstrap(expected));
        final write = slotWrite;
        if (write != null) slot.value = write;
        return attachStatus;
      }, exceptionalReturn: -1),
    ),
    'sas_pairing_host_detach_listener' => _keep(
      NativeCallable<Int32 Function(Uint64, Uint64)>.isolateLocal((
        int runtime,
        int host,
      ) {
        seen.add('$symbol[$runtime, $host]');
        return cleanupStatus;
      }, exceptionalReturn: -1),
    ),
    'sas_pairing_host_drive' => _keep(_drive(symbol)),
    'sas_pairing_host_recheck_after_resume' => _keep(_drive(symbol)),
    'sas_pairing_connection_close' => _keep(
      NativeCallable<Int32 Function(Uint64, Uint64, Uint64)>.isolateLocal((
        int runtime,
        int host,
        int connection,
      ) {
        seen.add('$symbol[$runtime, $host, $connection]');
        return cleanupStatus;
      }, exceptionalReturn: -1),
    ),
    _ => throw StateError('unexpected lookup of $symbol'),
  };

  void close() {
    for (final callable in _callables) {
      callable.close();
    }
  }
}

NativeBootstrapBytes bootstrapBytes(
  List<int> identity,
  List<int> algorithm,
  List<int> key,
  List<int> context,
) => (
  applicationIdentity: Uint8List.fromList(identity),
  keyAlgorithm: Uint8List.fromList(algorithm),
  publicKey: Uint8List.fromList(key),
  sharedContext: Uint8List.fromList(context),
);

void main() {
  late FakeNetworkExports exports;
  late FfiNativeNetworkApi api;

  setUp(() {
    exports = FakeNetworkExports();
    api = FfiNativeNetworkApi(exports.bindings);
  });
  tearDown(() => exports.close());

  group('attach', () {
    test(
      'the offered socket is in a typed in/out slot; the slot is read back',
      () {
        exports
          ..slotWrite = SAS_PAIRING_SOCKET_INVALID
          ..attachStatus = 0;
        final local = bootstrapBytes([1], [2], [3], [4]);
        expect(api.attachWindowsListener(7, 8, 0x1234, local, null), (
          status: 0,
          socketAfterCall: -1,
        ));
        expect(exports.slotOnEntry, [0x1234]);
        expect(exports.seen, [
          'sas_pairing_host_attach_windows_listener[7, 8]',
        ]);
        expect(exports.slotAddresses.single % sizeOf<UintPtr>(), 0);
        expect(exports.slotAddresses.single, isNot(0));
      },
    );

    test('an unchanged slot and another value are both reported raw', () {
      final local = bootstrapBytes([1], [2], [3], []);
      exports
        ..slotWrite = null
        ..attachStatus = 203;
      expect(api.attachWindowsListener(1, 2, 0x55, local, null), (
        status: 203,
        socketAfterCall: 0x55,
      ));
      exports
        ..slotWrite = 0x99
        ..attachStatus = 0;
      expect(api.attachWindowsListener(1, 2, 0x55, local, null), (
        status: 0,
        socketAfterCall: 0x99,
      ));
    });

    test(
      'Bootstrap fields cross as exact bytes with exact lengths, including 00 80 FF',
      () {
        final local = bootstrapBytes(
          [0x00, 0x80, 0xFF, 0x00],
          [0x78, 0x00, 0x32],
          List.generate(32, (i) => 255 - i),
          [0x00],
        );
        final expected = bootstrapBytes(
          [0xFF],
          [0x80, 0x80],
          [0x00],
          [0x01, 0x00],
        );
        api.attachWindowsListener(1, 2, 3, local, expected);
        expect(exports.locals.single, [
          [
            4,
            [0x00, 0x80, 0xFF, 0x00],
          ],
          [
            3,
            [0x78, 0x00, 0x32],
          ],
          [32, List.generate(32, (i) => 255 - i)],
          [
            1,
            [0x00],
          ],
        ]);
        expect(exports.expecteds.single, [
          [
            1,
            [0xFF],
          ],
          [
            2,
            [0x80, 0x80],
          ],
          [
            1,
            [0x00],
          ],
          [
            2,
            [0x01, 0x00],
          ],
        ]);
      },
    );

    test(
      'empty fields are null pointers with length 0; no expected is a null pointer',
      () {
        api.attachWindowsListener(
          1,
          2,
          3,
          bootstrapBytes([], [1], [], []),
          null,
        );
        expect(exports.locals.single, [
          [0, null],
          [
            1,
            [1],
          ],
          [0, null],
          [0, null],
        ]);
        expect(exports.expecteds.single, isNull);
      },
    );

    test('a 16,385-byte non-text field crosses unchanged', () {
      final key = [for (var i = 0; i < 16385; i++) (i * 31 + 7) & 0xFF];
      api.attachWindowsListener(
        1,
        2,
        3,
        bootstrapBytes([1], [2], key, []),
        null,
      );
      expect(exports.locals.single![2][0], 16385);
      expect(exports.locals.single![2][1], orderedEquals(key));
    });
  });

  group('drive and recheck', () {
    void writeRecord(sas_pairing_event_t record, int seed) {
      record
        ..kind = seed
        ..step_kind = seed + 1
        ..protocol_event = seed + 2
        ..reason = seed + 3
        ..deadline_kind = seed + 4
        ..cancel_state = seed + 5
        ..cancel_reason = seed + 6
        ..flags = 0xFFFFFFFF
        ..connection = -1
        ..run = -0x7FFFFFFFFFFFFFFF - 1
        ..result = seed + 7
        ..request_id_len = 64
        ..reserved = 0xFFFFFFFF;
      for (var i = 0; i < 64; i++) {
        record.request_id[i] = (seed + i) & 0xFF;
      }
    }

    test(
      'capacity is always 17; every produced record is copied field by field',
      () {
        exports
          ..driveCount = 2
          ..driveFailure = 404
          ..fill = (events) {
            writeRecord(events[0], 10);
            writeRecord(events[1], 20);
          };
        final result = api.drive(3, 4);
        expect(exports.capacities, [17]);
        expect(exports.seen, ['sas_pairing_host_drive[3, 4]']);
        expect(result.status, 0);
        expect(result.count, 2);
        expect(result.failure, 404);
        expect(result.events, hasLength(2));
        final e = result.events[1];
        expect(
          [
            e.kind,
            e.stepKind,
            e.protocolEvent,
            e.reason,
            e.deadlineKind,
            e.cancelState,
            e.cancelReason,
          ],
          [20, 21, 22, 23, 24, 25, 26],
        );
        expect(e.flags, 0xFFFFFFFF);
        expect(e.connection, -1, reason: 'uint64 all-ones bit pattern');
        expect(e.run, -0x7FFFFFFFFFFFFFFF - 1);
        expect(e.result, 27);
        expect(e.requestIdLength, 64);
        expect(e.reserved, 0xFFFFFFFF);
        expect(e.requestIdBytes, [
          for (var i = 0; i < 64; i++) (20 + i) & 0xFF,
        ]);
      },
    );

    test(
      'the record memory starts zeroed; records past out_count are not read',
      () {
        exports
          ..driveCount = 1
          ..fill = (events) {
            events[0].kind = 1;
            events[0].connection = 100;
            writeRecord(events[1], 50); // past out_count: never copied
          };
        final result = api.drive(1, 2);
        expect(result.events, hasLength(1));
        final e = result.events.single;
        expect(e.kind, 1);
        expect(e.connection, 100);
        expect(
          [e.stepKind, e.flags, e.run, e.result, e.requestIdLength, e.reserved],
          [0, 0, 0, 0, 0, 0],
        );
        expect(e.requestIdBytes, List.filled(64, 0));
      },
    );

    test(
      'a nonzero return copies no events; a count above 17 copies at most 17',
      () {
        exports
          ..driveStatus = 402
          ..driveCount = 3;
        expect(api.drive(1, 2), (
          status: 402,
          count: 3,
          failure: 0,
          events: const <NativeEventRecord>[],
        ));
        exports
          ..driveStatus = 0
          ..driveCount = 40
          ..fill = null;
        final result = api.drive(1, 2);
        expect(
          result.count,
          40,
          reason: 'reported raw for the wrapper to refuse',
        );
        expect(result.events, hasLength(17));
      },
    );

    test('recheck calls only the recheck export, with the same contract', () {
      exports.driveCount = 0;
      final result = api.recheckAfterResume(5, 6);
      expect(exports.seen, ['sas_pairing_host_recheck_after_resume[5, 6]']);
      expect(exports.capacities, [17]);
      expect([result.status, result.count, result.failure], [0, 0, 0]);
      expect(result.events, isEmpty);
    });
  });

  test('cleanup exports pass their handles and return the raw status', () {
    exports.cleanupStatus = 104;
    expect(api.detachListener(1, 2), 104);
    expect(api.connectionClose(3, 4, -1), 104);
    expect(exports.seen, [
      'sas_pairing_host_detach_listener[1, 2]',
      'sas_pairing_connection_close[3, 4, -1]',
    ]);
  });
}
