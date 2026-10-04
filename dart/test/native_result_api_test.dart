// P8.5 FFI marshalling of the private native result service (P8-D-005 rule 1): the production
// FfiNativeResultApi runs over the generated bindings, whose three result symbols resolve to Dart
// callbacks that observe exactly what crossed the C boundary. No native library is loaded.
import 'dart:ffi';
import 'dart:typed_data';

import 'package:sas_pairing/src/native/generated/sas_pairing_bindings.g.dart';
import 'package:sas_pairing/src/native/native_result_api.dart';
import 'package:test/test.dart';

typedef InfoNative =
    Int32 Function(Uint64, Uint64, Pointer<sas_pairing_result_info_t>);
typedef CopyNative =
    Int32 Function(Uint64, Uint64, Uint32, Pointer<Uint8>, Size, Pointer<Size>);
typedef DestroyNative = Int32 Function(Uint64, Uint64);

/// Fake C exports for the three result functions.
final class FakeResultExports {
  final List<String> seen = [];
  final List<NativeCallable<Function>> _callables = [];

  int status = 0;

  /// What info writes into `*out_info` (also on a failing status, to prove it is ignored).
  void Function(Pointer<sas_pairing_result_info_t> out)? fillInfo;
  final List<List<int>> infoOnEntry = [];
  final List<int> infoAddresses = [];

  /// What copy reports in `*out_required` and the bytes it writes into the buffer.
  int required = 0;
  List<int> write = const [];
  final List<int> bufferAddresses = [];
  final List<int> capacities = [];
  final List<int> fields = [];
  final List<List<int>> bufferOnEntry = [];
  final List<int> requiredOnEntry = [];
  final List<int> requiredAddresses = [];

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

  Pointer<NativeFunction<Function>> _lookup(String symbol) => switch (symbol) {
    'sas_pairing_result_info' => _keep(
      NativeCallable<InfoNative>.isolateLocal((
        int runtime,
        int result,
        Pointer<sas_pairing_result_info_t> out,
      ) {
        seen.add('$symbol[$runtime, $result]');
        infoAddresses.add(out.address);
        infoOnEntry.add(
          List.of(
            out.cast<Uint8>().asTypedList(sizeOf<sas_pairing_result_info_t>()),
          ),
        );
        fillInfo?.call(out);
        return status;
      }, exceptionalReturn: -1),
    ),
    'sas_pairing_result_copy' => _keep(
      NativeCallable<CopyNative>.isolateLocal((
        int runtime,
        int result,
        int field,
        Pointer<Uint8> buffer,
        int capacity,
        Pointer<Size> outRequired,
      ) {
        seen.add('$symbol[$runtime, $result, $field]');
        fields.add(field);
        capacities.add(capacity);
        bufferAddresses.add(buffer.address);
        bufferOnEntry.add(
          buffer == nullptr ? const [] : List.of(buffer.asTypedList(capacity)),
        );
        requiredAddresses.add(outRequired.address);
        requiredOnEntry.add(outRequired.value);
        outRequired.value = required;
        for (var i = 0; i < write.length && i < capacity; i++) {
          buffer[i] = write[i];
        }
        return status;
      }, exceptionalReturn: -1),
    ),
    'sas_pairing_result_destroy' => _keep(
      NativeCallable<DestroyNative>.isolateLocal((int runtime, int result) {
        seen.add('$symbol[$runtime, $result]');
        return status;
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

void fill(
  Pointer<sas_pairing_result_info_t> out, {
  List<int>? identity,
  int role = 2,
  int version = 1,
  int requestId = 16,
  int bootstrap = 100,
  int context = 0,
  int profile = 38,
}) {
  final record = out.ref;
  final bytes = identity ?? List.generate(32, (i) => 0xF0 ^ i);
  for (var i = 0; i < 32; i++) {
    record.ceremony_identity[i] = bytes[i];
  }
  record
    ..peer_role = role
    ..profile_version = version
    ..request_id_len = requestId
    ..peer_bootstrap_len = bootstrap
    ..shared_context_len = context
    ..profile_identifier_len = profile;
}

void main() {
  late FakeResultExports exports;
  late FfiNativeResultApi api;

  setUp(() {
    exports = FakeResultExports();
    api = FfiNativeResultApi(exports.bindings);
  });
  tearDown(() => exports.close());

  group('info', () {
    test('OK: every field copied from one zeroed, aligned record', () {
      exports
        ..status = 0
        ..fillInfo = (out) => fill(
          out,
          role: 1,
          version: 0xFFFFFFFF,
          requestId: 64,
          bootstrap: 16384,
          context: 8192,
          profile: 0xFFFFFFFF,
        );
      final answer = api.resultInfo(0x8000000000000001, 0xFFFFFFFFFFFFFFFE);
      expect(exports.seen, [
        'sas_pairing_result_info[${0x8000000000000001}, ${0xFFFFFFFFFFFFFFFE}]',
      ]);
      expect(exports.infoOnEntry.single, List.filled(56, 0));
      expect(exports.infoAddresses.single % 4, 0);
      expect(answer.status, 0);
      final info = answer.info!;
      expect(info.ceremonyIdentity, List.generate(32, (i) => 0xF0 ^ i));
      expect(
        [
          info.peerRole,
          info.profileVersion,
          info.requestIdLength,
          info.peerBootstrapLength,
          info.sharedContextLength,
          info.profileIdentifierLength,
        ],
        [1, 0xFFFFFFFF, 64, 16384, 8192, 0xFFFFFFFF],
      );
    });

    test('the identity is a copy that outlives the native record', () {
      exports
        ..status = 0
        ..fillInfo = (out) => fill(out, identity: List.filled(32, 0));
      final first = api.resultInfo(1, 2).info!.ceremonyIdentity;
      exports.fillInfo = (out) => fill(out, identity: List.filled(32, 9));
      api.resultInfo(1, 2);
      expect(first, List.filled(32, 0));
    });

    for (final failing in [3, 900, 777]) {
      test(
        'status $failing: no record is read, even if the export wrote one',
        () {
          exports
            ..status = failing
            ..fillInfo = fill;
          final answer = api.resultInfo(1, 2);
          expect(answer.status, failing);
          expect(answer.info, isNull);
        },
      );
    }
  });

  group('copy', () {
    test('each of the four field constants reaches native unchanged', () {
      exports.status = 0;
      for (final field in [
        SAS_PAIRING_RESULT_FIELD_REQUEST_ID,
        SAS_PAIRING_RESULT_FIELD_AUTHENTICATED_PEER_BOOTSTRAP,
        SAS_PAIRING_RESULT_FIELD_AUTHENTICATED_SHARED_CONTEXT,
        SAS_PAIRING_RESULT_FIELD_PROFILE_IDENTIFIER,
      ]) {
        api.resultCopy(1, 2, field, 0);
      }
      expect(exports.fields, [1, 2, 3, 4]);
      expect(exports.seen.first, 'sas_pairing_result_copy[1, 2, 1]');
    });

    test(
      'zero length: a null buffer with capacity 0, required 0, empty bytes',
      () {
        exports
          ..status = 0
          ..required = 0;
        final answer = api.resultCopy(
          1,
          2,
          SAS_PAIRING_RESULT_FIELD_AUTHENTICATED_SHARED_CONTEXT,
          0,
        );
        expect(exports.bufferAddresses.single, 0, reason: 'nullptr');
        expect(exports.capacities.single, 0);
        expect(answer.status, 0);
        expect(answer.required, 0);
        expect(answer.bytes, isA<Uint8List>());
        expect(answer.bytes, isEmpty);
      },
    );

    test(
      'nonzero length: an exact-capacity zeroed buffer, bytes copied exactly',
      () {
        final bytes = [0x00, 0x80, 0xFF, 0x00, 0x41, 0x00, 0x00];
        exports
          ..status = 0
          ..required = bytes.length
          ..write = bytes;
        final answer = api.resultCopy(
          1,
          2,
          SAS_PAIRING_RESULT_FIELD_AUTHENTICATED_PEER_BOOTSTRAP,
          bytes.length,
        );
        expect(exports.capacities.single, bytes.length);
        expect(exports.bufferAddresses.single, isNot(0));
        expect(exports.bufferOnEntry.single, List.filled(bytes.length, 0));
        expect(exports.requiredAddresses.single % sizeOf<Size>(), 0);
        expect(answer.required, bytes.length);
        expect(answer.bytes, bytes, reason: 'no terminator, no truncation');
      },
    );

    test('a large non-text field is copied with its full length', () {
      final bytes = List.generate(16384, (i) => (i * 7) & 0xFF);
      exports
        ..status = 0
        ..required = bytes.length
        ..write = bytes;
      final answer = api.resultCopy(1, 2, 2, bytes.length);
      expect(answer.bytes, bytes);
    });

    test('BUFFER_TOO_SMALL: the required value is reported, no bytes', () {
      exports
        ..status = 300
        ..required = 99
        ..write = List.filled(10, 1);
      final answer = api.resultCopy(1, 2, 2, 10);
      expect(answer.status, 300);
      expect(answer.required, 99);
      expect(answer.bytes, isNull);
    });

    test(
      'a failing status reports no bytes even if the buffer was written',
      () {
        exports
          ..status = 3
          ..required = 4
          ..write = [1, 2, 3, 4];
        final answer = api.resultCopy(1, 2, 1, 4);
        expect(answer.status, 3);
        expect(answer.bytes, isNull);
      },
    );

    test(
      'OK with a required length above the capacity never reads past it',
      () {
        exports
          ..status = 0
          ..required = 9
          ..write = [1, 2, 3, 4];
        final answer = api.resultCopy(1, 2, 1, 4);
        expect(answer.required, 9);
        expect(answer.bytes, [1, 2, 3, 4]);
      },
    );

    test(
      'OK with a required length below the capacity copies only that many',
      () {
        exports
          ..status = 0
          ..required = 2
          ..write = [7, 8, 9, 10];
        final answer = api.resultCopy(1, 2, 1, 4);
        expect(answer.required, 2);
        expect(answer.bytes, [7, 8]);
      },
    );

    test('a negative capacity never reaches native', () {
      expect(() => api.resultCopy(1, 2, 1, -1), throwsArgumentError);
      expect(exports.seen, isEmpty);
    });
  });

  group('destroy', () {
    test(
      'OK and failing statuses are returned raw, with the exact handles',
      () {
        for (final code in [0, 3, 900, 31337]) {
          exports.status = code;
          expect(api.resultDestroy(7, 0xFFFFFFFFFFFFFFFF), code);
        }
        expect(exports.seen.toSet(), {
          'sas_pairing_result_destroy[7, ${0xFFFFFFFFFFFFFFFF}]',
        });
        expect(exports.seen, hasLength(4));
      },
    );
  });
}
