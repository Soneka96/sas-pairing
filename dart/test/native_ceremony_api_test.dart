// P8.4 FFI marshalling of the private native ceremony service (P8-D-004 rule 8): the production
// FfiNativeCeremonyApi runs over the generated bindings, whose nine ceremony symbols resolve to
// Dart callbacks that observe exactly what crossed the C boundary. No native library is loaded.
import 'dart:ffi';
import 'dart:typed_data';

import 'package:sas_pairing/src/native/generated/sas_pairing_bindings.g.dart';
import 'package:sas_pairing/src/native/native_bootstrap.dart';
import 'package:sas_pairing/src/native/native_ceremony_api.dart';
import 'package:test/test.dart';

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

List<int> readAction(Pointer<sas_pairing_action_t> out) => [
  out.ref.event,
  out.ref.deadline_kind,
  out.ref.flags,
  out.ref.reserved,
  out.ref.run,
];

typedef StartNative =
    Int32 Function(
      Uint64,
      Uint64,
      Uint64,
      Pointer<sas_pairing_bootstrap_view_t>,
      Pointer<sas_pairing_bootstrap_view_t>,
      Pointer<sas_pairing_action_t>,
    );
typedef RunNative =
    Int32 Function(
      Uint64,
      Uint64,
      Uint64,
      Uint64,
      Pointer<sas_pairing_action_t>,
    );
typedef DecideNative =
    Int32 Function(
      Uint64,
      Uint64,
      Uint64,
      Uint64,
      Pointer<Uint8>,
      Pointer<sas_pairing_action_t>,
    );
typedef PresentNative =
    Int32 Function(
      Uint64,
      Uint64,
      Uint64,
      Uint64,
      Pointer<sas_pairing_sas_presentation_t>,
    );

/// Fake C exports for the nine ceremony functions.
final class FakeCeremonyExports {
  final List<String> seen = [];
  final List<NativeCallable<Function>> _callables = [];

  int status = 0;

  /// What the export writes into `*out_action` (also on a failing status, to prove it is ignored).
  List<int> writeAction = const [0, 0, 0, 0, 0];
  final List<List<int>> actionOnEntry = [];
  final List<int> actionAddresses = [];

  final List<List<SeenBytes>?> locals = [];
  final List<List<SeenBytes>?> expecteds = [];

  final List<List<int>> identities = [];
  final List<int> identityAddresses = [];

  void Function(Pointer<sas_pairing_sas_presentation_t> out)? fillPresentation;
  final List<List<int>> presentationOnEntry = [];
  final List<int> presentationAddresses = [];

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

  int _answer(Pointer<sas_pairing_action_t> out) {
    actionAddresses.add(out.address);
    actionOnEntry.add(readAction(out));
    out.ref
      ..event = writeAction[0]
      ..deadline_kind = writeAction[1]
      ..flags = writeAction[2]
      ..reserved = writeAction[3]
      ..run = writeAction[4];
    return status;
  }

  NativeCallable<RunNative> _run(String symbol) =>
      NativeCallable<RunNative>.isolateLocal((
        int runtime,
        int host,
        int connection,
        int run,
        Pointer<sas_pairing_action_t> out,
      ) {
        seen.add('$symbol[$runtime, $host, $connection, $run]');
        return _answer(out);
      }, exceptionalReturn: -1);

  NativeCallable<DecideNative> _decide(String symbol) =>
      NativeCallable<DecideNative>.isolateLocal((
        int runtime,
        int host,
        int connection,
        int run,
        Pointer<Uint8> identity,
        Pointer<sas_pairing_action_t> out,
      ) {
        seen.add('$symbol[$runtime, $host, $connection, $run]');
        identityAddresses.add(identity.address);
        identities.add(List.of(identity.asTypedList(32)));
        return _answer(out);
      }, exceptionalReturn: -1);

  Pointer<NativeFunction<Function>> _lookup(String symbol) => switch (symbol) {
    'sas_pairing_connection_start_initiator' => _keep(
      NativeCallable<StartNative>.isolateLocal((
        int runtime,
        int host,
        int connection,
        Pointer<sas_pairing_bootstrap_view_t> local,
        Pointer<sas_pairing_bootstrap_view_t> expected,
        Pointer<sas_pairing_action_t> out,
      ) {
        seen.add('$symbol[$runtime, $host, $connection]');
        locals.add(readBootstrap(local));
        expecteds.add(readBootstrap(expected));
        return _answer(out);
      }, exceptionalReturn: -1),
    ),
    'sas_pairing_run_authorize_exposure' ||
    'sas_pairing_run_expose_key' ||
    'sas_pairing_run_emit_bootstrap_mac' ||
    'sas_pairing_run_emit_initiator_finish' => _keep(_run(symbol)),
    'sas_pairing_run_approve_sas' ||
    'sas_pairing_run_reject_sas' ||
    'sas_pairing_run_cancel_sas' => _keep(_decide(symbol)),
    'sas_pairing_run_presentation' => _keep(
      NativeCallable<PresentNative>.isolateLocal((
        int runtime,
        int host,
        int connection,
        int run,
        Pointer<sas_pairing_sas_presentation_t> out,
      ) {
        seen.add('$symbol[$runtime, $host, $connection, $run]');
        presentationAddresses.add(out.address);
        presentationOnEntry.add(
          List.of(
            out.cast<Uint8>().asTypedList(
              sizeOf<sas_pairing_sas_presentation_t>(),
            ),
          ),
        );
        fillPresentation?.call(out);
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
  late FakeCeremonyExports exports;
  late FfiNativeCeremonyApi api;

  setUp(() {
    exports = FakeCeremonyExports();
    api = FfiNativeCeremonyApi(exports.bindings);
  });
  tearDown(() => exports.close());

  group('start', () {
    test('exact Bootstrap views; a null expected is a null pointer', () {
      exports
        ..status = 0
        ..writeAction = [1, 0, 1, 0, 0x7000];
      final local = bootstrapBytes([0x00, 0x80, 0xFF], [0x61], [7, 7], []);
      final result = api.startInitiator(1, 2, 3, local, null);
      expect(exports.seen, ['sas_pairing_connection_start_initiator[1, 2, 3]']);
      expect(exports.locals.single, [
        [
          3,
          [0x00, 0x80, 0xFF],
        ],
        [
          1,
          [0x61],
        ],
        [
          2,
          [7, 7],
        ],
        [0, null],
      ]);
      expect(exports.expecteds.single, isNull);
      expect(result.status, 0);
      final action = result.action!;
      expect(
        [
          action.event,
          action.deadlineKind,
          action.flags,
          action.reserved,
          action.run,
        ],
        [1, 0, 1, 0, 0x7000],
      );
    });

    test(
      'a non-null expected Bootstrap is passed exactly, also large and non-text',
      () {
        final big = List.generate(16385, (i) => i % 256);
        exports.writeAction = [1, 0, 1, 0, 9];
        api.startInitiator(
          1,
          2,
          3,
          bootstrapBytes([1], [2], [3], [4]),
          bootstrapBytes([0], [0x00, 0x00], big, [0xFF]),
        );
        final expected = exports.expecteds.single!;
        expect(expected[0], [
          1,
          [0],
        ]);
        expect(expected[1], [
          2,
          [0, 0],
        ]);
        expect(expected[2], [16385, big]);
        expect(expected[3], [
          1,
          [0xFF],
        ]);
      },
    );
  });

  group('action records', () {
    final runExports =
        <String, NativeActionResult Function(FfiNativeCeremonyApi api)>{
          'sas_pairing_run_authorize_exposure': (api) =>
              api.authorizeExposure(10, 20, 30, 40),
          'sas_pairing_run_expose_key': (api) => api.exposeKey(10, 20, 30, 40),
          'sas_pairing_run_emit_bootstrap_mac': (api) =>
              api.emitBootstrapMac(10, 20, 30, 40),
          'sas_pairing_run_emit_initiator_finish': (api) =>
              api.emitInitiatorFinish(10, 20, 30, 40),
          'sas_pairing_run_approve_sas': (api) =>
              api.approveSas(10, 20, 30, 40, Uint8List(32)),
          'sas_pairing_run_reject_sas': (api) =>
              api.rejectSas(10, 20, 30, 40, Uint8List(32)),
          'sas_pairing_run_cancel_sas': (api) =>
              api.cancelSas(10, 20, 30, 40, Uint8List(32)),
        };
    for (final MapEntry(key: symbol, value: call) in runExports.entries) {
      test(
        '$symbol: exact handles, one zeroed aligned record, copied on OK',
        () {
          exports
            ..status = 0
            ..writeAction = [3, 2, 1, 0, 0x8000000000000001];
          final result = call(api);
          expect(exports.seen, ['$symbol[10, 20, 30, 40]']);
          expect(exports.actionOnEntry.single, [0, 0, 0, 0, 0]);
          expect(exports.actionAddresses.single, isNot(0));
          expect(exports.actionAddresses.single % 8, 0);
          final action = result.action!;
          expect(
            [
              action.event,
              action.deadlineKind,
              action.flags,
              action.reserved,
              action.run,
            ],
            [3, 2, 1, 0, 0x8000000000000001],
            reason: '64-bit run bit pattern preserved',
          );
        },
      );

      test(
        '$symbol: a failing status returns no record, whatever was written',
        () {
          exports
            ..status = 205
            ..writeAction = [3, 0, 1, 0, 40];
          final result = call(api);
          expect(result.status, 205);
          expect(result.action, isNull);
        },
      );
    }

    test(
      'a decision passes exactly 32 identity bytes, disjoint from the record',
      () {
        final identity = Uint8List.fromList([
          0x00,
          for (var i = 1; i < 31; i++) i,
          0x00,
        ]);
        for (final call in [api.approveSas, api.rejectSas, api.cancelSas]) {
          call(1, 2, 3, 4, identity);
        }
        expect(exports.identities, List.filled(3, identity));
        for (var i = 0; i < 3; i++) {
          final id = exports.identityAddresses[i];
          final out = exports.actionAddresses[i];
          expect(id, isNot(0));
          expect(
            id + 32 <= out || out + sizeOf<sas_pairing_action_t>() <= id,
            isTrue,
            reason: 'no overlap',
          );
        }
      },
    );

    test('an identity of another length never reaches native', () {
      for (final length in [0, 31, 33]) {
        expect(
          () => api.approveSas(1, 2, 3, 4, Uint8List(length)),
          throwsArgumentError,
        );
      }
      expect(exports.seen, isEmpty);
    });
  });

  group('presentation', () {
    test('one zeroed aligned record; every byte copied on OK', () {
      exports
        ..status = 0
        ..fillPresentation = (out) {
          out.ref
            ..available = 7
            ..reserved = 9;
          for (var i = 0; i < 32; i++) {
            out.ref.ceremony_identity[i] = 255 - i;
          }
          final display = '1234 5678 9012'.codeUnits;
          for (var i = 0; i < 14; i++) {
            out.ref.decimal[i] = display[i];
          }
          out.ref.reserved_tail[0] = 1;
          out.ref.reserved_tail[1] = 2;
        };
      final result = api.presentation(5, 6, 7, 8);
      expect(exports.seen, ['sas_pairing_run_presentation[5, 6, 7, 8]']);
      expect(exports.presentationOnEntry.single, List.filled(56, 0));
      expect(exports.presentationAddresses.single % 4, 0);
      final record = result.presentation!;
      // Raw and uninterpreted: the wrapper validates.
      expect(record.available, 7);
      expect(record.reserved, 9);
      expect(record.ceremonyIdentity, [for (var i = 0; i < 32; i++) 255 - i]);
      expect(record.decimal, '1234 5678 9012'.codeUnits);
      expect(record.reservedTail, [1, 2]);
    });

    test('a failing status returns no record', () {
      exports
        ..status = 204
        ..fillPresentation = (out) => out.ref.available = 1;
      final result = api.presentation(5, 6, 7, 8);
      expect(result.status, 204);
      expect(result.presentation, isNull);
    });
  });
}
