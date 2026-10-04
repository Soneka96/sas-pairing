// P8.5 PairingResult wrapper (P8-D-005) over the deterministic fake native services: drive
// delivery without reading, runtime ownership and survival, exact-handle identity and never-reused
// handles, the explicit snapshot read and its info / copy contract, data admission after native
// FATAL versus after a contract violation, explicit and runtime-cascade destruction, and the
// immutable data snapshot. No native library is loaded.
import 'dart:typed_data';

import 'package:sas_pairing/sas_pairing.dart';
import 'package:sas_pairing/src/lifecycle.dart' show resultStoreOf;
import 'package:sas_pairing/src/native/native_network_api.dart';
import 'package:sas_pairing/src/native/native_result_api.dart';
import 'package:test/test.dart';

import 'support/fake_ceremony.dart';
import 'support/fake_lifecycle.dart';
import 'support/fake_network.dart';
import 'support/fake_result.dart';

Matcher nativeStatus(String name) => isA<SasPairingNativeException>().having(
  (e) => e.statusCode,
  'statusCode',
  status('SAS_PAIRING_$name'),
);

final Matcher contractViolation = isA<SasPairingContractException>();

final Matcher closedRead = isA<SasPairingClosedException>()
    .having((e) => e.objectKind, 'objectKind', 'SasPairingResult')
    .having((e) => e.operation, 'operation', 'read');

/// Fake runtime handle of [FakeNetworkHost].
const int runtimeHandle = 1000;

/// A fake host with connection 100 accepted.
FakeNetworkHost hostWithConnection() => FakeNetworkHost()..accept(100);

/// Delivers result [handle] on [connection] through one `STEP_CONFIRMED` drive event.
SasPairingResult deliver(
  FakeNetworkHost fake,
  int handle, {
  int connection = 100,
  List<int> requestId = const [1],
}) => fake
    .drive([
      step(connection, step: 'CONFIRMED', requestId: requestId, result: handle),
    ])
    .events
    .single
    .result!;

/// The result-service operations of the fake log, in order.
List<String> resultOps(FakeLifecycleApi api) => [
  for (final op in api.operations)
    if (op.startsWith('result')) op,
];

/// The arguments of every `resultCopy` call: [runtime, result, field, capacity].
List<List<int>> copyCalls(FakeLifecycleApi api) => [
  for (final call in api.calls)
    if (call.operation == 'resultCopy') call.arguments,
];

/// Every byte field of [data], with the identity bytes.
Map<String, Uint8List> byteFields(SasPairingResultData data) => {
  'requestId': data.requestId,
  'authenticatedPeerBootstrap': data.authenticatedPeerBootstrap,
  'authenticatedSharedContext': data.authenticatedSharedContext,
  'profileIdentifier': data.profileIdentifier,
  'ceremonyIdentity.bytes': data.ceremonyIdentity.bytes,
};

/// Makes the process context observe native FATAL through an unrelated normal call.
void latchFatal(FakeNetworkHost fake) {
  fake.api.scriptDrive(FakeDrive(status: fatal));
  expect(fake.host.drive, throwsA(nativeStatus('FATAL')));
  expect(fake.context.isFatal, isTrue);
}

/// Makes the process context observe an unrelated contract violation (an impossible event).
void latchContract(FakeNetworkHost fake) {
  expect(
    () => fake.drive([NativeEventRecord(kind: 0)]),
    throwsA(contractViolation),
  );
  expect(fake.context.isContractViolated, isTrue);
}

void expectReadable(FakeNetworkHost fake, SasPairingResult result) {
  expect(result.isClosed, isFalse);
  final before = fake.api.count('resultInfo');
  final data = result.read();
  expect(fake.api.count('resultInfo'), before + 1);
  expect(data.requestId, fake.api.results.defaultData.requestId);
}

void main() {
  group('delivery', () {
    test('a result event carries a public result and reads nothing', () {
      final fake = hostWithConnection();
      final before = fake.api.calls.length;
      final batch = fake.drive([
        step(100, step: 'CONFIRMED', requestId: [1], result: 500),
      ]);
      final event = batch.events.single;
      expect(event.result, isNotNull);
      expect(event.hasResult, isTrue);
      expect(event.result!.isClosed, isFalse);
      expect(event.run, isNull);
      // Only the drive crossed the boundary: no info, copy, or destroy.
      expect(fake.api.operations.sublist(before), ['drive']);
      expect(resultOps(fake.api), isEmpty);
    });

    test('hasResult mirrors result != null on every event kind', () {
      final fake = hostWithConnection();
      final events = fake.drive([
        accepted(101),
        inbound(100, requestId: [1], run: 5000),
        step(100, step: 'WRITTEN'),
        inbound(
          101,
          requestId: [2],
          protocol: 'INITIATOR_FINISH_ACK',
          result: 501,
        ),
        acceptRefused(),
        closed(100),
      ]).events;
      for (final event in events) {
        expect(event.hasResult, event.result != null, reason: '${event.kind}');
      }
      expect(
        [for (final e in events) e.hasResult],
        [false, false, false, true, false, false],
      );
    });

    test('the Responder and Initiator result events both deliver results', () {
      final fake = hostWithConnection();
      final responder = fake
          .drive([
            inbound(
              100,
              requestId: [1],
              protocol: 'INITIATOR_FINISH_ACK',
              result: 9000,
            ),
          ])
          .events
          .single
          .result!;
      final initiator = deliver(fake, 9001, requestId: [2]);
      expect(identical(responder, initiator), isFalse);
      expect(resultStoreOf(fake.runtime).live, [responder, initiator]);
    });

    test('one native handle is one public object, held by the runtime', () {
      final fake = hostWithConnection();
      final result = deliver(fake, 500);
      expect(resultStoreOf(fake.runtime).live.single, same(result));
      expect(resultStoreOf(fake.runtime).delivered(500), isTrue);
    });

    test('a second delivery of a live handle is a contract violation', () {
      final fake = hostWithConnection();
      final first = deliver(fake, 500);
      expect(
        () => deliver(fake, 500, requestId: [2]),
        throwsA(contractViolation),
      );
      expect(resultStoreOf(fake.runtime).live, [first]);
      expect(first.isClosed, isFalse);
      // The contract latch refuses later normal work without a native call.
      final before = fake.api.calls.length;
      expect(fake.host.drive, throwsA(contractViolation));
      expect(fake.api.calls.length, before);
    });

    test('a handle delivered twice in one batch is a contract violation', () {
      final fake = hostWithConnection();
      expect(
        () => fake.drive([
          step(100, step: 'CONFIRMED', requestId: [1], result: 500),
          step(100, step: 'CONFIRMED', requestId: [2], result: 500),
        ]),
        throwsA(contractViolation),
      );
    });

    test(
      'a handle delivered again after its result was closed is a contract violation',
      () {
        final fake = hostWithConnection();
        final first = deliver(fake, 500);
        first.close();
        expect(resultStoreOf(fake.runtime).live, isEmpty);
        expect(
          () => deliver(fake, 500, requestId: [2]),
          throwsA(contractViolation),
        );
        // No new object, and nothing was read.
        expect(resultStoreOf(fake.runtime).live, isEmpty);
        expect(resultOps(fake.api), ['resultDestroy']);
      },
    );

    test('another handle after a closed one is a new, distinct result', () {
      final fake = hostWithConnection();
      final first = deliver(fake, 500)..close();
      final second = deliver(fake, 501, requestId: [2]);
      expect(identical(first, second), isFalse);
      expect(second.isClosed, isFalse);
    });
  });

  group('read', () {
    test('one info, then exactly four copies at the reported lengths', () {
      final fake = hostWithConnection();
      final source = fake.api.results.defaultData;
      final data = deliver(fake, 500).read();
      expect(resultOps(fake.api), [
        'resultInfo',
        'resultCopy',
        'resultCopy',
        'resultCopy',
        'resultCopy',
      ]);
      expect(
        fake.api.calls.firstWhere((c) => c.operation == 'resultInfo').arguments,
        [runtimeHandle, 500],
      );
      expect(copyCalls(fake.api), [
        [runtimeHandle, 500, requestIdField, source.requestId.length],
        [runtimeHandle, 500, peerBootstrapField, source.peerBootstrap.length],
        [runtimeHandle, 500, sharedContextField, 0],
        [
          runtimeHandle,
          500,
          profileIdentifierField,
          source.profileIdentifier.length,
        ],
      ]);
      expect(data.ceremonyIdentity.bytes, source.identity);
      expect(data.peerRole, SasPairingPeerRole.responder);
      expect(data.profileVersion, 1);
      expect(data.requestId, source.requestId);
      expect(data.authenticatedPeerBootstrap, source.peerBootstrap);
      expect(data.authenticatedSharedContext, isEmpty);
      expect(data.profileIdentifier, source.profileIdentifier);
    });

    test('every read reads native again and returns the same values', () {
      final fake = hostWithConnection();
      final result = deliver(fake, 500);
      final a = result.read();
      final b = result.read();
      expect(fake.api.count('resultInfo'), 2);
      expect(fake.api.count('resultCopy'), 8);
      expect(identical(a, b), isFalse);
      expect(a.ceremonyIdentity, b.ceremonyIdentity);
      expect([a.peerRole, a.profileVersion], [b.peerRole, b.profileVersion]);
      expect(byteFields(a), byteFields(b));
      expect(result.isClosed, isFalse);
    });

    test('the result identity is the presentation identity type and value', () {
      final fake = hostWithConnection();
      final identity = List.generate(32, (i) => 0xC0 ^ i);
      fake.drive([
        inbound(100, requestId: [1], run: 5000),
      ]);
      final run = fake
          .drive([
            inbound(100, requestId: [1], protocol: 'RESPONDER_KEY', run: 5000),
          ])
          .events
          .single
          .run!;
      fake.api.ceremony.scriptPresentation(livePresentation(identity));
      final presented = run.presentation()!.ceremonyIdentity;
      fake.api.results.data[500] = FakeResultData(identity: identity);
      final data = deliver(fake, 500).read();
      expect(data.ceremonyIdentity, presented);
      expect(data.ceremonyIdentity.runtimeType, presented.runtimeType);
      expect(data.ceremonyIdentity.hashCode, presented.hashCode);
    });

    test('peer role: INITIATOR is initiator and RESPONDER is responder', () {
      final fake = hostWithConnection();
      fake.api.results.data[500] = FakeResultData(peerRole: role('INITIATOR'));
      fake.api.results.data[501] = FakeResultData(peerRole: role('RESPONDER'));
      expect(deliver(fake, 500).read().peerRole, SasPairingPeerRole.initiator);
      expect(
        deliver(fake, 501, requestId: [2]).read().peerRole,
        SasPairingPeerRole.responder,
      );
    });

    for (final (name, value) in [
      ('INVALID', role('INVALID')),
      ('3', 3),
      ('0xFFFFFFFF', 0xFFFFFFFF),
    ]) {
      test('peer role $name on success is a contract violation', () {
        final fake = hostWithConnection();
        fake.api.results.data[500] = FakeResultData(peerRole: value);
        final result = deliver(fake, 500);
        expect(result.read, throwsA(contractViolation));
        expect(fake.context.isContractViolated, isTrue);
        expect(fake.api.count('resultCopy'), 0, reason: 'nothing copied');
        // Further reads are refused locally; close still destroys.
        final before = fake.api.calls.length;
        expect(result.read, throwsA(contractViolation));
        expect(fake.api.calls.length, before);
        result.close();
        expect(resultOps(fake.api).last, 'resultDestroy');
      });
    }

    test('an all-zero ceremony identity is a valid hash output', () {
      final fake = hostWithConnection();
      fake.api.results.data[500] = FakeResultData(identity: List.filled(32, 0));
      expect(
        deliver(fake, 500).read().ceremonyIdentity.bytes,
        List.filled(32, 0),
      );
    });

    test('a ceremony identity of another length is a contract violation', () {
      final fake = hostWithConnection();
      final result = deliver(fake, 500);
      fake.api.results.scriptInfo(
        ok,
        FakeResultData(identity: List.filled(31, 1)).info(),
      );
      expect(result.read, throwsA(contractViolation));
    });

    test('SAS_PAIRING_OK without an info record is a contract violation', () {
      final fake = hostWithConnection();
      final result = deliver(fake, 500);
      fake.api.results.scriptInfo(ok);
      expect(result.read, throwsA(contractViolation));
    });

    test('the profile version is preserved exactly, never validated', () {
      for (final version in [0, 1, 2, 0xFFFF, 0xFFFFFFFF]) {
        final fake = hostWithConnection();
        fake.api.results.data[500] = FakeResultData(profileVersion: version);
        expect(deliver(fake, 500).read().profileVersion, version);
      }
    });

    test('byte fields are exact non-text bytes, never decoded', () {
      final fake = hostWithConnection();
      final source = FakeResultData(
        requestId: [0x00, 0xFF, 0x80, 0x00],
        peerBootstrap: [0xFE, 0x00, 0x00, 0xC3, 0x28],
        sharedContext: [0x00, 0x00, 0x0A, 0xFF],
        profileIdentifier: [0xFF, 0x00, 0xC3, 0x28, 0x00],
      );
      fake.api.results.data[500] = source;
      final data = deliver(fake, 500).read();
      expect(data.requestId, [0x00, 0xFF, 0x80, 0x00]);
      expect(data.authenticatedPeerBootstrap, [0xFE, 0x00, 0x00, 0xC3, 0x28]);
      expect(data.authenticatedSharedContext, [0x00, 0x00, 0x0A, 0xFF]);
      expect(data.profileIdentifier, [0xFF, 0x00, 0xC3, 0x28, 0x00]);
    });

    test(
      'an empty shared context and an empty profile identifier stay empty',
      () {
        final fake = hostWithConnection();
        fake.api.results.data[500] = FakeResultData(
          sharedContext: [],
          profileIdentifier: [],
        );
        final data = deliver(fake, 500).read();
        expect(data.authenticatedSharedContext, isA<Uint8List>());
        expect(data.authenticatedSharedContext, isEmpty);
        expect(data.profileIdentifier, isEmpty);
        expect(
          copyCalls(
            fake.api,
          ).where((c) => c[2] == sharedContextField).single[3],
          0,
          reason: 'a zero-length field is copied with capacity 0',
        );
      },
    );

    group('source-proven length bounds', () {
      final cases = <(String, FakeResultData Function(int length), int)>[
        ('request ID', (n) => FakeResultData(requestId: List.filled(n, 7)), 64),
        (
          'peer Bootstrap',
          (n) => FakeResultData(peerBootstrap: List.filled(n, 7)),
          16384,
        ),
        (
          'shared context',
          (n) => FakeResultData(sharedContext: List.filled(n, 7)),
          8192,
        ),
      ];
      for (final (name, make, max) in cases) {
        test('$name length $max is accepted', () {
          final fake = hostWithConnection();
          fake.api.results.data[500] = make(max);
          final data = deliver(fake, 500).read();
          expect(byteFields(data).values.any((f) => f.length == max), isTrue);
        });

        test(
          '$name length ${max + 1} is a contract violation before any copy',
          () {
            final fake = hostWithConnection();
            final result = deliver(fake, 500);
            fake.api.results.scriptInfo(ok, make(max + 1).info());
            expect(result.read, throwsA(contractViolation));
            expect(fake.api.count('resultCopy'), 0);
          },
        );
      }

      test('the profile identifier has no narrower bound and is preserved', () {
        final fake = hostWithConnection();
        fake.api.results.data[500] = FakeResultData(
          profileIdentifier: List.generate(70000, (i) => i & 0xFF),
        );
        final data = deliver(fake, 500).read();
        expect(data.profileIdentifier, hasLength(70000));
        expect(data.profileIdentifier[69999], 69999 & 0xFF);
      });

      test(
        'a negative length from a broken record is a contract violation',
        () {
          final fake = hostWithConnection();
          final result = deliver(fake, 500);
          fake.api.results.scriptInfo(
            ok,
            NativeResultInfoRecord(
              ceremonyIdentity: Uint8List(32),
              peerRole: role('INITIATOR'),
              profileVersion: 1,
              requestIdLength: 16,
              peerBootstrapLength: 10,
              sharedContextLength: 0,
              profileIdentifierLength: -1,
            ),
          );
          expect(result.read, throwsA(contractViolation));
          expect(fake.api.count('resultCopy'), 0);
        },
      );
    });

    group('copy length consistency', () {
      for (final reported in [15, 17]) {
        test(
          'OK with required $reported for a 16-byte request ID is a violation',
          () {
            final fake = hostWithConnection();
            final result = deliver(fake, 500);
            fake.api.results.scriptCopy(
              requestIdField,
              ok,
              required: reported,
              bytes: Uint8List(reported < 16 ? reported : 16),
            );
            expect(result.read, throwsA(contractViolation));
            // Nothing after the contradiction is copied, and no data exists.
            expect(fake.api.count('resultCopy'), 1);
            expect(result.isClosed, isFalse);
          },
        );
      }

      test(
        'OK with the right required length but other bytes is a violation',
        () {
          final fake = hostWithConnection();
          final result = deliver(fake, 500);
          fake.api.results.scriptCopy(
            requestIdField,
            ok,
            required: 16,
            bytes: Uint8List(15),
          );
          expect(result.read, throwsA(contractViolation));
        },
      );

      for (final required in [7, 8, 1000]) {
        test(
          'BUFFER_TOO_SMALL at the exact reported capacity (required $required) is a '
          'violation, never a retry',
          () {
            final fake = hostWithConnection();
            final source = fake.api.results.defaultData;
            final result = deliver(fake, 500);
            fake.api.results.scriptCopy(
              peerBootstrapField,
              status('SAS_PAIRING_BUFFER_TOO_SMALL'),
              required: required,
            );
            Object? caught;
            try {
              result.read();
            } catch (error) {
              caught = error;
            }
            expect(caught, contractViolation);
            expect(caught, isNot(isA<SasPairingNativeException>()));
            // The Bootstrap was asked for once, at exactly the reported length.
            final bootstrapCopies = copyCalls(
              fake.api,
            ).where((c) => c[2] == peerBootstrapField).toList();
            expect(bootstrapCopies, [
              [
                runtimeHandle,
                500,
                peerBootstrapField,
                source.peerBootstrap.length,
              ],
            ]);
            expect(fake.api.count('resultCopy'), 2);
          },
        );
      }
    });

    group('native failures', () {
      test(
        'a copy INVALID_HANDLE throws exactly and returns nothing partial',
        () {
          final fake = hostWithConnection();
          final result = deliver(fake, 500);
          fake.api.results.scriptCopy(
            sharedContextField,
            status('SAS_PAIRING_INVALID_HANDLE'),
          );
          expect(result.read, throwsA(nativeStatus('INVALID_HANDLE')));
          // Request ID and Bootstrap were copied, the shared context failed, nothing after.
          expect(copyCalls(fake.api).map((c) => c[2]), [
            requestIdField,
            peerBootstrapField,
            sharedContextField,
          ]);
          expect(result.isClosed, isFalse);
          expect(fake.context.isContractViolated, isFalse);
          expect(fake.context.isFatal, isFalse);
          // The next read is sent to native again and succeeds.
          expect(
            result.read().requestId,
            fake.api.results.defaultData.requestId,
          );
        },
      );

      test('a copy FATAL latches FATAL; the result stays closeable', () {
        final fake = hostWithConnection();
        final result = deliver(fake, 500);
        fake.api.results.scriptCopy(profileIdentifierField, fatal);
        expect(result.read, throwsA(nativeStatus('FATAL')));
        expect(fake.context.isFatal, isTrue);
        expect(result.isClosed, isFalse);
        result.close();
        expect(resultOps(fake.api).last, 'resultDestroy');
      });

      test('an unknown copy status is preserved', () {
        final fake = hostWithConnection();
        final result = deliver(fake, 500);
        fake.api.results.scriptCopy(requestIdField, 777);
        expect(
          result.read,
          throwsA(
            isA<SasPairingNativeException>()
                .having((e) => e.statusCode, 'statusCode', 777)
                .having((e) => e.knownStatus, 'knownStatus', isNull),
          ),
        );
        expect(fake.context.isFatal, isFalse);
      });

      test('an info INVALID_HANDLE throws exactly with no copy', () {
        final fake = hostWithConnection();
        final result = deliver(fake, 500);
        fake.api.results.scriptInfo(status('SAS_PAIRING_INVALID_HANDLE'));
        expect(result.read, throwsA(nativeStatus('INVALID_HANDLE')));
        expect(fake.api.count('resultCopy'), 0);
        expect(result.isClosed, isFalse);
      });

      test('an info FATAL latches FATAL; the result stays closeable', () {
        final fake = hostWithConnection();
        final result = deliver(fake, 500);
        fake.api.results.scriptInfo(fatal);
        expect(result.read, throwsA(nativeStatus('FATAL')));
        expect(fake.context.isFatal, isTrue);
        expect(fake.api.count('resultCopy'), 0);
        expect(result.isClosed, isFalse);
        result.close();
        expect(fake.api.count('resultDestroy'), 1);
      });
    });

    test('the snapshot is immutable through every public route', () {
      final fake = hostWithConnection();
      fake.api.results.data[500] = FakeResultData(sharedContext: [1, 2, 3]);
      final data = deliver(fake, 500).read();
      final original = {
        for (final MapEntry(:key, :value) in byteFields(data).entries)
          key: List.of(value),
      };
      for (final MapEntry(:key, :value) in byteFields(data).entries) {
        expect(() => value[0] = 0x55, throwsUnsupportedError, reason: key);
        expect(
          () => value.setAll(0, [0x55]),
          throwsUnsupportedError,
          reason: key,
        );
        expect(
          () => value.buffer.asUint8List()[0] = 0x55,
          throwsUnsupportedError,
          reason: key,
        );
        expect(
          () => value.buffer.asByteData().setUint8(0, 0x55),
          throwsUnsupportedError,
          reason: key,
        );
        expect(
          () => Uint8List.view(value.buffer)[0] = 0x55,
          throwsUnsupportedError,
          reason: key,
        );
      }
      expect({
        for (final MapEntry(:key, :value) in byteFields(data).entries)
          key: List.of(value),
      }, original);
    });

    test('the snapshot is a copy of what the service returned', () {
      final fake = hostWithConnection();
      final result = deliver(fake, 500);
      final served = Uint8List.fromList(fake.api.results.defaultData.requestId);
      fake.api.results.scriptCopy(
        requestIdField,
        ok,
        required: served.length,
        bytes: served,
      );
      final data = result.read();
      served[0] ^= 0xFF;
      expect(data.requestId, fake.api.results.defaultData.requestId);
    });
  });

  group('data admission', () {
    test('a result delivered before native FATAL is still read natively', () {
      final fake = hostWithConnection();
      final result = deliver(fake, 500);
      latchFatal(fake);
      final data = result.read();
      expect(resultOps(fake.api), [
        'resultInfo',
        'resultCopy',
        'resultCopy',
        'resultCopy',
        'resultCopy',
      ]);
      expect(data.requestId, fake.api.results.defaultData.requestId);
      // Normal operations stay refused.
      expect(fake.host.drive, throwsA(nativeStatus('FATAL')));
    });

    test('and destroyed natively after native FATAL', () {
      final fake = hostWithConnection();
      final result = deliver(fake, 500);
      latchFatal(fake);
      result.close();
      expect(resultOps(fake.api), ['resultDestroy']);
      expect(result.isClosed, isTrue);
    });

    test(
      'after a contract violation a read is refused locally, but close still destroys',
      () {
        final fake = hostWithConnection();
        final result = deliver(fake, 500);
        latchContract(fake);
        expect(result.read, throwsA(contractViolation));
        expect(resultOps(fake.api), isEmpty, reason: 'no info, no copy');
        result.close();
        expect(resultOps(fake.api), ['resultDestroy']);
        expect(result.isClosed, isTrue);
      },
    );

    test('a closed result is refused before any latch is consulted', () {
      final fake = hostWithConnection();
      final result = deliver(fake, 500)..close();
      latchContract(fake);
      expect(result.read, throwsA(closedRead));
    });

    test('a read after explicit close is local', () {
      final fake = hostWithConnection();
      final result = deliver(fake, 500)..close();
      final before = fake.api.calls.length;
      expect(result.read, throwsA(closedRead));
      expect(fake.api.calls.length, before);
    });
  });

  group('explicit close', () {
    test('one destroy with the exact handles, then nothing', () {
      final fake = hostWithConnection();
      final result = deliver(fake, 500);
      result.close();
      expect(result.isClosed, isTrue);
      expect(
        fake.api.calls
            .where((c) => c.operation == 'resultDestroy')
            .single
            .arguments,
        [runtimeHandle, 500],
      );
      result.close();
      expect(fake.api.count('resultDestroy'), 1);
      expect(resultStoreOf(fake.runtime).live, isEmpty);
      expect(resultStoreOf(fake.runtime).delivered(500), isTrue);
    });

    for (final (name, code) in [
      ('INVALID_HANDLE', status('SAS_PAIRING_INVALID_HANDLE')),
      ('FATAL', fatal),
      ('unknown 31337', 31337),
    ]) {
      test(
        'a failing destroy ($name) consumes the wrapper and throws once',
        () {
          final fake = hostWithConnection();
          final result = deliver(fake, 500);
          fake.api.results.scriptDestroy(code);
          expect(
            result.close,
            throwsA(
              isA<SasPairingNativeException>().having(
                (e) => e.statusCode,
                'statusCode',
                code,
              ),
            ),
          );
          expect(result.isClosed, isTrue);
          expect(fake.context.isFatal, code == fatal);
          expect(result.close, returnsNormally);
          expect(fake.api.count('resultDestroy'), 1);
          expect(result.read, throwsA(closedRead));
        },
      );
    }

    test('a FATAL destroy blocks no read of another result', () {
      final fake = hostWithConnection();
      final a = deliver(fake, 500);
      final b = deliver(fake, 501, requestId: [2]);
      fake.api.results.scriptDestroy(fatal);
      expect(a.close, throwsA(nativeStatus('FATAL')));
      expectReadable(fake, b);
    });

    test('data read before close stays usable after it', () {
      final fake = hostWithConnection();
      final result = deliver(fake, 500);
      final data = result.read();
      final copy = {
        for (final MapEntry(:key, :value) in byteFields(data).entries)
          key: List.of(value),
      };
      result.close();
      final before = fake.api.calls.length;
      expect({
        for (final MapEntry(:key, :value) in byteFields(data).entries)
          key: List.of(value),
      }, copy);
      expect(data.peerRole, SasPairingPeerRole.responder);
      expect(fake.api.calls.length, before, reason: 'plain Dart data');
    });
  });

  group('runtime ownership: what does not end a result', () {
    test('the run ending (its result event) leaves the result open', () {
      final fake = hostWithConnection();
      final run = fake
          .drive([
            inbound(100, requestId: [1], run: 5000),
          ])
          .events
          .single
          .run!;
      final result = deliver(fake, 500, requestId: [1]);
      expect(run.isEnded, isTrue);
      expectReadable(fake, result);
    });

    test('connection close leaves the result open', () {
      final fake = hostWithConnection();
      final connection = fake.drive([accepted(101)]).events.single.connection!;
      final result = deliver(fake, 500, connection: 101);
      connection.close();
      expect(connection.isClosed, isTrue);
      expect(fake.api.count('resultDestroy'), 0);
      expectReadable(fake, result);
    });

    test('a connectionClosed event leaves the result open', () {
      final fake = hostWithConnection();
      final result = deliver(fake, 500);
      fake.drive([closed(100)]);
      expectReadable(fake, result);
    });

    test('listener detach leaves the result open', () {
      final fake = hostWithConnection();
      final result = deliver(fake, 500);
      fake.host.detachListener();
      expect(fake.host.networkState, SasPairingHostNetworkState.detached);
      expect(fake.api.count('resultDestroy'), 0);
      expectReadable(fake, result);
    });

    for (final failure in ['NETWORK_POLL_FAILED', 'OWNERSHIP_UNCERTAIN']) {
      test('a later owner-loop failure ($failure) leaves the result open', () {
        final fake = hostWithConnection();
        final connection = fake
            .drive([accepted(101)])
            .events
            .single
            .connection!;
        final result = deliver(fake, 500);
        fake.drive([], failure: status('SAS_PAIRING_$failure'));
        expect(fake.host.networkState, SasPairingHostNetworkState.failedClosed);
        expect(connection.isClosed, isTrue);
        expect(fake.api.count('resultDestroy'), 0);
        expectReadable(fake, result);
      });
    }

    test(
      'a ceremony call that fails the loop closed leaves the result open',
      () {
        final fake = hostWithConnection();
        final run = fake
            .drive([
              inbound(100, requestId: [2], run: 5000),
            ])
            .events
            .single
            .run!;
        final result = deliver(fake, 500, requestId: [1]);
        fake.api.ceremony.scriptStatus(
          'authorizeExposure',
          status('SAS_PAIRING_OWNERSHIP_UNCERTAIN'),
        );
        expect(
          run.authorizeExposure,
          throwsA(nativeStatus('OWNERSHIP_UNCERTAIN')),
        );
        expect(fake.host.networkState, SasPairingHostNetworkState.failedClosed);
        expectReadable(fake, result);
      },
    );

    test('host close: exactly one host destroy, no result destroy', () {
      final fake = hostWithConnection();
      final result = deliver(fake, 500);
      final before = fake.api.calls.length;
      fake.host.close();
      expect(fake.api.operations.sublist(before), ['hostDestroy']);
      expectReadable(fake, result);
    });

    test(
      'authority close: exactly one authority release, no result destroy',
      () {
        final fake = hostWithConnection();
        final result = deliver(fake, 500);
        final before = fake.api.calls.length;
        fake.authority.close();
        expect(fake.api.operations.sublist(before), ['authorityRelease']);
        expect(fake.host.isClosed, isTrue);
        expectReadable(fake, result);
      },
    );

    test('a result outlives every networking object together', () {
      final fake = hostWithConnection();
      final result = deliver(fake, 500);
      fake.drive([closed(100)]);
      fake.host.detachListener();
      fake.host.close();
      fake.authority.close();
      // Native FATAL observed through an unrelated normal call of the still-open runtime.
      fake.api.script('authorityRegister', Scripted(fatal));
      expect(
        () => fake.runtime.registerAuthority(bytes([9])),
        throwsA(nativeStatus('FATAL')),
      );
      expect(fake.context.isFatal, isTrue);
      expectReadable(fake, result);
      result.close();
      expect(fake.api.count('resultDestroy'), 1);
    });
  });

  group('result + out_failure in the same drive', () {
    test('NETWORK_POLL_FAILED: the result is delivered and stays readable', () {
      final fake = hostWithConnection();
      final batch = fake.drive([
        step(100, step: 'CONFIRMED', requestId: [1], result: 500),
      ], failure: status('SAS_PAIRING_NETWORK_POLL_FAILED'));
      final result = batch.events.single.result!;
      expect(batch.failure!.knownStatus, SasPairingStatus.networkPollFailed);
      expect(fake.host.networkState, SasPairingHostNetworkState.failedClosed);
      expect(batch.events.single.connection!.isClosed, isTrue);
      expect(result.isClosed, isFalse);
      expectReadable(fake, result);
    });

    test('FATAL: the result is delivered, read, and destroyed natively', () {
      final fake = hostWithConnection();
      final batch = fake.drive([
        step(100, step: 'CONFIRMED', requestId: [1], result: 500),
      ], failure: fatal);
      final result = batch.events.single.result!;
      expect(batch.failure!.processRestartRequired, isTrue);
      expect(fake.context.isFatal, isTrue);
      expect(fake.host.networkState, SasPairingHostNetworkState.failedClosed);
      expect(batch.events.single.connection!.isClosed, isTrue);
      expect(result.isClosed, isFalse);
      final data = result.read();
      expect(resultOps(fake.api), [
        'resultInfo',
        'resultCopy',
        'resultCopy',
        'resultCopy',
        'resultCopy',
      ]);
      expect(data.requestId, fake.api.results.defaultData.requestId);
      result.close();
      expect(resultOps(fake.api).last, 'resultDestroy');
      expect(result.isClosed, isTrue);
    });
  });

  group('runtime close', () {
    test('one runtime destroy closes every result, with no result destroy', () {
      final fake = hostWithConnection();
      final a = deliver(fake, 500);
      final b = deliver(fake, 501, requestId: [2]);
      final c = deliver(fake, 502, requestId: [3]);
      final before = fake.api.calls.length;
      fake.runtime.close();
      expect(fake.api.operations.sublist(before), ['runtimeDestroy']);
      for (final result in [a, b, c]) {
        expect(result.isClosed, isTrue);
        final calls = fake.api.calls.length;
        expect(result.read, throwsA(closedRead));
        result.close();
        expect(fake.api.calls.length, calls, reason: 'local only');
      }
      expect(resultStoreOf(fake.runtime).live, isEmpty);
      expect(fake.api.count('resultDestroy'), 0);
    });

    test(
      'an explicitly closed result is not destroyed again by runtime close',
      () {
        final fake = hostWithConnection();
        final a = deliver(fake, 500)..close();
        final b = deliver(fake, 501, requestId: [2]);
        fake.runtime.close();
        expect(fake.api.count('resultDestroy'), 1);
        expect([a.isClosed, b.isClosed], [true, true]);
      },
    );

    test('a failing runtime destroy still closes every result', () {
      final fake = hostWithConnection();
      final result = deliver(fake, 500);
      fake.api.script(
        'runtimeDestroy',
        Scripted(status('SAS_PAIRING_INVALID_HANDLE')),
      );
      expect(fake.runtime.close, throwsA(nativeStatus('INVALID_HANDLE')));
      expect(result.isClosed, isTrue);
    });

    test('data read before runtime close stays usable after it', () {
      final fake = hostWithConnection();
      final data = deliver(fake, 500).read();
      fake.runtime.close();
      expect(data.requestId, fake.api.results.defaultData.requestId);
      expect(
        data.ceremonyIdentity.bytes,
        fake.api.results.defaultData.identity,
      );
      expect(
        data.profileIdentifier,
        fake.api.results.defaultData.profileIdentifier,
      );
    });
  });

  test('no result handle appears in any text', () {
    final fake = hostWithConnection();
    const handle = 987654;
    final result = deliver(fake, handle);
    final texts = <String>['$result', '${result.read()}'];
    fake.api.results.scriptInfo(status('SAS_PAIRING_INVALID_HANDLE'));
    try {
      result.read();
    } on Object catch (error) {
      texts.add('$error');
    }
    result.close();
    try {
      result.read();
    } on Object catch (error) {
      texts.add('$error');
    }
    try {
      deliver(fake, handle, requestId: [2]);
    } on Object catch (error) {
      texts.add('$error');
    }
    for (final text in texts) {
      expect(text, isNot(contains('$handle')));
    }
  });
}
