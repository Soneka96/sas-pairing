// P8.3 Windows listener ownership and cooperative network driver over a deterministic fake of
// the private native services (P8-D-003): the attach ownership matrix, detach, one bounded drive
// and recheck, the return value versus out_failure, event mapping and record invariants,
// connection identity and lifetime, LISTENER_DISABLED, RUN_UNTRACKED guidance, private run and
// result references, and the parent cascade. No native library is loaded, so these run on every
// platform.
import 'dart:typed_data';

import 'package:sas_pairing/sas_pairing.dart';
import 'package:sas_pairing/src/lifecycle.dart' show resultStoreOf;
import 'package:sas_pairing/src/native/abi_v1.dart';
import 'package:sas_pairing/src/native/native_network_api.dart';
import 'package:sas_pairing/src/network_refs.dart';
import 'package:sas_pairing/src/network.dart'
    show runReferenceOf, runReferencesOf;
import 'package:test/test.dart';

import 'support/fake_lifecycle.dart';
import 'support/fake_network.dart';

Matcher nativeStatus(String name) => isA<SasPairingNativeException>().having(
  (e) => e.statusCode,
  'statusCode',
  status('SAS_PAIRING_$name'),
);

final Matcher contractViolation = isA<SasPairingContractException>();

/// Every operation of the fake log except those listed.
List<String> networkCalls(FakeLifecycleApi api) => [
  for (final op in api.operations)
    if (const {
      'attachWindowsListener',
      'detachListener',
      'drive',
      'recheckAfterResume',
      'connectionClose',
    }.contains(op))
      op,
];

/// `ABANDONED_PARTIAL_FRAME` → `abandonedPartialFrame`.
String camel(String constant) {
  final words = constant.toLowerCase().split('_');
  return words.first +
      [
        for (final w in words.skip(1)) w[0].toUpperCase() + w.substring(1),
      ].join();
}

/// The namespace values whose names start with [prefix], by their camel-case suffix.
Map<String, int> namespace(String prefix) => {
  for (final entry in abiV1Namespaces.entries)
    if (entry.key.startsWith('SAS_PAIRING_$prefix'))
      camel(entry.key.substring('SAS_PAIRING_$prefix'.length)): entry.value,
};

void main() {
  group('listener socket token', () {
    test('starts untransferred; INVALID_SOCKET is refused', () {
      expect(token().isTransferred, isFalse);
      expect(
        () => SasPairingWindowsListenerSocket.fromNativeSocket(socketInvalid),
        throwsArgumentError,
      );
      expect(socketInvalid, -1, reason: 'UINTPTR_MAX as a 64-bit Dart int');
    });

    test('the raw socket value is never printed', () {
      final listener = SasPairingWindowsListenerSocket.fromNativeSocket(
        987654321,
      );
      expect('$listener', isNot(contains('987654321')));
    });
  });

  group('attach ownership matrix', () {
    (FakeNetworkHost, SasPairingWindowsListenerSocket) offer(
      FakeAttach? answer,
    ) {
      final fake = FakeNetworkHost(attach: false);
      if (answer != null) fake.api.scriptAttach(answer);
      return (fake, token(0x4242));
    }

    void attach(FakeNetworkHost fake, SasPairingWindowsListenerSocket t) =>
        fake.host.attachWindowsListener(listener: t, local: testBootstrap());

    test(
      'A. OK with the slot INVALID: transferred, attached, nothing driven',
      () {
        final (fake, t) = offer(FakeAttach(ok, adopted: true));
        attach(fake, t);
        expect(t.isTransferred, isTrue);
        expect(fake.host.networkState, SasPairingHostNetworkState.attached);
        expect(networkCalls(fake.api), ['attachWindowsListener']);
        expect(fake.api.calls.last.arguments, [1000, 1002, 0x4242]);
      },
    );

    test(
      'B. INVALID_BOOTSTRAP with the slot unchanged: caller still owns it',
      () {
        final (fake, t) = offer(
          FakeAttach(status('SAS_PAIRING_INVALID_BOOTSTRAP')),
        );
        expect(
          () => attach(fake, t),
          throwsA(nativeStatus('INVALID_BOOTSTRAP')),
        );
        expect(t.isTransferred, isFalse);
        expect(fake.host.networkState, SasPairingHostNetworkState.detached);
        expect(fake.context.isFatal, isFalse);
      },
    );

    test(
      'C. LISTENER_ALREADY_ATTACHED: the offered socket stays the caller\'s',
      () {
        final fake = FakeNetworkHost();
        final connection = fake.accept(100);
        final second = token(0x5151);
        fake.api.scriptAttach(
          FakeAttach(status('SAS_PAIRING_LISTENER_ALREADY_ATTACHED')),
        );
        expect(
          () => fake.host.attachWindowsListener(
            listener: second,
            local: testBootstrap(),
          ),
          throwsA(nativeStatus('LISTENER_ALREADY_ATTACHED')),
        );
        expect(second.isTransferred, isFalse);
        expect(fake.host.networkState, SasPairingHostNetworkState.attached);
        expect(
          connection.isClosed,
          isFalse,
          reason: 'existing network untouched',
        );
      },
    );

    test(
      'D. LISTENER_SETUP_FAILED with the slot INVALID: consumed, detached',
      () {
        final (fake, t) = offer(
          FakeAttach(
            status('SAS_PAIRING_LISTENER_SETUP_FAILED'),
            adopted: true,
          ),
        );
        expect(
          () => attach(fake, t),
          throwsA(nativeStatus('LISTENER_SETUP_FAILED')),
        );
        expect(t.isTransferred, isTrue);
        expect(fake.host.networkState, SasPairingHostNetworkState.detached);
        expect(fake.context.isFatal, isFalse);
      },
    );

    test(
      'E. FATAL with the slot unchanged: not transferred, FATAL latched',
      () {
        final (fake, t) = offer(FakeAttach(fatal));
        expect(() => attach(fake, t), throwsA(nativeStatus('FATAL')));
        expect(t.isTransferred, isFalse);
        expect(fake.context.isFatal, isTrue);
        expect(fake.host.networkState, SasPairingHostNetworkState.detached);
      },
    );

    test('F. FATAL with the slot INVALID: transferred, FATAL latched', () {
      final (fake, t) = offer(FakeAttach(fatal, adopted: true));
      expect(() => attach(fake, t), throwsA(nativeStatus('FATAL')));
      expect(t.isTransferred, isTrue);
      expect(fake.context.isFatal, isTrue);
      expect(fake.host.networkState, SasPairingHostNetworkState.detached);
    });

    test('G. OK with the slot unchanged: contract violation', () {
      final (fake, t) = offer(FakeAttach(ok));
      expect(() => attach(fake, t), throwsA(contractViolation));
      expect(t.isTransferred, isFalse);
      expect(fake.context.isContractViolated, isTrue);
      expect(fake.host.networkState, SasPairingHostNetworkState.detached);
    });

    for (final (name, code) in [
      ('OK', 0),
      ('FATAL', 900),
      ('INVALID_HANDLE', 2),
    ]) {
      test(
        'H. the slot changed to another socket value ($name): contract violation',
        () {
          final (fake, t) = offer(FakeAttach(code, slot: 0x9999));
          expect(() => attach(fake, t), throwsA(contractViolation));
          expect(t.isTransferred, isFalse);
          expect(fake.context.isContractViolated, isTrue);
          expect(fake.context.isFatal, code == fatal);
        },
      );
    }

    test(
      'UNSUPPORTED_PLATFORM and INVALID_HANDLE leave the socket with the caller',
      () {
        for (final name in [
          'UNSUPPORTED_PLATFORM',
          'INVALID_HANDLE',
          'INVALID_ARGUMENT',
        ]) {
          final (fake, t) = offer(FakeAttach(status('SAS_PAIRING_$name')));
          expect(() => attach(fake, t), throwsA(nativeStatus(name)));
          expect(t.isTransferred, isFalse, reason: name);
        }
      },
    );

    test(
      'a transferred token is refused locally; its stale value never reaches native',
      () {
        final fake = FakeNetworkHost(attach: false);
        final t = token(0x7777);
        fake.host.attachWindowsListener(listener: t, local: testBootstrap());
        fake.host.detachListener();
        final before = fake.api.calls.length;
        expect(
          () => fake.host.attachWindowsListener(
            listener: t,
            local: testBootstrap(),
          ),
          throwsStateError,
        );
        expect(fake.api.calls.length, before);
      },
    );

    test('attach is normal work: refused on a closed host and after FATAL', () {
      final closedHost = FakeNetworkHost(attach: false);
      closedHost.host.close();
      final before = closedHost.api.calls.length;
      expect(
        () => attach(closedHost, token()),
        throwsA(isA<SasPairingClosedException>()),
      );
      expect(closedHost.api.calls.length, before);

      final latched = FakeNetworkHost(attach: false);
      latched.api.script('authorityStatus', Scripted(fatal));
      expect(latched.authority.queryStatus, throwsA(nativeStatus('FATAL')));
      final t = token();
      final calls = latched.api.calls.length;
      expect(() => attach(latched, t), throwsA(nativeStatus('FATAL')));
      expect(latched.api.calls.length, calls);
      expect(t.isTransferred, isFalse);
    });

    test(
      'the exact Bootstrap bytes reach the native service; expected null stays null',
      () {
        final fake = FakeNetworkHost(attach: false);
        final local = SasPairingBootstrap(
          applicationIdentity: bytes([0x00, 0x80, 0xFF, 0x00]),
          keyAlgorithm: bytes([0x78, 0x00]),
          publicKey: bytes(List.generate(32, (i) => 255 - i)),
          sharedContext: Uint8List(0),
        );
        final expected = SasPairingBootstrap(
          applicationIdentity: bytes([0xFF]),
          keyAlgorithm: bytes([0x80, 0x80]),
          publicKey: bytes([0x00]),
          sharedContext: bytes([0x00, 0x00, 0x01]),
        );
        fake.host.attachWindowsListener(listener: token(), local: local);
        fake.host.detachListener();
        fake.host.attachWindowsListener(
          listener: token(),
          local: local,
          expected: expected,
        );
        final (firstLocal, firstExpected) = fake.api.attachedBootstraps[0];
        expect(firstLocal.applicationIdentity, [0x00, 0x80, 0xFF, 0x00]);
        expect(firstLocal.keyAlgorithm, [0x78, 0x00]);
        expect(firstLocal.publicKey, List.generate(32, (i) => 255 - i));
        expect(firstLocal.sharedContext, isEmpty);
        expect(firstExpected, isNull);
        final (_, secondExpected) = fake.api.attachedBootstraps[1];
        expect(secondExpected!.applicationIdentity, [0xFF]);
        expect(secondExpected.keyAlgorithm, [0x80, 0x80]);
        expect(secondExpected.publicKey, [0x00]);
        expect(secondExpected.sharedContext, [0x00, 0x00, 0x01]);
      },
    );
  });

  group('detach', () {
    test(
      'attached → detached; connections closed locally with no close calls',
      () {
        final fake = FakeNetworkHost();
        final a = fake.accept(100);
        final b = fake.accept(101);
        fake.host.detachListener();
        expect(fake.host.networkState, SasPairingHostNetworkState.detached);
        expect([a.isClosed, b.isClosed], [true, true]);
        expect(fake.api.count('detachListener'), 1);
        expect(fake.api.count('connectionClose'), 0);
        expect(fake.host.isClosed, isFalse);
        expect(fake.authority.isClosed, isFalse);
        expect(fake.runtime.isClosed, isFalse);
        a.close();
        expect(fake.api.count('connectionClose'), 0, reason: 'already closed');
      },
    );

    test(
      'OWNERSHIP_UNCERTAIN: detached, connections closed, thrown once, no retry',
      () {
        final fake = FakeNetworkHost();
        final a = fake.accept(100);
        fake.api.script(
          'detachListener',
          Scripted(status('SAS_PAIRING_OWNERSHIP_UNCERTAIN')),
        );
        expect(
          fake.host.detachListener,
          throwsA(nativeStatus('OWNERSHIP_UNCERTAIN')),
        );
        expect(fake.host.networkState, SasPairingHostNetworkState.detached);
        expect(a.isClosed, isTrue);
        expect(fake.api.count('detachListener'), 1);
        expect(fake.api.count('connectionClose'), 0);
      },
    );

    test('detach is cleanup: it still reaches native after FATAL', () {
      final fake = FakeNetworkHost();
      fake.api.script('authorityStatus', Scripted(fatal));
      expect(fake.authority.queryStatus, throwsA(nativeStatus('FATAL')));
      fake.host.detachListener();
      expect(fake.api.count('detachListener'), 1);
      expect(fake.host.networkState, SasPairingHostNetworkState.detached);
    });

    test('detach leaves the host usable: attach L1, detach, attach L2', () {
      final fake = FakeNetworkHost(attach: false);
      final l1 = token(1);
      final l2 = token(2);
      fake.host.attachWindowsListener(listener: l1, local: testBootstrap());
      final c1 = fake.accept(100);
      fake.host.detachListener();
      fake.host.attachWindowsListener(listener: l2, local: testBootstrap());
      expect([l1.isTransferred, l2.isTransferred], [true, true]);
      expect(fake.host.networkState, SasPairingHostNetworkState.attached);
      expect(c1.isClosed, isTrue);
      final c2 = fake.accept(200);
      expect(identical(c1, c2), isFalse);
      expect(c2.isClosed, isFalse);
      expect(networkCalls(fake.api), [
        'attachWindowsListener',
        'drive',
        'detachListener',
        'attachWindowsListener',
        'drive',
      ]);
      expect(fake.api.count('authorityRelease'), 0);
      expect(fake.api.count('hostDestroy'), 0);
    });

    test('detach on a closed host does nothing', () {
      final fake = FakeNetworkHost();
      fake.host.close();
      fake.host.detachListener();
      expect(fake.api.count('detachListener'), 0);
      expect(fake.host.networkState, SasPairingHostNetworkState.detached);
    });
  });

  group('drive', () {
    test('OK, no events, no failure: an empty batch', () {
      final fake = FakeNetworkHost();
      final batch = fake.host.drive();
      expect(batch.events, isEmpty);
      expect(batch.failure, isNull);
      expect(() => batch.events.add(batch.events.first), throwsA(anything));
      expect(fake.api.count('drive'), 1);
      expect(fake.host.networkState, SasPairingHostNetworkState.attached);
    });

    test(
      'one public call is exactly one native call; recheck calls only the recheck',
      () {
        final fake = FakeNetworkHost();
        fake.host.drive();
        expect(networkCalls(fake.api), ['attachWindowsListener', 'drive']);
        fake.host.recheckAfterResume();
        expect(networkCalls(fake.api), [
          'attachWindowsListener',
          'drive',
          'recheckAfterResume',
        ]);
        expect(fake.api.calls.last.arguments, [1000, 1002]);
      },
    );

    for (final name in [
      'LISTENER_NOT_ATTACHED',
      'HANDLES_EXHAUSTED',
      'INVALID_HANDLE',
      'UNSUPPORTED_PLATFORM',
      'BUFFER_TOO_SMALL',
    ]) {
      test('top-level $name: no batch, no state change', () {
        final fake = FakeNetworkHost();
        final c = fake.accept(100);
        fake.api.scriptDrive(
          FakeDrive(status: status('SAS_PAIRING_$name'), events: [step(100)]),
        );
        expect(fake.host.drive, throwsA(nativeStatus(name)));
        expect(fake.host.networkState, SasPairingHostNetworkState.attached);
        expect(c.isClosed, isFalse);
        expect(fake.context.isFatal, isFalse);
      });
    }

    test('top-level FATAL: no batch, FATAL latched, state unchanged', () {
      final fake = FakeNetworkHost();
      fake.api.scriptDrive(FakeDrive(status: fatal));
      expect(fake.host.drive, throwsA(nativeStatus('FATAL')));
      expect(fake.context.isFatal, isTrue);
      expect(fake.host.networkState, SasPairingHostNetworkState.attached);
    });

    for (final name in [
      'NETWORK_POLL_FAILED',
      'OWNERSHIP_UNCERTAIN',
      'FATAL',
    ]) {
      test(
        'OK + events + out_failure $name: events delivered, then failed closed',
        () {
          final fake = FakeNetworkHost();
          final earlier = fake.accept(99);
          final batch = fake.drive([
            accepted(100),
            step(99),
          ], failure: status('SAS_PAIRING_$name'));
          expect(batch.events.map((e) => e.kind), [
            SasPairingEventKind.connectionAccepted,
            SasPairingEventKind.connectionStep,
          ]);
          expect(identical(batch.events[1].connection, earlier), isTrue);
          expect(batch.failure!.statusCode, status('SAS_PAIRING_$name'));
          expect(batch.failure!.knownStatus, isNotNull);
          expect(batch.failure!.processRestartRequired, name == 'FATAL');
          expect(fake.context.isFatal, name == 'FATAL');
          expect(
            fake.host.networkState,
            SasPairingHostNetworkState.failedClosed,
          );
          expect(batch.events[0].connection!.isClosed, isTrue);
          expect(earlier.isClosed, isTrue);
          expect(fake.api.count('connectionClose'), 0);
        },
      );
    }

    test('OK + no events + OWNER_LOOP_CLOSED: failed closed, empty batch', () {
      final fake = FakeNetworkHost();
      final c = fake.accept(100);
      final batch = fake.drive(
        [],
        failure: status('SAS_PAIRING_OWNER_LOOP_CLOSED'),
      );
      expect(batch.events, isEmpty);
      expect(batch.failure!.knownStatus, SasPairingStatus.ownerLoopClosed);
      expect(fake.host.networkState, SasPairingHostNetworkState.failedClosed);
      expect(c.isClosed, isTrue);
    });

    test(
      'an unknown out_failure is preserved and still fails closed (no FATAL)',
      () {
        final fake = FakeNetworkHost();
        final batch = fake.drive([], failure: 777);
        expect(batch.failure!.statusCode, 777);
        expect(batch.failure!.knownStatus, isNull);
        expect(batch.failure!.processRestartRequired, isFalse);
        expect(fake.host.networkState, SasPairingHostNetworkState.failedClosed);
        expect(fake.context.isFatal, isFalse);
      },
    );

    test(
      'after failing closed the next drive still goes to native; nothing is synthesized',
      () {
        final fake = FakeNetworkHost();
        fake.drive([], failure: status('SAS_PAIRING_NETWORK_POLL_FAILED'));
        final before = fake.api.count('drive');
        final again = fake.drive(
          [],
          failure: status('SAS_PAIRING_OWNER_LOOP_CLOSED'),
        );
        expect(fake.api.count('drive'), before + 1);
        expect(again.failure!.knownStatus, SasPairingStatus.ownerLoopClosed);
        fake.host.detachListener();
        expect(fake.host.networkState, SasPairingHostNetworkState.detached);
      },
    );

    test(
      'drive and recheck are normal work: refused when closed or after FATAL',
      () {
        final fake = FakeNetworkHost();
        fake.api.script('authorityStatus', Scripted(fatal));
        expect(fake.authority.queryStatus, throwsA(nativeStatus('FATAL')));
        final before = fake.api.calls.length;
        expect(fake.host.drive, throwsA(nativeStatus('FATAL')));
        expect(fake.host.recheckAfterResume, throwsA(nativeStatus('FATAL')));
        expect(fake.api.calls.length, before);

        final closedHost = FakeNetworkHost();
        closedHost.host.close();
        final calls = closedHost.api.calls.length;
        expect(
          closedHost.host.drive,
          throwsA(isA<SasPairingClosedException>()),
        );
        expect(
          closedHost.host.recheckAfterResume,
          throwsA(isA<SasPairingClosedException>()),
        );
        expect(closedHost.api.calls.length, calls);
        expect(
          closedHost.host.networkState,
          SasPairingHostNetworkState.detached,
        );
      },
    );

    test('more than 17 events is a contract violation', () {
      final fake = FakeNetworkHost();
      fake.api.scriptDrive(
        FakeDrive(count: 18, events: List.filled(17, acceptRefused())),
      );
      expect(fake.host.drive, throwsA(contractViolation));
      expect(fake.context.isContractViolated, isTrue);
    });

    test(
      'native event order is kept exactly (no sorting, grouping, or deduplication)',
      () {
        final fake = FakeNetworkHost();
        final batch = fake.drive([
          accepted(300),
          acceptRefused(),
          accepted(100),
          step(300, step: 'WRITTEN'),
          acceptRefused(),
          step(100, step: 'DISCARDED'),
          step(300, step: 'WRITTEN'),
          closed(100),
        ]);
        expect(batch.events.map((e) => '${e.kind.name}/${e.stepKind.name}'), [
          'connectionAccepted/none',
          'acceptRefused/none',
          'connectionAccepted/none',
          'connectionStep/written',
          'acceptRefused/none',
          'connectionStep/discarded',
          'connectionStep/written',
          'connectionClosed/none',
        ]);
        final c300 = batch.events[0].connection;
        final c100 = batch.events[2].connection;
        expect(
          [for (final e in batch.events) e.connection].map(
            (c) => identical(c, c300) ? 300 : (identical(c, c100) ? 100 : null),
          ),
          [300, null, 100, 300, null, 100, 300, 100],
        );
      },
    );
  });

  group('out_failure FATAL', () {
    test(
      'the batch and its events are returned, FATAL is latched, cleanup still works',
      () {
        final fake = FakeNetworkHost();
        final batch = fake.drive([accepted(100)], failure: fatal);
        expect(batch.events, hasLength(1));
        expect(
          batch.events.single.kind,
          SasPairingEventKind.connectionAccepted,
        );
        expect(batch.failure!.statusCode, 900);
        expect(batch.failure!.processRestartRequired, isTrue);
        expect(fake.context.isFatal, isTrue);

        final before = fake.api.calls.length;
        expect(fake.host.drive, throwsA(nativeStatus('FATAL')));
        expect(fake.host.recheckAfterResume, throwsA(nativeStatus('FATAL')));
        expect(
          () => fake.host.attachWindowsListener(
            listener: token(),
            local: testBootstrap(),
          ),
          throwsA(nativeStatus('FATAL')),
        );
        expect(fake.authority.createHost, throwsA(nativeStatus('FATAL')));
        expect(
          () => fake.runtime.registerAuthority(bytes([9])),
          throwsA(nativeStatus('FATAL')),
        );
        expect(fake.api.calls.length, before, reason: 'refused locally');

        fake.host.detachListener();
        fake.host.close();
        fake.runtime.close();
        expect(fake.api.operations.skip(before), [
          'detachListener',
          'hostDestroy',
          'runtimeDestroy',
        ]);
      },
    );
  });

  group('event mapping', () {
    test(
      'every frozen value of every event namespace maps to its named enum value',
      () {
        final tables = <String, (Map<String, int>, List<Enum>)>{
          'STEP_': (namespace('STEP_'), SasPairingStepKind.values),
          'PROTOCOL_EVENT_': (
            namespace('PROTOCOL_EVENT_'),
            SasPairingProtocolEvent.values,
          ),
          'EVENT_REASON_': (
            namespace('EVENT_REASON_'),
            SasPairingEventReason.values,
          ),
          'DEADLINE_': (namespace('DEADLINE_'), SasPairingDeadlineKind.values),
          'CANCEL_STATE_': (
            namespace('CANCEL_STATE_'),
            SasPairingCancelState.values,
          ),
          'CANCEL_REASON_': (
            namespace('CANCEL_REASON_'),
            SasPairingCancelReason.values,
          ),
        };
        for (final MapEntry(key: prefix, value: (frozen, values))
            in tables.entries) {
          // The enum has exactly one value per frozen constant, named after it.
          expect(
            values.map((v) => v.name).toSet(),
            frozen.keys.toSet(),
            reason: prefix,
          );
          for (final MapEntry(key: name, value: code) in frozen.entries) {
            final fake = FakeNetworkHost();
            fake.accept(100);
            final record = NativeEventRecord(
              kind: abi('EVENT_CONNECTION_STEP'),
              connection: 100,
              stepKind: prefix == 'STEP_' ? code : 0,
              protocolEvent: prefix == 'PROTOCOL_EVENT_' ? code : 0,
              reason: prefix == 'EVENT_REASON_' ? code : 0,
              deadlineKind: prefix == 'DEADLINE_' ? code : 0,
              cancelState: prefix == 'CANCEL_STATE_' ? code : 0,
              cancelReason: prefix == 'CANCEL_REASON_' ? code : 0,
            );
            final event = fake.drive([record]).events.single;
            final mapped = switch (prefix) {
              'STEP_' => event.stepKind,
              'PROTOCOL_EVENT_' => event.protocolEvent,
              'EVENT_REASON_' => event.reason,
              'DEADLINE_' => event.deadlineKind,
              'CANCEL_STATE_' => event.cancelState,
              _ => event.cancelReason,
            };
            expect(mapped.name, name, reason: '$prefix$name = $code');
          }
        }
      },
    );

    test(
      'the five produced event kinds map exactly; INVALID is not a public kind',
      () {
        final kinds = namespace('EVENT_')
          ..removeWhere(
            (name, _) => name.startsWith('reason') || name.startsWith('flag'),
          );
        expect(kinds.keys.toSet(), {
          'invalid',
          'connectionAccepted',
          'acceptRefused',
          'listenerDisabled',
          'connectionStep',
          'connectionClosed',
        });
        expect(
          SasPairingEventKind.values.map((k) => k.name).toSet(),
          kinds.keys.toSet()..remove('invalid'),
        );
        final fake = FakeNetworkHost();
        final batch = fake.drive([
          accepted(100),
          acceptRefused(),
          step(100),
          closed(100),
          listenerDisabled(),
        ]);
        expect(batch.events.map((e) => e.kind.name), [
          'connectionAccepted',
          'acceptRefused',
          'connectionStep',
          'connectionClosed',
          'listenerDisabled',
        ]);
        for (final (index, name) in [
          (0, 'connectionAccepted'),
          (1, 'acceptRefused'),
          (2, 'connectionStep'),
          (3, 'connectionClosed'),
          (4, 'listenerDisabled'),
        ]) {
          expect(kinds[name], abi('EVENT_${_upper(name)}'), reason: name);
          expect(batch.events[index].kind.name, name);
        }
      },
    );

    test(
      'reasons on accept refusals, listener events, and closes are preserved',
      () {
        final fake = FakeNetworkHost();
        fake.accept(100);
        final batch = fake.drive([
          acceptRefused(reason: 'RESOURCE_LIMITED'),
          closed(100, reason: 'READINESS_FAILURE'),
          listenerDisabled(reason: 'LISTENER_READINESS'),
        ]);
        expect(batch.events.map((e) => e.reason), [
          SasPairingEventReason.resourceLimited,
          SasPairingEventReason.readinessFailure,
          SasPairingEventReason.listenerReadiness,
        ]);
        expect(batch.events[0].connection, isNull);
        expect(batch.events[2].connection, isNull);
      },
    );
  });

  group('frozen record invariants', () {
    void violates(String what, NativeEventRecord Function() record) {
      test('$what is a contract violation that blocks normal work', () {
        final fake = FakeNetworkHost();
        fake.accept(100);
        expect(() => fake.drive([record()]), throwsA(contractViolation));
        expect(fake.context.isContractViolated, isTrue);
        final before = fake.api.calls.length;
        expect(fake.host.drive, throwsA(contractViolation));
        expect(fake.authority.createHost, throwsA(contractViolation));
        expect(fake.api.calls.length, before);
        // Cleanup stays allowed.
        fake.host.close();
        expect(fake.api.count('hostDestroy'), 1);
      });
    }

    violates(
      'event kind INVALID (0)',
      () => NativeEventRecord(kind: abi('EVENT_INVALID')),
    );
    violates('an unknown event kind', () => NativeEventRecord(kind: 6));
    violates(
      'an unknown step kind value',
      () => NativeEventRecord(
        kind: abi('EVENT_CONNECTION_STEP'),
        connection: 100,
        stepKind: 8,
      ),
    );
    violates(
      'an unknown protocol event',
      () => NativeEventRecord(
        kind: abi('EVENT_CONNECTION_STEP'),
        connection: 100,
        protocolEvent: 13,
      ),
    );
    violates(
      'an unknown reason',
      () => NativeEventRecord(kind: abi('EVENT_ACCEPT_REFUSED'), reason: 16),
    );
    violates(
      'an unknown deadline kind',
      () => NativeEventRecord(
        kind: abi('EVENT_CONNECTION_STEP'),
        connection: 100,
        deadlineKind: 5,
      ),
    );
    violates(
      'an unknown cancel state',
      () => NativeEventRecord(
        kind: abi('EVENT_CONNECTION_STEP'),
        connection: 100,
        cancelState: 4,
      ),
    );
    violates(
      'an unknown cancel reason',
      () => NativeEventRecord(
        kind: abi('EVENT_CONNECTION_STEP'),
        connection: 100,
        cancelReason: 5,
      ),
    );
    violates('an unknown flag bit 0x4', () => step(100, flags: 0x4));
    violates(
      'an unknown flag bit 0x80000000',
      () => step(100, flags: 0x80000000 | 0x1),
    );
    violates('request_id_len 65', () => step(100, requestIdLength: 65));
    violates('a nonzero reserved field', () => step(100, reserved: 1));
    violates(
      'a nonzero request ID byte past its length',
      () => step(
        100,
        requestIdLength: 2,
        requestIdBytes: requestIdArray([1, 2, 3]),
      ),
    );
    violates('connectionAccepted without a connection', () => accepted(0));
    violates('connectionStep without a connection', () => step(0));
    violates('connectionClosed without a connection', () => closed(0));
    violates(
      'acceptRefused with a connection',
      () =>
          NativeEventRecord(kind: abi('EVENT_ACCEPT_REFUSED'), connection: 100),
    );
    violates(
      'listenerDisabled with a connection',
      () => NativeEventRecord(
        kind: abi('EVENT_LISTENER_DISABLED'),
        connection: 100,
      ),
    );
    violates(
      'a run on a non-step event',
      () => NativeEventRecord(
        kind: abi('EVENT_CONNECTION_CLOSED'),
        connection: 100,
        run: 5,
      ),
    );
    violates(
      'a result on a non-step event',
      () => NativeEventRecord(kind: abi('EVENT_ACCEPT_REFUSED'), result: 5),
    );
    violates(
      'flags on a non-step event',
      () => NativeEventRecord(
        kind: abi('EVENT_CONNECTION_ACCEPTED'),
        connection: 101,
        flags: 1,
      ),
    );
    violates(
      'both a run and a result',
      () => inbound(100, requestId: [1], run: 5, result: 6),
    );
    violates(
      'RUN_UNTRACKED with a run',
      () => inbound(100, requestId: [1], run: 5, flags: runUntrackedFlag),
    );
    violates('a duplicate connectionAccepted', () => accepted(100));
    violates('connectionStep for an unknown connection', () => step(777));
    violates('connectionClosed for an unknown connection', () => closed(777));

    test('request ID lengths 0 and 64 are valid and copied exactly', () {
      final fake = FakeNetworkHost();
      fake.accept(100);
      final full = List.generate(64, (i) => (i * 37 + 0x80) & 0xFF)..[0] = 0x00;
      final batch = fake.drive([
        step(100, step: 'WRITTEN'),
        step(
          100,
          step: 'DEADLINE',
          deadline: 'ABSOLUTE_TIMEOUT',
          requestId: full,
        ),
      ]);
      expect(batch.events[0].requestId, isEmpty);
      expect(batch.events[1].requestId, full);
      expect(batch.events[1].requestId, hasLength(64));
      expect(() => batch.events[1].requestId[0] = 1, throwsUnsupportedError);
      expect(fake.context.isContractViolated, isFalse);
    });

    test('a violation in a later record changes no state before it', () {
      final fake = FakeNetworkHost();
      expect(
        () => fake.drive([accepted(100), step(100, reserved: 1)]),
        throwsA(contractViolation),
      );
      // The bad record was found before the accept was applied: no wrapper was made.
      expect(fake.host.networkState, SasPairingHostNetworkState.attached);
      fake.host.detachListener();
      expect(fake.api.count('connectionClose'), 0);
    });
  });

  group('connections', () {
    test(
      'one native handle maps to one Dart object across events and batches',
      () {
        final fake = FakeNetworkHost();
        final batch = fake.drive([accepted(100), step(100), closed(100)]);
        final c = batch.events[0].connection!;
        expect(identical(batch.events[1].connection, c), isTrue);
        expect(identical(batch.events[2].connection, c), isTrue);
        expect(c.isClosed, isTrue, reason: 'closed by its closed event');
        expect('$c', isNot(contains('100')));

        final d = fake.accept(101);
        final later = fake.drive([step(101)]);
        expect(identical(later.events.single.connection, d), isTrue);
        expect(d.isClosed, isFalse);
      },
    );

    test(
      'connectionClosed closes locally with no native call; the handle is forgotten',
      () {
        final fake = FakeNetworkHost();
        final c = fake.accept(100);
        fake.drive([closed(100)]);
        expect(c.isClosed, isTrue);
        c.close();
        expect(fake.api.count('connectionClose'), 0);
        expect(() => fake.drive([step(100)]), throwsA(contractViolation));
      },
    );

    test('manual close: one native call, consuming, idempotent', () {
      final fake = FakeNetworkHost();
      final c = fake.accept(100);
      c.close();
      expect(c.isClosed, isTrue);
      expect(fake.api.count('connectionClose'), 1);
      expect(fake.api.calls.last.arguments, [1000, 1002, 100]);
      c.close();
      expect(fake.api.count('connectionClose'), 1);
      expect(() => fake.drive([step(100)]), throwsA(contractViolation));
    });

    test(
      'manual close with a native error: closed anyway, thrown once, not retried',
      () {
        final fake = FakeNetworkHost();
        final c = fake.accept(100);
        final sibling = fake.accept(101);
        fake.api.script(
          'connectionClose',
          Scripted(status('SAS_PAIRING_INVALID_HANDLE')),
        );
        expect(c.close, throwsA(nativeStatus('INVALID_HANDLE')));
        expect(c.isClosed, isTrue);
        c.close();
        expect(fake.api.count('connectionClose'), 1);
        expect(sibling.isClosed, isFalse);
        expect(fake.host.networkState, SasPairingHostNetworkState.attached);
      },
    );

    test(
      'OWNERSHIP_UNCERTAIN from close fails the loop closed: every connection closed',
      () {
        final fake = FakeNetworkHost();
        final a = fake.accept(100);
        final b = fake.accept(101);
        fake.api.script(
          'connectionClose',
          Scripted(status('SAS_PAIRING_OWNERSHIP_UNCERTAIN')),
        );
        expect(a.close, throwsA(nativeStatus('OWNERSHIP_UNCERTAIN')));
        expect([a.isClosed, b.isClosed], [true, true]);
        expect(fake.host.networkState, SasPairingHostNetworkState.failedClosed);
        expect(
          fake.api.count('connectionClose'),
          1,
          reason: 'no sibling close',
        );
        b.close();
        expect(fake.api.count('connectionClose'), 1);
      },
    );

    test(
      'close is cleanup: allowed after FATAL; a FATAL close latches and stays closed',
      () {
        final fake = FakeNetworkHost();
        final a = fake.accept(100);
        final b = fake.accept(101);
        fake.api.script('connectionClose', Scripted(fatal));
        expect(a.close, throwsA(nativeStatus('FATAL')));
        expect(a.isClosed, isTrue);
        expect(fake.context.isFatal, isTrue);
        b.close();
        expect(fake.api.count('connectionClose'), 2);
        expect(b.isClosed, isTrue);
      },
    );
  });

  group('LISTENER_DISABLED', () {
    test(
      'keeps connections alive; distinct from failedClosed and detached',
      () {
        final fake = FakeNetworkHost();
        final c = fake.accept(100);
        final batch = fake.drive([listenerDisabled(reason: 'LISTENER_IO')]);
        expect(batch.events.single.reason, SasPairingEventReason.listenerIo);
        expect(
          fake.host.networkState,
          SasPairingHostNetworkState.listenerDisabled,
        );
        expect(c.isClosed, isFalse);
        final later = fake.drive([step(100, step: 'WRITTEN')]);
        expect(identical(later.events.single.connection, c), isTrue);
        expect(
          fake.host.networkState,
          SasPairingHostNetworkState.listenerDisabled,
        );
        fake.host.detachListener();
        expect(c.isClosed, isTrue);
        expect(fake.host.networkState, SasPairingHostNetworkState.detached);
        expect(fake.api.count('connectionClose'), 0);
      },
    );
  });

  group('RUN_UNTRACKED and WRITE_PENDING', () {
    test(
      'RUN_UNTRACKED: exposed with close guidance, never closed automatically',
      () {
        final fake = FakeNetworkHost();
        final c = fake.accept(100);
        final tracked = fake
            .drive([
              inbound(100, requestId: [0xAA], run: 5000),
            ])
            .events
            .single;
        final batch = fake.drive([
          inbound(100, requestId: [0xBB], flags: runUntrackedFlag),
          step(100, step: 'WRITTEN'),
        ]);
        final event = batch.events.first;
        expect(event.runUntracked, isTrue);
        expect(event.shouldCloseConnection, isTrue);
        expect(event.hasTrackedRun, isFalse);
        expect(runReferenceOf(event), isNull);
        expect(event.writePending, isFalse);
        // Every event is delivered and nothing was closed behind the consumer's back.
        expect(batch.events, hasLength(2));
        expect(c.isClosed, isFalse);
        expect(fake.api.count('connectionClose'), 0);
        // No other run reference was evicted or retargeted.
        expect(runReferenceOf(tracked)!.isValid, isTrue);
        expect(runReferencesOf(c).map((r) => r.handle), [5000]);
        // The consumer follows the guidance after the batch.
        for (final e in batch.events) {
          if (e.shouldCloseConnection) e.connection!.close();
        }
        expect(c.isClosed, isTrue);
        expect(fake.api.count('connectionClose'), 1);
      },
    );

    test(
      'WRITE_PENDING is metadata only; without RUN_UNTRACKED there is no guidance',
      () {
        final fake = FakeNetworkHost();
        final c = fake.accept(100);
        final event = fake
            .drive([
              step(
                100,
                step: 'INBOUND',
                protocol: 'ACCEPT',
                flags: writePendingFlag,
                requestId: [1],
                run: 7,
              ),
            ])
            .events
            .single;
        expect(event.writePending, isTrue);
        expect(event.runUntracked, isFalse);
        expect(event.shouldCloseConnection, isFalse);
        expect(c.isClosed, isFalse);
        expect(fake.host.networkState, SasPairingHostNetworkState.attached);
        expect(fake.context.isFatal, isFalse);
        final both = fake
            .drive([
              inbound(
                100,
                requestId: [2],
                flags: writePendingFlag | runUntrackedFlag,
              ),
            ])
            .events
            .single;
        expect(
          [both.writePending, both.runUntracked, both.shouldCloseConnection],
          [true, true, true],
        );
      },
    );
  });

  group('private run references', () {
    test(
      'exact native handles are kept privately; request IDs never become run identity',
      () {
        final fake = FakeNetworkHost();
        final c = fake.accept(100);
        final first = fake
            .drive([
              inbound(100, requestId: [0xA0], run: 5000),
            ])
            .events
            .single;
        final ref = runReferenceOf(first)!;
        expect(first.hasTrackedRun, isTrue);
        expect(ref.handle, 5000);
        expect(ref.isValid, isTrue);

        // The same exact run again: the same reference.
        final again = fake
            .drive([
              step(
                100,
                step: 'INBOUND',
                protocol: 'INITIATOR_KEY',
                requestId: [0xA0],
                run: 5000,
              ),
            ])
            .events
            .single;
        expect(identical(runReferenceOf(again), ref), isTrue);

        // A replacement run under the reused request ID: a new reference; the old one is never
        // retargeted (it still names exactly 5000) and is invalidated by the native rule.
        final replacement = fake
            .drive([
              inbound(100, requestId: [0xA0], run: 5001),
            ])
            .events
            .single;
        final newRef = runReferenceOf(replacement)!;
        expect(identical(newRef, ref), isFalse);
        expect(newRef.handle, 5001);
        expect(ref.handle, 5000);
        expect(ref.isValid, isFalse);

        // Another request ID: independent.
        final other = runReferenceOf(
          fake
              .drive([
                inbound(100, requestId: [0xB0], run: 5002),
              ])
              .events
              .single,
        )!;
        expect(runReferencesOf(c).map((r) => r.handle), [5001, 5002]);
        expect(newRef.isValid && other.isValid, isTrue);
        expect('$first', isNot(contains('5000')));
      },
    );

    test('visible endings invalidate references under their request ID only', () {
      final fake = FakeNetworkHost();
      final c = fake.accept(100);
      NativeRunRef run(List<int> id, int handle) => runReferenceOf(
        fake.drive([inbound(100, requestId: id, run: handle)]).events.single,
      )!;

      final a = run([1], 11);
      final b = run([2], 12);
      final d = run([3], 13);
      final e = run([4], 14);
      final f = run([5], 15);

      // START_DUPLICATE with run 0 ends nothing.
      fake.drive([
        inbound(100, requestId: [2], protocol: 'START_DUPLICATE'),
      ]);
      expect(b.isValid, isTrue);
      // Any other inbound frame with run 0 ends the run under its request ID.
      fake.drive([
        inbound(100, requestId: [2], protocol: 'PEER_CANCEL'),
      ]);
      expect(b.isValid, isFalse);
      // A deadline with a request ID ends it; one without a request ID names nothing.
      fake.drive([step(100, step: 'DEADLINE', deadline: 'INACTIVITY_TIMEOUT')]);
      expect(d.isValid, isTrue);
      fake.drive([
        step(
          100,
          step: 'DEADLINE',
          deadline: 'INACTIVITY_TIMEOUT',
          requestId: [3],
        ),
      ]);
      expect(d.isValid, isFalse);
      // A result ends the run under its request ID.
      fake.drive([
        step(100, step: 'CONFIRMED', requestId: [1], result: 9001),
      ]);
      expect(a.isValid, isFalse);
      // Refused, unconfirmed, discarded, and written name no run: references may go stale.
      fake.drive([
        step(100, step: 'REFUSED', reason: 'ROUTE_REFUSED'),
        step(100, step: 'UNCONFIRMED', reason: 'ROUTE_REFUSED'),
        step(100, step: 'DISCARDED'),
        step(100, step: 'WRITTEN'),
      ]);
      expect([e.isValid, f.isValid], [true, true]);
      expect(runReferencesOf(c).map((r) => r.handle), [14, 15]);
      // Closing the connection invalidates every remaining reference.
      c.close();
      expect([e.isValid, f.isValid], [false, false]);
    });

    for (final teardown in [
      'closed event',
      'detach',
      'owner-loop failure',
      'host close',
      'authority close',
      'runtime close',
    ]) {
      test('$teardown invalidates every run reference of the connection', () {
        final fake = FakeNetworkHost();
        fake.accept(100);
        final ref = runReferenceOf(
          fake
              .drive([
                inbound(100, requestId: [1], run: 77),
              ])
              .events
              .single,
        )!;
        switch (teardown) {
          case 'closed event':
            fake.drive([closed(100)]);
          case 'detach':
            fake.host.detachListener();
          case 'owner-loop failure':
            fake.drive([], failure: status('SAS_PAIRING_NETWORK_POLL_FAILED'));
          case 'host close':
            fake.host.close();
          case 'authority close':
            fake.authority.close();
          case 'runtime close':
            fake.runtime.close();
        }
        expect(ref.isValid, isFalse);
        expect(ref.handle, 77, reason: 'never retargeted');
      });
    }
  });

  group('runtime-owned results (P8.3, public since P8.5)', () {
    test(
      'results are retained at runtime lifetime and only runtime close ends them',
      () {
        final fake = FakeNetworkHost();
        final c = fake.accept(100);
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
            .single;
        final initiator = fake
            .drive([
              step(100, step: 'CONFIRMED', requestId: [2], result: 9001),
            ])
            .events
            .single;
        expect([responder.hasResult, initiator.hasResult], [true, true]);
        expect(
          [responder.hasTrackedRun, initiator.hasTrackedRun],
          [false, false],
        );
        final r1 = responder.result!;
        final r2 = initiator.result!;
        expect(resultStoreOf(fake.runtime).live, [r1, r2]);
        expect(resultStoreOf(fake.runtime).delivered(9000), isTrue);
        expect(resultStoreOf(fake.runtime).delivered(9001), isTrue);

        c.close();
        fake.host.detachListener();
        fake.drive([], failure: status('SAS_PAIRING_NETWORK_POLL_FAILED'));
        fake.host.close();
        fake.authority.close();
        expect([r1.isClosed, r2.isClosed], [false, false]);
        expect(resultStoreOf(fake.runtime).live, hasLength(2));
        // No drive or teardown destroys, reads, or interprets a result.
        expect(
          fake.api.operations.where(
            (op) => op.toLowerCase().contains('result'),
          ),
          isEmpty,
        );
        fake.runtime.close();
        expect([r1.isClosed, r2.isClosed], [true, true]);
        expect('$responder', isNot(contains('9000')));
        expect('$r1', isNot(contains('9000')));
      },
    );

    test('a result handle delivered twice is a contract violation', () {
      final fake = FakeNetworkHost();
      fake.accept(100);
      fake.drive([
        step(100, step: 'CONFIRMED', requestId: [1], result: 9000),
      ]);
      expect(
        () => fake.drive([
          step(100, step: 'CONFIRMED', requestId: [2], result: 9000),
        ]),
        throwsA(contractViolation),
      );
    });

    test('a result delivered with an owner-loop failure is still retained', () {
      final fake = FakeNetworkHost();
      fake.accept(100);
      final batch = fake.drive([
        step(100, step: 'CONFIRMED', requestId: [1], result: 9000),
      ], failure: status('SAS_PAIRING_OWNERSHIP_UNCERTAIN'));
      expect(batch.events.single.hasResult, isTrue);
      expect(batch.events.single.result!.isClosed, isFalse);
      expect(fake.host.networkState, SasPairingHostNetworkState.failedClosed);
    });
  });

  group('parent cascade with live connections', () {
    test('host close: 1 host_destroy, 0 detach, 0 connection close', () {
      final fake = FakeNetworkHost();
      final a = fake.accept(100);
      final b = fake.accept(101);
      final before = fake.api.calls.length;
      fake.host.close();
      expect(fake.api.operations.skip(before), ['hostDestroy']);
      expect([a.isClosed, b.isClosed], [true, true]);
      expect(fake.host.networkState, SasPairingHostNetworkState.detached);
      expect(fake.authority.isClosed, isFalse);
    });

    test('host close with a native error still closes every connection', () {
      final fake = FakeNetworkHost();
      final a = fake.accept(100);
      fake.api.script(
        'hostDestroy',
        Scripted(status('SAS_PAIRING_OWNERSHIP_UNCERTAIN')),
      );
      expect(fake.host.close, throwsA(nativeStatus('OWNERSHIP_UNCERTAIN')));
      expect(a.isClosed, isTrue);
      expect(fake.host.networkState, SasPairingHostNetworkState.detached);
    });

    test(
      'authority close: 1 authority_release, no host, detach, or connection cleanup',
      () {
        final fake = FakeNetworkHost();
        final second = fake.authority.createHost();
        second.attachWindowsListener(
          listener: token(9),
          local: testBootstrap(),
        );
        final a = fake.accept(100);
        fake.api.scriptDrive(FakeDrive(events: [accepted(200)]));
        final b = second.drive().events.single.connection!;
        final before = fake.api.calls.length;
        fake.authority.close();
        expect(fake.api.operations.skip(before), ['authorityRelease']);
        expect([fake.host.isClosed, second.isClosed], [true, true]);
        expect([a.isClosed, b.isClosed], [true, true]);
        expect([
          fake.host.networkState,
          second.networkState,
        ], everyElement(SasPairingHostNetworkState.detached));
        expect(fake.runtime.isClosed, isFalse);
      },
    );

    test('runtime close: 1 runtime_destroy and no child cleanup export', () {
      final fake = FakeNetworkHost();
      final otherAuthority = fake.runtime.registerAuthority(bytes([2]));
      final otherHost = otherAuthority.createHost();
      otherHost.attachWindowsListener(
        listener: token(8),
        local: testBootstrap(),
      );
      final a = fake.accept(100);
      fake.api.scriptDrive(FakeDrive(events: [accepted(300)]));
      final b = otherHost.drive().events.single.connection!;
      final before = fake.api.calls.length;
      fake.runtime.close();
      expect(fake.api.operations.skip(before), ['runtimeDestroy']);
      expect([fake.authority, otherAuthority].map((x) => x.isClosed), [
        true,
        true,
      ]);
      expect([fake.host.isClosed, otherHost.isClosed], [true, true]);
      expect([a.isClosed, b.isClosed], [true, true]);
      expect(otherHost.networkState, SasPairingHostNetworkState.detached);
    });
  });

  group('resume recheck', () {
    test('uses the same mapper, connections, and failure rules as drive', () {
      final fake = FakeNetworkHost();
      final c = fake.accept(100);
      fake.api.scriptDrive(
        FakeDrive(
          events: [
            step(
              100,
              step: 'DEADLINE',
              deadline: 'PENDING_EXPIRED',
              cancelState: 'NOT_BUILT',
              requestId: [1],
            ),
          ],
        ),
      );
      final batch = fake.host.recheckAfterResume();
      final event = batch.events.single;
      expect(identical(event.connection, c), isTrue);
      expect(event.deadlineKind, SasPairingDeadlineKind.pendingExpired);
      expect(event.cancelState, SasPairingCancelState.notBuilt);
      expect(batch.failure, isNull);

      fake.api.scriptDrive(
        FakeDrive(
          events: [step(100)],
          failure: status('SAS_PAIRING_NETWORK_POLL_FAILED'),
        ),
      );
      final failed = fake.host.recheckAfterResume();
      expect(failed.events, hasLength(1));
      expect(failed.failure!.knownStatus, SasPairingStatus.networkPollFailed);
      expect(c.isClosed, isTrue);
      expect(fake.host.networkState, SasPairingHostNetworkState.failedClosed);
      expect(fake.api.count('drive'), 1, reason: 'only the accept above');
      expect(fake.api.count('recheckAfterResume'), 2);
    });
  });
}

String _upper(String camelName) => camelName
    .replaceAllMapped(RegExp('[A-Z]'), (m) => '_${m[0]}')
    .toUpperCase();
