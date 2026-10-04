// P8.4 runs, trusted-local ceremony control, and SAS presentation over a deterministic fake of the
// private native services (P8-D-004): exact-handle run identity and request-ID learning, the
// local Initiator start, every run action's method-specific success contract, the action and
// presentation record invariants, deadlines, WRITE_PENDING status versus the WRITE_PENDING flag,
// known-ended runs and the first native RUN_ENDED, the lifecycle side effects of CONNECTION_ENDED,
// OWNERSHIP_UNCERTAIN, OWNER_LOOP_CLOSED, and FATAL, explicit step separation, and decisions bound
// to the presented ceremony identity. No native library is loaded, so these run on every
// platform.
import 'dart:typed_data';

import 'package:sas_pairing/sas_pairing.dart';
import 'package:sas_pairing/src/native/abi_v1.dart';
import 'package:sas_pairing/src/native/native_ceremony_api.dart';
import 'package:sas_pairing/src/network.dart'
    show runReferenceOf, runReferenceOfRun, runReferencesOf;
import 'package:test/test.dart';

import 'support/fake_ceremony.dart';
import 'support/fake_lifecycle.dart';
import 'support/fake_network.dart';

TypeMatcher<SasPairingNativeException> nativeStatus(String name) =>
    isA<SasPairingNativeException>().having(
      (e) => e.statusCode,
      'statusCode',
      status('SAS_PAIRING_$name'),
    );

final TypeMatcher<SasPairingRunEndedException> runEnded =
    isA<SasPairingRunEndedException>();
final Matcher contractViolation = isA<SasPairingContractException>();

const ceremonyOperations = {
  'startInitiator',
  'authorizeExposure',
  'exposeKey',
  'presentation',
  'approveSas',
  'emitBootstrapMac',
  'rejectSas',
  'cancelSas',
  'emitInitiatorFinish',
};

const runMethods = [
  'authorizeExposure',
  'exposeKey',
  'approveSas',
  'emitBootstrapMac',
  'rejectSas',
  'cancelSas',
  'emitInitiatorFinish',
];

/// `SAS_APPROVED` → `sasApproved`.
String camel(String abiName) {
  final words = abiName.toLowerCase().split('_');
  return words.first +
      words.skip(1).map((w) => w[0].toUpperCase() + w.substring(1)).join();
}

/// The frozen local-event names, `INVALID` excluded, in ABI order.
final List<String> producedLocalEvents = [
  for (final entry in abiV1Namespaces.entries)
    if (entry.key.startsWith('SAS_PAIRING_LOCAL_EVENT_') &&
        entry.key != 'SAS_PAIRING_LOCAL_EVENT_INVALID')
      entry.key.substring('SAS_PAIRING_LOCAL_EVENT_'.length),
];

const deadlineKinds = [
  'ABSOLUTE_TIMEOUT',
  'INACTIVITY_TIMEOUT',
  'PENDING_EXPIRED',
  'CLOCK_UNAVAILABLE',
];

/// The ordinary successes of each run method: (event, stays live, WRITE_PENDING).
const Map<String, List<(String, bool, bool)>> ordinary = {
  'authorizeExposure': [('EXPOSURE_AUTHORIZED', true, false)],
  'exposeKey': [('KEY_EXPOSED', true, true)],
  'approveSas': [
    ('SAS_APPROVED', true, false),
    ('SAS_ALREADY_APPROVED', true, false),
  ],
  'emitBootstrapMac': [
    ('BOOTSTRAP_MAC_EMITTED', true, true),
    ('BOOTSTRAP_MAC_ALREADY_EMITTED', true, false),
  ],
  'rejectSas': [('SAS_REJECTED', false, true), ('SAS_REJECTED', false, false)],
  'cancelSas': [
    ('SAS_CANCELLED', false, true),
    ('SAS_CANCELLED', false, false),
  ],
  'emitInitiatorFinish': [
    ('INITIATOR_FINISH_EMITTED', true, true),
    ('INITIATOR_FINISH_ALREADY_EMITTED', true, false),
  ],
};

/// A fake host with one accepted connection (native handle 100).
final class Fixture {
  Fixture() : fake = FakeNetworkHost() {
    connection = fake.accept(100);
  }

  final FakeNetworkHost fake;
  late final SasPairingConnection connection;

  FakeNativeCeremonyApi get ceremony => fake.api.ceremony;

  /// A run reported by an inbound drive event on [connectionHandle].
  SasPairingRun track(
    int handle,
    List<int> requestId, {
    int connectionHandle = 100,
    String protocol = 'START_ACCEPTED',
  }) => fake
      .drive([
        inbound(
          connectionHandle,
          requestId: requestId,
          run: handle,
          protocol: protocol,
        ),
      ])
      .events
      .single
      .run!;

  /// The identity of a live presentation of [run], filled with [value].
  SasPairingCeremonyIdentity identity(SasPairingRun run, [int value = 9]) {
    ceremony.scriptPresentation(livePresentation(identityOf(value)));
    return run.presentation()!.ceremonyIdentity;
  }

  int get callCount => fake.api.calls.length;

  /// The ceremony and drive operations recorded since [from].
  List<String> callsSince(int from) => [
    for (final call in fake.api.calls.skip(from)) call.operation,
  ];

  /// The ceremony operations of the whole log.
  List<String> get ceremonyCalls => [
    for (final op in fake.api.operations)
      if (ceremonyOperations.contains(op)) op,
  ];
}

SasPairingLocalAction invoke(
  String method,
  SasPairingRun run,
  SasPairingCeremonyIdentity identity,
) => switch (method) {
  'authorizeExposure' => run.authorizeExposure(),
  'exposeKey' => run.exposeKey(),
  'approveSas' => run.approveSas(identity),
  'emitBootstrapMac' => run.emitBootstrapMac(),
  'rejectSas' => run.rejectSas(identity),
  'cancelSas' => run.cancelSas(identity),
  'emitInitiatorFinish' => run.emitInitiatorFinish(),
  _ => throw ArgumentError(method),
};

/// The contract latch is set: later normal work is refused without a native call, and explicit
/// cleanup still makes its one native call.
void expectContractLatched(Fixture f) {
  expect(f.fake.context.isContractViolated, isTrue);
  final before = f.callCount;
  expect(f.fake.host.drive, throwsA(contractViolation));
  expect(f.callCount, before);
  f.fake.host.close();
  expect(f.callsSince(before), ['hostDestroy']);
}

void main() {
  group('local events', () {
    test('exactly the twelve produced frozen values, named after them', () {
      expect(producedLocalEvents, hasLength(12));
      expect(SasPairingLocalEvent.values.map((e) => e.name).toList(), [
        for (final name in producedLocalEvents) camel(name),
      ]);
      expect(
        SasPairingLocalEvent.values.map((e) => e.name),
        isNot(contains('invalid')),
      );
    });

    // Every produced value maps to its enum value through a method that allows it.
    const allowedBy = {
      'INITIATOR_STARTED': 'startInitiator',
      'EXPOSURE_AUTHORIZED': 'authorizeExposure',
      'KEY_EXPOSED': 'exposeKey',
      'SAS_APPROVED': 'approveSas',
      'SAS_ALREADY_APPROVED': 'approveSas',
      'BOOTSTRAP_MAC_EMITTED': 'emitBootstrapMac',
      'BOOTSTRAP_MAC_ALREADY_EMITTED': 'emitBootstrapMac',
      'INITIATOR_FINISH_EMITTED': 'emitInitiatorFinish',
      'INITIATOR_FINISH_ALREADY_EMITTED': 'emitInitiatorFinish',
      'SAS_REJECTED': 'rejectSas',
      'SAS_CANCELLED': 'cancelSas',
      'DEADLINE': 'authorizeExposure',
    };
    test('every produced value maps to its enum value', () {
      expect(allowedBy.keys.toSet(), producedLocalEvents.toSet());
      for (final MapEntry(key: name, value: method) in allowedBy.entries) {
        final f = Fixture();
        final SasPairingLocalAction action;
        if (method == 'startInitiator') {
          action = f.connection.startInitiator(local: testBootstrap());
        } else {
          final run = f.track(5000, [1]);
          final identity = f.identity(run);
          final live = !const {
            'SAS_REJECTED',
            'SAS_CANCELLED',
            'DEADLINE',
          }.contains(name);
          final pending = const {
            'KEY_EXPOSED',
            'BOOTSTRAP_MAC_EMITTED',
            'INITIATOR_FINISH_EMITTED',
          }.contains(name);
          f.ceremony.scriptAction(
            method,
            actionRecord(
              name,
              run: live ? 5000 : 0,
              flags: pending ? actionWritePending : 0,
              deadline: name == 'DEADLINE' ? 'ABSOLUTE_TIMEOUT' : 'NONE',
            ),
          );
          action = invoke(method, run, identity);
        }
        expect(action.event.name, camel(name), reason: name);
      }
    });

    for (final value in [0, 13, 0xFFFFFFFF]) {
      test('local event $value on success is a contract violation', () {
        final f = Fixture();
        final run = f.track(5000, [1]);
        f.ceremony.scriptAction(
          'authorizeExposure',
          NativeActionRecord(event: value, run: 5000),
        );
        expect(run.authorizeExposure, throwsA(contractViolation));
        expectContractLatched(f);
      });
    }
  });

  group('startInitiator', () {
    test(
      'one native call with the exact Bootstrap bytes; a new live run with an unknown request ID',
      () {
        final f = Fixture();
        final before = f.callCount;
        final local = testBootstrap(3);
        final action = f.connection.startInitiator(local: local);
        expect(f.callsSince(before), ['startInitiator']);
        expect(f.fake.api.calls.last.arguments, [1000, 1002, 100]);
        expect(action.event, SasPairingLocalEvent.initiatorStarted);
        expect(action.writePending, isTrue);
        expect(action.deadlineKind, SasPairingDeadlineKind.none);
        final run = action.run!;
        expect(run.isEnded, isFalse);
        final ref = runReferenceOfRun(run);
        expect(ref.handle, 7000);
        expect(ref.requestId, isNull, reason: 'never fabricated');
        expect(runReferencesOf(f.connection), [ref]);
        final (sentLocal, sentExpected) = f.ceremony.startedBootstraps.single;
        expect(sentLocal.applicationIdentity, local.applicationIdentity);
        expect(sentLocal.keyAlgorithm, local.keyAlgorithm);
        expect(sentLocal.publicKey, local.publicKey);
        expect(sentLocal.sharedContext, isEmpty);
        expect(sentExpected, isNull, reason: 'no expected peer Bootstrap');
        // Nothing else happened: no drive, authorization, or exposure.
        expect(f.ceremonyCalls, ['startInitiator']);
        expect(f.fake.api.count('drive'), 1, reason: 'only the accept drive');
      },
    );

    test('a non-null expected Bootstrap is passed exactly', () {
      final f = Fixture();
      final expected = SasPairingBootstrap(
        applicationIdentity: bytes([0x00, 0x80, 0xFF]),
        keyAlgorithm: bytes([0x41]),
        publicKey: bytes(List.filled(40, 0xEE)),
        sharedContext: bytes([7, 0]),
      );
      f.connection.startInitiator(local: testBootstrap(), expected: expected);
      final (_, sent) = f.ceremony.startedBootstraps.single;
      expect(sent!.applicationIdentity, [0x00, 0x80, 0xFF]);
      expect(sent.keyAlgorithm, [0x41]);
      expect(sent.publicKey, List.filled(40, 0xEE));
      expect(sent.sharedContext, [7, 0]);
    });

    test('two starts give two distinct runs', () {
      final f = Fixture();
      final a = f.connection.startInitiator(local: testBootstrap()).run!;
      final b = f.connection.startInitiator(local: testBootstrap()).run!;
      expect(identical(a, b), isFalse);
      expect(runReferencesOf(f.connection).map((r) => r.handle), [7000, 7001]);
    });

    final invalid = <String, NativeActionRecord Function()>{
      'a zero run handle': () =>
          actionRecord('INITIATOR_STARTED', flags: actionWritePending),
      'the handle of a live run': () => actionRecord(
        'INITIATOR_STARTED',
        flags: actionWritePending,
        run: 5000,
      ),
      'the handle of a live run of another connection': () => actionRecord(
        'INITIATOR_STARTED',
        flags: actionWritePending,
        run: 6000,
      ),
      'another local event': () =>
          actionRecord('KEY_EXPOSED', flags: actionWritePending, run: 7000),
      'no WRITE_PENDING flag': () =>
          actionRecord('INITIATOR_STARTED', run: 7000),
      'an unknown flag bit': () =>
          actionRecord('INITIATOR_STARTED', flags: 0x3, run: 7000),
      'a deadline kind': () => actionRecord(
        'INITIATOR_STARTED',
        flags: actionWritePending,
        run: 7000,
        deadline: 'ABSOLUTE_TIMEOUT',
      ),
      'a nonzero reserved field': () => actionRecord(
        'INITIATOR_STARTED',
        flags: actionWritePending,
        run: 7000,
        reserved: 1,
      ),
    };
    for (final MapEntry(key: name, value: record) in invalid.entries) {
      test('success with $name is a contract violation and creates no run', () {
        final f = Fixture();
        f.track(5000, [1]);
        f.fake.accept(200);
        f.track(6000, [2], connectionHandle: 200);
        final before = runReferencesOf(f.connection);
        f.ceremony.scriptAction('startInitiator', record());
        expect(
          () => f.connection.startInitiator(local: testBootstrap()),
          throwsA(contractViolation),
        );
        expect(runReferencesOf(f.connection), before);
        expectContractLatched(f);
      });
    }

    test('a closed connection refuses locally, with no native call', () {
      final f = Fixture();
      f.connection.close();
      final before = f.callCount;
      expect(
        () => f.connection.startInitiator(local: testBootstrap()),
        throwsA(
          isA<SasPairingClosedException>()
              .having((e) => e.objectKind, 'kind', 'SasPairingConnection')
              .having((e) => e.operation, 'operation', 'startInitiator'),
        ),
      );
      expect(f.callCount, before);
    });

    test('FATAL latches the process and creates no run', () {
      final f = Fixture();
      f.ceremony.scriptStatus('startInitiator', fatal);
      expect(
        () => f.connection.startInitiator(local: testBootstrap()),
        throwsA(nativeStatus('FATAL')),
      );
      expect(f.fake.context.isFatal, isTrue);
      expect(runReferencesOf(f.connection), isEmpty);
      final before = f.callCount;
      expect(
        () => f.connection.startInitiator(local: testBootstrap()),
        throwsA(nativeStatus('FATAL')),
      );
      expect(f.callCount, before, reason: 'refused locally after FATAL');
      f.connection.close();
      expect(f.callsSince(before), ['connectionClose'], reason: 'cleanup');
    });

    for (final name in [
      'WRITE_PENDING',
      'INVALID_BOOTSTRAP',
      'RESOURCE_LIMITED',
      'HANDLES_EXHAUSTED',
      'INVALID_HANDLE',
      'LISTENER_NOT_ATTACHED',
      'UNSUPPORTED_PLATFORM',
      'REQUEST_ID_GENERATION_FAILED',
    ]) {
      test('$name creates no run and changes nothing else', () {
        final f = Fixture();
        final before = f.callCount;
        f.ceremony.scriptStatus('startInitiator', status('SAS_PAIRING_$name'));
        expect(
          () => f.connection.startInitiator(local: testBootstrap()),
          throwsA(nativeStatus(name)),
        );
        expect(f.callsSince(before), ['startInitiator'], reason: 'no drive');
        expect(runReferencesOf(f.connection), isEmpty);
        expect(f.connection.isClosed, isFalse);
        expect(f.fake.host.networkState, SasPairingHostNetworkState.attached);
        expect(f.fake.context.isFatal, isFalse);
      });
    }

    test(
      'CONNECTION_ENDED closes the connection locally, without a close call',
      () {
        final f = Fixture();
        final other = f.fake.accept(200);
        f.ceremony.scriptStatus(
          'startInitiator',
          status('SAS_PAIRING_CONNECTION_ENDED'),
        );
        expect(
          () => f.connection.startInitiator(local: testBootstrap()),
          throwsA(nativeStatus('CONNECTION_ENDED')),
        );
        expect(f.connection.isClosed, isTrue);
        expect(other.isClosed, isFalse);
        expect(f.fake.api.count('connectionClose'), 0);
        // The host no longer holds it: a later step event for it breaks the contract.
        expect(() => f.fake.drive([step(100)]), throwsA(contractViolation));
      },
    );

    for (final name in ['OWNERSHIP_UNCERTAIN', 'OWNER_LOOP_CLOSED']) {
      test('$name fails the host network closed', () {
        final f = Fixture();
        final other = f.fake.accept(200);
        f.ceremony.scriptStatus('startInitiator', status('SAS_PAIRING_$name'));
        expect(
          () => f.connection.startInitiator(local: testBootstrap()),
          throwsA(nativeStatus(name)),
        );
        expect([f.connection.isClosed, other.isClosed], [true, true]);
        expect(
          f.fake.host.networkState,
          SasPairingHostNetworkState.failedClosed,
        );
        expect(f.fake.api.count('connectionClose'), 0);
        expect(f.fake.api.count('detachListener'), 0);
      });
    }
  });

  group('run identity', () {
    test(
      'a local run is valid before its request ID is known, then learns it from the event naming it',
      () {
        final f = Fixture();
        final started = f.connection.startInitiator(local: testBootstrap());
        final run = started.run!;
        final ref = runReferenceOfRun(run);
        expect(ref.requestId, isNull);
        // The run works before its request ID is known.
        expect(run.authorizeExposure().run, same(run));

        final accept = f.fake
            .drive([
              inbound(
                100,
                requestId: [0xA1, 0xA2],
                run: 7000,
                protocol: 'ACCEPT',
              ),
            ])
            .events
            .single;
        expect(identical(accept.run, run), isTrue);
        expect(identical(runReferenceOf(accept), ref), isTrue);
        expect(ref.requestId, [0xA1, 0xA2]);
        // The same request ID again changes nothing.
        final key = f.fake
            .drive([
              inbound(
                100,
                requestId: [0xA1, 0xA2],
                run: 7000,
                protocol: 'RESPONDER_KEY',
              ),
            ])
            .events
            .single;
        expect(identical(key.run, run), isTrue);
        expect(run.isEnded, isFalse);
      },
    );

    test(
      'the same handle under a different request ID is a contract violation',
      () {
        final f = Fixture();
        final run = f.connection.startInitiator(local: testBootstrap()).run!;
        f.fake.drive([
          inbound(100, requestId: [0xA1], run: 7000, protocol: 'ACCEPT'),
        ]);
        expect(
          () => f.fake.drive([
            inbound(
              100,
              requestId: [0xB1],
              run: 7000,
              protocol: 'RESPONDER_KEY',
            ),
          ]),
          throwsA(contractViolation),
        );
        expect(runReferenceOfRun(run).requestId, [0xA1], reason: 'unchanged');
        expectContractLatched(f);
      },
    );

    test(
      'a tracked run reported under another request ID is a contract violation',
      () {
        final f = Fixture();
        f.track(5000, [1]);
        expect(
          () => f.fake.drive([
            inbound(100, requestId: [2], run: 5000, protocol: 'INITIATOR_KEY'),
          ]),
          throwsA(contractViolation),
        );
      },
    );

    test(
      'learning a request ID ends the stale runs under it, exactly as the native start did',
      () {
        final f = Fixture();
        final stale = f.track(5000, [0xA1]);
        final other = f.track(5001, [0xB1]);
        final local = f.connection.startInitiator(local: testBootstrap()).run!;
        expect(stale.isEnded, isFalse, reason: 'unknown ID: nothing guessed');
        f.fake.drive([
          inbound(100, requestId: [0xA1], run: 7000, protocol: 'ACCEPT'),
        ]);
        expect(stale.isEnded, isTrue);
        expect(other.isEnded, isFalse);
        expect(local.isEnded, isFalse);
      },
    );

    test(
      'a run with an unknown request ID is never ended by a request-ID ending',
      () {
        final f = Fixture();
        final local = f.connection.startInitiator(local: testBootstrap()).run!;
        f.fake.drive([
          inbound(100, requestId: [0xA1], protocol: 'PEER_CANCEL'),
          step(
            100,
            step: 'DEADLINE',
            deadline: 'ABSOLUTE_TIMEOUT',
            requestId: [0xA1],
          ),
          step(100, step: 'CONFIRMED', requestId: [0xC1], result: 9000),
        ]);
        expect(local.isEnded, isFalse);
        expect(runReferencesOf(f.connection).map((r) => r.handle), [7000]);
      },
    );

    test('a reused request ID never retargets a run: Run A != Run B', () {
      final f = Fixture();
      final a = f.track(100, [0x58]);
      final b = f.track(101, [0x58]);
      expect(identical(a, b), isFalse);
      expect(
        a.isEnded,
        isTrue,
        reason: 'the new handle proves the old run ended',
      );
      expect(b.isEnded, isFalse);
      expect(runReferenceOfRun(a).handle, 100, reason: 'never retargeted');
      expect(runReferenceOfRun(b).handle, 101);
      final before = f.callCount;
      expect(a.authorizeExposure, throwsA(runEnded));
      expect(f.callCount, before);
      expect(b.authorizeExposure().run, same(b));
      expect(f.fake.api.calls.last.arguments, [1000, 1002, 100, 101]);
    });

    test('one native run handle is one Dart run across events and actions', () {
      final f = Fixture();
      final run = f.track(5000, [1]);
      final again = f.fake
          .drive([
            inbound(100, requestId: [1], run: 5000, protocol: 'INITIATOR_KEY'),
          ])
          .events
          .single;
      expect(identical(again.run, run), isTrue);
      expect(again.hasTrackedRun, isTrue);
      final action = run.exposeKey();
      expect(identical(action.run, run), isTrue);
      // An event without a run: hasTrackedRun is exactly run != null.
      final written = f.fake.drive([step(100)]).events.single;
      expect(written.run, isNull);
      expect(written.hasTrackedRun, isFalse);
    });

    test(
      'a started run and the later event naming its handle are the same object',
      () {
        final f = Fixture();
        final action = f.connection.startInitiator(local: testBootstrap());
        final event = f.fake
            .drive([
              inbound(100, requestId: [9], run: 7000, protocol: 'ACCEPT'),
            ])
            .events
            .single;
        expect(identical(action.run, event.run), isTrue);
      },
    );
  });

  group('run actions', () {
    for (final method in runMethods) {
      test('$method: one native call on the exact handles, no chaining', () {
        final f = Fixture();
        final run = f.track(5000, [1]);
        final identity = f.identity(run);
        final before = f.callCount;
        final action = invoke(method, run, identity);
        expect(f.callsSince(before), [method]);
        expect(f.fake.api.calls.last.arguments, [1000, 1002, 100, 5000]);
        final (event, live, pending) = ordinary[method]!.first;
        expect(action.event.name, camel(event));
        expect(action.writePending, pending);
        expect(action.deadlineKind, SasPairingDeadlineKind.none);
        if (live) {
          expect(identical(action.run, run), isTrue);
          expect(run.isEnded, isFalse);
        } else {
          expect(action.run, isNull);
          expect(run.isEnded, isTrue);
        }
      });

      test('$method: every ordinary success is accepted exactly', () {
        for (final (event, live, pending) in ordinary[method]!) {
          final f = Fixture();
          final run = f.track(5000, [1]);
          final identity = f.identity(run);
          f.ceremony.scriptAction(
            method,
            actionRecord(
              event,
              run: live ? 5000 : 0,
              flags: pending ? actionWritePending : 0,
            ),
          );
          final action = invoke(method, run, identity);
          expect(action.event.name, camel(event));
          expect(action.writePending, pending);
          expect(action.run, live ? same(run) : isNull);
          expect(run.isEnded, !live);
          expect(
            runReferencesOf(f.connection).map((r) => r.handle),
            live ? [5000] : isEmpty,
          );
        }
      });

      test(
        '$method: a known but different local event is a contract violation',
        () {
          final allowed = {for (final (event, _, _) in ordinary[method]!) event}
            ..add('DEADLINE');
          for (final event in producedLocalEvents) {
            if (allowed.contains(event)) continue;
            final f = Fixture();
            final run = f.track(5000, [1]);
            final identity = f.identity(run);
            // The record is otherwise well formed for the event it names.
            final terminal = const {
              'SAS_REJECTED',
              'SAS_CANCELLED',
            }.contains(event);
            f.ceremony.scriptAction(
              method,
              actionRecord(event, run: terminal ? 0 : 5000),
            );
            expect(
              () => invoke(method, run, identity),
              throwsA(contractViolation),
              reason: '$method → $event',
            );
            expect(run.isEnded, isFalse, reason: 'checked before any change');
            expect(f.fake.context.isContractViolated, isTrue);
          }
        },
      );

      test(
        '$method: the wrong WRITE_PENDING flag or run handle is a contract violation',
        () {
          for (final (event, live, pending) in ordinary[method]!) {
            final cases = <String, NativeActionRecord>{
              if (live)
                'the opposite flag': actionRecord(
                  event,
                  run: 5000,
                  flags: pending ? 0 : actionWritePending,
                ),
              if (live)
                'run 0': actionRecord(
                  event,
                  flags: pending ? actionWritePending : 0,
                ),
              if (live)
                'a different run handle': actionRecord(
                  event,
                  run: 5001,
                  flags: pending ? actionWritePending : 0,
                ),
              if (!live)
                'a live run': actionRecord(
                  event,
                  run: 5000,
                  flags: pending ? actionWritePending : 0,
                ),
              'a deadline kind': actionRecord(
                event,
                run: live ? 5000 : 0,
                flags: pending ? actionWritePending : 0,
                deadline: 'INACTIVITY_TIMEOUT',
              ),
            };
            for (final MapEntry(key: name, value: record) in cases.entries) {
              final f = Fixture();
              final run = f.track(5000, [1]);
              final identity = f.identity(run);
              f.ceremony.scriptAction(method, record);
              expect(
                () => invoke(method, run, identity),
                throwsA(contractViolation),
                reason: '$method $event with $name',
              );
              expect(run.isEnded, isFalse, reason: '$event with $name');
            }
          }
        },
      );

      for (final kind in deadlineKinds) {
        test(
          '$method: DEADLINE ($kind) ends the run; the action did not happen',
          () {
            for (final pending in [false, true]) {
              final f = Fixture();
              final run = f.track(5000, [1]);
              final identity = f.identity(run);
              f.ceremony.scriptAction(
                method,
                actionRecord(
                  'DEADLINE',
                  deadline: kind,
                  flags: pending ? actionWritePending : 0,
                ),
              );
              final action = invoke(method, run, identity);
              expect(action.event, SasPairingLocalEvent.deadline);
              expect(action.deadlineKind.name, camel(kind));
              expect(action.writePending, pending);
              expect(action.run, isNull);
              expect(run.isEnded, isTrue);
              expect(runReferencesOf(f.connection), isEmpty);
              final before = f.callCount;
              expect(() => invoke(method, run, identity), throwsA(runEnded));
              expect(f.callCount, before);
            }
          },
        );
      }

      test('$method: DEADLINE needs a deadline kind and run 0', () {
        for (final record in [
          actionRecord('DEADLINE'),
          actionRecord('DEADLINE', deadline: 'ABSOLUTE_TIMEOUT', run: 5000),
        ]) {
          final f = Fixture();
          final run = f.track(5000, [1]);
          final identity = f.identity(run);
          f.ceremony.scriptAction(method, record);
          expect(
            () => invoke(method, run, identity),
            throwsA(contractViolation),
          );
          expect(run.isEnded, isFalse);
        }
      });

      test(
        '$method: first RUN_ENDED is the native status 204; later calls are local',
        () {
          final f = Fixture();
          final run = f.track(5000, [1]);
          final identity = f.identity(run);
          f.ceremony.scriptStatus(method, status('SAS_PAIRING_RUN_ENDED'));
          expect(
            () => invoke(method, run, identity),
            throwsA(
              isA<SasPairingNativeException>()
                  .having((e) => e.statusCode, 'statusCode', 204)
                  .having(
                    (e) => e.knownStatus,
                    'known',
                    SasPairingStatus.runEnded,
                  ),
            ),
          );
          expect(run.isEnded, isTrue);
          expect(runReferencesOf(f.connection), isEmpty);
          final before = f.callCount;
          expect(
            () => invoke(method, run, identity),
            throwsA(
              runEnded.having(
                (e) => e.operation,
                'operation',
                'SasPairingRun.$method',
              ),
            ),
          );
          expect(run.presentation, throwsA(runEnded));
          expect(f.callCount, before, reason: 'no native call');
          expect(f.connection.isClosed, isFalse);
        },
      );

      test('$method: WRITE_PENDING status means the action did not run', () {
        final f = Fixture();
        final run = f.track(5000, [1]);
        final identity = f.identity(run);
        f.ceremony.scriptStatus(method, status('SAS_PAIRING_WRITE_PENDING'));
        final before = f.callCount;
        expect(
          () => invoke(method, run, identity),
          throwsA(
            isA<SasPairingNativeException>().having(
              (e) => e.knownStatus,
              'known',
              SasPairingStatus.writePending,
            ),
          ),
        );
        // No action, no drive, no retry: exactly the one refused call.
        expect(f.callsSince(before), [method]);
        expect(run.isEnded, isFalse);
        expect(f.connection.isClosed, isFalse);
        // A later call still reaches native.
        invoke(method, run, identity);
        expect(f.callsSince(before), [method, method]);
      });
    }

    test(
      'a successful WRITE_PENDING flag returns the action; presentation still reaches native',
      () {
        final f = Fixture();
        final run = f.track(5000, [1]);
        f.ceremony.scriptAction(
          'exposeKey',
          actionRecord('KEY_EXPOSED', run: 5000, flags: actionWritePending),
        );
        final action = run.exposeKey();
        expect(action.writePending, isTrue);
        expect(action.event, SasPairingLocalEvent.keyExposed);
        expect(identical(action.run, run), isTrue);
        expect(run.isEnded, isFalse);
        final before = f.callCount;
        f.ceremony.scriptPresentation(livePresentation(identityOf(4)));
        final presented = run.presentation();
        expect(f.callsSince(before), [
          'presentation',
        ], reason: 'not blocked locally');
        expect(presented!.decimal, '1234 5678 9012');
        // No automatic drive after a successful action with retained output.
        expect(
          f.fake.api.count('drive'),
          2,
          reason: 'the accept and track drives only',
        );
      },
    );

    for (final flags in [0x2, 0x80000001, 0x80000000]) {
      test('action flags $flags are a contract violation', () {
        final f = Fixture();
        final run = f.track(5000, [1]);
        final identity = f.identity(run);
        f.ceremony.scriptAction(
          'rejectSas',
          actionRecord('SAS_REJECTED', flags: flags),
        );
        expect(() => run.rejectSas(identity), throwsA(contractViolation));
        expect(run.isEnded, isFalse);
        expectContractLatched(f);
      });
    }

    test('action flags 0 and WRITE_PENDING are both valid where allowed', () {
      for (final flags in [0, actionWritePending]) {
        final f = Fixture();
        final run = f.track(5000, [1]);
        final identity = f.identity(run);
        f.ceremony.scriptAction(
          'cancelSas',
          actionRecord('SAS_CANCELLED', flags: flags),
        );
        expect(run.cancelSas(identity).writePending, flags != 0);
      }
    });

    test(
      'a nonzero reserved field latches the contract; cleanup stays allowed',
      () {
        final f = Fixture();
        final run = f.track(5000, [1]);
        final sibling = f.track(5001, [2]);
        f.ceremony.scriptAction(
          'authorizeExposure',
          actionRecord('EXPOSURE_AUTHORIZED', run: 5000, reserved: 7),
        );
        expect(run.authorizeExposure, throwsA(contractViolation));
        final before = f.callCount;
        expect(sibling.exposeKey, throwsA(contractViolation));
        expect(sibling.presentation, throwsA(contractViolation));
        expect(
          () => f.connection.startInitiator(local: testBootstrap()),
          throwsA(contractViolation),
        );
        expect(f.callCount, before, reason: 'no native call');
        f.connection.close();
        expect(f.callsSince(before), ['connectionClose']);
        expect([run.isEnded, sibling.isEnded], [true, true]);
      },
    );

    test('OK without an action record is a contract violation', () {
      final f = Fixture();
      final run = f.track(5000, [1]);
      f.ceremony.script('exposeKey', FakeCeremonyAnswer.action(ok));
      expect(run.exposeKey, throwsA(contractViolation));
    });
  });

  group('explicit steps', () {
    test('authorizeExposure does not expose', () {
      final f = Fixture();
      final run = f.track(5000, [1]);
      final before = f.callCount;
      final action = run.authorizeExposure();
      expect(f.callsSince(before), ['authorizeExposure']);
      expect(action.writePending, isFalse, reason: 'no key output');
    });

    test('approveSas does not emit BOOTSTRAP_MAC, drive, or finish', () {
      final f = Fixture();
      final run = f.track(5000, [1]);
      final identity = f.identity(run);
      final before = f.callCount;
      final action = run.approveSas(identity);
      expect(f.callsSince(before), ['approveSas']);
      expect(action.event, SasPairingLocalEvent.sasApproved);
      expect(action.writePending, isFalse);
    });

    test('emitBootstrapMac does not emit INITIATOR_FINISH or drive', () {
      final f = Fixture();
      final run = f.track(5000, [1]);
      final before = f.callCount;
      final action = run.emitBootstrapMac();
      expect(f.callsSince(before), ['emitBootstrapMac']);
      expect(action.event, SasPairingLocalEvent.bootstrapMacEmitted);
      expect(action.writePending, isTrue);
    });

    test(
      'reject and cancel are distinct native calls with distinct events',
      () {
        final f = Fixture();
        final a = f.track(5000, [1]);
        final b = f.track(5001, [2]);
        final ia = f.identity(a, 1);
        final ib = f.identity(b, 2);
        var before = f.callCount;
        final rejected = a.rejectSas(ia);
        expect(f.callsSince(before), ['rejectSas']);
        before = f.callCount;
        final cancelled = b.cancelSas(ib);
        expect(f.callsSince(before), ['cancelSas']);
        expect(rejected.event, SasPairingLocalEvent.sasRejected);
        expect(cancelled.event, SasPairingLocalEvent.sasCancelled);
        expect([a.isEnded, b.isEnded], [true, true]);
        expect(f.ceremony.identities.map((i) => i.first).toList(), [1, 2]);
      },
    );

    test('a terminal action closes nothing: the connection stays open', () {
      final f = Fixture();
      final run = f.track(5000, [1]);
      run.rejectSas(f.identity(run));
      expect(f.connection.isClosed, isFalse);
      expect(f.fake.api.count('connectionClose'), 0);
    });

    test(
      'a Responder finish gets NOT_INITIATOR; the run is not guessed ended',
      () {
        final f = Fixture();
        final run = f.track(5000, [1]);
        f.ceremony.scriptStatus(
          'emitInitiatorFinish',
          status('SAS_PAIRING_NOT_INITIATOR'),
        );
        expect(
          run.emitInitiatorFinish,
          throwsA(
            nativeStatus(
              'NOT_INITIATOR',
            ).having((e) => e.processRestartRequired, 'restart', isFalse),
          ),
        );
        expect(run.isEnded, isFalse);
        expect(run.authorizeExposure().run, same(run), reason: 'still usable');
      },
    );
  });

  group('ceremony refusals change nothing', () {
    for (final name in [
      'CEREMONY_INVALID_STATE',
      'NO_LIVE_SAS',
      'CEREMONY_IDENTITY_MISMATCH',
      'NOT_LOCALLY_APPROVED',
      'TRANSCRIPT_MISMATCH',
      'COMPLETED',
      'MISSING_AUTHORIZATION',
      'STALE_AUTHORIZATION',
      'BUSY',
      'EXHAUSTED',
      'APPROVALS_NOT_AUTHENTICATED',
      'CEREMONY_TIMED_OUT',
      'CEREMONY_CRYPTO_ERROR',
      'INVALID_HANDLE',
      'LISTENER_NOT_ATTACHED',
      'UNSUPPORTED_PLATFORM',
      'RESOURCE_LIMITED',
    ]) {
      test(name, () {
        final f = Fixture();
        final run = f.track(5000, [1]);
        f.ceremony.scriptStatus('exposeKey', status('SAS_PAIRING_$name'));
        expect(run.exposeKey, throwsA(nativeStatus(name)));
        expect(run.isEnded, isFalse);
        expect(f.connection.isClosed, isFalse);
        expect(f.fake.host.networkState, SasPairingHostNetworkState.attached);
        expect(f.fake.context.isFatal, isFalse);
        expect(f.fake.context.isContractViolated, isFalse);
        final before = f.callCount;
        run.exposeKey();
        expect(f.callsSince(before), [
          'exposeKey',
        ], reason: 'still reaches native');
      });
    }

    test('an unknown status is preserved exactly and changes nothing', () {
      final f = Fixture();
      final run = f.track(5000, [1]);
      f.ceremony.scriptStatus('approveSas', 777);
      final identity = f.identity(run);
      expect(
        () => run.approveSas(identity),
        throwsA(
          isA<SasPairingNativeException>()
              .having((e) => e.statusCode, 'code', 777)
              .having((e) => e.knownStatus, 'known', isNull),
        ),
      );
      expect(run.isEnded, isFalse);
    });
  });

  group('lifecycle side effects', () {
    test(
      'CONNECTION_ENDED closes the connection and ends all of its runs, without a close call',
      () {
        final f = Fixture();
        final r1 = f.track(5000, [1]);
        final r2 = f.track(5001, [2]);
        final local = f.connection.startInitiator(local: testBootstrap()).run!;
        final otherConnection = f.fake.accept(200);
        final otherRun = f.track(6000, [3], connectionHandle: 200);
        f.ceremony.scriptStatus(
          'exposeKey',
          status('SAS_PAIRING_CONNECTION_ENDED'),
        );
        final before = f.callCount;
        expect(r1.exposeKey, throwsA(nativeStatus('CONNECTION_ENDED')));
        expect(f.callsSince(before), ['exposeKey']);
        expect(f.connection.isClosed, isTrue);
        expect([r1.isEnded, r2.isEnded, local.isEnded], [true, true, true]);
        expect(otherConnection.isClosed, isFalse);
        expect(otherRun.isEnded, isFalse);
        expect(f.fake.host.networkState, SasPairingHostNetworkState.attached);
        expect(f.fake.api.count('connectionClose'), 0);
        final after = f.callCount;
        expect(r2.authorizeExposure, throwsA(runEnded));
        f.connection.close(); // already closed: nothing
        expect(f.callCount, after);
      },
    );

    for (final name in ['OWNERSHIP_UNCERTAIN', 'OWNER_LOOP_CLOSED']) {
      for (final via in ['an action', 'presentation']) {
        test('$name from $via fails the host network closed', () {
          final f = Fixture();
          final r1 = f.track(5000, [1]);
          final other = f.fake.accept(200);
          final r2 = f.track(6000, [2], connectionHandle: 200);
          final before = f.callCount;
          if (via == 'presentation') {
            f.ceremony.scriptStatus(
              'presentation',
              status('SAS_PAIRING_$name'),
            );
            expect(r1.presentation, throwsA(nativeStatus(name)));
          } else {
            f.ceremony.scriptStatus(
              'emitBootstrapMac',
              status('SAS_PAIRING_$name'),
            );
            expect(r1.emitBootstrapMac, throwsA(nativeStatus(name)));
          }
          expect(f.callsSince(before), hasLength(1), reason: 'no cleanup call');
          expect([f.connection.isClosed, other.isClosed], [true, true]);
          expect([r1.isEnded, r2.isEnded], [true, true]);
          expect(
            f.fake.host.networkState,
            SasPairingHostNetworkState.failedClosed,
          );
          expect(f.fake.context.isFatal, isFalse);
          // The host and its parents stay; detach is the consumer's explicit cleanup.
          expect(f.fake.host.isClosed, isFalse);
          f.fake.host.detachListener();
          expect(f.fake.host.networkState, SasPairingHostNetworkState.detached);
        });
      }
    }

    test(
      'FATAL latches the process; the run is not guessed ended; cleanup still works',
      () {
        final f = Fixture();
        final run = f.track(5000, [1]);
        final identity = f.identity(run);
        f.ceremony.scriptStatus('approveSas', fatal);
        expect(
          () => run.approveSas(identity),
          throwsA(
            nativeStatus(
              'FATAL',
            ).having((e) => e.processRestartRequired, 'restart', isTrue),
          ),
        );
        expect(f.fake.context.isFatal, isTrue);
        expect(run.isEnded, isFalse);
        expect(f.connection.isClosed, isFalse);
        final before = f.callCount;
        for (final method in runMethods) {
          expect(
            () => invoke(method, run, identity),
            throwsA(nativeStatus('FATAL')),
            reason: method,
          );
        }
        expect(run.presentation, throwsA(nativeStatus('FATAL')));
        expect(
          () => f.connection.startInitiator(local: testBootstrap()),
          throwsA(nativeStatus('FATAL')),
        );
        expect(f.callCount, before, reason: 'refused without a native call');
        f.connection.close();
        f.fake.host.detachListener();
        f.fake.runtime.close();
        expect(f.callsSince(before), [
          'connectionClose',
          'detachListener',
          'runtimeDestroy',
        ]);
      },
    );

    test('FATAL from presentation latches too', () {
      final f = Fixture();
      final run = f.track(5000, [1]);
      f.ceremony.scriptStatus('presentation', fatal);
      expect(run.presentation, throwsA(nativeStatus('FATAL')));
      expect(f.fake.context.isFatal, isTrue);
    });

    test(
      'a known-ended run is refused before the process latch is consulted',
      () {
        final f = Fixture();
        final run = f.track(5000, [1]);
        final live = f.track(5001, [2]);
        run.cancelSas(f.identity(run));
        f.ceremony.scriptStatus('exposeKey', fatal);
        expect(live.exposeKey, throwsA(nativeStatus('FATAL')));
        final before = f.callCount;
        expect(run.exposeKey, throwsA(runEnded));
        expect(f.callCount, before);
      },
    );

    for (final teardown in [
      'visible ending event',
      'result event',
      'deadline event',
      'connection close',
      'closed event',
      'detach',
      'owner-loop failure',
      'host close',
      'authority close',
      'runtime close',
    ]) {
      test(
        '$teardown ends the public run; later actions are refused locally',
        () {
          final f = Fixture();
          final run = f.track(5000, [1]);
          final identity = f.identity(run);
          expect(run.isEnded, isFalse);
          switch (teardown) {
            case 'visible ending event':
              f.fake.drive([
                inbound(100, requestId: [1], protocol: 'PEER_CANCEL'),
              ]);
            case 'result event':
              f.fake.drive([
                inbound(
                  100,
                  requestId: [1],
                  protocol: 'INITIATOR_FINISH_ACK',
                  result: 9000,
                ),
              ]);
            case 'deadline event':
              f.fake.drive([
                step(
                  100,
                  step: 'DEADLINE',
                  deadline: 'ABSOLUTE_TIMEOUT',
                  requestId: [1],
                ),
              ]);
            case 'connection close':
              f.connection.close();
            case 'closed event':
              f.fake.drive([closed(100)]);
            case 'detach':
              f.fake.host.detachListener();
            case 'owner-loop failure':
              f.fake.drive(
                [],
                failure: status('SAS_PAIRING_NETWORK_POLL_FAILED'),
              );
            case 'host close':
              f.fake.host.close();
            case 'authority close':
              f.fake.authority.close();
            case 'runtime close':
              f.fake.runtime.close();
          }
          expect(run.isEnded, isTrue);
          final before = f.callCount;
          for (final method in runMethods) {
            expect(
              () => invoke(method, run, identity),
              throwsA(runEnded),
              reason: method,
            );
          }
          expect(run.presentation, throwsA(runEnded));
          expect([
            for (final op in f.callsSince(before))
              if (ceremonyOperations.contains(op)) op,
          ], isEmpty);
        },
      );
    }

    test('endings the native contract leaves invisible are not guessed', () {
      final f = Fixture();
      final run = f.track(5000, [1]);
      f.fake.drive([
        step(100, step: 'REFUSED', reason: 'ROUTE_REFUSED'),
        step(100, step: 'UNCONFIRMED', reason: 'ROUTE_REFUSED'),
        step(100, step: 'DISCARDED'),
        step(100, step: 'DEADLINE', deadline: 'INACTIVITY_TIMEOUT'),
        inbound(100, requestId: [1], protocol: 'START_DUPLICATE'),
      ]);
      expect(run.isEnded, isFalse, reason: 'may be stale until RUN_ENDED');
    });
  });

  group('presentation', () {
    test(
      'available = 0 with every other byte zero is null; the run stays live',
      () {
        final f = Fixture();
        final run = f.track(5000, [1]);
        final before = f.callCount;
        expect(run.presentation(), isNull);
        expect(f.callsSince(before), ['presentation']);
        expect(f.fake.api.calls.last.arguments, [1000, 1002, 100, 5000]);
        expect(run.isEnded, isFalse);
      },
    );

    test('a live presentation: exact decimal and identity, immutable', () {
      final f = Fixture();
      final run = f.track(5000, [1]);
      final identityBytes = [for (var i = 0; i < 32; i++) i * 7 % 256];
      final record = livePresentation(identityBytes, display: '1234 5678 9012');
      f.ceremony.scriptPresentation(record);
      final presented = run.presentation()!;
      expect(presented.decimal, '1234 5678 9012');
      expect(presented.decimal.length, 14);
      final identity = presented.ceremonyIdentity;
      expect(identity.bytes, identityBytes);
      // Changing the native copy afterwards does not reach the identity.
      record.ceremonyIdentity[0] = 0xFF;
      expect(identity.bytes[0], identityBytes[0]);
      // Writes through the getter, its buffer, or a view of its buffer throw.
      expect(() => identity.bytes[0] = 1, throwsUnsupportedError);
      expect(
        () => identity.bytes.buffer.asUint8List()[0] = 1,
        throwsUnsupportedError,
      );
      expect(() => identity.bytes.setAll(0, [1]), throwsUnsupportedError);
      expect(identity.bytes, identityBytes);
      // Value equality.
      f.ceremony.scriptPresentation(livePresentation(identityBytes));
      final again = run.presentation()!.ceremonyIdentity;
      expect(again, identity);
      expect(again.hashCode, identity.hashCode);
      expect(identical(again, identity), isFalse);
      f.ceremony.scriptPresentation(livePresentation(identityOf(1)));
      expect(run.presentation()!.ceremonyIdentity, isNot(identity));
      expect(identity, isNot(equals(identityBytes)), reason: 'not a byte list');
    });

    test('every decimal digit and the two spaces are accepted', () {
      for (final display in [
        '0000 0000 0000',
        '9999 9999 9999',
        '1000 9191 4567',
      ]) {
        final f = Fixture();
        final run = f.track(5000, [1]);
        f.ceremony.scriptPresentation(
          livePresentation(identityOf(1), display: display),
        );
        expect(run.presentation()!.decimal, display);
      }
    });

    final zeroCases = <String, NativePresentationRecord Function()>{
      'reserved': () => NativePresentationRecord(available: 0, reserved: 1),
      'an identity byte': () => NativePresentationRecord(
        available: 0,
        ceremonyIdentity: Uint8List(32)..[31] = 1,
      ),
      'a decimal byte': () => NativePresentationRecord(
        available: 0,
        decimal: Uint8List(14)..[0] = 0x31,
      ),
      'a reserved tail byte': () => NativePresentationRecord(
        available: 0,
        reservedTail: Uint8List(2)..[1] = 1,
      ),
    };
    for (final MapEntry(key: name, value: record) in zeroCases.entries) {
      test('available = 0 with a nonzero $name is a contract violation', () {
        final f = Fixture();
        final run = f.track(5000, [1]);
        f.ceremony.scriptPresentation(record());
        expect(run.presentation, throwsA(contractViolation));
        expect(run.isEnded, isFalse);
        expectContractLatched(f);
      });
    }

    final malformed = <String, NativePresentationRecord Function()>{
      'available = 2': () => NativePresentationRecord(
        available: 2,
        ceremonyIdentity: Uint8List.fromList(identityOf(1)),
        decimal: ascii14('1234 5678 9012'),
      ),
      'available = 0xFFFFFFFF': () =>
          NativePresentationRecord(available: 0xFFFFFFFF),
      'a nonzero reserved field': () => NativePresentationRecord(
        available: 1,
        reserved: 1,
        ceremonyIdentity: Uint8List.fromList(identityOf(1)),
        decimal: ascii14('1234 5678 9012'),
      ),
      'a nonzero reserved tail': () => NativePresentationRecord(
        available: 1,
        ceremonyIdentity: Uint8List.fromList(identityOf(1)),
        decimal: ascii14('1234 5678 9012'),
        reservedTail: Uint8List.fromList([0, 1]),
      ),
      'a 13-byte display': () => NativePresentationRecord(
        available: 1,
        ceremonyIdentity: Uint8List.fromList(identityOf(1)),
        decimal: Uint8List.fromList('1234 5678 901'.codeUnits),
      ),
      'a 15-byte display': () => NativePresentationRecord(
        available: 1,
        ceremonyIdentity: Uint8List.fromList(identityOf(1)),
        decimal: Uint8List.fromList('1234 5678 90123'.codeUnits),
      ),
      'a 31-byte identity': () => NativePresentationRecord(
        available: 1,
        ceremonyIdentity: Uint8List(31),
        decimal: ascii14('1234 5678 9012'),
      ),
      'a tab instead of a space': () =>
          livePresentation(identityOf(1), display: '1234\t5678 9012'),
      'a space at the wrong offset': () =>
          livePresentation(identityOf(1), display: '123 45678 9012'),
      'no spaces': () =>
          livePresentation(identityOf(1), display: '12345678901234'),
      'a letter': () =>
          livePresentation(identityOf(1), display: '1234 5678 901A'),
      'a NUL terminator': () =>
          livePresentation(identityOf(1), display: '1234 5678 901\x00'),
      'a non-ASCII digit': () => NativePresentationRecord(
        available: 1,
        ceremonyIdentity: Uint8List.fromList(identityOf(1)),
        // U+0661 ARABIC-INDIC DIGIT ONE in UTF-8 (D9 A1) where an ASCII digit belongs.
        decimal: Uint8List.fromList([
          0xD9, 0xA1, 0x33, 0x34, 0x20, 0x35, 0x36, 0x37, 0x38, 0x20, //
          0x39, 0x30, 0x31, 0x32,
        ]),
      ),
      'a byte above ASCII': () => NativePresentationRecord(
        available: 1,
        ceremonyIdentity: Uint8List.fromList(identityOf(1)),
        decimal: ascii14('1234 5678 9012')..[0] = 0xB1,
      ),
      'a slash below the digits': () =>
          livePresentation(identityOf(1), display: '1234 5678 901/'),
      'a colon above the digits': () =>
          livePresentation(identityOf(1), display: '1234 5678 901:'),
    };
    for (final MapEntry(key: name, value: record) in malformed.entries) {
      test('a live presentation with $name is a contract violation', () {
        final f = Fixture();
        final run = f.track(5000, [1]);
        f.ceremony.scriptPresentation(record());
        expect(run.presentation, throwsA(contractViolation));
        expectContractLatched(f);
      });
    }

    test('OK without a presentation record is a contract violation', () {
      final f = Fixture();
      final run = f.track(5000, [1]);
      f.ceremony.script('presentation', FakeCeremonyAnswer.presentation(ok));
      expect(run.presentation, throwsA(contractViolation));
    });

    test('RUN_ENDED: the first is native status 204, then local refusal', () {
      final f = Fixture();
      final run = f.track(5000, [1]);
      f.ceremony.scriptStatus('presentation', status('SAS_PAIRING_RUN_ENDED'));
      expect(run.presentation, throwsA(nativeStatus('RUN_ENDED')));
      expect(run.isEnded, isTrue);
      final before = f.callCount;
      expect(run.presentation, throwsA(runEnded));
      expect(run.exposeKey, throwsA(runEnded));
      expect(f.callCount, before);
    });

    test(
      'presentation is read-only: it never changes the run or connection',
      () {
        final f = Fixture();
        final run = f.track(5000, [1]);
        for (var i = 0; i < 3; i++) {
          f.ceremony.scriptPresentation(livePresentation(identityOf(1)));
          run.presentation();
        }
        expect(run.isEnded, isFalse);
        expect(f.ceremonyCalls, [
          'presentation',
          'presentation',
          'presentation',
        ]);
      },
    );
  });

  group('ceremony identity binding', () {
    test('a decision passes exactly the 32 presented bytes', () {
      final f = Fixture();
      final run = f.track(5000, [1]);
      final bytes32 = [for (var i = 0; i < 32; i++) 255 - i];
      f.ceremony.scriptPresentation(livePresentation(bytes32));
      final identity = run.presentation()!.ceremonyIdentity;
      run.approveSas(identity);
      expect(f.ceremony.identities.single, bytes32);
    });

    test(
      'an identity from another presentation still reaches the native check',
      () {
        final f = Fixture();
        final a = f.track(5000, [1]);
        final b = f.track(5001, [2]);
        final identityA = f.identity(a, 0xAA);
        final identityB = f.identity(b, 0xBB);
        expect(identityA, isNot(identityB));
        f.ceremony.scriptStatus(
          'approveSas',
          status('SAS_PAIRING_CEREMONY_IDENTITY_MISMATCH'),
        );
        final before = f.callCount;
        expect(
          () => a.approveSas(identityB),
          throwsA(nativeStatus('CEREMONY_IDENTITY_MISMATCH')),
        );
        expect(f.callsSince(before), [
          'approveSas',
        ], reason: 'not blocked in Dart');
        expect(f.fake.api.calls.last.arguments, [1000, 1002, 100, 5000]);
        expect(f.ceremony.identities.single, identityOf(0xBB));
        expect(a.isEnded, isFalse);
        expect(a.approveSas(identityA).event, SasPairingLocalEvent.sasApproved);
      },
    );
  });

  group('results stay private and unchanged', () {
    test('a completed run delivers a result only through a drive event', () {
      final f = Fixture();
      final action = f.connection.startInitiator(local: testBootstrap());
      final run = action.run!;
      f.fake.drive([
        inbound(100, requestId: [5], run: 7000, protocol: 'ACCEPT'),
      ]);
      run.authorizeExposure();
      run.exposeKey();
      run.approveSas(f.identity(run));
      run.emitBootstrapMac();
      run.emitInitiatorFinish();
      final done = f.fake
          .drive([
            step(100, step: 'CONFIRMED', requestId: [5], result: 9000),
          ])
          .events
          .single;
      expect(done.hasResult, isTrue);
      expect(done.run, isNull);
      expect(run.isEnded, isTrue, reason: 'the result made its end visible');
      // No result export exists in the ceremony service, and nothing destroyed it.
      expect(
        f.fake.api.operations.where((op) => op.contains('result')),
        isEmpty,
      );
    });
  });
}
