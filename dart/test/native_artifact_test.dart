// Real native artifact smoke (P8.1 success criterion): the actual P7 ABI v1 library, built with
// `cargo build --manifest-path core/Cargo.toml --release --features native-abi`, loads through
// the production process loader from the explicit SAS_PAIRING_NATIVE_LIBRARY path, exports all
// 25 frozen symbols under their exact names, and reports ABI version 1. No stateful export is
// called in the test process. This is the only test file that loads the real library in the test
// process (one native owner isolate, P8-D-001 N); the P8.2 real lifecycle scenarios, the P8.3
// real network scenarios, and the P8.4 real two-endpoint ceremony run in child OS processes
// (test/support/lifecycle_child.dart, test/support/network_child.dart, and
// test/support/ceremony_child.dart), each with its own single owner isolate.
import 'dart:convert';
import 'dart:io';

import 'package:sas_pairing/sas_pairing.dart';
import 'package:sas_pairing/src/native/abi_v1.dart';
import 'package:sas_pairing/src/native/native_library_loader.dart';
import 'package:test/test.dart';

final String? artifact = Platform.environment['SAS_PAIRING_NATIVE_LIBRARY'];

/// Runs one fresh-process scenario: a loader scenario (test/support/loader_child.dart), a
/// lifecycle scenario (test/support/lifecycle_child.dart), a network scenario
/// (test/support/network_child.dart), or a ceremony scenario (test/support/ceremony_child.dart).
Future<List<Map<String, Object?>>> runChild(
  String scenario, {
  String script = 'test/support/loader_child.dart',
}) async {
  final result = await Process.run(Platform.resolvedExecutable, [
    'run',
    script,
    scenario,
    artifact!,
  ]);
  final line = (result.stdout as String)
      .split('\n')
      .firstWhere(
        (l) => l.startsWith('RESULT '),
        orElse: () => throw StateError(
          'child $scenario failed (${result.exitCode}): ${result.stdout}${result.stderr}',
        ),
      );
  return [
    for (final step in jsonDecode(line.substring(7)) as List<Object?>)
      step! as Map<String, Object?>,
  ];
}

void main() {
  final path = artifact;
  if (path == null || path.isEmpty) {
    test('the real native artifact is supplied', () {
      if (Platform.environment['CI'] == 'true') {
        fail('SAS_PAIRING_NATIVE_LIBRARY must name the native artifact in CI');
      }
      markTestSkipped(
        'Set SAS_PAIRING_NATIVE_LIBRARY to the absolute path of the native-abi artifact.',
      );
    });
    return;
  }

  test('the process loader loads the real artifact: ABI version 1', () {
    final loaded = NativeLibraryLoader.initialize(libraryPath: path);
    expect(loaded.abiVersion, requiredAbiVersion);
    expect(loaded.abiVersion, 1);
    expect(loaded.libraryPath, File(path).resolveSymbolicLinksSync());
    // The version query is the constant export: calling it again changes nothing.
    expect(loaded.bindings.sas_pairing_abi_version(), 1);
  });

  test(
    'the real artifact exports all 25 frozen symbols by their exact names',
    () {
      final image = NativeLibraryLoader.initialize(libraryPath: path).image;
      final missing = [
        for (final symbol in abiV1Exports)
          if (!image.providesSymbol(symbol)) symbol,
      ];
      expect(missing, isEmpty);
      expect(abiV1Exports, hasLength(25));
      // No alias or alternate name is looked up or accepted.
      for (final absent in [
        'sas_pairing_reset',
        'sas_pairing_unload',
        'sas_pairing_abi_version_v2',
        'SAS_PAIRING_ABI_VERSION',
      ]) {
        expect(image.providesSymbol(absent), isFalse, reason: absent);
      }
    },
  );

  test(
    'a second initialization returns the same retained library, opening nothing',
    () {
      final first = NativeLibraryLoader.initialize(libraryPath: path);
      expect(
        identical(NativeLibraryLoader.initialize(libraryPath: path), first),
        isTrue,
      );
      expect(
        identical(
          NativeLibraryLoader.initialize(libraryPath: '/no/such/library'),
          first,
        ),
        isTrue,
        reason: 'the path is not inspected after READY',
      );
      expect(identical(NativeLibraryLoader.instance, first), isTrue);
      expect(
        identical(NativeLibraryLoader.instance.bindings, first.bindings),
        isTrue,
      );
    },
  );

  test(
    'real lifecycle (Windows): runtime, binary-scope authority, hosts, cascades',
    () async {
      final steps = {
        for (final step in await runChild(
          'windows-lifecycle',
          script: 'test/support/lifecycle_child.dart',
        ))
          step['step']! as String: step,
      };
      expect(steps['runtime']!['closed'], isFalse);
      expect(
        steps['second live runtime']!['failure'],
        SasPairingStatus.alreadyInitialized.code,
      );
      expect(steps['authority']!['state'], 'ready');
      expect(steps['authority']!['remaining'], 10);
      expect(
        steps['same scope while registered']!['failure'],
        SasPairingStatus.alreadyRegistered.code,
      );
      expect(
        steps['empty scope']!['failure'],
        SasPairingStatus.invalidScope.code,
      );
      expect(steps['hosts'], containsPair('a', false));
      expect(steps['hosts'], containsPair('b', false));
      final afterHostA = steps['host A closed']!;
      expect(afterHostA['a'], isTrue);
      expect(afterHostA['b'], isFalse);
      expect(afterHostA['authorityClosed'], isFalse);
      expect(afterHostA['state'], 'ready');
      expect(afterHostA['remaining'], 10);
      final afterAuthority = steps['authority closed']!;
      expect(afterAuthority['authority'], isTrue);
      expect(afterAuthority['b'], isTrue, reason: 'closed by the cascade');
      expect(afterAuthority['runtime'], isFalse);
      expect(
        afterAuthority['queryAfterClose'],
        'SasPairingAuthority.queryStatus',
      );
      expect(steps['re-registered']!['state'], 'ready');
      expect(steps['re-registered']!['remaining'], 10);
      final cascade = steps['runtime closed with live children']!;
      expect(cascade['runtime'], isTrue);
      expect(cascade['authorities'], [true, true]);
      expect(cascade['hosts'], [true, true, true]);
      final recreated = steps['recreated runtime']!;
      expect(recreated['sameImage'], isTrue);
      expect(recreated['state'], 'ready');
      expect(recreated['remaining'], 10);
      expect(steps['done']!['closed'], [true, true]);
    },
    skip: Platform.isWindows ? false : 'Windows pairing platform only',
    timeout: const Timeout(Duration(minutes: 2)),
  );

  test(
    'real lifecycle (Linux): runtime works, authority registration fails closed',
    () async {
      final steps = {
        for (final step in await runChild(
          'linux-lifecycle',
          script: 'test/support/lifecycle_child.dart',
        ))
          step['step']! as String: step,
      };
      expect(steps['runtime']!['closed'], isFalse);
      expect(
        steps['register']!['failure'],
        SasPairingStatus.unsupportedPlatform.code,
      );
      expect(
        steps['empty scope']!['failure'],
        SasPairingStatus.invalidScope.code,
      );
      expect(steps['runtime closed']!['closed'], isTrue);
      expect(
        steps['recreated runtime']!['register'],
        SasPairingStatus.unsupportedPlatform.code,
      );
      expect(steps['done']!['closed'], isTrue);
    },
    skip: Platform.isLinux ? false : 'Linux only',
    timeout: const Timeout(Duration(minutes: 2)),
  );

  // P8.3 real network scenarios (P8-D-003): each in a child OS process with its own single
  // native owner isolate, over loopback listeners made by the test-only WinSock harness. The
  // harness closes a listening socket only while its token is untransferred.
  Future<Map<String, Map<String, Object?>>> networkChild(
    String scenario,
  ) async => {
    for (final step in await runChild(
      scenario,
      script: 'test/support/network_child.dart',
    ))
      step['step']! as String: step,
  };

  test(
    'real network (Windows): attach, ownership transfer, bounded drive, detach',
    () async {
      final steps = await networkChild('windows-attach-detach');
      expect(steps['host']!['state'], 'detached');
      expect(
        steps['drive before attach']!['failure'],
        SasPairingStatus.listenerNotAttached.code,
      );
      final refused = steps['invalid bootstrap']!;
      expect(refused['failure'], SasPairingStatus.invalidBootstrap.code);
      expect(refused['transferred'], isFalse);
      expect(refused['state'], 'detached');
      expect(
        steps['invalid bootstrap socket closed by caller']!['closedByHarness'],
        isTrue,
      );
      expect(steps['attached']!['transferred'], isTrue);
      expect(steps['attached']!['state'], 'attached');
      final second = steps['second attach']!;
      expect(second['failure'], SasPairingStatus.listenerAlreadyAttached.code);
      expect(second['transferred'], isFalse);
      expect(second['state'], 'attached');
      final drive = steps['one drive without a client']!;
      expect(drive['events'], 0);
      expect(drive['failure'], isNull);
      expect(drive['state'], 'attached');
      expect(
        drive['elapsedMs']! as int,
        lessThan(5000),
        reason: 'one bounded call (one readiness wait of at most 250 ms)',
      );
      expect(steps['recheck']!['events'], 0);
      expect(steps['recheck']!['failure'], isNull);
      final detached = steps['detached']!;
      expect(detached['state'], 'detached');
      expect(detached['hostClosed'], isFalse);
      expect(detached['authorityClosed'], isFalse);
      expect(detached['authority'], {'state': 'ready', 'remaining': 10});
      expect(
        steps['drive after detach']!['failure'],
        SasPairingStatus.listenerNotAttached.code,
      );
      expect(steps['host closed']!['state'], 'detached');
      expect(steps['done']!['transferred'], [false, true, false]);
      expect(steps['done']!['closedByHarness'], [true, false, true]);
    },
    skip: Platform.isWindows ? false : 'Windows pairing platform only',
    timeout: const Timeout(Duration(minutes: 2)),
  );

  test(
    'real network (Windows): loopback accept, same wrapper, peer close',
    () async {
      final steps = await networkChild('windows-accept');
      expect(steps['accepted']!['closed'], isFalse);
      expect(steps['accepted']!['acceptedEvents'], 1);
      expect(steps['accepted']!['state'], 'attached');
      final closedByPeer = steps['closed by peer']!;
      expect(closedByPeer['sameObject'], isTrue);
      expect(closedByPeer['everyLaterEventSameObject'], isTrue);
      expect(closedByPeer['closed'], isTrue);
      expect(closedByPeer['kinds'], contains('connectionClosed'));
      expect(steps['detached']!['state'], 'detached');
      expect(steps['done']!['transferred'], isTrue);
      expect(steps['done']!['closedByHarness'], isFalse);
    },
    skip: Platform.isWindows ? false : 'Windows pairing platform only',
    timeout: const Timeout(Duration(minutes: 2)),
  );

  test(
    'real network (Windows): listener replacement L1, detach, L2; connection close',
    () async {
      final steps = await networkChild('windows-reattach');
      expect(steps['L1 accepted']!['state'], 'attached');
      expect(steps['L1 accepted']!['c1Closed'], isFalse);
      final detached = steps['L1 detached']!;
      expect(detached['state'], 'detached');
      expect(
        detached['c1Closed'],
        isTrue,
        reason: 'no stale connection survives L1',
      );
      expect(detached['l1Transferred'], isTrue);
      expect(steps['L2 attached']!['state'], 'attached');
      expect(steps['L2 attached']!['l2Transferred'], isTrue);
      final l2 = steps['L2 accepted']!;
      expect(l2['distinct'], isTrue);
      expect(l2['c1Closed'], isTrue);
      expect(l2['c2Closed'], isFalse);
      expect(steps['c2 closed manually']!['c2Closed'], isTrue);
      expect(steps['c2 closed manually']!['state'], 'attached');
      final accounting = steps['accounting']!;
      expect(accounting['before'], {'state': 'ready', 'remaining': 10});
      expect(accounting['after'], accounting['before']);
      expect(steps['host closed']!['state'], 'detached');
      expect(steps['done']!['transferred'], [true, true]);
      expect(steps['done']!['closedByHarness'], [false, false]);
    },
    skip: Platform.isWindows ? false : 'Windows pairing platform only',
    timeout: const Timeout(Duration(minutes: 2)),
  );

  // P8.4 real two-endpoint ceremony (P8-D-004): one child OS process, one runtime, two
  // authorities, hosts, listeners, and accepted connections, both endpoints driven only through
  // the public API; a test-only byte-transparent relay joins the two accepted sockets.
  test(
    'real ceremony (Windows): two public Dart endpoints, explicit steps, equal SAS, local results',
    () async {
      final steps = {
        for (final step in await runChild(
          'windows-happy-path',
          script: 'test/support/ceremony_child.dart',
        ))
          step['step']! as String: step,
      };
      Map<String, Object?> action(
        String event, {
        required bool writePending,
        bool hasRun = true,
      }) => {
        'event': event,
        'writePending': writePending,
        'deadlineKind': 'none',
        'hasRun': hasRun,
      };
      Map<String, Object?> of(String step) => {...steps[step]!}..remove('step');

      expect(steps['attached']!['authorityA'], {
        'state': 'ready',
        'remaining': 10,
      });
      expect(steps['accepted'], {'step': 'accepted', 'a': false, 'b': false});
      // Start: a live run, START retained; nothing else happened.
      expect(of('A start'), {
        ...action('initiatorStarted', writePending: true),
        'runEnded': false,
      });
      // The second start before any drive did not run: native WRITE_PENDING, and B later sees
      // exactly one START.
      expect(
        steps['A second start before drive']!['failure'],
        SasPairingStatus.writePending.code,
      );
      // The Responder run surfaces on B through a drive event.
      expect(of('B start accepted'), {
        'sameConnection': true,
        'hasTrackedRun': true,
        'writePending': true,
        'requestIdLength': 16,
      });
      // The event naming A's run carries the same object; its request ID was learned.
      expect(of('A accept'), {'sameRun': true, 'requestIdsEqual': true});
      // Authorization spends nothing and produces no key output; exposure spends one
      // opportunity (the authority's guard is now held: busy).
      expect(of('A authorize'), {
        ...action('exposureAuthorized', writePending: false),
        'sameRun': true,
        'authority': {'state': 'ready', 'remaining': 10},
      });
      expect(of('A expose'), {
        ...action('keyExposed', writePending: true),
        'sameRun': true,
        'authority': {'state': 'busy', 'remaining': 0},
      });
      expect(of('A presentation while key pending'), {'available': false});
      expect(of('B initiator key'), {'sameRun': true});
      expect(
        of('B authorize'),
        action('exposureAuthorized', writePending: false),
      );
      expect(of('B expose'), {
        ...action('keyExposed', writePending: true),
        'authority': {'state': 'busy', 'remaining': 0},
      });
      // Presentation is not blocked by a retained write: B's SAS is live while its key waits.
      final presentedB = of('B presentation while key pending');
      final presentedA = of('A presentation');
      final display = RegExp(r'^[0-9]{4} [0-9]{4} [0-9]{4}$');
      for (final presented in [presentedA, presentedB]) {
        expect(presented['available'], isTrue);
        expect(presented['decimal'], matches(display));
        expect(presented['identity'], matches(RegExp(r'^[0-9a-f]{64}$')));
      }
      expect(presentedA['decimal'], presentedB['decimal']);
      expect(presentedA['identity'], presentedB['identity']);
      expect(of('SAS comparison'), {
        'decimalEqual': true,
        'identityEqual': true,
      });
      // MATCH is explicit and emits nothing: no frame was written on either side.
      expect(of('A approve'), action('sasApproved', writePending: false));
      expect(of('after A approve: one drive of each host'), {
        'a': isEmpty,
        'b': isEmpty,
        'aPresentation': {'available': false},
      });
      // BOOTSTRAP_MAC is a separate explicit step; a second one before the drive did not run.
      expect(
        of('A emit MAC'),
        action('bootstrapMacEmitted', writePending: true),
      );
      expect(
        steps['A second MAC before drive']!['failure'],
        SasPairingStatus.writePending.code,
      );
      expect(
        of('A MAC retry after drive'),
        action('bootstrapMacAlreadyEmitted', writePending: false),
      );
      expect(of('B approve'), action('sasApproved', writePending: false));
      expect(
        of('B emit MAC'),
        action('bootstrapMacEmitted', writePending: true),
      );
      expect(of('MACs authenticated'), {'aSameRun': true, 'bSameRun': true});
      // The Responder cannot emit INITIATOR_FINISH; its run continues.
      expect(of('B initiator finish'), {
        'failure': SasPairingStatus.notInitiator.code,
        'runEnded': false,
      });
      // Only the Initiator emits INITIATOR_FINISH, explicitly; the native library confirmed the
      // final ACK itself and both endpoints surfaced exactly one local result.
      expect(
        of('A finish'),
        action('initiatorFinishEmitted', writePending: true),
      );
      final results = of('results');
      expect(results['a'], 'connectionStep/confirmed/none/result');
      expect(results['b'], 'connectionStep/inbound/initiatorFinishAck/result');
      expect(results['aResults'], 1);
      expect(results['bResults'], 1);
      expect(results['runAEnded'], isTrue);
      expect(results['runBEnded'], isTrue);
      expect(results['authorityA'], {'state': 'ready', 'remaining': 9});
      expect(results['authorityB'], {'state': 'ready', 'remaining': 9});
      expect(results['startAcceptedAtB'], 1);
      expect(results['relayAToB'], greaterThan(0));
      expect(results['relayBToA'], greaterThan(0));
      expect(steps['ended run refused locally']!['refused'], isTrue);
      expect(of('detached'), {
        'a': 'detached',
        'b': 'detached',
        'connectionsClosed': true,
      });
      expect(steps['done']!['transferred'], [true, true]);
      expect(steps['done']!['closedByHarness'], [false, false]);
    },
    skip: Platform.isWindows ? false : 'Windows pairing platform only',
    timeout: const Timeout(Duration(minutes: 3)),
  );

  test('fresh process: a pre-load failure leaves the loader usable', () async {
    final steps = await runChild('missing-then-valid');
    expect(steps[0]['ready'], isFalse);
    expect(steps[0]['failure'], NativeLoadFailure.invalidLibraryPath.name);
    expect(steps[0]['processRestartRequired'], isFalse);
    expect(steps[1]['ready'], isTrue);
    expect(steps[1]['abiVersion'], 1);
  }, timeout: const Timeout(Duration(minutes: 2)));

  test(
    'fresh process: a loaded foreign image poisons the loader for the process',
    () async {
      final steps = await runChild('foreign-then-valid');
      expect(steps[0]['ready'], isFalse);
      expect(steps[0]['failure'], NativeLoadFailure.missingSymbol.name);
      expect(steps[0]['processRestartRequired'], isTrue);
      for (final symbol in abiV1Exports) {
        expect(steps[0]['message'], contains(symbol));
      }
      // The valid artifact is never opened: the same permanent failure is reported again.
      expect(steps[1]['ready'], isFalse);
      expect(steps[1]['identity'], steps[0]['identity']);
      expect(steps[1]['message'], steps[0]['message']);
    },
    timeout: const Timeout(Duration(minutes: 2)),
  );
}
