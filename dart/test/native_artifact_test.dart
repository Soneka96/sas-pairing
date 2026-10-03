// Real native artifact smoke (P8.1 success criterion): the actual P7 ABI v1 library, built with
// `cargo build --manifest-path core/Cargo.toml --release --features native-abi`, loads through
// the production process loader from the explicit SAS_PAIRING_NATIVE_LIBRARY path, exports all
// 25 frozen symbols under their exact names, and reports ABI version 1. No stateful export is
// called in the test process. This is the only test file that loads the real library in the test
// process (one native owner isolate, P8-D-001 N); the P8.2 real lifecycle scenarios run in child
// OS processes (test/support/lifecycle_child.dart), each with its own single owner isolate.
import 'dart:convert';
import 'dart:io';

import 'package:sas_pairing/sas_pairing.dart';
import 'package:sas_pairing/src/native/abi_v1.dart';
import 'package:sas_pairing/src/native/native_library_loader.dart';
import 'package:test/test.dart';

final String? artifact = Platform.environment['SAS_PAIRING_NATIVE_LIBRARY'];

/// Runs one fresh-process scenario: a loader scenario (test/support/loader_child.dart) or a
/// lifecycle scenario (test/support/lifecycle_child.dart).
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
