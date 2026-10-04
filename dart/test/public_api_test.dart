// Public surface (P8-D-002 A, M; P8.2.1; P8-D-003 B; P8-D-004 rule 1): a package consumer that
// imports only the public entrypoint sees exactly the lifecycle, status, and exception types,
// including the public initialization failure, the P8.3 Bootstrap, listener-transfer, drive,
// event, and connection types, and the P8.4 run, local action, local event, SAS presentation,
// ceremony identity, and run-ended types; raw FFI, handles, sockets, event, action, and
// presentation records, run and result references, the loader and its exception, and the native
// services are not part of it.
import 'dart:io';
import 'dart:typed_data';

import 'package:sas_pairing/sas_pairing.dart';
import 'package:test/test.dart';

import 'support/repository.dart';

const publicNames = {
  'SasPairingRuntime',
  'SasPairingAuthority',
  'SasPairingHost',
  'SasPairingAuthorityState',
  'SasPairingAuthorityStatus',
  'SasPairingStatus',
  'SasPairingNativeException',
  'SasPairingClosedException',
  'SasPairingContractException',
  'SasPairingInitializationException',
  'SasPairingInitializationFailure',
  'SasPairingBootstrap',
  'SasPairingWindowsListenerSocket',
  'SasPairingHostNetworkState',
  'SasPairingConnection',
  'SasPairingDriveBatch',
  'SasPairingDriveFailure',
  'SasPairingEvent',
  'SasPairingEventKind',
  'SasPairingStepKind',
  'SasPairingProtocolEvent',
  'SasPairingEventReason',
  'SasPairingDeadlineKind',
  'SasPairingCancelState',
  'SasPairingCancelReason',
  'SasPairingRun',
  'SasPairingLocalAction',
  'SasPairingLocalEvent',
  'SasPairingSasPresentation',
  'SasPairingCeremonyIdentity',
  'SasPairingRunEndedException',
};

const prohibitedNames = [
  'Pointer',
  'DynamicLibrary',
  'SasPairingNativeBindings',
  'NativeLibraryLoader',
  'LoadedNativeLibrary',
  'NativeLifecycleApi',
  'FfiNativeLifecycleApi',
  'NativeProcessContext',
  'NativeLibraryInitializationException',
  'NativeLoadFailure',
  'createRuntime',
  'initializeProcessContext',
  'NativeNetworkApi',
  'FfiNativeNetworkApi',
  'NativeEventRecord',
  'NativeRunRef',
  'NativeResultRef',
  'NativeResultStore',
  'HostNetwork',
  'runReferenceOf',
  'resultReferenceOf',
  'runReferencesOf',
  'resultStoreOf',
  'sas_pairing_event_t',
  'sas_pairing_bootstrap_view_t',
  'NativeCeremonyApi',
  'FfiNativeCeremonyApi',
  'NativeActionRecord',
  'NativeActionResult',
  'NativePresentationRecord',
  'NativePresentationResult',
  'NativeBootstrapBytes',
  'nativeBootstrapBytes',
  'nativeBootstrapView',
  'runReferenceOfRun',
  'sas_pairing_action_t',
  'sas_pairing_sas_presentation_t',
];

/// The files the entrypoint exports from.
const publicFiles = [
  'lib/src/lifecycle.dart',
  'lib/src/status.dart',
  'lib/src/exceptions.dart',
  'lib/src/bootstrap.dart',
  'lib/src/network.dart',
];

/// Every file that declares a public type: the exported files and the `ceremony.dart` part of
/// `network.dart` (P8.4).
const publicSources = [...publicFiles, 'lib/src/ceremony.dart'];

String code(String source) => source
    .split('\n')
    .map((line) => line.replaceFirst(RegExp(r'//.*$'), ''))
    .join('\n');

void main() {
  test('the intended public names are reachable from the entrypoint alone', () {
    final types = <Type>[
      SasPairingRuntime,
      SasPairingAuthority,
      SasPairingHost,
      SasPairingAuthorityState,
      SasPairingAuthorityStatus,
      SasPairingStatus,
      SasPairingNativeException,
      SasPairingClosedException,
      SasPairingContractException,
      SasPairingInitializationException,
      SasPairingInitializationFailure,
      SasPairingBootstrap,
      SasPairingWindowsListenerSocket,
      SasPairingHostNetworkState,
      SasPairingConnection,
      SasPairingDriveBatch,
      SasPairingDriveFailure,
      SasPairingEvent,
      SasPairingEventKind,
      SasPairingStepKind,
      SasPairingProtocolEvent,
      SasPairingEventReason,
      SasPairingDeadlineKind,
      SasPairingCancelState,
      SasPairingCancelReason,
      SasPairingRun,
      SasPairingLocalAction,
      SasPairingLocalEvent,
      SasPairingSasPresentation,
      SasPairingCeremonyIdentity,
      SasPairingRunEndedException,
    ];
    expect(types.map((t) => '$t').toSet(), publicNames);
    expect(SasPairingStatus.values, hasLength(48));
    expect(SasPairingAuthorityState.values.map((s) => s.name), [
      'ready',
      'busy',
      'exhausted',
    ]);
    const SasPairingRuntime Function({required String nativeLibraryPath})
    create = SasPairingRuntime.create;
    expect(create, isNotNull);
    final closed = SasPairingClosedException('SasPairingHost', 'close');
    expect(closed.objectKind, 'SasPairingHost');
    final native = SasPairingNativeException('op', SasPairingStatus.busy.code);
    expect(native.knownStatus, SasPairingStatus.busy);
    expect(
      SasPairingContractException('op', 'x').processRestartRequired,
      isTrue,
    );
  });

  test('a consumer can use the P8.3 network API from the entrypoint alone', () {
    // Compiles only if every P8.3 member is reachable through the entrypoint; no native library
    // is needed to type-check a consumer.
    void consumer(SasPairingHost host, int alreadyBoundSocket) {
      final listener = SasPairingWindowsListenerSocket.fromNativeSocket(
        alreadyBoundSocket,
      );
      final local = SasPairingBootstrap(
        applicationIdentity: Uint8List.fromList([1]),
        keyAlgorithm: Uint8List.fromList([2]),
        publicKey: Uint8List.fromList([3]),
        sharedContext: Uint8List(0),
      );
      host.attachWindowsListener(listener: listener, local: local);
      host.attachWindowsListener(
        listener: listener,
        local: local,
        expected: local,
      );
      final bool transferred = listener.isTransferred;
      final SasPairingHostNetworkState state = host.networkState;
      final SasPairingDriveBatch batch = host.drive();
      final SasPairingDriveBatch resumed = host.recheckAfterResume();
      final SasPairingDriveFailure? failure = batch.failure;
      for (final SasPairingEvent event in [
        ...batch.events,
        ...resumed.events,
      ]) {
        final values = <Object?>[
          event.kind,
          event.stepKind,
          event.protocolEvent,
          event.reason,
          event.deadlineKind,
          event.cancelState,
          event.cancelReason,
          event.writePending,
          event.runUntracked,
          event.requestId,
          event.hasTrackedRun,
          event.hasResult,
        ];
        final SasPairingConnection? connection = event.connection;
        if (event.shouldCloseConnection) connection?.close();
        expect([values, connection?.isClosed, transferred, state], isNotNull);
      }
      expect([
        failure?.statusCode,
        failure?.knownStatus,
        failure?.processRestartRequired,
      ], isNotNull);
      host.detachListener();
    }

    expect(consumer, isNotNull);
    expect(SasPairingHostNetworkState.values.map((s) => s.name), [
      'detached',
      'attached',
      'listenerDisabled',
      'failedClosed',
    ]);
    expect(SasPairingEventKind.values, hasLength(5));
    expect(SasPairingStepKind.values, hasLength(8));
    expect(SasPairingProtocolEvent.values, hasLength(13));
    expect(SasPairingEventReason.values, hasLength(16));
    expect(SasPairingDeadlineKind.values, hasLength(5));
    expect(SasPairingCancelState.values, hasLength(4));
    expect(SasPairingCancelReason.values, hasLength(5));
  });

  test('a consumer can use the P8.4 ceremony API from the entrypoint alone', () {
    // Compiles only if every P8.4 member is reachable through the entrypoint, with no private
    // import, handle, or pointer; no native library is needed to type-check a consumer.
    void consumer(SasPairingHost host, SasPairingBootstrap local) {
      for (final SasPairingEvent event in host.drive().events) {
        final SasPairingRun? run = event.run;
        expect(event.hasTrackedRun, run != null);
        final SasPairingConnection? connection = event.connection;
        final SasPairingLocalAction started = connection!.startInitiator(
          local: local,
        );
        connection.startInitiator(local: local, expected: local);
        final SasPairingRun? startedRun = started.run;
        final List<Object?> fields = [
          started.event,
          started.deadlineKind,
          started.writePending,
          startedRun?.isEnded,
        ];
        if (run == null) continue;
        final SasPairingLocalAction authorized = run.authorizeExposure();
        final SasPairingLocalAction exposed = run.exposeKey();
        final SasPairingSasPresentation? presented = run.presentation();
        if (presented == null) continue;
        final String decimal = presented.decimal;
        final SasPairingCeremonyIdentity identity = presented.ceremonyIdentity;
        final Uint8List identityBytes = identity.bytes;
        // The application decides; the package never does.
        final userChoseMatch = decimal.isNotEmpty;
        if (userChoseMatch) {
          run.approveSas(identity);
          run.emitBootstrapMac();
          run.emitInitiatorFinish();
        } else {
          run.rejectSas(identity);
          run.cancelSas(identity);
        }
        expect([fields, authorized, exposed, identityBytes], isNotNull);
      }
    }

    expect(consumer, isNotNull);
    expect(SasPairingLocalEvent.values, hasLength(12));
    expect(
      SasPairingRunEndedException('SasPairingRun.exposeKey').operation,
      'SasPairingRun.exposeKey',
    );
  });

  test('the P8.4 public types carry no handle, result, or protocol field', () {
    final ceremony = code(readPackageFile('lib/src/ceremony.dart'));
    Set<String> members(String kind) {
      final body = RegExp(
        'final class $kind \\{(.*?)\\n\\}',
        dotAll: true,
      ).firstMatch(ceremony)!.group(1)!;
      return {
        for (final m in RegExp(
          r'^  (?:final [\w<>?]+ |[\w<>?]+ get |[\w<>?]+ )(\w+)\b',
          multiLine: true,
        ).allMatches(body))
          if (!m[1]!.startsWith('_') && m[1] != 'operator') m[1]!,
      };
    }

    // Exactly the four payload fields: no raw flags, run handle, protocol bytes, or result.
    expect(members('SasPairingLocalAction'), {
      'event',
      'run',
      'deadlineKind',
      'writePending',
    });
    expect(members('SasPairingSasPresentation'), {
      'ceremonyIdentity',
      'decimal',
    });
    expect(members('SasPairingCeremonyIdentity'), {'bytes', 'hashCode'});
    // No public constructor can make an identity, a presentation, an action, or a run.
    for (final kind in [
      'SasPairingRun',
      'SasPairingLocalAction',
      'SasPairingSasPresentation',
      'SasPairingCeremonyIdentity',
    ]) {
      expect(
        // A private constructor (`$kind._(`) is allowed; an unnamed or public named one is not.
        RegExp(
          '^  $kind(\\.[A-Za-z]\\w*)?\\(',
          multiLine: true,
        ).hasMatch(ceremony),
        isFalse,
        reason: kind,
      );
    }
    // The run's public surface is exactly the reviewed explicit steps.
    final run = RegExp(
      r'final class SasPairingRun \{(.*?)\n\}',
      dotAll: true,
    ).firstMatch(ceremony)!.group(1)!;
    expect(
      {
        for (final m in RegExp(
          r'^  [\w<>?]+ (?:get )?([a-z]\w*)\b',
          multiLine: true,
        ).allMatches(run))
          m[1]!,
      },
      {
        'isEnded',
        'authorizeExposure',
        'exposeKey',
        'presentation',
        'approveSas',
        'emitBootstrapMac',
        'rejectSas',
        'cancelSas',
        'emitInitiatorFinish',
      },
    );
  });

  test(
    'no public P8.3 or P8.4 member exposes a private native type or raw value',
    () {
      final network = code(readPackageFile('lib/src/network.dart'));
      final bootstrap = code(readPackageFile('lib/src/bootstrap.dart'));
      final ceremony = code(readPackageFile('lib/src/ceremony.dart'));
      for (final source in [network, bootstrap, ceremony]) {
        for (final m in RegExp(
          r'final class (SasPairing\w+)\b[^{]*\{(.*?)\n\}',
          dotAll: true,
        ).allMatches(source)) {
          final body = m[2]!;
          // A public field or getter typed by a private native type, or a raw-value getter.
          expect(
            RegExp(
              // `hashCode` (the ceremony identity's value equality) is no raw value.
              r'(final\s+|^\s+)(Native\w*|HostNetwork|int)\??\s+(get\s+)?'
              r'(?!_|hashCode\b)\w*'
              r'([Hh]andle|[Ss]ocket|[Rr]aw|[Ff]lags|[Cc]ode|[Rr]un|[Rr]esult)\w*\b',
              multiLine: true,
            ).firstMatch(body)?.group(0),
            m[1] == 'SasPairingDriveFailure' ? 'final int statusCode' : null,
            reason: m[1],
          );
          expect(
            RegExp(
              r'^\s+(final\s+)?(Native\w*|HostNetwork)\??\s+(get\s+)?(?!_)\w+',
              multiLine: true,
            ).firstMatch(body)?.group(0),
            isNull,
            reason: m[1],
          );
        }
      }
      // The enums keep their raw ABI values private.
      for (final m in RegExp(
        r'enum (SasPairing\w+) \{(.*?)\n\}',
        dotAll: true,
      ).allMatches(network + ceremony)) {
        expect(m[2], isNot(contains('final int code')), reason: m[1]);
        expect(m[2], isNot(contains('get code')), reason: m[1]);
      }
    },
  );

  test(
    'the entrypoint exports exactly the public names, from the three public files',
    () {
      final entry = code(readPackageFile('lib/sas_pairing.dart'));
      final exports = RegExp(
        r"""export\s+'([^']+)'\s+show\s+([^;]+);""",
      ).allMatches(entry).toList();
      expect(
        RegExp(r'\bexport\b').allMatches(entry),
        hasLength(exports.length),
        reason: 'every export has an explicit show list',
      );
      expect({for (final m in exports) 'lib/${m[1]}'}, publicFiles.toSet());
      final shown = {
        for (final m in exports)
          for (final name in m[2]!.split(',')) name.trim(),
      };
      expect(shown, publicNames);
      for (final name in prohibitedNames) {
        expect(shown, isNot(contains(name)));
        expect(RegExp('\\b$name\\b').hasMatch(entry), isFalse, reason: name);
      }
      expect(entry, isNot(contains('src/native')));
      expect(
        RegExp(r'^\s*(import|part)\b', multiLine: true).hasMatch(entry),
        isFalse,
      );
    },
  );

  test('public files expose no raw FFI type, handle, pointer, or binding', () {
    final rawAccess = RegExp(
      r"\b(Pointer|DynamicLibrary|SasPairingNativeBindings|NativeLibraryLoader|"
      r"LoadedNativeLibrary|NativeLifecycleApi|FfiNativeLifecycleApi|FfiNativeNetworkApi|"
      r"FfiNativeCeremonyApi|Struct|nullptr|sas_pairing_event_t|sas_pairing_bootstrap_view_t|"
      r"sas_pairing_action_t|sas_pairing_sas_presentation_t)\b|"
      r"import 'dart:ffi'|import 'package:ffi",
    );
    final publicHandle = RegExp(
      r'\bget\s+(?!_)\w*([Hh]andle|[Pp]ointer|[Bb]inding|[Aa]ddress|[Ss]cope|[Ss]ocket)\w*\b|'
      r'\bfinal\s+[\w<>?]+\s+(?!_)\w*([Hh]andle|[Pp]ointer|[Bb]inding|[Aa]ddress|[Ss]cope)\w*\s*[;=]',
    );
    for (final path in publicSources) {
      final source = code(readPackageFile(path));
      expect(rawAccess.firstMatch(source)?.group(0), isNull, reason: path);
      expect(publicHandle.firstMatch(source)?.group(0), isNull, reason: path);
    }
  });

  group('initialization failures are public and typed', () {
    test('the seven categories and their restart classes', () {
      final restart = {
        for (final failure in SasPairingInitializationFailure.values)
          failure.name: SasPairingInitializationException(
            failure,
            'm',
          ).processRestartRequired,
      };
      expect(restart, {
        'unsupportedPointerWidth': false,
        'invalidLibraryPath': false,
        'openFailed': false,
        'missingSymbol': true,
        'abiVersionQueryFailed': true,
        'abiVersionMismatch': true,
        'verificationFailed': true,
      });
    });

    // The real process loader of this test isolate: these pre-load failures open nothing, so
    // it stays uninitialized and no native library is ever loaded here.
    final cases = {
      'an empty path': ('', SasPairingInitializationFailure.invalidLibraryPath),
      'a relative path': (
        'sas_pairing_core.dll',
        SasPairingInitializationFailure.invalidLibraryPath,
      ),
      'a missing absolute file': (
        File('sas_pairing_missing_${pid}_library').absolute.path,
        SasPairingInitializationFailure.invalidLibraryPath,
      ),
      'a file the OS cannot load': (
        File('pubspec.yaml').absolute.path,
        SasPairingInitializationFailure.openFailed,
      ),
    };
    for (final MapEntry(key: name, value: (path, failure)) in cases.entries) {
      test('SasPairingRuntime.create with $name', () {
        Object? caught;
        try {
          SasPairingRuntime.create(nativeLibraryPath: path);
        } on SasPairingInitializationException catch (error) {
          caught = error;
          expect(error.failure, failure);
          expect(error.processRestartRequired, isFalse);
          expect(error.message, isNotEmpty);
          expect(error.toString(), contains('(${failure.name})'));
        }
        expect(caught.runtimeType, SasPairingInitializationException);
        expect(
          '$caught',
          isNot(
            anyOf(
              contains('NativeLibraryInitializationException'),
              contains('NativeLoadFailure'),
            ),
          ),
        );
      });
    }
  });

  test('the private loader failure types are no part of the public contract', () {
    final exceptions = readPackageFile('lib/src/exceptions.dart');
    final lifecycle = readPackageFile('lib/src/lifecycle.dart');
    final private = RegExp(
      r'\b(NativeLibraryInitializationException|NativeLoadFailure)\b',
    );
    // The public exception file knows nothing of the loader.
    expect(private.hasMatch(exceptions), isFalse);
    expect(exceptions, isNot(contains('native/')));
    // The public exception holds only its public category and message: no cause, no inner
    // exception, no private field.
    final body = RegExp(
      r'final class SasPairingInitializationException implements Exception \{(.*?)\n\}',
      dotAll: true,
    ).firstMatch(exceptions)!.group(1)!;
    expect(
      {
        for (final m in RegExp(
          r'^\s*final\s+(\w+)\s+(\w+);',
          multiLine: true,
        ).allMatches(body))
          '${m[1]} ${m[2]}',
      },
      {'SasPairingInitializationFailure failure', 'String message'},
    );
    // No documentation in the lifecycle names the private types; in code they appear only in
    // the import and the one translation boundary below SasPairingRuntime.create.
    final docs = lifecycle
        .split('\n')
        .where((line) => line.trimLeft().startsWith('///'))
        .join('\n');
    expect(private.hasMatch(docs), isFalse);
    expect(docs, contains('[SasPairingInitializationException]'));
    final boundary = RegExp(
      r"^import 'native/native_library_loader\.dart'.*?;$|"
      r'^NativeProcessContext initializeProcessContext\(.*?^\}$|'
      r'^SasPairingInitializationFailure _publicFailure\(.*?^    \};$',
      multiLine: true,
      dotAll: true,
    );
    expect(boundary.allMatches(lifecycle), hasLength(3));
    expect(private.hasMatch(code(lifecycle.replaceAll(boundary, ''))), isFalse);
    expect(
      RegExp(
        r'on NativeLibraryInitializationException catch',
      ).allMatches(lifecycle),
      hasLength(1),
    );
    final create = RegExp(
      r'static SasPairingRuntime create\(\{required String nativeLibraryPath\}\) =>(.*?);\n',
      dotAll: true,
    ).firstMatch(lifecycle)!.group(1)!;
    expect(create, contains('initializeProcessContext('));
  });

  test(
    'lifecycle, network, and ceremony wrappers use object identity and print no handle',
    () {
      final source =
          code(readPackageFile('lib/src/lifecycle.dart')) +
          code(readPackageFile('lib/src/network.dart')) +
          code(readPackageFile('lib/src/ceremony.dart'));
      for (final kind in [
        'SasPairingRuntime',
        'SasPairingAuthority',
        'SasPairingHost',
        'SasPairingConnection',
        'SasPairingWindowsListenerSocket',
        'SasPairingEvent',
        'SasPairingRun',
        'SasPairingLocalAction',
        'SasPairingSasPresentation',
      ]) {
        final body = RegExp(
          'final class $kind \\{(.*?)\\n\\}',
          dotAll: true,
        ).firstMatch(source)!.group(1)!;
        expect(body, isNot(contains('operator ==')), reason: kind);
        expect(body, isNot(contains('hashCode')), reason: kind);
        expect(body, isNot(contains('toString')), reason: kind);
      }
    },
  );

  test('no public lifecycle file is reachable except through the entrypoint', () {
    // Only lib/sas_pairing.dart may export; lib/src is private by Dart convention.
    for (final file in Directory(
      'lib',
    ).listSync(recursive: true).whereType<File>()) {
      final path = file.path.replaceAll(r'\', '/');
      if (path == 'lib/sas_pairing.dart') continue;
      expect(
        code(file.readAsStringSync()),
        isNot(contains('export ')),
        reason: path,
      );
    }
  });
}
