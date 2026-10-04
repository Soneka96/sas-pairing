// Package scope guards (P8-D-001 to P8-D-005): the public entrypoint exports only the P8.2
// lifecycle, P8.3 network, P8.4 ceremony-control, and P8.5 result surface, the package is pure
// Dart with one runtime dependency, the native library has no escape hatch (close, unload,
// reload, reset), cleanup is explicit (no finalizer, no child-by-child cleanup), and there is no
// background machinery (timer, stream, isolate, callback, loop), socket binding, protocol code,
// cryptography, SAS generation, automatic approval or action chaining, final-ACK confirmation,
// Dart-side ceremony accounting, trust verdict, generic result-field API, peer-Bootstrap
// parsing, or trust automation from a result. P8.3 allows the Windows listener transfer, the
// cooperative drive, events, and connections; P8.4 allows the public run, the nine explicit
// ceremony-control methods, and the SAS presentation model; P8.5 allows the runtime-owned result
// with its explicit read and close. Updated in P8.2, P8.3, P8.4, and P8.5, never removed.
import 'dart:io';

import 'package:test/test.dart';

import 'support/repository.dart';

/// Hand-written library sources (the generated bindings are checked separately).
List<File> handWrittenSources() => [
  for (final entity in Directory('lib').listSync(recursive: true))
    if (entity is File &&
        entity.path.endsWith('.dart') &&
        !entity.path.replaceAll(r'\', '/').contains('/generated/'))
      entity,
];

/// [source] without comments, so documentation may name what the code must not do.
String code(String source) => source
    .split('\n')
    .map((line) => line.replaceFirst(RegExp(r'//.*$'), ''))
    .join('\n');

String slashes(File file) => file.path.replaceAll(r'\', '/');

void main() {
  test(
    'the public entrypoint exports only the lifecycle and network surface',
    () {
      final entry = code(readPackageFile('lib/sas_pairing.dart'));
      expect(
        entry,
        isNot(matches(RegExp(r'^\s*(import|part)\b', multiLine: true))),
      );
      final targets = [
        for (final m in RegExp(r"export\s+'([^']+)'").allMatches(entry)) m[1],
      ];
      expect(targets, [
        'src/bootstrap.dart',
        'src/exceptions.dart',
        'src/lifecycle.dart',
        'src/network.dart',
        'src/status.dart',
      ]);
    },
  );

  test('only the entrypoint exports, and nothing exports the native layer', () {
    for (final file in Directory(
      'lib',
    ).listSync(recursive: true).whereType<File>()) {
      final path = slashes(file);
      final source = code(file.readAsStringSync());
      expect(source, isNot(contains("export 'src/native")), reason: path);
      if (path != 'lib/sas_pairing.dart') {
        expect(source, isNot(contains('export ')), reason: path);
      }
    }
  });

  test(
    'pure Dart package: one runtime dependency, no Flutter, not published',
    () {
      final pubspec = readPackageFile('pubspec.yaml');
      expect(pubspec, contains('name: sas_pairing\n'));
      expect(pubspec, contains('version: 0.1.0-dev.1\n'));
      expect(pubspec, contains('publish_to: none\n'));
      expect(pubspec.toLowerCase(), isNot(contains('flutter')));
      final runtime = RegExp(
        r'^dependencies:\n((?:  .*\n)*)',
        multiLine: true,
      ).firstMatch(pubspec.replaceAll('\r\n', '\n'));
      expect(runtime!.group(1)!.trim().split('\n'), ['ffi: ^2.2.0']);
    },
  );

  test(
    'no escape hatch, background machinery, later-increment API, or protocol code',
    () {
      final forbidden = <String, RegExp>{
        'library unload/reload/reset or fatal recovery': RegExp(
          r'\b(dispose|unload|reload|reopen\w*|reset\w*|replace\w*|clearFatal|'
          r'tryRecover|recover\w*|recreate\w*|releaseNative|destroyNative|'
          r'resetAfterFatal|reloadAfterFatal|createFreshNativeState)\s*\(',
        ),
        'finalizers': RegExp(r'\b(Native)?Finalizer\b'),
        'timers, isolates, streams, async loops': RegExp(
          r'\b(Timer|Isolate|ReceivePort|SendPort|Stream\w*|Future|async|await)\b',
        ),
        'native callbacks': RegExp(
          r'\b(NativeCallable|NativeFunction|fromFunction)\b',
        ),
        'automatic drive loops': RegExp(r'\bwhile\s*\(|\bdo\s*\{|for\s*\(\s*;'),
        'sockets and socket binding': RegExp(
          r'\b(Raw)?(Server)?Socket\b|\b(WSAStartup|WSACleanup|closesocket|'
          r'getsockname|setsockopt|ioctlsocket|InternetAddress)\b|'
          r'ws2_32|\bWSA\w+|\blisten\s*\(',
        ),
        // P8.5: results are read only as a whole snapshot; the frozen buffer plumbing stays
        // private to the result service and the one read.
        'generic result-field API or raw result access': RegExp(
          r'\b(copyField|readRawField|readField|rawField\w*|nativeResultInfo|'
          r'requiredLength|resultField\w*|SasPairingResultField|nativeHandle|rawHandle)\b',
        ),
        'trust automation or a bilateral interpretation of a result': RegExp(
          r'\b\w*(persist|enroll|bilateral|peerSucceeded|peerCompleted|peerSuccess|'
          r'committed|isTrusted|trustedPeer|trustPeer|verifiedDevice|peerIdentity)\w*\b',
          caseSensitive: false,
        ),
        // The frozen local-event names (`sasApproved`, ...) are reported outcomes, not SAS
        // logic.
        'SAS logic or SAS generation': RegExp(
          r'(?<![A-Za-z_])(sas|Sas|SAS)'
          r'(?!Pairing|_pairing|_PAIRING|Approved\b|AlreadyApproved\b|Rejected\b|'
          r'Cancelled\b)',
        ),
        'protocol frames, transcripts, deadlines, or attempt accounting': RegExp(
          // Frozen value names such as `abandonedPartialFrame` or `transcriptMismatch` are
          // reported data, not protocol code; `emitBootstrapMac` is the one reviewed explicit
          // native action (P8-D-004), which computes and sends nothing in Dart.
          r'\b(?!emitBootstrapMac\b)(encode|decode|parse|serialize|build|write|read|emit|'
          r'send|confirm|hash|compute|generate)\w*(Frame|Mac|Ack|Sas|Transcript|RequestId)'
          r'\w*\b|'
          r'\b\w*([Ll]imiter|[Oo]pportunityBudget)\w*\b|'
          r'\b(DateTime|Stopwatch|Duration|clock)\b',
        ),
        'automatic approval, action chaining, or final-ACK confirmation': RegExp(
          r'\b(authorizeAndExpose|exposeAndPresent|approveAndEmit\w*|emitAndFinish|'
          r'completePairing|completeRun|finishAutomatically|autoApprove\w*|'
          r'autoReject\w*|(confirm|send|sent|complete|write)\w*FinalAck\w*|'
          r'finalAck(Sent|Confirmed|Written)|confirmSent|ackSent|finishAck|'
          r'compareSas\w*|sasMatches|decimalMatches)\b',
          caseSensitive: false,
        ),
        // A private mutable state field of these kinds would duplicate native authority (the
        // P8.2 `_maxAuthorityOpportunities` validation bound is a constant, not state).
        'Dart-side ceremony accounting or a write-pending gate': RegExp(
          r'\b(bool|int)\??\s+_(isAuthorized|authorized|exposed|opportunit|remaining|'
          r'spent|guard|writePending|pendingWrite|outbound)\w*\b',
        ),
        'trust verdicts': RegExp(
          r'\b(isAttack|isCompromised|peerMalicious|shouldTrustPeer|authenticationFailed|'
          r'isTrusted|trustPeer|isMalicious)\b',
        ),
        'cryptography, hashing, or randomness': RegExp(
          r'\b(sha\d+|hmac|hkdf|x25519|Digest|Random)\b',
          caseSensitive: false,
        ),
        'text conversion of bytes (other than the one validated SAS display)':
            RegExp(
              r'\b(utf8|Utf8|toNativeUtf8|latin1|ascii|codeUnits|fromCharCodes)\b',
            ),
        'library discovery': RegExp(
          r'DynamicLibrary\.(process|executable)\b|PATH',
        ),
      };
      // The one reviewed text conversion: the fourteen validated ASCII bytes of the native
      // decimal SAS display become `SasPairingSasPresentation.decimal` (P8-D-004 rule 5).
      const display = 'String.fromCharCodes(decimal)';
      for (final file in handWrittenSources()) {
        // String literals are data (the frozen export-name table names every export).
        var source = code(
          file.readAsStringSync(),
        ).replaceAll(RegExp(r"'[^'\n]*'"), "''");
        if (slashes(file) == 'lib/src/ceremony.dart') {
          expect(display.allMatches(source), hasLength(1));
          source = source.replaceFirst(display, '');
        }
        for (final rule in forbidden.entries) {
          expect(
            rule.value.hasMatch(source),
            isFalse,
            reason:
                '${file.path}: ${rule.key}: ${rule.value.firstMatch(source)?.group(0)}',
          );
        }
      }
    },
  );

  test('the native library is never closed, and no wrapper closes another', () {
    for (final file in handWrittenSources()) {
      final path = slashes(file);
      final source = code(file.readAsStringSync());
      final closes = RegExp(r'\bclose\s*\(').allMatches(source).length;
      if (path == 'lib/src/lifecycle.dart') {
        // Exactly the three wrapper declarations; no child-by-child cleanup call.
        expect(closes, 3, reason: path);
        expect(RegExp(r'void close\(\) \{').allMatches(source), hasLength(3));
      } else if (path == 'lib/src/network.dart') {
        // Exactly the connection's declaration: the drive never closes a connection itself.
        expect(closes, 1, reason: path);
        expect(RegExp(r'void close\(\) \{').allMatches(source), hasLength(1));
      } else if (path == 'lib/src/result.dart') {
        // Exactly the result's declaration: nothing closes a result on its behalf.
        expect(closes, 1, reason: path);
        expect(RegExp(r'void close\(\) \{').allMatches(source), hasLength(1));
      } else {
        expect(closes, 0, reason: path);
      }
    }
  });

  test('closing a host or parent issues no detach or connection close first', () {
    final lifecycle = code(readPackageFile('lib/src/lifecycle.dart'));
    for (final kind in [
      'SasPairingRuntime',
      'SasPairingAuthority',
      'SasPairingHost',
    ]) {
      final body = RegExp(
        'final class $kind \\{.*?\\n  void close\\(\\) \\{(.*?)\\n  \\}',
        dotAll: true,
      ).firstMatch(lifecycle)!.group(1)!;
      expect(
        RegExp(
          r'\.(detach\w*|connectionClose|hostDestroy|authorityRelease|runtimeDestroy|'
          r'resultDestroy|close)\(',
        ).allMatches(body).map((m) => m[1]).toList(),
        [
          {
            'SasPairingRuntime': 'runtimeDestroy',
            'SasPairingAuthority': 'authorityRelease',
            'SasPairingHost': 'hostDestroy',
          }[kind],
        ],
        reason: kind,
      );
    }
  });

  test(
    'native calls: the seven lifecycle, five network, nine ceremony, and three result exports, each in its service',
    () {
      const services = {
        'lib/src/native/native_lifecycle_api.dart': {
          'sas_pairing_runtime_create',
          'sas_pairing_runtime_destroy',
          'sas_pairing_authority_register',
          'sas_pairing_authority_release',
          'sas_pairing_authority_status',
          'sas_pairing_host_create',
          'sas_pairing_host_destroy',
        },
        'lib/src/native/native_network_api.dart': {
          'sas_pairing_host_attach_windows_listener',
          'sas_pairing_host_detach_listener',
          'sas_pairing_host_drive',
          'sas_pairing_host_recheck_after_resume',
          'sas_pairing_connection_close',
        },
        'lib/src/native/native_ceremony_api.dart': {
          'sas_pairing_connection_start_initiator',
          'sas_pairing_run_authorize_exposure',
          'sas_pairing_run_expose_key',
          'sas_pairing_run_presentation',
          'sas_pairing_run_approve_sas',
          'sas_pairing_run_emit_bootstrap_mac',
          'sas_pairing_run_reject_sas',
          'sas_pairing_run_cancel_sas',
          'sas_pairing_run_emit_initiator_finish',
        },
        // Exactly the three result-data exports (P8-D-005 rule 1).
        'lib/src/native/native_result_api.dart': {
          'sas_pairing_result_info',
          'sas_pairing_result_copy',
          'sas_pairing_result_destroy',
        },
      };
      final call = RegExp(r'\.(sas_pairing_\w+)\b');
      for (final file in handWrittenSources()) {
        final path = slashes(file);
        final called = {
          for (final m in call.allMatches(code(file.readAsStringSync()))) m[1]!,
        }..remove('sas_pairing_abi_version');
        expect(called, services[path] ?? isEmpty, reason: path);
      }
    },
  );

  test(
    'FFI memory is handled only by the lifecycle, network, ceremony, and result services',
    () {
      final memory = RegExp(
        r'\b(calloc|malloc|using|Arena|nullptr|asTypedList)\b|Pointer<',
      );
      for (final file in handWrittenSources()) {
        final path = slashes(file);
        if (const {
          'lib/src/native/native_lifecycle_api.dart',
          'lib/src/native/native_network_api.dart',
          'lib/src/native/native_ceremony_api.dart',
          'lib/src/native/native_result_api.dart',
          // The one shared Bootstrap marshaller, used by the network and ceremony services.
          'lib/src/native/native_bootstrap.dart',
        }.contains(path)) {
          continue;
        }
        expect(
          memory.firstMatch(code(file.readAsStringSync()))?.group(0),
          isNull,
          reason: path,
        );
      }
    },
  );

  test(
    'every ceremony method makes exactly its own one native call and chains nothing',
    () {
      final ceremony = code(readPackageFile('lib/src/ceremony.dart'));
      const methods = {
        'authorizeExposure': 'authorizeExposure',
        'exposeKey': 'exposeKey',
        'approveSas': 'approveSas',
        'emitBootstrapMac': 'emitBootstrapMac',
        'rejectSas': 'rejectSas',
        'cancelSas': 'cancelSas',
        'emitInitiatorFinish': 'emitInitiatorFinish',
      };
      for (final MapEntry(key: method, value: export) in methods.entries) {
        final body = RegExp(
          // The whole call, up to the method's own closing line.
          'SasPairingLocalAction $method\\([^)]*\\) => _act\\((.*?)\\n  \\);\\n',
          dotAll: true,
        ).firstMatch(ceremony)?.group(1);
        expect(body, isNotNull, reason: method);
        expect(RegExp(r'\bapi\.(\w+)\(').allMatches(body!).map((m) => m[1]), [
          export,
        ], reason: method);
      }
      // Neither the run nor the start drives, rechecks, closes, or calls a second action.
      for (final forbidden in [
        RegExp(r'\.drive\('),
        RegExp(r'recheckAfterResume\('),
        RegExp(r'\bclose\('),
        RegExp(r'connectionClose\('),
      ]) {
        expect(forbidden.hasMatch(ceremony), isFalse, reason: '$forbidden');
      }
    },
  );

  test(
    'a result read uses only the data admission, a result close none, and a drive reads nothing',
    () {
      final result = code(readPackageFile('lib/src/result.dart'));
      String body(String signature) => RegExp(
        '\\n  $signature \\{(.*?)\\n  \\}\\n',
        dotAll: true,
      ).firstMatch(result)!.group(1)!;
      final read = body(r'SasPairingResultData read\(\)');
      final close = body(r'void close\(\)');
      // Native FATAL never blocks reading an existing result (P8-D-005 G).
      expect(result, isNot(contains('admitNormal')));
      expect(RegExp(r'\badmitData\(').allMatches(read), hasLength(1));
      expect(RegExp(r'\badmit\w*\(').allMatches(close), isEmpty);
      // One info and the four field copies, each named exactly once; destroy only in close.
      expect(RegExp(r'\.resultInfo\(').allMatches(result), hasLength(1));
      expect(RegExp(r'\.resultCopy\(').allMatches(result), hasLength(1));
      expect(RegExp(r'\.resultDestroy\(').allMatches(close), hasLength(1));
      expect(RegExp(r'\.resultDestroy\(').allMatches(result), hasLength(1));
      for (final field in [
        'REQUEST_ID',
        'AUTHENTICATED_PEER_BOOTSTRAP',
        'AUTHENTICATED_SHARED_CONTEXT',
        'PROFILE_IDENTIFIER',
      ]) {
        expect(
          RegExp('raw\\.SAS_PAIRING_RESULT_FIELD_$field\\b').allMatches(read),
          hasLength(1),
          reason: field,
        );
      }
      // No resize-and-retry: no loop in the result file, and BUFFER_TOO_SMALL is a violation.
      expect(RegExp(r'\b(for|while|do)\b').hasMatch(read), isFalse);
      // The drive's event mapping and every other file never read or destroy a result.
      for (final file in handWrittenSources()) {
        final path = slashes(file);
        if (const {
          'lib/src/result.dart',
          'lib/src/native/native_result_api.dart',
        }.contains(path)) {
          continue;
        }
        expect(
          RegExp(
            r'\b(resultInfo|resultCopy|resultDestroy)\b',
          ).hasMatch(code(file.readAsStringSync())),
          isFalse,
          reason: path,
        );
      }
    },
  );

  test(
    'the authenticated peer Bootstrap stays bytes: no parsing or protocol model in Dart',
    () {
      for (final file in handWrittenSources()) {
        final path = slashes(file);
        final source = code(file.readAsStringSync());
        final uses = RegExp(
          r'\bauthenticatedPeerBootstrap\b',
        ).allMatches(source);
        if (path == 'lib/src/result.dart') {
          // The constructor parameter, its initializer (twice), the field, and the one
          // constructor argument: the bytes are never inspected.
          expect(uses, hasLength(5), reason: path);
        } else {
          expect(uses, isEmpty, reason: path);
        }
      }
      final result = code(readPackageFile('lib/src/result.dart'));
      // No Bootstrap model, byte-level parsing primitive, or decoder in the result file.
      expect(
        RegExp(
          r'\b(SasPairingBootstrap|bootstrap\.dart|ByteData|getUint\d+|getInt\d+|'
          r'sublist|getRange|skip|take|indexOf|asByteData|BytesBuilder)\b|'
          r'\b\w*(parse|decode|deserialize)\w*\b',
          caseSensitive: false,
        ).firstMatch(result)?.group(0),
        isNull,
      );
    },
  );

  test('exactly one DynamicLibrary.open, inside the loader', () {
    final opens = [
      for (final file in handWrittenSources())
        for (final _ in RegExp(
          r'DynamicLibrary\.open\(',
        ).allMatches(code(file.readAsStringSync())))
          slashes(file),
    ];
    expect(opens, ['lib/src/native/native_library_loader.dart']);
  });

  test('the generated bindings never close the library', () {
    expect(readPackageFile(generatedBindingsPath), isNot(contains('.close(')));
  });

  test('no native binary is part of the package', () {
    final binaries = [
      for (final entity in packageRoot.listSync(recursive: true))
        if (entity is File &&
            !entity.path.replaceAll(r'\', '/').contains('/.dart_tool/') &&
            RegExp(r'\.(dll|so|dylib|lib|a)$').hasMatch(entity.path))
          entity.path,
    ];
    expect(binaries, isEmpty);
  });
}
