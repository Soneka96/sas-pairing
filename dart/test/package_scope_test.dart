// Package scope guards (P8-D-001, P8-D-002, P8-D-003): the public entrypoint exports only the
// P8.2 lifecycle and P8.3 network surface, the package is pure Dart with one runtime dependency,
// the native library has no escape hatch (close, unload, reload, reset), cleanup is explicit (no
// finalizer, no child-by-child cleanup), and there is no background machinery (timer, stream,
// isolate, callback, loop), socket binding, later-increment API (ceremony, SAS, run, result), or
// protocol code. P8.3 allows the Windows listener transfer, the cooperative drive, events, and
// connections. Updated in P8.2 and P8.3, never removed.
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
        'ceremony, SAS, run, result, or presentation API (later increments)': RegExp(
          r'\b(SasPairingRun(?!time)\w*|SasPairingResult\w*|SasPresentation\w*|'
          r'SasPairingSasPresentation\w*|SasPairingCeremony\w*|\w*[Pp]resentation\w*|'
          r'startInitiator|authorizeExposure|exposeKey|approve\w*|reject\w*|'
          r'cancelSas|emitBootstrapMac|emitInitiatorFinish|resultInfo|resultCopy|'
          r'resultDestroy)\b',
        ),
        'SAS logic': RegExp(
          r'(?<![A-Za-z_])(sas|Sas|SAS)(?!Pairing|_pairing|_PAIRING)',
        ),
        'protocol frames, transcripts, deadlines, or attempt accounting': RegExp(
          // Frozen value names such as `abandonedPartialFrame` or `transcriptMismatch` are
          // reported data, not protocol code.
          r'\b(encode|decode|parse|serialize|build|write|read|emit|send|confirm|hash|'
          r'compute|generate)\w*(Frame|Mac|Ack|Sas|Transcript|RequestId)\w*\b|'
          r'\b\w*([Ll]imiter|[Oo]pportunityBudget)\w*\b|'
          r'\b(DateTime|Stopwatch|Duration|clock)\b',
        ),
        'cryptography, hashing, or randomness': RegExp(
          r'\b(sha\d+|hmac|hkdf|x25519|Digest|Random)\b',
          caseSensitive: false,
        ),
        'text conversion of bytes': RegExp(
          r'\b(utf8|Utf8|toNativeUtf8|latin1|ascii|codeUnits|fromCharCodes)\b',
        ),
        'library discovery': RegExp(
          r'DynamicLibrary\.(process|executable)\b|PATH',
        ),
      };
      for (final file in handWrittenSources()) {
        // String literals are data (the frozen export-name table names every export).
        final source = code(
          file.readAsStringSync(),
        ).replaceAll(RegExp(r"'[^'\n]*'"), "''");
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
          r'\.(detach\w*|connectionClose|hostDestroy|authorityRelease|runtimeDestroy)\(',
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
    'stateful native calls: the seven lifecycle and five network exports, each in its service',
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
        // No ceremony action, presentation, or result export is called anywhere.
        'lib/src/native/native_network_api.dart': {
          'sas_pairing_host_attach_windows_listener',
          'sas_pairing_host_detach_listener',
          'sas_pairing_host_drive',
          'sas_pairing_host_recheck_after_resume',
          'sas_pairing_connection_close',
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

  test('FFI memory is handled only by the lifecycle and network services', () {
    final memory = RegExp(
      r'\b(calloc|malloc|using|Arena|nullptr|asTypedList)\b|Pointer<',
    );
    for (final file in handWrittenSources()) {
      final path = slashes(file);
      if (path == 'lib/src/native/native_lifecycle_api.dart' ||
          path == 'lib/src/native/native_network_api.dart') {
        continue;
      }
      expect(
        memory.firstMatch(code(file.readAsStringSync()))?.group(0),
        isNull,
        reason: path,
      );
    }
  });

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
