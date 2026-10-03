// Package scope guards (P8-D-001, P8-D-002): the public entrypoint exports only the P8.2
// lifecycle surface, the package is pure Dart with one runtime dependency, the native library
// has no escape hatch (close, unload, reload, reset), lifecycle cleanup is explicit (no
// finalizer, no child-by-child cleanup), and there is no background machinery, socket, network,
// later-increment API, or protocol code. Updated in P8.2, never removed.
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
  test('the public entrypoint exports only the P8.2 lifecycle surface', () {
    final entry = code(readPackageFile('lib/sas_pairing.dart'));
    expect(
      entry,
      isNot(matches(RegExp(r'^\s*(import|part)\b', multiLine: true))),
    );
    final targets = [
      for (final m in RegExp(r"export\s+'([^']+)'").allMatches(entry)) m[1],
    ];
    expect(targets, [
      'src/exceptions.dart',
      'src/lifecycle.dart',
      'src/status.dart',
    ]);
  });

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
        'sockets': RegExp(r'\b(Raw)?(Server)?Socket\b'),
        'listener, network drive, or later-increment objects': RegExp(
          r'\b(\w*Listener\w*|attach\w*|detach\w*|drive\w*|recheck\w*|'
          r'Bootstrap|SasBootstrap|PeerBootstrap|SasPairingBootstrap\w*|'
          r'SasPairingConnection\w*|SasPairingRun(?!time)\w*|SasPairingResult\w*|'
          r'SasPresentation\w*|SasPairingSasPresentation\w*|SasPairingCeremony\w*)\b',
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
      } else {
        expect(closes, 0, reason: path);
      }
    }
  });

  test(
    'stateful native calls: the seven lifecycle exports, only in the lifecycle service',
    () {
      const service = 'lib/src/native/native_lifecycle_api.dart';
      final call = RegExp(r'\.(sas_pairing_\w+)\(');
      for (final file in handWrittenSources()) {
        final path = slashes(file);
        final called = {
          for (final m in call.allMatches(code(file.readAsStringSync()))) m[1]!,
        }..remove('sas_pairing_abi_version');
        if (path == service) {
          expect(called, {
            'sas_pairing_runtime_create',
            'sas_pairing_runtime_destroy',
            'sas_pairing_authority_register',
            'sas_pairing_authority_release',
            'sas_pairing_authority_status',
            'sas_pairing_host_create',
            'sas_pairing_host_destroy',
          });
        } else {
          expect(called, isEmpty, reason: path);
        }
      }
    },
  );

  test('FFI memory is handled only by the lifecycle service', () {
    final memory = RegExp(
      r'\b(calloc|malloc|using|Arena|nullptr|asTypedList)\b|Pointer<',
    );
    for (final file in handWrittenSources()) {
      final path = slashes(file);
      if (path == 'lib/src/native/native_lifecycle_api.dart') continue;
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
