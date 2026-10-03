// P8.1 scope guards (P8-D-001): the public entrypoint exports nothing raw, the package is pure
// Dart with one runtime dependency, and the private native layer has no lifecycle escape
// hatch (close, unload, reload, reset), no background machinery, and no protocol code.
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

void main() {
  test('the public entrypoint exports and imports nothing', () {
    final entry = code(readPackageFile('lib/sas_pairing.dart'));
    expect(
      entry,
      isNot(matches(RegExp(r'^\s*(export|import|part)\b', multiLine: true))),
    );
    expect(
      readPackageFile('lib/sas_pairing.dart'),
      contains('No pairing API is available yet'),
    );
  });

  test('no file in lib/ re-exports the private native layer', () {
    for (final file in Directory(
      'lib',
    ).listSync(recursive: true).whereType<File>()) {
      expect(
        code(file.readAsStringSync()),
        isNot(contains('export ')),
        reason: file.path,
      );
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

  test('no lifecycle escape hatch, background machinery, or protocol code', () {
    final forbidden = <String, RegExp>{
      'library close/unload/reload/reset': RegExp(
        r'\b(close|dispose|unload|reload|reopen\w*|reset\w*|replace\w*|'
        r'resetAfterFatal|reloadAfterFatal|createFreshNativeState)\s*\(',
      ),
      'finalizers': RegExp(r'\b(Native)?Finalizer\b'),
      'timers, isolates, streams, async loops': RegExp(
        r'\b(Timer|Isolate|ReceivePort|SendPort|Stream\w*|Future|async|await)\b',
      ),
      'sockets': RegExp(r'\b(Raw)?(Server)?Socket\b'),
      'cryptography or hashing': RegExp(
        r'\b(sha\d+|hmac|hkdf|x25519|Digest|Random\.secure)\b',
        caseSensitive: false,
      ),
      'stateful native calls': RegExp(r'\.sas_pairing_(?!abi_version\b)\w+\('),
      'library discovery': RegExp(
        r'DynamicLibrary\.(process|executable)\b|PATH',
      ),
    };
    for (final file in handWrittenSources()) {
      final source = code(file.readAsStringSync());
      for (final rule in forbidden.entries) {
        expect(
          rule.value.hasMatch(source),
          isFalse,
          reason:
              '${file.path}: ${rule.key}: ${rule.value.firstMatch(source)?.group(0)}',
        );
      }
    }
  });

  test('exactly one DynamicLibrary.open, inside the loader', () {
    final opens = [
      for (final file in handWrittenSources())
        for (final _ in RegExp(
          r'DynamicLibrary\.open\(',
        ).allMatches(code(file.readAsStringSync())))
          file.path.replaceAll(r'\', '/'),
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
