// Distribution guards (P8-D-006): the native artifact is distributed separately as a Windows x64
// CI artifact, so the package itself keeps the P8-D-001 loader exactly: an explicit absolute
// path is the only way to load the library, nothing is discovered (no PATH, current, executable,
// or package directory, no environment variable, no file name alone), nothing is downloaded,
// no binary or native-assets hook is part of the package, and it is never published.
import 'dart:io';

import 'package:sas_pairing/sas_pairing.dart';
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

/// [source] without line comments; string literals are kept.
String code(String source) => source
    .split('\n')
    .map((line) => line.replaceFirst(RegExp(r'//.*$'), ''))
    .join('\n');

String slashes(File file) => file.path.replaceAll(r'\', '/');

void main() {
  test('SasPairingRuntime.create(nativeLibraryPath:) is the only way to load', () {
    final lifecycle = code(readPackageFile('lib/src/lifecycle.dart'));
    final factories = [
      for (final m in RegExp(
        r'static\s+SasPairingRuntime\s+(\w+)\s*\(',
      ).allMatches(lifecycle))
        m[1],
    ];
    expect(factories, ['create']);
    expect(
      lifecycle,
      contains(
        'static SasPairingRuntime create({required String nativeLibraryPath})',
      ),
    );
    // The path is handed to the loader unchanged; nothing derives or defaults it.
    expect(
      lifecycle,
      contains('NativeProcessContext.forLibrary(nativeLibraryPath)'),
    );
  });

  test('the one DynamicLibrary.open loads the validated explicit path', () {
    final loader = code(
      readPackageFile('lib/src/native/native_library_loader.dart'),
    );
    final opens = [
      for (final m in RegExp(
        r'DynamicLibrary\.open\(([^)]*)\)',
      ).allMatches(loader))
        m[1],
    ];
    expect(opens, ['path']);
    expect(
      loader,
      contains('final path = _platform.resolveLibraryPath(libraryPath);'),
    );
    expect(
      loader,
      contains(
        "if (!file.isAbsolute) throw invalid('the path must be absolute');",
      ),
    );
  });

  test(
    'no library discovery, environment lookup, download, or embedded binary',
    () {
      final forbidden = <String, RegExp>{
        'a library file name or extension in a string literal': RegExp(
          r'''['"][^'"\n]*(sas_pairing_core|\.dll\b|\.so\b|\.dylib\b)[^'"\n]*['"]''',
        ),
        'environment, executable, script, or working-directory discovery':
            RegExp(
              r'\bPlatform\.(environment|resolvedExecutable|executable|script|'
              r'packageConfig)\b|\bDirectory\.(current|systemTemp)\b|'
              r'\bString\.fromEnvironment\b|\bIsolate\.resolvePackageUri\b',
            ),
        'searching or defaulting a library location': RegExp(
          r'\b(createDefault|defaultLibrary\w*|findLibrary\w*|searchPath\w*|'
          r'locateLibrary\w*|discover\w*|libraryDirectory|nativeAssets?\w*)\b',
          caseSensitive: false,
        ),
        'downloading or running anything': RegExp(
          r'\b(HttpClient|HttpRequest|WebSocket|Process\.(run|start)\w*)\b|'
          r'''['"]https?://|package:http/|\bUri\.(parse|https?)\b''',
        ),
        'an embedded binary': RegExp(
          r'\bbase64(Decode|Url)?\b|\bTVqQ|\\x4d\\x5a',
          caseSensitive: false,
        ),
      };
      for (final file in handWrittenSources()) {
        final source = code(file.readAsStringSync());
        for (final rule in forbidden.entries) {
          expect(
            rule.value.hasMatch(source),
            isFalse,
            reason:
                '${slashes(file)}: ${rule.key}: ${rule.value.firstMatch(source)?.group(0)}',
          );
        }
      }
    },
  );

  test('no native-assets or build hook, and no binary under lib/', () {
    expect(Directory('hook').existsSync(), isFalse);
    expect(File('build.dart').existsSync(), isFalse);
    final pubspec = readPackageFile('pubspec.yaml');
    expect(pubspec, isNot(matches(RegExp(r'^\s*hooks\s*:', multiLine: true))));
    expect(
      pubspec,
      isNot(matches(RegExp(r'\b(native_assets\w*|code_assets|hooks)\b'))),
    );
    final nonDart = [
      for (final entity in Directory('lib').listSync(recursive: true))
        if (entity is File && !entity.path.endsWith('.dart')) slashes(entity),
    ];
    expect(nonDart, isEmpty);
  });

  test('the package is never published and its metadata is current', () {
    final pubspec = readPackageFile('pubspec.yaml').replaceAll('\r\n', '\n');
    expect(pubspec, contains('\npublish_to: none\n'));
    expect(pubspec, contains('\nversion: 0.1.0-dev.1\n'));
    for (final stale in ['No pairing API yet', 'not decided', 'in progress']) {
      expect(pubspec, isNot(contains(stale)));
    }
    expect(readPackageFile('CHANGELOG.md'), contains('\n## 0.1.0-dev.1\n'));
    for (final license in ['LICENSE-MIT', 'LICENSE-APACHE']) {
      expect(
        File(license).readAsBytesSync(),
        File('${repositoryRoot.path}/$license').readAsBytesSync(),
        reason: '$license must be an unmodified copy of the repository license',
      );
    }
  });

  // The real process loader of this test isolate: relative names are refused before anything
  // is opened, even when a file of that name exists in the current directory, so no OS search
  // can ever pick a library.
  for (final name in [
    'sas_pairing_core.dll',
    'pubspec.yaml',
    './pubspec.yaml',
  ]) {
    test('a relative or bare library name is never resolved: $name', () {
      expect(
        () => SasPairingRuntime.create(nativeLibraryPath: name),
        throwsA(
          isA<SasPairingInitializationException>()
              .having(
                (e) => e.failure,
                'failure',
                SasPairingInitializationFailure.invalidLibraryPath,
              )
              .having(
                (e) => e.processRestartRequired,
                'processRestartRequired',
                isFalse,
              ),
        ),
      );
    });
  }
}
