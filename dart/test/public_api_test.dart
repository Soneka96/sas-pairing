// P8.2 public surface (P8-D-002 A, M; P8.2.1): a package consumer that imports only the public
// entrypoint sees exactly the lifecycle, status, and exception types, including the public
// initialization failure; raw FFI, handles, the loader and its exception, and the native
// lifecycle service are not part of it.
import 'dart:io';

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
];

/// The files the entrypoint exports from.
const publicFiles = [
  'lib/src/lifecycle.dart',
  'lib/src/status.dart',
  'lib/src/exceptions.dart',
];

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
        expect(entry, isNot(contains(name)), reason: name);
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
      r"LoadedNativeLibrary|NativeLifecycleApi|FfiNativeLifecycleApi|Struct|nullptr)\b|"
      r"import 'dart:ffi'|import 'package:ffi",
    );
    final publicHandle = RegExp(
      r'\bget\s+(?!_)\w*([Hh]andle|[Pp]ointer|[Bb]inding|[Aa]ddress|[Ss]cope)\w*\b|'
      r'\bfinal\s+[\w<>?]+\s+(?!_)\w*([Hh]andle|[Pp]ointer|[Bb]inding|[Aa]ddress|[Ss]cope)\w*\s*[;=]',
    );
    for (final path in publicFiles) {
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

  test('lifecycle wrappers use object identity and print no handle', () {
    final source = code(readPackageFile('lib/src/lifecycle.dart'));
    for (final kind in [
      'SasPairingRuntime',
      'SasPairingAuthority',
      'SasPairingHost',
    ]) {
      final body = RegExp(
        'final class $kind \\{(.*?)\\n\\}',
        dotAll: true,
      ).firstMatch(source)!.group(1)!;
      expect(body, isNot(contains('operator ==')), reason: kind);
      expect(body, isNot(contains('hashCode')), reason: kind);
      expect(body, isNot(contains('toString')), reason: kind);
    }
  });

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
