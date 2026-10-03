// P8.2 public surface (P8-D-002 A): a package consumer that imports only the public entrypoint
// sees exactly the lifecycle, status, and exception types; raw FFI, handles, the loader, and
// the native lifecycle service are not part of it.
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
  'createRuntime',
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
