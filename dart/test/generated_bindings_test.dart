// The generated raw bindings are the one C declaration layer: exactly the 25 frozen functions,
// each signature derived from the frozen header, the frozen C types mapped faithfully, every
// generated constant mirrored, and the ffigen filter equal to the one Dart export list.
import 'dart:ffi';

import 'package:sas_pairing/src/native/abi_v1.dart';
import 'package:sas_pairing/src/native/generated/sas_pairing_bindings.g.dart';
import 'package:test/test.dart';

import 'support/repository.dart';

/// A tear-off of every generated function: the analyzer rejects this file if any is missing.
/// Tearing off a method looks nothing up and calls nothing.
final Map<String, Object Function(SasPairingNativeBindings)>
generatedFunctions = {
  'sas_pairing_abi_version': (b) => b.sas_pairing_abi_version,
  'sas_pairing_runtime_create': (b) => b.sas_pairing_runtime_create,
  'sas_pairing_runtime_destroy': (b) => b.sas_pairing_runtime_destroy,
  'sas_pairing_authority_register': (b) => b.sas_pairing_authority_register,
  'sas_pairing_authority_release': (b) => b.sas_pairing_authority_release,
  'sas_pairing_authority_status': (b) => b.sas_pairing_authority_status,
  'sas_pairing_host_create': (b) => b.sas_pairing_host_create,
  'sas_pairing_host_destroy': (b) => b.sas_pairing_host_destroy,
  'sas_pairing_host_attach_windows_listener': (b) =>
      b.sas_pairing_host_attach_windows_listener,
  'sas_pairing_host_detach_listener': (b) => b.sas_pairing_host_detach_listener,
  'sas_pairing_host_drive': (b) => b.sas_pairing_host_drive,
  'sas_pairing_host_recheck_after_resume': (b) =>
      b.sas_pairing_host_recheck_after_resume,
  'sas_pairing_connection_close': (b) => b.sas_pairing_connection_close,
  'sas_pairing_result_info': (b) => b.sas_pairing_result_info,
  'sas_pairing_result_copy': (b) => b.sas_pairing_result_copy,
  'sas_pairing_result_destroy': (b) => b.sas_pairing_result_destroy,
  'sas_pairing_connection_start_initiator': (b) =>
      b.sas_pairing_connection_start_initiator,
  'sas_pairing_run_authorize_exposure': (b) =>
      b.sas_pairing_run_authorize_exposure,
  'sas_pairing_run_expose_key': (b) => b.sas_pairing_run_expose_key,
  'sas_pairing_run_presentation': (b) => b.sas_pairing_run_presentation,
  'sas_pairing_run_approve_sas': (b) => b.sas_pairing_run_approve_sas,
  'sas_pairing_run_emit_bootstrap_mac': (b) =>
      b.sas_pairing_run_emit_bootstrap_mac,
  'sas_pairing_run_reject_sas': (b) => b.sas_pairing_run_reject_sas,
  'sas_pairing_run_cancel_sas': (b) => b.sas_pairing_run_cancel_sas,
  'sas_pairing_run_emit_initiator_finish': (b) =>
      b.sas_pairing_run_emit_initiator_finish,
};

/// The expected Dart FFI native type of each fundamental C type of the ABI.
const Map<String, String> fundamentalTypes = {
  'int32_t': 'ffi.Int32',
  'uint8_t': 'ffi.Uint8',
  'uint32_t': 'ffi.Uint32',
  'uint64_t': 'ffi.Uint64',
  'uintptr_t': 'ffi.UintPtr',
  'size_t': 'ffi.Size',
};

String _collapse(String s) => s
    .replaceAll(RegExp(r'\s+'), ' ')
    .replaceAll('( ', '(')
    .replaceAll(', )', ')')
    .replaceAll(' )', ')')
    .trim();

/// Native signatures declared by the generated lookups, by symbol.
Map<String, String> generatedSignatures(String source) => {
  for (final m in RegExp(
    r"_lookup<\s*ffi\.NativeFunction<(.*?)>\s*>\(\s*'(\w+)',?\s*\)",
    dotAll: true,
  ).allMatches(source))
    m.group(2)!: _collapse(m.group(1)!),
};

/// The Dart FFI signature each header declaration must generate: C `const` has no FFI
/// counterpart; an ABI typedef keeps its name; a pointer becomes `ffi.Pointer<T>`.
Map<String, String> expectedSignatures(String header) {
  String ffiType(String c) {
    final type = c.replaceAll('const ', '').trim();
    if (type.endsWith('*')) {
      return 'ffi.Pointer<${ffiType(type.substring(0, type.length - 1))}>';
    }
    return fundamentalTypes[type] ??
        (type.startsWith('sas_pairing_') && type.endsWith('_t')
            ? type
            : throw StateError('Unmapped C type "$type"'));
  }

  final declarations = <String, String>{};
  for (final m in RegExp(
    r'^(\w+) (sas_pairing_\w+)\(([^)]*)\);',
    multiLine: true,
  ).allMatches(header)) {
    final params = m.group(3)!.trim() == 'void'
        ? <String>[]
        : [
            for (final param in m.group(3)!.split(','))
              ffiType(param.trim().replaceFirst(RegExp(r'\w+$'), '')),
          ];
    final name = m.group(2)!;
    if (declarations.containsKey(name)) throw StateError('Duplicate $name');
    declarations[name] =
        '${ffiType(m.group(1)!)} Function(${params.join(', ')})';
  }
  return declarations;
}

void main() {
  final generated = readPackageFile(generatedBindingsPath);
  final header = readRepositoryFile(headerPath);

  test('the generated bindings declare exactly the 25 frozen functions', () {
    final symbols = generatedSignatures(generated).keys.toSet();
    expect(symbols, hasLength(25));
    expect(symbols, abiV1Exports.toSet());
    expect(generatedFunctions.keys.toList(), abiV1Exports);
    final bindings = SasPairingNativeBindings.fromLookup(
      <T extends NativeType>(String symbol) =>
          throw StateError('looked up $symbol'),
    );
    for (final tearOff in generatedFunctions.values) {
      expect(tearOff(bindings), isA<Function>());
    }
  });

  test('the ffigen function filter is exactly the frozen export list', () {
    final config = readPackageFile('ffigen.yaml').replaceAll('\r\n', '\n');
    final block = RegExp(
      r'^functions:\n  include:\n((?:    - .*\n)+)',
      multiLine: true,
    ).firstMatch(config);
    expect(block, isNotNull, reason: 'functions.include block in ffigen.yaml');
    final listed = [
      for (final line in block!.group(1)!.trim().split('\n'))
        line.trim().substring(2).trim(),
    ];
    expect(listed, abiV1Exports);
  });

  test(
    'every generated signature is the header declaration of that export',
    () {
      final declared = expectedSignatures(header);
      expect(declared.keys.toSet(), abiV1Exports.toSet());
      final actual = generatedSignatures(generated);
      for (final symbol in abiV1Exports) {
        expect(actual[symbol], declared[symbol], reason: symbol);
      }
    },
  );

  test('every frozen ABI typedef maps to its exact fundamental FFI type', () {
    final sections = parseManifestTables(readRepositoryFile(manifestPath));
    final types = uniqueRows(
      manifestTable(sections, 6, ['Type', 'C type']).rows,
      'type',
    );
    expect(types, hasLength(21));
    final typedefs = {
      for (final m in RegExp(
        r'^typedef (sas_pairing_\w+) = (ffi\.\w+);$',
        multiLine: true,
      ).allMatches(generated))
        m.group(1)!: m.group(2)!,
    };
    expect(typedefs.keys.toSet(), types.keys.toSet());
    for (final entry in types.entries) {
      expect(
        typedefs[entry.key],
        fundamentalTypes[entry.value[1]],
        reason: entry.key,
      );
    }
    // Pointer-sized C types stay pointer-sized in Dart: never a hard-coded 64-bit integer.
    expect(typedefs['sas_pairing_socket_t'], 'ffi.UintPtr');
    expect(generated, contains('@ffi.Size()\n  external int len;'));
    expect(generated, contains('external ffi.Pointer<ffi.Uint8> data;'));
  });

  test('the generated records are exactly the six frozen records', () {
    final records = {
      for (final m in RegExp(
        r'^final class (\w+) extends ffi\.(\w+)',
        multiLine: true,
      ).allMatches(generated))
        m.group(1)!: m.group(2)!,
    };
    expect(records.keys.toSet(), abiV1RecordSizes.keys.toSet());
    expect(records.values.toSet(), {
      'Struct',
    }, reason: 'no union or opaque type');
  });

  test(
    'every generated constant is mirrored exactly in the Dart ABI tables',
    () {
      final constants = <String, int>{};
      for (final m in RegExp(
        r'^const int (\w+) = (-?\d+);$',
        multiLine: true,
      ).allMatches(generated)) {
        expect(constants.containsKey(m.group(1)), isFalse);
        constants[m.group(1)!] = int.parse(m.group(2)!);
      }
      final mirrored = {
        ...abiV1Version,
        ...abiV1Statuses,
        ...abiV1Namespaces,
        ...abiV1Scalars,
      };
      expect(constants.keys.toSet(), mirrored.keys.toSet());
      for (final entry in constants.entries) {
        expect(mirrored[entry.key], entry.value, reason: entry.key);
      }
    },
  );
}
