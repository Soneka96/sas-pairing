// Repository consistency: the Dart ABI v1 tables equal the frozen manifest row for row
// (docs/p7-native-abi/abi-v1-manifest.md, P7-D-013). Missing, duplicate, changed, and
// unexpected rows all fail.
import 'package:sas_pairing/src/native/abi_v1.dart';
import 'package:test/test.dart';

import 'support/record_layout.dart';
import 'support/repository.dart';

void main() {
  final sections = parseManifestTables(readRepositoryFile(manifestPath));

  Map<String, int> nameValueTable(int section, List<String> header) {
    final rows = uniqueRows(
      manifestTable(sections, section, header).rows,
      'value',
    );
    return {
      for (final entry in rows.entries)
        entry.key: manifestValue(entry.value.last),
    };
  }

  void expectSameTable(Map<String, int> manifest, Map<String, int> dart) {
    expect(
      dart.keys.toSet().difference(manifest.keys.toSet()),
      isEmpty,
      reason: 'Dart values missing from the manifest',
    );
    expect(
      manifest.keys.toSet().difference(dart.keys.toSet()),
      isEmpty,
      reason: 'manifest values missing from the Dart ABI table',
    );
    for (final name in manifest.keys) {
      expect(dart[name], manifest[name], reason: name);
    }
  }

  test('§1 version: ABI version 1 and the reserved invalid value 0', () {
    final manifest = nameValueTable(1, ['Name', 'Value']);
    expectSameTable(manifest, abiV1Version);
    expect(manifest['SAS_PAIRING_ABI_VERSION'], requiredAbiVersion);
    expect(requiredAbiVersion, 1);
  });

  test('§2 exports: exactly the 25 frozen exports, in manifest order', () {
    final table = manifestTable(sections, 2, ['#', 'Export', 'Fatal class']);
    uniqueRows([for (final row in table.rows) row.sublist(1)], 'export');
    final exports = [for (final row in table.rows) row[1]];
    expect([
      for (final row in table.rows) int.parse(row[0]),
    ], List<int>.generate(exports.length, (i) => i + 1));
    expect(exports, hasLength(25));
    expect(abiV1Exports, exports);
  });

  test('§3 statuses: the 48 frozen status values', () {
    final manifest = nameValueTable(3, ['Name', 'Value']);
    expect(manifest, hasLength(48));
    expectSameTable(manifest, abiV1Statuses);
    expect(
      abiV1Statuses.values.toSet(),
      hasLength(48),
      reason: 'no status value is reused',
    );
  });

  test('§4 integer namespaces: the 84 frozen values', () {
    final manifest = nameValueTable(4, ['Name', 'Type', 'Value']);
    expect(manifest, hasLength(84));
    expectSameTable(manifest, abiV1Namespaces);
  });

  test(
    '§5 handle invalid values and scalar constants: the 11 frozen values',
    () {
      final manifest = nameValueTable(5, ['Name', 'Type', 'Value']);
      expect(manifest, hasLength(11));
      expectSameTable(manifest, abiV1Scalars);
      expect(
        abiV1Scalars['SAS_PAIRING_SOCKET_INVALID'],
        -1,
        reason: 'UINTPTR_MAX',
      );
    },
  );

  test('§7 records: the six frozen record sizes', () {
    final rows = uniqueRows(
      manifestTable(sections, 7, ['Record', 'Size', 'Align']).rows,
      'record',
    );
    final manifest = {
      for (final entry in rows.entries) entry.key: int.parse(entry.value[1]),
    };
    expect(manifest, hasLength(6));
    expectSameTable(manifest, abiV1RecordSizes);
    expectSameTable(manifest, generatedRecordSizes);
  });

  test('§7 records: every field offset and size of the generated records', () {
    final table = manifestTable(sections, 7, [
      'Record',
      'Field',
      'Offset',
      'Size',
    ]);
    final seen = <String>{};
    for (final row in table.rows) {
      final key = '${row[0]}.${row[1]}';
      expect(seen.add(key), isTrue, reason: 'duplicate manifest field $key');
      expect(
        recordFieldWriters[row[0]]?.containsKey(row[1]),
        isTrue,
        reason: 'manifest field $key has no generated field',
      );
      final measured = measureField(row[0], row[1]);
      expect(measured.offset, int.parse(row[2]), reason: '$key offset');
      expect(measured.size, int.parse(row[3]), reason: '$key size');
    }
    final generated = {
      for (final record in recordFieldWriters.entries)
        for (final field in record.value.keys) '${record.key}.$field',
    };
    expect(
      generated.difference(seen),
      isEmpty,
      reason: 'generated fields missing from the manifest',
    );
  });
}
