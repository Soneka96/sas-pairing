// Repository files the consistency tests read, and a strict parser for the stable Markdown tables
// of the frozen ABI v1 manifest. Only table rows are parsed; prose is ignored.
import 'dart:io';

/// The package root (`dart/`): `dart test` runs from there.
final Directory packageRoot = Directory.current;

/// The repository root, one level above the package.
final Directory repositoryRoot = packageRoot.parent;

String readRepositoryFile(String relativePath) {
  final file = File('${repositoryRoot.path}/$relativePath');
  if (!file.existsSync()) {
    throw StateError('Missing repository file: $relativePath');
  }
  return file.readAsStringSync();
}

String readPackageFile(String relativePath) {
  final file = File('${packageRoot.path}/$relativePath');
  if (!file.existsSync()) {
    throw StateError('Missing package file: $relativePath');
  }
  return file.readAsStringSync();
}

const String manifestPath = 'docs/p7-native-abi/abi-v1-manifest.md';
const String headerPath = 'core/include/sas_pairing.h';
const String generatedBindingsPath =
    'lib/src/native/generated/sas_pairing_bindings.g.dart';

/// One Markdown table: its header cells and its data rows (cells trimmed, backticks removed).
final class ManifestTable {
  ManifestTable(this.header, this.rows);
  final List<String> header;
  final List<List<String>> rows;
}

/// The tables of each numbered `## N. Title` section of the manifest, by section number.
Map<int, List<ManifestTable>> parseManifestTables(String markdown) {
  final sections = <int, List<ManifestTable>>{};
  int? section;
  List<String>? pending;
  void flush() {
    final lines = pending;
    pending = null;
    if (lines == null || section == null) return;
    if (lines.length < 2 || !RegExp(r'^\|[\s:|-]+\|$').hasMatch(lines[1])) {
      throw FormatException('Malformed table in manifest section $section');
    }
    final header = _cells(lines.first);
    final rows = [for (final line in lines.skip(2)) _cells(line)];
    for (final row in rows) {
      if (row.length != header.length) {
        throw FormatException(
          'Manifest section $section: row "${row.join(' | ')}" has '
          '${row.length} cells, expected ${header.length}',
        );
      }
    }
    sections.putIfAbsent(section, () => []).add(ManifestTable(header, rows));
  }

  for (final line in markdown.split('\n').map((l) => l.trimRight())) {
    final heading = RegExp(r'^## (\d+)\. ').firstMatch(line);
    if (heading != null) {
      flush();
      section = int.parse(heading.group(1)!);
      continue;
    }
    if (line.startsWith('|')) {
      (pending ??= []).add(line);
    } else {
      flush();
    }
  }
  flush();
  return sections;
}

List<String> _cells(String line) {
  final inner = line.substring(1, line.length - 1);
  return [for (final cell in inner.split('|')) cell.trim().replaceAll('`', '')];
}

/// The single table of [section] whose header is exactly [header].
ManifestTable manifestTable(
  Map<int, List<ManifestTable>> sections,
  int section,
  List<String> header,
) {
  final matches = [
    for (final table in sections[section] ?? const <ManifestTable>[])
      if (table.header.join('|') == header.join('|')) table,
  ];
  if (matches.length != 1) {
    throw StateError(
      'Manifest section $section: expected exactly one table with header '
      '$header, found ${matches.length}',
    );
  }
  return matches.single;
}

/// [rows] keyed by their first cell; a duplicate key is an error.
Map<String, List<String>> uniqueRows(List<List<String>> rows, String what) {
  final byKey = <String, List<String>>{};
  for (final row in rows) {
    if (byKey.containsKey(row.first)) {
      throw StateError('Duplicate $what row in the manifest: ${row.first}');
    }
    byKey[row.first] = row;
  }
  return byKey;
}

/// A manifest numeric cell: decimal, `0x` hexadecimal, or `UINTPTR_MAX`, which on the supported
/// 64-bit target is the all-ones pattern that a Dart `int` reads as -1.
int manifestValue(String cell) {
  if (cell == 'UINTPTR_MAX') return -1;
  if (cell.startsWith('0x')) return int.parse(cell.substring(2), radix: 16);
  return int.parse(cell);
}
