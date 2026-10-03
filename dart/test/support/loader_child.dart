// A fresh process for one real-loader scenario (run by native_artifact_test.dart): the process
// loader can never be reset, so each scenario that needs an uninitialized loader gets its own
// OS process. Prints one `RESULT <json>` line.
//
//   dart run test/support/loader_child.dart missing-then-valid <artifact>
//   dart run test/support/loader_child.dart foreign-then-valid <artifact>
import 'dart:convert';
import 'dart:io';

import 'package:sas_pairing/src/native/native_library_loader.dart';

Map<String, Object?> attempt(String path) {
  try {
    final loaded = NativeLibraryLoader.initialize(libraryPath: path);
    return {'ready': true, 'abiVersion': loaded.abiVersion};
  } on NativeLibraryInitializationException catch (e) {
    return {
      'ready': false,
      'failure': e.failure.name,
      'processRestartRequired': e.processRestartRequired,
      'message': e.message,
      'identity': identityHashCode(e),
    };
  }
}

/// A real native library that is not sas-pairing: loading it succeeds, so an image is owned.
String foreignLibrary() {
  if (Platform.isWindows) {
    return '${Platform.environment['SystemRoot']}\\System32\\kernel32.dll';
  }
  for (final line in File('/proc/self/maps').readAsLinesSync()) {
    final path = line.split(' ').last;
    if (RegExp(r'/libc\.so\.6$').hasMatch(path)) return path;
  }
  throw StateError('no libc.so.6 mapped in this process');
}

void main(List<String> args) {
  final artifact = args[1];
  final steps = switch (args[0]) {
    'missing-then-valid' => [
      attempt(
        '${File(artifact).parent.path}${Platform.pathSeparator}missing_library.bin',
      ),
      attempt(artifact),
    ],
    'foreign-then-valid' => [attempt(foreignLibrary()), attempt(artifact)],
    final other => throw ArgumentError('unknown scenario $other'),
  };
  stdout.writeln('RESULT ${jsonEncode(steps)}');
}
