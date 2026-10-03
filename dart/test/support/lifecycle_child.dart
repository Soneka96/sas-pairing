// A fresh OS process for one real-native lifecycle scenario (run by native_artifact_test.dart).
// This process has exactly one isolate, which is its one native owner (P8-D-001 N); the test
// process never registers an authority itself. Prints one `RESULT <json>` line.
//
//   dart run test/support/lifecycle_child.dart windows-lifecycle <artifact>
//   dart run test/support/lifecycle_child.dart linux-lifecycle <artifact>
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:sas_pairing/sas_pairing.dart';
import 'package:sas_pairing/src/native/native_library_loader.dart';

final List<Map<String, Object?>> steps = [];

void record(String step, [Map<String, Object?> data = const {}]) =>
    steps.add({'step': step, ...data});

Map<String, Object?> status(SasPairingAuthority authority) {
  final status = authority.queryStatus();
  return {
    'state': status.state.name,
    'remaining': status.remainingOpportunities,
  };
}

/// The native status of a failing [action], or null if it succeeded.
int? failure(void Function() action) {
  try {
    action();
    return null;
  } on SasPairingNativeException catch (e) {
    return e.statusCode;
  }
}

/// A unique, non-text test scope: a literal, this process ID, and the bytes 00 80 FF.
Uint8List scope(String tag) => Uint8List.fromList([
  ...utf8.encode('sas-pairing-dart-p8.2-$tag-$pid-'),
  0x00,
  0x80,
  0xFF,
]);

void windowsLifecycle(String artifact) {
  final runtime = SasPairingRuntime.create(nativeLibraryPath: artifact);
  final image = NativeLibraryLoader.instance;
  record('runtime', {'closed': runtime.isClosed});
  record('second live runtime', {
    'failure': failure(
      () => SasPairingRuntime.create(nativeLibraryPath: artifact),
    ),
  });

  final authority = runtime.registerAuthority(scope('a'));
  record('authority', status(authority));
  record('same scope while registered', {
    'failure': failure(() => runtime.registerAuthority(scope('a'))),
  });
  record('empty scope', {
    'failure': failure(() => runtime.registerAuthority(Uint8List(0))),
  });

  final hostA = authority.createHost();
  final hostB = authority.createHost();
  record('hosts', {'a': hostA.isClosed, 'b': hostB.isClosed});
  hostA.close();
  record('host A closed', {
    'a': hostA.isClosed,
    'b': hostB.isClosed,
    'authorityClosed': authority.isClosed,
    ...status(authority),
  });
  authority.close();
  record('authority closed', {
    'authority': authority.isClosed,
    'b': hostB.isClosed,
    'runtime': runtime.isClosed,
    'queryAfterClose': () {
      try {
        authority.queryStatus();
        return 'no exception';
      } on SasPairingClosedException catch (e) {
        return '${e.objectKind}.${e.operation}';
      }
    }(),
  });

  // Re-registration continues the same process session under a new object.
  final again = runtime.registerAuthority(scope('a'));
  final other = runtime.registerAuthority(scope('b'));
  final hosts = [again.createHost(), other.createHost(), other.createHost()];
  record('re-registered', status(again));
  runtime.close();
  record('runtime closed with live children', {
    'runtime': runtime.isClosed,
    'authorities': [again.isClosed, other.isClosed],
    'hosts': [for (final h in hosts) h.isClosed],
  });
  runtime.close();
  again.close();
  for (final h in hosts) {
    h.close();
  }

  // A new runtime over the same loaded image: the path is not read again.
  final next = SasPairingRuntime.create(nativeLibraryPath: '/not/read/again');
  final reRegistered = next.registerAuthority(scope('a'));
  record('recreated runtime', {
    'sameImage': identical(NativeLibraryLoader.instance, image),
    ...status(reRegistered),
  });
  next.close();
  record('done', {
    'closed': [next.isClosed, reRegistered.isClosed],
  });
}

void linuxLifecycle(String artifact) {
  final runtime = SasPairingRuntime.create(nativeLibraryPath: artifact);
  record('runtime', {'closed': runtime.isClosed});
  record('register', {
    'failure': failure(() => runtime.registerAuthority(scope('linux'))),
  });
  record('empty scope', {
    'failure': failure(() => runtime.registerAuthority(Uint8List(0))),
  });
  runtime.close();
  record('runtime closed', {'closed': runtime.isClosed});
  final next = SasPairingRuntime.create(nativeLibraryPath: artifact);
  record('recreated runtime', {
    'register': failure(() => next.registerAuthority(scope('linux'))),
  });
  next.close();
  record('done', {'closed': next.isClosed});
}

void main(List<String> args) {
  final artifact = args[1];
  switch (args[0]) {
    case 'windows-lifecycle':
      windowsLifecycle(artifact);
    case 'linux-lifecycle':
      linuxLifecycle(artifact);
    default:
      throw ArgumentError('unknown scenario ${args[0]}');
  }
  stdout.writeln('RESULT ${jsonEncode(steps)}');
}
