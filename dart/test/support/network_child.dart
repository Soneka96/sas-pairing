// A fresh OS process for one real-native P8.3 network scenario on Windows (run by
// native_artifact_test.dart). This process has exactly one isolate, which is its one native
// owner (P8-D-001 N). Prints one `RESULT <json>` line.
//
//   dart run test/support/network_child.dart windows-attach-detach <artifact>
//   dart run test/support/network_child.dart windows-accept <artifact>
//   dart run test/support/network_child.dart windows-reattach <artifact>
//
// The listening sockets come from the test-only WinSock harness. Ownership rule under test: the
// harness closes a socket only while its token is NOT transferred; once transferred, the native
// library owns it and the harness never touches it again.
import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:sas_pairing/sas_pairing.dart';

import 'winsock.dart';

final List<Map<String, Object?>> steps = [];

void record(String step, [Map<String, Object?> data = const {}]) =>
    steps.add({'step': step, ...data});

/// The Bootstrap the core's own ABI listener tests accept (core/src/abi/tests/listener.rs
/// `local_view`): application `p7-listener-application`, key algorithm `x25519`, a 32-byte key
/// of 7s, and an empty shared context.
SasPairingBootstrap validBootstrap() => SasPairingBootstrap(
  applicationIdentity: Uint8List.fromList(
    utf8.encode('p7-listener-application'),
  ),
  keyAlgorithm: Uint8List.fromList(utf8.encode('x25519')),
  publicKey: Uint8List.fromList(List.filled(32, 7)),
  sharedContext: Uint8List(0),
);

/// The same, with the uppercase key algorithm the core refuses (`invalid_view` there).
SasPairingBootstrap invalidBootstrap() => SasPairingBootstrap(
  applicationIdentity: Uint8List.fromList(
    utf8.encode('p7-listener-application'),
  ),
  keyAlgorithm: Uint8List.fromList(utf8.encode('X25519')),
  publicKey: Uint8List.fromList(List.filled(32, 7)),
  sharedContext: Uint8List(0),
);

/// A unique, non-text authority scope for this process.
Uint8List scope(String tag) => Uint8List.fromList([
  ...utf8.encode('sas-pairing-dart-p8.3-$tag-$pid-'),
  0x00,
  0x80,
  0xFF,
]);

/// The native status of a failing [action], or null if it succeeded.
int? failure(void Function() action) {
  try {
    action();
    return null;
  } on SasPairingNativeException catch (e) {
    return e.statusCode;
  }
}

/// One harness socket and its transfer token, closed by the harness only while untransferred.
final class Offered {
  Offered(this.winsock) : listener = winsock.listenLoopback() {
    token = SasPairingWindowsListenerSocket.fromNativeSocket(listener.socket);
  }

  final TestWinSock winsock;
  final TestListener listener;
  late final SasPairingWindowsListenerSocket token;
  bool closedByHarness = false;

  int get port => listener.port;

  /// The caller-side cleanup: close only a socket the caller still owns.
  void release() {
    if (!token.isTransferred && !closedByHarness) {
      winsock.close(listener.socket);
      closedByHarness = true;
    }
  }
}

/// Drives [host] up to [attempts] times (yielding to the event loop between calls) until an
/// event satisfies [until]; returns every event seen. Bounded: never an infinite loop.
Future<List<SasPairingEvent>> driveUntil(
  SasPairingHost host,
  bool Function(SasPairingEvent event) until, {
  int attempts = 60,
}) async {
  final seen = <SasPairingEvent>[];
  for (var i = 0; i < attempts; i++) {
    final batch = host.drive();
    if (batch.failure != null) {
      throw StateError('owner loop failed: ${batch.failure}');
    }
    seen.addAll(batch.events);
    if (batch.events.any(until)) return seen;
    await Future<void>.delayed(const Duration(milliseconds: 20));
  }
  throw StateError(
    'no matching event after $attempts drives: ${seen.map((e) => e.kind.name).toList()}',
  );
}

Future<void> attachDetach(String artifact) async {
  final winsock = TestWinSock.open();
  final runtime = SasPairingRuntime.create(nativeLibraryPath: artifact);
  final offered = <Offered>[];
  try {
    final authority = runtime.registerAuthority(scope('attach'));
    final host = authority.createHost();
    record('host', {'state': host.networkState.name});
    record('drive before attach', {'failure': failure(host.drive)});

    // A pre-adoption refusal: the socket stays the caller's, and the harness closes it.
    final refused = Offered(winsock);
    offered.add(refused);
    record('invalid bootstrap', {
      'failure': failure(
        () => host.attachWindowsListener(
          listener: refused.token,
          local: invalidBootstrap(),
        ),
      ),
      'transferred': refused.token.isTransferred,
      'state': host.networkState.name,
    });
    refused.release();
    record('invalid bootstrap socket closed by caller', {
      'closedByHarness': refused.closedByHarness,
    });

    final l1 = Offered(winsock);
    offered.add(l1);
    host.attachWindowsListener(listener: l1.token, local: validBootstrap());
    record('attached', {
      'transferred': l1.token.isTransferred,
      'state': host.networkState.name,
    });

    final second = Offered(winsock);
    offered.add(second);
    record('second attach', {
      'failure': failure(
        () => host.attachWindowsListener(
          listener: second.token,
          local: validBootstrap(),
        ),
      ),
      'transferred': second.token.isTransferred,
      'state': host.networkState.name,
    });
    second.release();

    final watch = Stopwatch()..start();
    final batch = host.drive();
    watch.stop();
    record('one drive without a client', {
      'events': batch.events.length,
      'failure': batch.failure?.statusCode,
      'elapsedMs': watch.elapsedMilliseconds,
      'state': host.networkState.name,
    });
    final resumed = host.recheckAfterResume();
    record('recheck', {
      'events': resumed.events.length,
      'failure': resumed.failure?.statusCode,
    });

    host.detachListener();
    record('detached', {
      'state': host.networkState.name,
      'hostClosed': host.isClosed,
      'authorityClosed': authority.isClosed,
      'authority': status(authority),
    });
    record('drive after detach', {'failure': failure(host.drive)});
    host.close();
    record('host closed', {'state': host.networkState.name});
  } finally {
    for (final o in offered) {
      o.release();
    }
    runtime.close();
  }
  record('done', {
    'transferred': [for (final o in offered) o.token.isTransferred],
    'closedByHarness': [for (final o in offered) o.closedByHarness],
  });
}

Map<String, Object?> status(SasPairingAuthority authority) {
  final s = authority.queryStatus();
  return {'state': s.state.name, 'remaining': s.remainingOpportunities};
}

Future<void> accept(String artifact) async {
  final winsock = TestWinSock.open();
  final runtime = SasPairingRuntime.create(nativeLibraryPath: artifact);
  final l1 = Offered(winsock);
  Socket? client;
  try {
    final authority = runtime.registerAuthority(scope('accept'));
    final host = authority.createHost();
    host.attachWindowsListener(listener: l1.token, local: validBootstrap());
    client = await Socket.connect(InternetAddress.loopbackIPv4, l1.port);
    final acceptedEvents = await driveUntil(
      host,
      (e) => e.kind == SasPairingEventKind.connectionAccepted,
    );
    final acceptedEvent = acceptedEvents.firstWhere(
      (e) => e.kind == SasPairingEventKind.connectionAccepted,
    );
    final connection = acceptedEvent.connection!;
    record('accepted', {
      'closed': connection.isClosed,
      'acceptedEvents': acceptedEvents
          .where((e) => e.kind == SasPairingEventKind.connectionAccepted)
          .length,
      'state': host.networkState.name,
    });

    client.destroy();
    final later = await driveUntil(
      host,
      (e) => e.kind == SasPairingEventKind.connectionClosed,
    );
    final closedEvent = later.firstWhere(
      (e) => e.kind == SasPairingEventKind.connectionClosed,
    );
    record('closed by peer', {
      'sameObject': identical(closedEvent.connection, connection),
      'everyLaterEventSameObject': later
          .where((e) => e.connection != null)
          .every((e) => identical(e.connection, connection)),
      'closed': connection.isClosed,
      'reason': closedEvent.reason.name,
      'kinds': [for (final e in later) e.kind.name],
    });
    connection.close(); // already closed: no native call, no exception
    host.detachListener();
    record('detached', {'state': host.networkState.name});
  } finally {
    client?.destroy();
    l1.release();
    runtime.close();
  }
  record('done', {
    'transferred': l1.token.isTransferred,
    'closedByHarness': l1.closedByHarness,
  });
}

Future<void> reattach(String artifact) async {
  final winsock = TestWinSock.open();
  final runtime = SasPairingRuntime.create(nativeLibraryPath: artifact);
  final l1 = Offered(winsock);
  final l2 = Offered(winsock);
  final clients = <Socket>[];
  try {
    final authority = runtime.registerAuthority(scope('reattach'));
    final host = authority.createHost();
    final before = status(authority);

    host.attachWindowsListener(listener: l1.token, local: validBootstrap());
    clients.add(await Socket.connect(InternetAddress.loopbackIPv4, l1.port));
    final c1 =
        (await driveUntil(
              host,
              (e) => e.kind == SasPairingEventKind.connectionAccepted,
            ))
            .firstWhere((e) => e.kind == SasPairingEventKind.connectionAccepted)
            .connection!;
    record('L1 accepted', {
      'state': host.networkState.name,
      'c1Closed': c1.isClosed,
    });

    host.detachListener();
    record('L1 detached', {
      'state': host.networkState.name,
      'c1Closed': c1.isClosed,
      'l1Transferred': l1.token.isTransferred,
    });

    host.attachWindowsListener(listener: l2.token, local: validBootstrap());
    record('L2 attached', {
      'state': host.networkState.name,
      'l2Transferred': l2.token.isTransferred,
    });
    clients.add(await Socket.connect(InternetAddress.loopbackIPv4, l2.port));
    final c2 =
        (await driveUntil(
              host,
              (e) => e.kind == SasPairingEventKind.connectionAccepted,
            ))
            .firstWhere((e) => e.kind == SasPairingEventKind.connectionAccepted)
            .connection!;
    record('L2 accepted', {
      'distinct': !identical(c1, c2),
      'c1Closed': c1.isClosed,
      'c2Closed': c2.isClosed,
    });

    c2.close();
    record('c2 closed manually', {
      'c2Closed': c2.isClosed,
      'state': host.networkState.name,
    });
    c2.close(); // idempotent: no native call, no exception
    final after = status(authority);
    record('accounting', {'before': before, 'after': after});
    host.close();
    record('host closed', {'state': host.networkState.name});
  } finally {
    for (final client in clients) {
      client.destroy();
    }
    l1.release();
    l2.release();
    runtime.close();
  }
  record('done', {
    'transferred': [l1.token.isTransferred, l2.token.isTransferred],
    'closedByHarness': [l1.closedByHarness, l2.closedByHarness],
  });
}

Future<void> main(List<String> args) async {
  final artifact = args[1];
  switch (args[0]) {
    case 'windows-attach-detach':
      await attachDetach(artifact);
    case 'windows-accept':
      await accept(artifact);
    case 'windows-reattach':
      await reattach(artifact);
    default:
      throw ArgumentError('unknown scenario ${args[0]}');
  }
  stdout.writeln('RESULT ${jsonEncode(steps)}');
}
