// A fresh OS process for the real-native P8.4 two-endpoint ceremony on Windows (run by
// native_artifact_test.dart). This process has exactly one isolate, which is its one native
// owner (P8-D-001 N). Prints one `RESULT <json>` line.
//
//   dart run test/support/ceremony_child.dart windows-happy-path <artifact>
//
// Topology (one runtime, two independent endpoints, both driven ONLY through the public
// package:sas_pairing API):
//
//   Runtime
//     ├── Authority A → Host A → Listener A → Connection A   (protocol Initiator)
//     └── Authority B → Host B → Listener B → Connection B   (protocol Responder)
//
// The test-only relay below opens one loopback TCP client to each listener and copies every
// byte it reads from one socket to the other, unchanged: it never parses, builds, inspects, or
// alters a protocol frame and computes nothing. Every protocol frame is produced and written by
// the native library inside a public drive. TCP direction is not protocol role: both native
// endpoints accepted their connection, and endpoint A starts the Initiator on its accepted one.
import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:sas_pairing/sas_pairing.dart';

import 'winsock.dart';

final List<Map<String, Object?>> steps = [];

void record(String step, [Map<String, Object?> data = const {}]) =>
    steps.add({'step': step, ...data});

Uint8List text(String value) => Uint8List.fromList(utf8.encode(value));

const String sharedContext = 'p8.4 two-sided shared context';

/// Endpoint A's trusted-local configuration (Initiator).
SasPairingBootstrap bootstrapA() => SasPairingBootstrap(
  applicationIdentity: text('p8.4 two-sided endpoint A (Initiator)'),
  keyAlgorithm: text('p84.test-key'),
  publicKey: Uint8List.fromList(List.filled(32, 0xA8)),
  sharedContext: text(sharedContext),
);

/// Endpoint B's trusted-local configuration (Responder).
SasPairingBootstrap bootstrapB() => SasPairingBootstrap(
  applicationIdentity: text('p8.4 two-sided endpoint B (Responder)'),
  keyAlgorithm: text('p84.test-key'),
  publicKey: Uint8List.fromList(List.filled(32, 0xB8)),
  sharedContext: text(sharedContext),
);

/// A unique, non-text authority scope for this process.
Uint8List scope(String tag) => Uint8List.fromList([
  ...utf8.encode('sas-pairing-dart-p8.4-$tag-$pid-'),
  0x00,
  0x80,
  0xFF,
]);

String hex(Uint8List bytes) =>
    bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

/// The native status of a failing [action], or null if it succeeded.
int? failure(void Function() action) {
  try {
    action();
    return null;
  } on SasPairingNativeException catch (e) {
    return e.statusCode;
  }
}

Map<String, Object?> status(SasPairingAuthority authority) {
  final s = authority.queryStatus();
  return {'state': s.state.name, 'remaining': s.remainingOpportunities};
}

Map<String, Object?> describe(SasPairingLocalAction action) => {
  'event': action.event.name,
  'writePending': action.writePending,
  'deadlineKind': action.deadlineKind.name,
  'hasRun': action.run != null,
};

String describeEvent(SasPairingEvent e) => [
  e.kind.name,
  e.stepKind.name,
  e.protocolEvent.name,
  if (e.writePending) 'writePending',
  if (e.run != null) 'run',
  if (e.hasResult) 'result',
].join('/');

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

  void release() {
    if (!token.isTransferred && !closedByHarness) {
      winsock.close(listener.socket);
      closedByHarness = true;
    }
  }
}

/// TEST-ONLY byte-transparent relay between two loopback TCP clients: every byte read from one
/// socket is written to the other unchanged. It counts bytes and nothing else.
final class Relay {
  Relay._(this._a, this._b) {
    _a.listen((data) {
      aToB += data.length;
      _b.add(data);
    }, onError: (Object _) {});
    _b.listen((data) {
      bToA += data.length;
      _a.add(data);
    }, onError: (Object _) {});
  }

  static Future<Relay> connect(int portA, int portB) async {
    final a = await Socket.connect(InternetAddress.loopbackIPv4, portA);
    final b = await Socket.connect(InternetAddress.loopbackIPv4, portB);
    a.setOption(SocketOption.tcpNoDelay, true);
    b.setOption(SocketOption.tcpNoDelay, true);
    return Relay._(a, b);
  }

  final Socket _a;
  final Socket _b;
  int aToB = 0;
  int bToA = 0;

  void close() {
    _a.destroy();
    _b.destroy();
  }
}

/// Two hosts driven alternately (each drive is one bounded native call), yielding to the event
/// loop between calls so that the relay can copy bytes. Every event is kept per host, in order.
final class Pump {
  Pump(this.a, this.b);

  final SasPairingHost a;
  final SasPairingHost b;
  final List<SasPairingEvent> eventsA = [];
  final List<SasPairingEvent> eventsB = [];

  List<SasPairingEvent> _drive(
    SasPairingHost host,
    List<SasPairingEvent> into,
  ) {
    final batch = host.drive();
    if (batch.failure != null) {
      throw StateError('owner loop failed: ${batch.failure}');
    }
    into.addAll(batch.events);
    return batch.events;
  }

  /// Drives both hosts until [until] finds a matching event among those produced from now on;
  /// returns that event. Bounded: never an endless loop.
  Future<SasPairingEvent> until(
    String what,
    SasPairingEvent? Function(List<SasPairingEvent> a, List<SasPairingEvent> b)
    until, {
    int rounds = 60,
  }) async {
    final fromA = eventsA.length;
    final fromB = eventsB.length;
    for (var i = 0; i < rounds; i++) {
      _drive(a, eventsA);
      await Future<void>.delayed(const Duration(milliseconds: 5));
      _drive(b, eventsB);
      await Future<void>.delayed(const Duration(milliseconds: 5));
      final found = until(eventsA.sublist(fromA), eventsB.sublist(fromB));
      if (found != null) return found;
    }
    throw StateError(
      'no "$what" after $rounds rounds: A ${eventsA.sublist(fromA).map(describeEvent).toList()} '
      'B ${eventsB.sublist(fromB).map(describeEvent).toList()}',
    );
  }

  /// One drive of [host] alone: the events it produced.
  List<SasPairingEvent> once(SasPairingHost host) =>
      _drive(host, identical(host, a) ? eventsA : eventsB);
}

SasPairingEvent? firstWhere(
  List<SasPairingEvent> events,
  bool Function(SasPairingEvent e) test,
) {
  for (final e in events) {
    if (test(e)) return e;
  }
  return null;
}

bool isInbound(SasPairingEvent e, SasPairingProtocolEvent protocol) =>
    e.kind == SasPairingEventKind.connectionStep &&
    e.stepKind == SasPairingStepKind.inbound &&
    e.protocolEvent == protocol;

Map<String, Object?> presentationData(SasPairingSasPresentation? p) => {
  'available': p != null,
  if (p != null) 'decimal': p.decimal,
  if (p != null) 'identity': hex(p.ceremonyIdentity.bytes),
};

Future<void> happyPath(String artifact) async {
  final winsock = TestWinSock.open();
  final runtime = SasPairingRuntime.create(nativeLibraryPath: artifact);
  final la = Offered(winsock);
  final lb = Offered(winsock);
  Relay? relay;
  try {
    final authorityA = runtime.registerAuthority(scope('a'));
    final authorityB = runtime.registerAuthority(scope('b'));
    final hostA = authorityA.createHost();
    final hostB = authorityB.createHost();
    hostA.attachWindowsListener(
      listener: la.token,
      local: bootstrapA(),
      expected: bootstrapB(),
    );
    hostB.attachWindowsListener(
      listener: lb.token,
      local: bootstrapB(),
      expected: bootstrapA(),
    );
    record('attached', {
      'a': hostA.networkState.name,
      'b': hostB.networkState.name,
      'authorityA': status(authorityA),
      'authorityB': status(authorityB),
    });

    relay = await Relay.connect(la.port, lb.port);
    final pump = Pump(hostA, hostB);
    bool accepted(SasPairingEvent e) =>
        e.kind == SasPairingEventKind.connectionAccepted;
    await pump.until(
      'both accepted',
      (a, b) =>
          firstWhere(a, accepted) != null && firstWhere(b, accepted) != null
          ? a.first
          : null,
    );
    final connectionA = firstWhere(pump.eventsA, accepted)!.connection!;
    final connectionB = firstWhere(pump.eventsB, accepted)!.connection!;
    record('accepted', {'a': connectionA.isClosed, 'b': connectionB.isClosed});

    // 1. Endpoint A starts the Initiator explicitly; nothing else happens.
    final start = connectionA.startInitiator(
      local: bootstrapA(),
      expected: bootstrapB(),
    );
    final runA = start.run!;
    record('A start', {...describe(start), 'runEnded': runA.isEnded});
    // A second start while START is retained: native WRITE_PENDING, and nothing starts.
    record('A second start before drive', {
      'failure': failure(
        () => connectionA.startInitiator(
          local: bootstrapA(),
          expected: bootstrapB(),
        ),
      ),
    });

    // 2. The Responder run surfaces on B through a drive event; ACCEPT is retained there.
    final startAccepted = await pump.until(
      'START_ACCEPTED at B',
      (a, b) => firstWhere(
        b,
        (e) => isInbound(e, SasPairingProtocolEvent.startAccepted),
      ),
    );
    final runB = startAccepted.run!;
    record('B start accepted', {
      'sameConnection': identical(startAccepted.connection, connectionB),
      'hasTrackedRun': startAccepted.hasTrackedRun,
      'writePending': startAccepted.writePending,
      'requestIdLength': startAccepted.requestId.length,
    });

    // 3. ACCEPT reaches A and names A's run: the same object the start returned.
    final acceptAtA = await pump.until(
      'ACCEPT at A',
      (a, b) =>
          firstWhere(a, (e) => isInbound(e, SasPairingProtocolEvent.accept)),
    );
    record('A accept', {
      'sameRun': identical(acceptAtA.run, runA),
      'requestIdsEqual':
          hex(acceptAtA.requestId) == hex(startAccepted.requestId),
    });

    // 4. A: explicit authorization (spends nothing), then the explicit spending exposure.
    final authorizedA = runA.authorizeExposure();
    record('A authorize', {
      ...describe(authorizedA),
      'sameRun': identical(authorizedA.run, runA),
      'authority': status(authorityA),
    });
    final exposedA = runA.exposeKey();
    record('A expose', {
      ...describe(exposedA),
      'sameRun': identical(exposedA.run, runA),
      'authority': status(authorityA),
    });
    // Read-only presentation while A's key is retained: reaches native (no SAS yet).
    record('A presentation while key pending', {
      ...presentationData(runA.presentation()),
    });

    // 5. INITIATOR_KEY reaches B.
    final keyAtB = await pump.until(
      'INITIATOR_KEY at B',
      (a, b) => firstWhere(
        b,
        (e) => isInbound(e, SasPairingProtocolEvent.initiatorKey),
      ),
    );
    record('B initiator key', {'sameRun': identical(keyAtB.run, runB)});

    // 6. B: authorize and expose; its SAS is presentable while its key is still retained.
    final authorizedB = runB.authorizeExposure();
    final exposedB = runB.exposeKey();
    record('B authorize', describe(authorizedB));
    record('B expose', {
      ...describe(exposedB),
      'authority': status(authorityB),
    });
    final presentedB = runB.presentation();
    record('B presentation while key pending', presentationData(presentedB));

    // 7. RESPONDER_KEY reaches A; A's SAS is live.
    await pump.until(
      'RESPONDER_KEY at A',
      (a, b) => firstWhere(
        a,
        (e) => isInbound(e, SasPairingProtocolEvent.responderKey),
      ),
    );
    final presentedA = runA.presentation();
    record('A presentation', presentationData(presentedA));
    record('SAS comparison', {
      'decimalEqual': presentedA!.decimal == presentedB!.decimal,
      'identityEqual':
          presentedA.ceremonyIdentity == presentedB.ceremonyIdentity,
    });

    // 8. The test plays both users and explicitly chooses MATCH on A only after both SAS values
    //    were obtained. MATCH emits nothing.
    final approvedA = runA.approveSas(presentedA.ceremonyIdentity);
    record('A approve', describe(approvedA));
    record('after A approve: one drive of each host', {
      'a': pump.once(hostA).map(describeEvent).toList(),
      'b': pump.once(hostB).map(describeEvent).toList(),
      'aPresentation': presentationData(runA.presentation()),
    });

    // 9. A's BOOTSTRAP_MAC is a separate explicit step. A second mutating action before the
    //    drive is refused natively with WRITE_PENDING and does not happen; after the drive the
    //    retry reports the MAC as already emitted (it was produced exactly once).
    final macA = runA.emitBootstrapMac();
    record('A emit MAC', describe(macA));
    record('A second MAC before drive', {
      'failure': failure(runA.emitBootstrapMac),
    });
    await pump.until(
      'MAC written by A',
      (a, b) => firstWhere(
        a,
        (e) =>
            identical(e.connection, connectionA) &&
            e.stepKind == SasPairingStepKind.written,
      ),
    );
    record('A MAC retry after drive', describe(runA.emitBootstrapMac()));

    // 10. B: MATCH, then its own MAC.
    final approvedB = runB.approveSas(presentedB.ceremonyIdentity);
    record('B approve', describe(approvedB));
    final macB = runB.emitBootstrapMac();
    record('B emit MAC', describe(macB));

    // 11. Both MACs are authenticated by their peers.
    await pump.until('both MACs authenticated', (a, b) {
      bool mac(SasPairingEvent e) =>
          isInbound(e, SasPairingProtocolEvent.bootstrapMacAuthenticated);
      final atA = firstWhere(pump.eventsA, mac);
      final atB = firstWhere(pump.eventsB, mac);
      return atA != null && atB != null ? atA : null;
    });
    record('MACs authenticated', {
      'aSameRun': identical(
        firstWhere(
          pump.eventsA,
          (e) =>
              isInbound(e, SasPairingProtocolEvent.bootstrapMacAuthenticated),
        )!.run,
        runA,
      ),
      'bSameRun': identical(
        firstWhere(
          pump.eventsB,
          (e) =>
              isInbound(e, SasPairingProtocolEvent.bootstrapMacAuthenticated),
        )!.run,
        runB,
      ),
    });

    // With nothing retained on B, the Responder's INITIATOR_FINISH is refused by its role
    // (NOT_INITIATOR) and its run continues.
    record('B initiator finish', {
      'failure': failure(runB.emitInitiatorFinish),
      'runEnded': runB.isEnded,
    });

    // 12. Only the Initiator, explicitly, emits INITIATOR_FINISH. No final-ACK call exists: the
    //     native library writes the frames and confirms the final ACK itself.
    final finishA = runA.emitInitiatorFinish();
    record('A finish', describe(finishA));

    // 13. Drive until both local results are surfaced (result contents are P8.5 work).
    await pump.until(
      'both local results',
      (a, b) =>
          firstWhere(pump.eventsA, (e) => e.hasResult) != null &&
              firstWhere(pump.eventsB, (e) => e.hasResult) != null
          ? a.isEmpty
                ? b.first
                : a.first
          : null,
    );
    final resultA = firstWhere(pump.eventsA, (e) => e.hasResult)!;
    final resultB = firstWhere(pump.eventsB, (e) => e.hasResult)!;
    record('results', {
      'a': describeEvent(resultA),
      'b': describeEvent(resultB),
      'aResults': pump.eventsA.where((e) => e.hasResult).length,
      'bResults': pump.eventsB.where((e) => e.hasResult).length,
      'runAEnded': runA.isEnded,
      'runBEnded': runB.isEnded,
      'authorityA': status(authorityA),
      'authorityB': status(authorityB),
      'startAcceptedAtB': pump.eventsB
          .where((e) => isInbound(e, SasPairingProtocolEvent.startAccepted))
          .length,
      'relayAToB': relay.aToB,
      'relayBToA': relay.bToA,
    });
    record('ended run refused locally', {
      'refused': () {
        try {
          runA.emitInitiatorFinish();
          return false;
        } on SasPairingRunEndedException {
          return true;
        }
      }(),
    });

    hostA.detachListener();
    hostB.detachListener();
    record('detached', {
      'a': hostA.networkState.name,
      'b': hostB.networkState.name,
      'connectionsClosed': connectionA.isClosed && connectionB.isClosed,
    });
  } finally {
    relay?.close();
    la.release();
    lb.release();
    runtime.close();
  }
  record('done', {
    'transferred': [la.token.isTransferred, lb.token.isTransferred],
    'closedByHarness': [la.closedByHarness, lb.closedByHarness],
  });
}

Future<void> main(List<String> args) async {
  final artifact = args[1];
  switch (args[0]) {
    case 'windows-happy-path':
      await happyPath(artifact);
    default:
      throw ArgumentError('unknown scenario ${args[0]}');
  }
  stdout.writeln('RESULT ${jsonEncode(steps)}');
}
