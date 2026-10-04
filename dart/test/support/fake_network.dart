// Raw drive-event records for the fake network service, built by frozen ABI v1 names (manifest
// §4), and a fake host with an attached listener. No native library is loaded.
import 'dart:typed_data';

import 'package:sas_pairing/sas_pairing.dart';
import 'package:sas_pairing/src/native/abi_v1.dart';
import 'package:sas_pairing/src/native/native_network_api.dart';
import 'package:sas_pairing/src/native/native_process_context.dart';

import 'fake_lifecycle.dart';

/// The value of a frozen namespace constant, by its name without the `SAS_PAIRING_` prefix.
int abi(String name) => abiV1Namespaces['SAS_PAIRING_$name']!;

final int writePendingFlag = abi('EVENT_FLAG_WRITE_PENDING');
final int runUntrackedFlag = abi('EVENT_FLAG_RUN_UNTRACKED');

/// A 64-byte request ID array holding [bytes] followed by zeros.
Uint8List requestIdArray(List<int> bytes) =>
    Uint8List(NativeEventRecord.requestIdCapacity)..setAll(0, bytes);

NativeEventRecord accepted(int connection) => NativeEventRecord(
  kind: abi('EVENT_CONNECTION_ACCEPTED'),
  connection: connection,
);

NativeEventRecord acceptRefused({String reason = 'RESOURCE_LIMITED'}) =>
    NativeEventRecord(
      kind: abi('EVENT_ACCEPT_REFUSED'),
      reason: abi('EVENT_REASON_$reason'),
    );

NativeEventRecord listenerDisabled({String reason = 'LISTENER_IO'}) =>
    NativeEventRecord(
      kind: abi('EVENT_LISTENER_DISABLED'),
      reason: abi('EVENT_REASON_$reason'),
    );

NativeEventRecord closed(int connection, {String reason = 'PEER_CLOSED'}) =>
    NativeEventRecord(
      kind: abi('EVENT_CONNECTION_CLOSED'),
      connection: connection,
      reason: abi('EVENT_REASON_$reason'),
    );

/// A `CONNECTION_STEP` of [connection]; names are frozen constant suffixes.
NativeEventRecord step(
  int connection, {
  String step = 'WRITTEN',
  String protocol = 'NONE',
  String reason = 'NONE',
  String deadline = 'NONE',
  String cancelState = 'NONE',
  String cancelReason = 'NONE',
  int flags = 0,
  int run = 0,
  int result = 0,
  List<int> requestId = const [],
  int? requestIdLength,
  int reserved = 0,
  Uint8List? requestIdBytes,
}) => NativeEventRecord(
  kind: abi('EVENT_CONNECTION_STEP'),
  connection: connection,
  stepKind: abi('STEP_$step'),
  protocolEvent: abi('PROTOCOL_EVENT_$protocol'),
  reason: abi('EVENT_REASON_$reason'),
  deadlineKind: abi('DEADLINE_$deadline'),
  cancelState: abi('CANCEL_STATE_$cancelState'),
  cancelReason: abi('CANCEL_REASON_$cancelReason'),
  flags: flags,
  run: run,
  result: result,
  requestIdLength: requestIdLength ?? requestId.length,
  reserved: reserved,
  requestIdBytes: requestIdBytes ?? requestIdArray(requestId),
);

/// An inbound step with a live tracked [run] under [requestId].
NativeEventRecord inbound(
  int connection, {
  required List<int> requestId,
  String protocol = 'START_ACCEPTED',
  int run = 0,
  int result = 0,
  int flags = 0,
}) => step(
  connection,
  step: 'INBOUND',
  protocol: protocol,
  requestId: requestId,
  run: run,
  result: result,
  flags: flags,
);

/// A Bootstrap over arbitrary non-text bytes.
SasPairingBootstrap testBootstrap([int seed = 1]) => SasPairingBootstrap(
  applicationIdentity: Uint8List.fromList([seed, 0x00, 0x80, 0xFF]),
  keyAlgorithm: Uint8List.fromList([0x61, seed]),
  publicKey: Uint8List.fromList(List.filled(32, seed)),
  sharedContext: Uint8List(0),
);

/// A listener token over a fake socket value.
SasPairingWindowsListenerSocket token([int socket = 0x1234]) =>
    SasPairingWindowsListenerSocket.fromNativeSocket(socket);

/// A fake runtime, authority, and host whose listener is attached (fake handles: runtime 1000,
/// authority 1001, host 1002).
final class FakeNetworkHost {
  FakeNetworkHost._(
    this.runtime,
    this.authority,
    this.host,
    this.api,
    this.context,
  );

  factory FakeNetworkHost({bool attach = true}) {
    final (runtime, api, context) = fakeRuntime();
    final authority = runtime.registerAuthority(bytes([1]));
    final host = authority.createHost();
    if (attach) {
      host.attachWindowsListener(listener: token(), local: testBootstrap());
    }
    return FakeNetworkHost._(runtime, authority, host, api, context);
  }

  final SasPairingRuntime runtime;
  final SasPairingAuthority authority;
  final SasPairingHost host;
  final FakeLifecycleApi api;
  final NativeProcessContext context;

  /// Drives once over [events] (and [failure]), returning the batch.
  SasPairingDriveBatch drive(List<NativeEventRecord> events, {int? failure}) {
    api.scriptDrive(FakeDrive(events: events, failure: failure));
    return host.drive();
  }

  /// Accepts one connection with native handle [handle] and returns its wrapper.
  SasPairingConnection accept(int handle) =>
      drive([accepted(handle)]).events.single.connection!;
}
