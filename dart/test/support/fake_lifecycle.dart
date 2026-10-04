// A deterministic fake of the private native lifecycle and network services, with the ceremony
// service of fake_ceremony.dart sharing its call log: no native library is loaded. Every call is
// recorded in one log; each operation answers from its script queue first and otherwise succeeds
// (new nonzero handles, READY with 10 remaining, attach adopting the socket, an empty drive).
import 'dart:typed_data';

import 'package:sas_pairing/src/lifecycle.dart';
import 'package:sas_pairing/src/native/abi_v1.dart';
import 'package:sas_pairing/src/native/native_bootstrap.dart';
import 'package:sas_pairing/src/native/native_lifecycle_api.dart';
import 'package:sas_pairing/src/native/native_network_api.dart';
import 'package:sas_pairing/src/native/native_process_context.dart';

import 'fake_ceremony.dart';

int status(String name) => abiV1Statuses[name]!;
int namespaceValue(String name) => abiV1Namespaces[name]!;

final int ok = status('SAS_PAIRING_OK');
final int fatal = status('SAS_PAIRING_FATAL');

/// One recorded native call: the operation and its integer arguments.
final class FakeCall {
  FakeCall(this.operation, this.arguments);
  final String operation;
  final List<int> arguments;

  @override
  String toString() => '$operation(${arguments.join(', ')})';
}

/// One scripted answer: a status and, for creations and status queries, the outputs.
final class Scripted {
  Scripted(this.status, {this.handle = 0, this.state = 0, this.remaining = 0});
  final int status;
  final int handle;
  final int state;
  final int remaining;
}

final class FakeLifecycleApi implements NativeLifecycleApi, NativeNetworkApi {
  final List<FakeCall> calls = [];

  /// The fake ceremony service, recording into the same [calls] log.
  late final FakeNativeCeremonyApi ceremony = FakeNativeCeremonyApi(calls);

  /// Copies of the scope bytes each authorityRegister call received.
  final List<Uint8List> scopes = [];

  final Map<String, List<Scripted>> _script = {};
  int _nextHandle = 1000;

  /// Queues [answer] for the next call of [operation].
  void script(String operation, Scripted answer) =>
      _script.putIfAbsent(operation, () => []).add(answer);

  int count(String operation) =>
      calls.where((call) => call.operation == operation).length;

  List<String> get operations => [for (final call in calls) call.operation];

  Scripted? _next(String operation, List<int> arguments) {
    calls.add(FakeCall(operation, arguments));
    final queue = _script[operation];
    if (queue == null || queue.isEmpty) return null;
    return queue.removeAt(0);
  }

  NativeHandleResult _create(String operation, List<int> arguments) {
    final answer = _next(operation, arguments);
    if (answer == null) return (status: ok, handle: _nextHandle++);
    return (status: answer.status, handle: answer.handle);
  }

  int _cleanup(String operation, List<int> arguments) =>
      _next(operation, arguments)?.status ?? ok;

  @override
  NativeHandleResult runtimeCreate() => _create('runtimeCreate', const []);

  @override
  int runtimeDestroy(int runtime) => _cleanup('runtimeDestroy', [runtime]);

  @override
  NativeHandleResult authorityRegister(int runtime, Uint8List scope) {
    scopes.add(Uint8List.fromList(scope));
    return _create('authorityRegister', [runtime]);
  }

  @override
  int authorityRelease(int runtime, int authority) =>
      _cleanup('authorityRelease', [runtime, authority]);

  @override
  NativeAuthorityStatusResult authorityStatus(int runtime, int authority) {
    final answer = _next('authorityStatus', [runtime, authority]);
    if (answer == null) {
      return (
        status: ok,
        state: namespaceValue('SAS_PAIRING_AUTHORITY_READY'),
        remaining: 10,
      );
    }
    return (
      status: answer.status,
      state: answer.state,
      remaining: answer.remaining,
    );
  }

  @override
  NativeHandleResult hostCreate(int runtime, int authority) =>
      _create('hostCreate', [runtime, authority]);

  @override
  int hostDestroy(int runtime, int host) =>
      _cleanup('hostDestroy', [runtime, host]);

  // --- Network (P8.3) ---------------------------------------------------------------------

  /// Copies of the Bootstrap fields each attach received: (local, expected or null).
  final List<(NativeBootstrapBytes, NativeBootstrapBytes?)> attachedBootstraps =
      [];

  final List<FakeAttach> _attaches = [];
  final List<FakeDrive> _drives = [];

  /// Queues the next attach answer.
  void scriptAttach(FakeAttach answer) => _attaches.add(answer);

  /// Queues the next drive or recheck answer (one queue, shared, in call order).
  void scriptDrive(FakeDrive answer) => _drives.add(answer);

  static NativeBootstrapBytes _copy(NativeBootstrapBytes bootstrap) => (
    applicationIdentity: Uint8List.fromList(bootstrap.applicationIdentity),
    keyAlgorithm: Uint8List.fromList(bootstrap.keyAlgorithm),
    publicKey: Uint8List.fromList(bootstrap.publicKey),
    sharedContext: Uint8List.fromList(bootstrap.sharedContext),
  );

  @override
  NativeAttachResult attachWindowsListener(
    int runtime,
    int host,
    int socket,
    NativeBootstrapBytes local,
    NativeBootstrapBytes? expected,
  ) {
    calls.add(FakeCall('attachWindowsListener', [runtime, host, socket]));
    attachedBootstraps.add((
      _copy(local),
      expected == null ? null : _copy(expected),
    ));
    if (_attaches.isEmpty) return (status: ok, socketAfterCall: socketInvalid);
    final answer = _attaches.removeAt(0);
    return (
      status: answer.status,
      socketAfterCall: answer.adopted ? socketInvalid : (answer.slot ?? socket),
    );
  }

  @override
  int detachListener(int runtime, int host) =>
      _cleanup('detachListener', [runtime, host]);

  NativeDriveResult _drive(String operation, int runtime, int host) {
    calls.add(FakeCall(operation, [runtime, host]));
    if (_drives.isEmpty) {
      return (status: ok, count: 0, failure: ok, events: const []);
    }
    final answer = _drives.removeAt(0);
    return (
      status: answer.status,
      count: answer.count ?? answer.events.length,
      failure: answer.failure,
      events: answer.status == ok ? answer.events : const [],
    );
  }

  @override
  NativeDriveResult drive(int runtime, int host) =>
      _drive('drive', runtime, host);

  @override
  NativeDriveResult recheckAfterResume(int runtime, int host) =>
      _drive('recheckAfterResume', runtime, host);

  @override
  int connectionClose(int runtime, int host, int connection) =>
      _cleanup('connectionClose', [runtime, host, connection]);
}

final int socketInvalid = abiV1Scalars['SAS_PAIRING_SOCKET_INVALID']!;

/// One scripted attach answer: a status, and the slot after the call (`adopted`: INVALID;
/// otherwise [slot], defaulting to the offered socket).
final class FakeAttach {
  FakeAttach(this.status, {this.adopted = false, this.slot});
  final int status;
  final bool adopted;
  final int? slot;
}

/// One scripted drive or recheck answer. [count] defaults to the number of [events].
final class FakeDrive {
  FakeDrive({int? status, this.events = const [], int? failure, this.count})
    : status = status ?? ok,
      failure = failure ?? ok;
  final int status;
  final List<NativeEventRecord> events;
  final int failure;
  final int? count;
}

/// A fresh fake process context and its fake service.
(NativeProcessContext, FakeLifecycleApi) fakeContext() {
  final api = FakeLifecycleApi();
  return (NativeProcessContext(api, api, api.ceremony), api);
}

/// A runtime over a fresh fake context.
(SasPairingRuntime, FakeLifecycleApi, NativeProcessContext) fakeRuntime() {
  final (context, api) = fakeContext();
  return (createRuntime(context), api, context);
}

Uint8List bytes(List<int> values) => Uint8List.fromList(values);
