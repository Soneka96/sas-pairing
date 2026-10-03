// A deterministic fake of the private native lifecycle service: no native library is loaded.
// Every call is recorded; each operation answers from its script queue first and otherwise
// succeeds (new nonzero handles, READY with 10 remaining).
import 'dart:typed_data';

import 'package:sas_pairing/src/lifecycle.dart';
import 'package:sas_pairing/src/native/abi_v1.dart';
import 'package:sas_pairing/src/native/native_lifecycle_api.dart';
import 'package:sas_pairing/src/native/native_process_context.dart';

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

final class FakeLifecycleApi implements NativeLifecycleApi {
  final List<FakeCall> calls = [];

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
}

/// A fresh fake process context and its fake service.
(NativeProcessContext, FakeLifecycleApi) fakeContext() {
  final api = FakeLifecycleApi();
  return (NativeProcessContext(api), api);
}

/// A runtime over a fresh fake context.
(SasPairingRuntime, FakeLifecycleApi, NativeProcessContext) fakeRuntime() {
  final (context, api) = fakeContext();
  return (createRuntime(context), api, context);
}

Uint8List bytes(List<int> values) => Uint8List.fromList(values);
