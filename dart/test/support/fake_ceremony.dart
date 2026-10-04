// A deterministic fake of the private native ceremony service (P8-D-004): no native library is
// loaded. Every call is recorded in the shared fake call log with its integer arguments; each
// operation answers from its script queue first and otherwise succeeds with the frozen ordinary
// outcome of that export (a start returns a new run handle from 7000 up).
import 'dart:typed_data';

import 'package:sas_pairing/src/native/abi_v1.dart';
import 'package:sas_pairing/src/native/native_bootstrap.dart';
import 'package:sas_pairing/src/native/native_ceremony_api.dart';

import 'fake_lifecycle.dart';

/// The value of a frozen local-event constant, by its name without `SAS_PAIRING_LOCAL_EVENT_`.
int localEvent(String name) =>
    abiV1Namespaces['SAS_PAIRING_LOCAL_EVENT_$name']!;

final int actionWritePending =
    abiV1Namespaces['SAS_PAIRING_ACTION_FLAG_WRITE_PENDING']!;

/// One raw action record, built by frozen names.
NativeActionRecord actionRecord(
  String event, {
  int flags = 0,
  int run = 0,
  String deadline = 'NONE',
  int reserved = 0,
}) => NativeActionRecord(
  event: localEvent(event),
  deadlineKind: abiV1Namespaces['SAS_PAIRING_DEADLINE_$deadline']!,
  flags: flags,
  reserved: reserved,
  run: run,
);

/// The fourteen ASCII bytes of [display].
Uint8List ascii14(String display) => Uint8List.fromList(display.codeUnits);

/// A live presentation record: [identity] (32 bytes) and [display].
NativePresentationRecord livePresentation(
  List<int> identity, {
  String display = '1234 5678 9012',
}) => NativePresentationRecord(
  available: 1,
  ceremonyIdentity: Uint8List.fromList(identity),
  decimal: ascii14(display),
);

/// A 32-byte identity filled with [value].
List<int> identityOf(int value) => List.filled(32, value);

/// One scripted ceremony answer: a status and, for `SAS_PAIRING_OK`, the record; [record] may
/// also compute the record from the input run handle.
final class FakeCeremonyAnswer {
  FakeCeremonyAnswer.action(this.status, [NativeActionRecord? action])
    : _action = action,
      _presentation = null;
  FakeCeremonyAnswer.presentation(
    this.status, [
    NativePresentationRecord? presentation,
  ]) : _action = null,
       _presentation = presentation;

  final int status;
  final NativeActionRecord? _action;
  final NativePresentationRecord? _presentation;
}

final class FakeNativeCeremonyApi implements NativeCeremonyApi {
  FakeNativeCeremonyApi(this.calls);

  /// The shared call log of the fake process context.
  final List<FakeCall> calls;

  /// Copies of the Bootstrap fields each start received: (local, expected or null).
  final List<(NativeBootstrapBytes, NativeBootstrapBytes?)> startedBootstraps =
      [];

  /// Copies of the identity bytes each decision received, in call order.
  final List<Uint8List> identities = [];

  final Map<String, List<FakeCeremonyAnswer>> _script = {};
  int _nextRun = 7000;

  /// Queues [answer] for the next call of [operation].
  void script(String operation, FakeCeremonyAnswer answer) =>
      _script.putIfAbsent(operation, () => []).add(answer);

  /// Queues a nonzero (or zero) [status] with no record for the next [operation].
  void scriptStatus(String operation, int status) => script(
    operation,
    operation == 'presentation'
        ? FakeCeremonyAnswer.presentation(status)
        : FakeCeremonyAnswer.action(status),
  );

  /// Queues `SAS_PAIRING_OK` with [record] for the next [operation].
  void scriptAction(String operation, NativeActionRecord record) =>
      script(operation, FakeCeremonyAnswer.action(ok, record));

  /// Queues `SAS_PAIRING_OK` with [record] for the next presentation.
  void scriptPresentation(NativePresentationRecord record) =>
      script('presentation', FakeCeremonyAnswer.presentation(ok, record));

  FakeCeremonyAnswer? _next(String operation, List<int> arguments) {
    calls.add(FakeCall(operation, arguments));
    final queue = _script[operation];
    if (queue == null || queue.isEmpty) return null;
    return queue.removeAt(0);
  }

  NativeActionResult _act(
    String operation,
    List<int> arguments,
    NativeActionRecord Function() ordinary,
  ) {
    final answer = _next(operation, arguments);
    if (answer == null) return (status: ok, action: ordinary());
    return (
      status: answer.status,
      action: answer.status == ok ? answer._action : null,
    );
  }

  static NativeBootstrapBytes _copy(NativeBootstrapBytes bootstrap) => (
    applicationIdentity: Uint8List.fromList(bootstrap.applicationIdentity),
    keyAlgorithm: Uint8List.fromList(bootstrap.keyAlgorithm),
    publicKey: Uint8List.fromList(bootstrap.publicKey),
    sharedContext: Uint8List.fromList(bootstrap.sharedContext),
  );

  @override
  NativeActionResult startInitiator(
    int runtime,
    int host,
    int connection,
    NativeBootstrapBytes local,
    NativeBootstrapBytes? expected,
  ) {
    startedBootstraps.add((
      _copy(local),
      expected == null ? null : _copy(expected),
    ));
    return _act(
      'startInitiator',
      [runtime, host, connection],
      () => actionRecord(
        'INITIATOR_STARTED',
        flags: actionWritePending,
        run: _nextRun++,
      ),
    );
  }

  @override
  NativeActionResult authorizeExposure(
    int runtime,
    int host,
    int connection,
    int run,
  ) => _act('authorizeExposure', [
    runtime,
    host,
    connection,
    run,
  ], () => actionRecord('EXPOSURE_AUTHORIZED', run: run));

  @override
  NativeActionResult exposeKey(
    int runtime,
    int host,
    int connection,
    int run,
  ) => _act('exposeKey', [
    runtime,
    host,
    connection,
    run,
  ], () => actionRecord('KEY_EXPOSED', flags: actionWritePending, run: run));

  @override
  NativePresentationResult presentation(
    int runtime,
    int host,
    int connection,
    int run,
  ) {
    final answer = _next('presentation', [runtime, host, connection, run]);
    if (answer == null) {
      return (status: ok, presentation: NativePresentationRecord(available: 0));
    }
    return (
      status: answer.status,
      presentation: answer.status == ok ? answer._presentation : null,
    );
  }

  NativeActionResult _decide(
    String operation,
    int runtime,
    int host,
    int connection,
    int run,
    Uint8List identity,
    NativeActionRecord Function() ordinary,
  ) {
    identities.add(Uint8List.fromList(identity));
    return _act(operation, [runtime, host, connection, run], ordinary);
  }

  @override
  NativeActionResult approveSas(
    int runtime,
    int host,
    int connection,
    int run,
    Uint8List ceremonyIdentity,
  ) => _decide(
    'approveSas',
    runtime,
    host,
    connection,
    run,
    ceremonyIdentity,
    () => actionRecord('SAS_APPROVED', run: run),
  );

  @override
  NativeActionResult emitBootstrapMac(
    int runtime,
    int host,
    int connection,
    int run,
  ) => _act(
    'emitBootstrapMac',
    [runtime, host, connection, run],
    () => actionRecord(
      'BOOTSTRAP_MAC_EMITTED',
      flags: actionWritePending,
      run: run,
    ),
  );

  @override
  NativeActionResult rejectSas(
    int runtime,
    int host,
    int connection,
    int run,
    Uint8List ceremonyIdentity,
  ) => _decide(
    'rejectSas',
    runtime,
    host,
    connection,
    run,
    ceremonyIdentity,
    () => actionRecord('SAS_REJECTED', flags: actionWritePending),
  );

  @override
  NativeActionResult cancelSas(
    int runtime,
    int host,
    int connection,
    int run,
    Uint8List ceremonyIdentity,
  ) => _decide(
    'cancelSas',
    runtime,
    host,
    connection,
    run,
    ceremonyIdentity,
    () => actionRecord('SAS_CANCELLED', flags: actionWritePending),
  );

  @override
  NativeActionResult emitInitiatorFinish(
    int runtime,
    int host,
    int connection,
    int run,
  ) => _act(
    'emitInitiatorFinish',
    [runtime, host, connection, run],
    () => actionRecord(
      'INITIATOR_FINISH_EMITTED',
      flags: actionWritePending,
      run: run,
    ),
  );
}
