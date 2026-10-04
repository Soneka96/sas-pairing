// A deterministic fake of the private native result service (P8-D-005 rule 1): no native library
// is loaded. Every call is recorded in the shared fake call log with its integer arguments. Info
// and copy answer from their script queues first and otherwise from the stored source data of
// the result handle (or the default data), exactly as the frozen exports would: info OK with the
// lengths, copy BUFFER_TOO_SMALL below the length and OK with the bytes otherwise. Destroy
// answers from its queue, otherwise OK.
import 'dart:typed_data';

import 'package:sas_pairing/src/native/abi_v1.dart';
import 'package:sas_pairing/src/native/native_result_api.dart';

import 'fake_lifecycle.dart';

/// The value of a frozen result-field constant, by its name without `SAS_PAIRING_RESULT_FIELD_`.
int resultField(String name) =>
    abiV1Namespaces['SAS_PAIRING_RESULT_FIELD_$name']!;

/// The value of a frozen role constant, by its name without `SAS_PAIRING_ROLE_`.
int role(String name) => abiV1Namespaces['SAS_PAIRING_ROLE_$name']!;

final int requestIdField = resultField('REQUEST_ID');
final int peerBootstrapField = resultField('AUTHENTICATED_PEER_BOOTSTRAP');
final int sharedContextField = resultField('AUTHENTICATED_SHARED_CONTEXT');
final int profileIdentifierField = resultField('PROFILE_IDENTIFIER');

/// The source data of one fake native result.
final class FakeResultData {
  FakeResultData({
    List<int>? identity,
    int? peerRole,
    this.profileVersion = 1,
    List<int>? requestId,
    List<int>? peerBootstrap,
    List<int>? sharedContext,
    List<int>? profileIdentifier,
  }) : identity = Uint8List.fromList(identity ?? List.filled(32, 0xA5)),
       peerRole = peerRole ?? role('RESPONDER'),
       requestId = Uint8List.fromList(
         requestId ?? List.generate(16, (i) => 0x10 + i),
       ),
       peerBootstrap = Uint8List.fromList(
         peerBootstrap ?? [0x00, 0x80, 0xFF, 0x20, 0x01, 0x07, 0x00],
       ),
       sharedContext = Uint8List.fromList(sharedContext ?? const []),
       profileIdentifier = Uint8List.fromList(
         profileIdentifier ??
             'sas-pairing-vodozemac-profile-draft-01'.codeUnits,
       );

  final Uint8List identity;
  final int peerRole;
  final int profileVersion;
  final Uint8List requestId;
  final Uint8List peerBootstrap;
  final Uint8List sharedContext;
  final Uint8List profileIdentifier;

  Uint8List bytesOf(int field) => switch (field) {
    _ when field == requestIdField => requestId,
    _ when field == peerBootstrapField => peerBootstrap,
    _ when field == sharedContextField => sharedContext,
    _ when field == profileIdentifierField => profileIdentifier,
    _ => throw ArgumentError.value(field, 'field'),
  };

  NativeResultInfoRecord info() => NativeResultInfoRecord(
    ceremonyIdentity: Uint8List.fromList(identity),
    peerRole: peerRole,
    profileVersion: profileVersion,
    requestIdLength: requestId.length,
    peerBootstrapLength: peerBootstrap.length,
    sharedContextLength: sharedContext.length,
    profileIdentifierLength: profileIdentifier.length,
  );
}

final class FakeNativeResultApi implements NativeResultApi {
  FakeNativeResultApi(this.calls);

  /// The shared call log of the fake process context.
  final List<FakeCall> calls;

  /// The source data of each result handle; others use [defaultData].
  final Map<int, FakeResultData> data = {};
  FakeResultData defaultData = FakeResultData();

  final List<NativeResultInfoResult> _infos = [];
  final Map<int, List<NativeResultCopyResult>> _copies = {};
  final List<int> _destroys = [];

  /// Queues the next info answer.
  void scriptInfo(int status, [NativeResultInfoRecord? info]) =>
      _infos.add((status: status, info: info));

  /// Queues the next copy answer of [field].
  void scriptCopy(
    int field,
    int status, {
    int required = 0,
    Uint8List? bytes,
  }) => _copies.putIfAbsent(field, () => []).add((
    status: status,
    required: required,
    bytes: bytes,
  ));

  /// Queues the next destroy status.
  void scriptDestroy(int status) => _destroys.add(status);

  FakeResultData _of(int result) => data[result] ?? defaultData;

  @override
  NativeResultInfoResult resultInfo(int runtime, int result) {
    calls.add(FakeCall('resultInfo', [runtime, result]));
    if (_infos.isNotEmpty) return _infos.removeAt(0);
    return (status: ok, info: _of(result).info());
  }

  @override
  NativeResultCopyResult resultCopy(
    int runtime,
    int result,
    int field,
    int capacity,
  ) {
    calls.add(FakeCall('resultCopy', [runtime, result, field, capacity]));
    final queue = _copies[field];
    if (queue != null && queue.isNotEmpty) return queue.removeAt(0);
    final source = _of(result).bytesOf(field);
    if (capacity < source.length) {
      return (
        status: status('SAS_PAIRING_BUFFER_TOO_SMALL'),
        required: source.length,
        bytes: null,
      );
    }
    return (
      status: ok,
      required: source.length,
      bytes: Uint8List.fromList(source),
    );
  }

  @override
  int resultDestroy(int runtime, int result) {
    calls.add(FakeCall('resultDestroy', [runtime, result]));
    return _destroys.isEmpty ? ok : _destroys.removeAt(0);
  }
}
