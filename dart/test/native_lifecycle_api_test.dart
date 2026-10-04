// P8.2 FFI marshalling of the private native lifecycle service (P8-D-002 J, L): the production
// FfiNativeLifecycleApi runs over the generated bindings, whose seven lifecycle symbols resolve to
// Dart callbacks that observe exactly what crossed the C boundary. No native library is loaded.
import 'dart:ffi';
import 'dart:typed_data';

import 'package:sas_pairing/src/native/generated/sas_pairing_bindings.g.dart';
import 'package:sas_pairing/src/native/native_lifecycle_api.dart';
import 'package:test/test.dart';

/// What one fake export call saw.
final class Seen {
  Seen(this.export, this.arguments, {this.scope, this.scopeAddress = -1});
  final String export;
  final List<int> arguments;
  final List<int>? scope;
  final int scopeAddress;
}

/// Fake C exports for the seven lifecycle functions.
final class FakeExports {
  final List<Seen> seen = [];
  final List<int> outputAddresses = [];
  final List<NativeCallable<Function>> _callables = [];

  int status = 0;
  int handle = 0;
  int state = 0;
  int remaining = 0;

  late final SasPairingNativeBindings bindings =
      SasPairingNativeBindings.fromLookup(
        <T extends NativeType>(String symbol) => _lookup(symbol).cast<T>(),
      );

  Pointer<NativeFunction<Function>> _keep<F extends Function>(
    NativeCallable<F> callable,
  ) {
    _callables.add(callable);
    return callable.nativeFunction;
  }

  Pointer<NativeFunction<Function>> _lookup(String symbol) => switch (symbol) {
    'sas_pairing_runtime_create' => _keep(
      NativeCallable<Int32 Function(Pointer<Uint64>)>.isolateLocal((
        Pointer<Uint64> out,
      ) {
        seen.add(Seen(symbol, const []));
        outputAddresses.add(out.address);
        out.value = handle;
        return status;
      }, exceptionalReturn: -1),
    ),
    'sas_pairing_runtime_destroy' => _keep(
      NativeCallable<Int32 Function(Uint64)>.isolateLocal((int runtime) {
        seen.add(Seen(symbol, [runtime]));
        return status;
      }, exceptionalReturn: -1),
    ),
    'sas_pairing_authority_register' => _keep(
      NativeCallable<
        Int32 Function(Uint64, Pointer<Uint8>, Size, Pointer<Uint64>)
      >.isolateLocal((
        int runtime,
        Pointer<Uint8> scope,
        int length,
        Pointer<Uint64> out,
      ) {
        seen.add(
          Seen(
            symbol,
            [runtime, length],
            scope: scope == nullptr ? null : List.of(scope.asTypedList(length)),
            scopeAddress: scope.address,
          ),
        );
        outputAddresses.add(out.address);
        out.value = handle;
        return status;
      }, exceptionalReturn: -1),
    ),
    'sas_pairing_authority_release' => _keep(
      NativeCallable<Int32 Function(Uint64, Uint64)>.isolateLocal((
        int runtime,
        int authority,
      ) {
        seen.add(Seen(symbol, [runtime, authority]));
        return status;
      }, exceptionalReturn: -1),
    ),
    'sas_pairing_authority_status' => _keep(
      NativeCallable<
        Int32 Function(Uint64, Uint64, Pointer<Uint32>, Pointer<Uint32>)
      >.isolateLocal((
        int runtime,
        int authority,
        Pointer<Uint32> outState,
        Pointer<Uint32> outRemaining,
      ) {
        seen.add(Seen(symbol, [runtime, authority]));
        outputAddresses
          ..add(outState.address)
          ..add(outRemaining.address);
        outState.value = state;
        outRemaining.value = remaining;
        return status;
      }, exceptionalReturn: -1),
    ),
    'sas_pairing_host_create' => _keep(
      NativeCallable<
        Int32 Function(Uint64, Uint64, Pointer<Uint64>)
      >.isolateLocal((int runtime, int authority, Pointer<Uint64> out) {
        seen.add(Seen(symbol, [runtime, authority]));
        outputAddresses.add(out.address);
        out.value = handle;
        return status;
      }, exceptionalReturn: -1),
    ),
    'sas_pairing_host_destroy' => _keep(
      NativeCallable<Int32 Function(Uint64, Uint64)>.isolateLocal((
        int runtime,
        int host,
      ) {
        seen.add(Seen(symbol, [runtime, host]));
        return status;
      }, exceptionalReturn: -1),
    ),
    _ => throw StateError('unexpected lookup of $symbol'),
  };

  void close() {
    for (final callable in _callables) {
      callable.close();
    }
  }
}

void main() {
  late FakeExports exports;
  late FfiNativeLifecycleApi api;

  setUp(() {
    exports = FakeExports();
    api = FfiNativeLifecycleApi(exports.bindings);
  });
  tearDown(() => exports.close());

  // One output slot per call. Slots are freed when their call returns, so a later call may
  // reuse an address; distinctness only matters within one call.
  void expectAlignedOutputs(int count) {
    expect(exports.outputAddresses, hasLength(count));
    for (final address in exports.outputAddresses) {
      expect(address, isNot(0));
      expect(address % 8, 0, reason: 'aligned for the slot type');
    }
  }

  test(
    'runtime_create: one typed output slot, raw status and handle returned',
    () {
      exports
        ..status = 0
        ..handle = 41;
      expect(api.runtimeCreate(), (status: 0, handle: 41));
      exports
        ..status = 3
        ..handle = 0;
      expect(api.runtimeCreate(), (status: 3, handle: 0));
      expectAlignedOutputs(2);
    },
  );

  test(
    'authority_register: the exact scope bytes, including 00 80 FF, pointer plus length',
    () {
      exports.handle = 7;
      final scope = Uint8List.fromList([0x00, 0x80, 0xFF, 0x00, 0x41, 0x00]);
      expect(api.authorityRegister(5, scope), (status: 0, handle: 7));
      final seen = exports.seen.single;
      expect(seen.arguments, [
        5,
        6,
      ], reason: 'runtime and the full length, past every NUL');
      expect(seen.scope, [0x00, 0x80, 0xFF, 0x00, 0x41, 0x00]);
      expect(seen.scopeAddress, isNot(0));
      expect(scope, [
        0x00,
        0x80,
        0xFF,
        0x00,
        0x41,
        0x00,
      ], reason: 'caller buffer untouched');
      expectAlignedOutputs(1);
      final out = exports.outputAddresses.single;
      expect(
        out >= seen.scopeAddress + 6 || out + 8 <= seen.scopeAddress,
        isTrue,
        reason: 'the output slot does not overlap the scope copy',
      );
    },
  );

  test(
    'authority_register: a scope that is not text or UTF-8 crosses unchanged',
    () {
      final scope = Uint8List.fromList([
        for (var i = 0; i < 1024; i++) (i * 37 + 11) & 0xFF,
      ]);
      api.authorityRegister(1, scope);
      expect(exports.seen.single.scope, orderedEquals(scope));
      expect(exports.seen.single.arguments, [1, 1024]);
    },
  );

  test(
    'authority_register: an empty scope is a null pointer with length 0',
    () {
      exports.status = 100;
      expect(api.authorityRegister(9, Uint8List(0)), (status: 100, handle: 0));
      final seen = exports.seen.single;
      expect(seen.scopeAddress, 0);
      expect(seen.scope, isNull);
      expect(seen.arguments, [9, 0]);
    },
  );

  test(
    'authority_status: two distinct typed slots, raw values returned uninterpreted',
    () {
      exports
        ..state = 1
        ..remaining = 10;
      expect(api.authorityStatus(2, 3), (status: 0, state: 1, remaining: 10));
      exports
        ..state = 0xFFFFFFFF
        ..remaining = 0xFFFFFFFF;
      expect(api.authorityStatus(2, 3), (
        status: 0,
        state: 0xFFFFFFFF,
        remaining: 0xFFFFFFFF,
      ));
      expect(exports.seen.map((s) => s.arguments), [
        [2, 3],
        [2, 3],
      ]);
      expect(exports.outputAddresses, hasLength(4));
      for (final address in exports.outputAddresses) {
        expect(address % 4, 0);
        expect(address, isNot(0));
      }
      expect(exports.outputAddresses[0], isNot(exports.outputAddresses[1]));
    },
  );

  test('host_create: 64-bit handles cross as their exact bit patterns', () {
    const high = -0x7FFFFFFFFFFFFFFF - 1; // 0x8000000000000000 as uint64
    exports.handle = -1; // 0xFFFFFFFFFFFFFFFF as uint64
    expect(api.hostCreate(high, 0x7FFFFFFFFFFFFFFF), (status: 0, handle: -1));
    expect(exports.seen.single.arguments, [high, 0x7FFFFFFFFFFFFFFF]);
    expectAlignedOutputs(1);
  });

  test('cleanup exports pass their handles and return the raw status', () {
    exports.status = 104;
    expect(api.hostDestroy(1, 2), 104);
    expect(api.authorityRelease(3, 4), 104);
    expect(api.runtimeDestroy(5), 104);
    expect(exports.seen.map((s) => '${s.export}${s.arguments}'), [
      'sas_pairing_host_destroy[1, 2]',
      'sas_pairing_authority_release[3, 4]',
      'sas_pairing_runtime_destroy[5]',
    ]);
  });
}
