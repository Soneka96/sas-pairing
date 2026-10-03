/// The private native lifecycle service (P8-D-002 L): the seven lifecycle exports of the frozen
/// ABI v1, with every piece of FFI memory handled here.
///
/// Private to the package. This is not a second declaration layer: it calls only the generated
/// bindings. It returns raw status values and raw output values without interpreting them; the
/// lifecycle wrappers decide what they mean. Every native allocation is made for one
/// synchronous call and freed before it returns.
library;

import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import 'generated/sas_pairing_bindings.g.dart';

/// A creation result: the raw status and the raw output handle (meaningful only on OK).
typedef NativeHandleResult = ({int status, int handle});

/// An authority status result: the raw status and both raw outputs (meaningful only on OK).
typedef NativeAuthorityStatusResult = ({int status, int state, int remaining});

/// The lifecycle exports the wrappers use. Production: [FfiNativeLifecycleApi]; tests supply a
/// deterministic fake.
abstract interface class NativeLifecycleApi {
  /// `sas_pairing_runtime_create`.
  NativeHandleResult runtimeCreate();

  /// `sas_pairing_runtime_destroy` (cleanup).
  int runtimeDestroy(int runtime);

  /// `sas_pairing_authority_register` with the exact bytes of [scope] (pointer plus length).
  NativeHandleResult authorityRegister(int runtime, Uint8List scope);

  /// `sas_pairing_authority_release` (cleanup).
  int authorityRelease(int runtime, int authority);

  /// `sas_pairing_authority_status`.
  NativeAuthorityStatusResult authorityStatus(int runtime, int authority);

  /// `sas_pairing_host_create`.
  NativeHandleResult hostCreate(int runtime, int authority);

  /// `sas_pairing_host_destroy` (cleanup).
  int hostDestroy(int runtime, int host);
}

/// The production service over the one generated binding object of the loaded image.
final class FfiNativeLifecycleApi implements NativeLifecycleApi {
  FfiNativeLifecycleApi(this._bindings);

  final SasPairingNativeBindings _bindings;

  @override
  NativeHandleResult runtimeCreate() => using((arena) {
    final out = arena<sas_pairing_runtime_t>();
    final status = _bindings.sas_pairing_runtime_create(out);
    return (status: status, handle: out.value);
  });

  @override
  int runtimeDestroy(int runtime) =>
      _bindings.sas_pairing_runtime_destroy(runtime);

  @override
  NativeHandleResult authorityRegister(int runtime, Uint8List scope) => using((
    arena,
  ) {
    // Exact bytes, pointer plus length: no encoding, no terminator. An empty scope goes
    // through as a null pointer with length 0, and the native core decides.
    final Pointer<Uint8> bytes;
    if (scope.isEmpty) {
      bytes = nullptr;
    } else {
      bytes = arena<Uint8>(scope.length);
      bytes.asTypedList(scope.length).setAll(0, scope);
    }
    final out = arena<sas_pairing_authority_t>();
    final status = _bindings.sas_pairing_authority_register(
      runtime,
      bytes,
      scope.length,
      out,
    );
    return (status: status, handle: out.value);
  });

  @override
  int authorityRelease(int runtime, int authority) =>
      _bindings.sas_pairing_authority_release(runtime, authority);

  @override
  NativeAuthorityStatusResult authorityStatus(int runtime, int authority) =>
      using((arena) {
        final state = arena<sas_pairing_authority_state_t>();
        final remaining = arena<Uint32>();
        final status = _bindings.sas_pairing_authority_status(
          runtime,
          authority,
          state,
          remaining,
        );
        return (status: status, state: state.value, remaining: remaining.value);
      });

  @override
  NativeHandleResult hostCreate(int runtime, int authority) => using((arena) {
    final out = arena<sas_pairing_host_t>();
    final status = _bindings.sas_pairing_host_create(runtime, authority, out);
    return (status: status, handle: out.value);
  });

  @override
  int hostDestroy(int runtime, int host) =>
      _bindings.sas_pairing_host_destroy(runtime, host);
}
