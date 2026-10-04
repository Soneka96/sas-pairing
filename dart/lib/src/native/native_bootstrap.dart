/// The one private native Bootstrap marshaller (P8-D-003 C, P8-D-004 rule 8), shared by listener
/// attach and the local Initiator start.
///
/// Private to the package. It builds one `sas_pairing_bootstrap_view_t` of four
/// `sas_pairing_bytes_view_t` from exact byte copies: an empty field is a null pointer with
/// length 0, any other field an exact copy in temporary native memory owned by the caller's
/// arena and freed when that one synchronous call returns. No encoding, terminator, semantic
/// validation, or retained pointer: the native core alone decides whether a Bootstrap is valid.
library;

import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import '../bootstrap.dart';
import 'generated/sas_pairing_bindings.g.dart';

/// The four exact byte fields of one Bootstrap configuration, in ABI order.
typedef NativeBootstrapBytes = ({
  Uint8List applicationIdentity,
  Uint8List keyAlgorithm,
  Uint8List publicKey,
  Uint8List sharedContext,
});

/// The exact bytes of [bootstrap], unchanged.
NativeBootstrapBytes nativeBootstrapBytes(SasPairingBootstrap bootstrap) => (
  applicationIdentity: bootstrap.applicationIdentity,
  keyAlgorithm: bootstrap.keyAlgorithm,
  publicKey: bootstrap.publicKey,
  sharedContext: bootstrap.sharedContext,
);

/// One Bootstrap view over exact copies of the four fields, valid until [arena] is released.
Pointer<sas_pairing_bootstrap_view_t> nativeBootstrapView(
  Arena arena,
  NativeBootstrapBytes bootstrap,
) {
  final view = arena<sas_pairing_bootstrap_view_t>();
  _bytes(arena, view.ref.application_identity, bootstrap.applicationIdentity);
  _bytes(arena, view.ref.key_algorithm, bootstrap.keyAlgorithm);
  _bytes(arena, view.ref.public_key, bootstrap.publicKey);
  _bytes(arena, view.ref.shared_context, bootstrap.sharedContext);
  return view;
}

/// Exact bytes, pointer plus length: an empty field is a null pointer with length 0, any other
/// field an exact copy. No encoding, no terminator.
void _bytes(Arena arena, sas_pairing_bytes_view_t view, Uint8List bytes) {
  if (bytes.isEmpty) {
    view
      ..data = nullptr
      ..len = 0;
    return;
  }
  final copy = arena<Uint8>(bytes.length);
  copy.asTypedList(bytes.length).setAll(0, bytes);
  view
    ..data = copy
    ..len = bytes.length;
}
