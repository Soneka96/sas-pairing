/// The public Bootstrap value (P8-D-003 C).
library;

import 'dart:typed_data';

/// One immutable Bootstrap configuration: exactly four byte strings, passed to the native core
/// as they are.
///
/// The bytes are arbitrary: they are not text, may contain `0x00`, and are never encoded,
/// terminated, normalized, or parsed in Dart. Each field is copied when the value is created, so
/// later changes to the caller's lists do not affect it, and every getter returns an
/// unmodifiable view (writing through it, its buffer, or a view of its buffer throws).
///
/// Dart does not validate a Bootstrap: field bounds, the key-algorithm alphabet, and the
/// canonical frame bound belong to the native core, which refuses an invalid configuration with
/// `SasPairingStatus.invalidBootstrap` (thrown as a `SasPairingNativeException` by the operation
/// that uses it).
final class SasPairingBootstrap {
  /// A Bootstrap over copies of the four exact byte fields.
  SasPairingBootstrap({
    required Uint8List applicationIdentity,
    required Uint8List keyAlgorithm,
    required Uint8List publicKey,
    required Uint8List sharedContext,
  }) : _applicationIdentity = _freeze(applicationIdentity),
       _keyAlgorithm = _freeze(keyAlgorithm),
       _publicKey = _freeze(publicKey),
       _sharedContext = _freeze(sharedContext);

  final Uint8List _applicationIdentity;
  final Uint8List _keyAlgorithm;
  final Uint8List _publicKey;
  final Uint8List _sharedContext;

  /// The application identity bytes.
  Uint8List get applicationIdentity => _applicationIdentity;

  /// The key algorithm bytes.
  Uint8List get keyAlgorithm => _keyAlgorithm;

  /// The public key bytes.
  Uint8List get publicKey => _publicKey;

  /// The shared context bytes (may be empty).
  Uint8List get sharedContext => _sharedContext;

  static Uint8List _freeze(Uint8List bytes) =>
      Uint8List.fromList(bytes).asUnmodifiableView();
}
