// P8.3 Bootstrap value (P8-D-003 C): four arbitrary byte fields, defensively copied, exposed only
// as unmodifiable views, never converted to text, and never validated in Dart.
import 'dart:typed_data';

import 'package:sas_pairing/sas_pairing.dart';
import 'package:test/test.dart';

void main() {
  Uint8List b(List<int> values) => Uint8List.fromList(values);

  test('keeps the exact bytes, including 00, 80, and FF', () {
    final bootstrap = SasPairingBootstrap(
      applicationIdentity: b([0x00, 0x80, 0xFF]),
      keyAlgorithm: b([0xFF, 0x00]),
      publicKey: b([0x80]),
      sharedContext: b([]),
    );
    expect(bootstrap.applicationIdentity, [0x00, 0x80, 0xFF]);
    expect(bootstrap.keyAlgorithm, [0xFF, 0x00]);
    expect(bootstrap.publicKey, [0x80]);
    expect(bootstrap.sharedContext, isEmpty);
  });

  test('later changes to the caller\'s lists do not change it', () {
    final identity = b([1, 2, 3]);
    final algorithm = b([4]);
    final key = b(List.filled(32, 7));
    final context = b([0x00, 0x80, 0xFF]);
    final bootstrap = SasPairingBootstrap(
      applicationIdentity: identity,
      keyAlgorithm: algorithm,
      publicKey: key,
      sharedContext: context,
    );
    identity[0] = 0xEE;
    algorithm[0] = 0xEE;
    key.fillRange(0, 32, 0xEE);
    context[2] = 0x00;
    expect(bootstrap.applicationIdentity, [1, 2, 3]);
    expect(bootstrap.keyAlgorithm, [4]);
    expect(bootstrap.publicKey, List.filled(32, 7));
    expect(bootstrap.sharedContext, [0x00, 0x80, 0xFF]);
  });

  test(
    'getters cannot be used to change it: views, buffers, and byte data are read-only',
    () {
      final bootstrap = SasPairingBootstrap(
        applicationIdentity: b([1, 2]),
        keyAlgorithm: b([3]),
        publicKey: b([4]),
        sharedContext: b([5]),
      );
      for (final field in [
        bootstrap.applicationIdentity,
        bootstrap.keyAlgorithm,
        bootstrap.publicKey,
        bootstrap.sharedContext,
      ]) {
        final before = List.of(field);
        expect(() => field[0] = 0xEE, throwsUnsupportedError);
        expect(
          () => field.buffer.asUint8List()[0] = 0xEE,
          throwsUnsupportedError,
        );
        expect(
          () => Uint8List.view(field.buffer)[0] = 0xEE,
          throwsUnsupportedError,
        );
        expect(
          () => field.buffer.asByteData().setUint8(0, 0xEE),
          throwsUnsupportedError,
        );
        expect(field, before);
      }
      expect(bootstrap.applicationIdentity, [1, 2]);
    },
  );

  test('Dart validates nothing semantic: the native core decides', () {
    // An uppercase key algorithm (which the core refuses), empty fields, and a 20,000-byte
    // field (beyond the core's frame bound) are all constructible values.
    final bootstrap = SasPairingBootstrap(
      applicationIdentity: b([]),
      keyAlgorithm: b('X25519'.codeUnits),
      publicKey: Uint8List(20000),
      sharedContext: b([]),
    );
    expect(bootstrap.publicKey, hasLength(20000));
    expect(bootstrap.applicationIdentity, isEmpty);
  });
}
