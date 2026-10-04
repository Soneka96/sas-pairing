// The loader state machine (P8-D-001): uninitialized → ready, or uninitialized → permanently
// failed. Fake platforms drive every case without loading a library; each test owns a fresh
// loader, and none of them touches this isolate's process loader.
import 'dart:io';

import 'package:sas_pairing/src/native/abi_v1.dart';
import 'package:sas_pairing/src/native/native_library_loader.dart';
import 'package:test/test.dart';

import 'support/fake_native.dart';

const String good = '/fake/libsas_pairing_core.so';
const String other = '/fake/other/libsas_pairing_core.so';

Matcher failsWith(NativeLoadFailure failure) => throwsA(
  isA<NativeLibraryInitializationException>().having(
    (e) => e.failure,
    'failure',
    failure,
  ),
);

void main() {
  final fakes = <FakeImage>[];
  FakeImage image({
    int version = 1,
    Set<String>? symbols,
    bool bindFails = false,
  }) {
    final fake = FakeImage(
      version: version,
      symbols: symbols,
      bindFails: bindFails,
    );
    fakes.add(fake);
    return fake;
  }

  tearDown(() {
    for (final fake in fakes) {
      fake.close();
    }
    fakes.clear();
  });

  group('ready', () {
    test(
      'one open, all 25 symbols preflighted in order, then ABI version 1',
      () {
        final fake = image();
        final platform = FakePlatform({good: fake});
        final loader = NativeLibraryLoader(platform);

        final loaded = loader.load(good);

        expect(platform.opened, [good]);
        expect(fake.preflighted, abiV1Exports);
        expect(fake.binds, 1);
        expect(fake.lookedUp, [
          'sas_pairing_abi_version',
        ], reason: 'no stateful export');
        expect(loaded.abiVersion, requiredAbiVersion);
        expect(loaded.libraryPath, good);
        expect(identical(loaded.image, fake), isTrue);
        expect(identical(loader.retainedImage, fake), isTrue);
        expect(identical(loader.loaded, loaded), isTrue);
      },
    );

    test('a second initialization returns the same object and opens nothing', () {
      final platform = FakePlatform({good: image(), other: image()});
      final loader = NativeLibraryLoader(platform);
      final first = loader.load(good);

      expect(identical(loader.load(good), first), isTrue);
      // After READY the path argument is not inspected: no path swap is possible.
      expect(identical(loader.load(other), first), isTrue);
      expect(identical(loader.load('not even a path'), first), isTrue);
      expect(identical(loader.load(good).bindings, first.bindings), isTrue);
      expect(platform.opened, [good]);
      expect(platform.resolved, [good]);
    });
  });

  group('failure before an image is loaded (retry allowed)', () {
    test('an unsupported pointer width fails before any path work or open', () {
      final platform = FakePlatform({good: image()}, pointerSize: 4);
      final loader = NativeLibraryLoader(platform);

      expect(
        () => loader.load(good),
        failsWith(NativeLoadFailure.unsupportedPointerWidth),
      );
      expect(platform.resolved, isEmpty);
      expect(platform.opened, isEmpty);
      expect(loader.retainedImage, isNull);
      expect(() => loader.loaded, throwsStateError);
    });

    test('an invalid path opens nothing; a later valid path loads', () {
      final platform = FakePlatform({good: image()});
      final loader = NativeLibraryLoader(platform);

      try {
        loader.load('/fake/missing.so');
        fail('expected a failure');
      } on NativeLibraryInitializationException catch (e) {
        expect(e.failure, NativeLoadFailure.invalidLibraryPath);
        expect(e.processRestartRequired, isFalse);
      }
      expect(platform.opened, isEmpty);
      expect(loader.retainedImage, isNull);
      expect(() => loader.loaded, throwsStateError);

      expect(loader.load(good).abiVersion, 1);
      expect(platform.opened, [good]);
    });

    test('an OS load failure owns no image; a later valid path loads', () {
      final platform = FakePlatform({other: null, good: image()});
      final loader = NativeLibraryLoader(platform);

      expect(() => loader.load(other), failsWith(NativeLoadFailure.openFailed));
      expect(loader.retainedImage, isNull);
      expect(loader.load(good).abiVersion, 1);
      expect(platform.opened, [other, good]);
    });
  });

  group('failure after an image is loaded (permanent for the process)', () {
    void expectPermanent(
      FakePlatform platform,
      NativeLibraryLoader loader,
      FakeImage loadedImage,
      NativeLoadFailure failure,
    ) {
      NativeLibraryInitializationException? first;
      try {
        loader.load(good);
        fail('expected a failure');
      } on NativeLibraryInitializationException catch (e) {
        first = e;
      }
      expect(first.failure, failure);
      expect(first.processRestartRequired, isTrue);
      expect(first.toString(), contains('Restart the OS process'));
      // The loaded image stays referenced; nothing else is ever opened.
      expect(identical(loader.retainedImage, loadedImage), isTrue);
      for (final path in [good, other]) {
        expect(
          () => loader.load(path),
          throwsA(same(first)),
          reason: 'no reload, no alternate image',
        );
      }
      expect(() => loader.loaded, throwsA(same(first)));
      expect(platform.opened, [good]);
    }

    test('a missing frozen export', () {
      final missing = image(
        symbols: abiV1Exports.toSet()..remove('sas_pairing_run_cancel_sas'),
      );
      final platform = FakePlatform({good: missing, other: image()});
      final loader = NativeLibraryLoader(platform);
      expectPermanent(
        platform,
        loader,
        missing,
        NativeLoadFailure.missingSymbol,
      );
      expect(missing.binds, 0, reason: 'no bindings over a partial image');
      expect(
        () => loader.load(good),
        throwsA(
          isA<NativeLibraryInitializationException>().having(
            (e) => e.message,
            'message',
            contains('sas_pairing_run_cancel_sas'),
          ),
        ),
      );
    });

    test('an image with none of the exports reports all 25', () {
      final foreign = image(symbols: {});
      final loader = NativeLibraryLoader(FakePlatform({good: foreign}));
      expect(
        () => loader.load(good),
        throwsA(
          isA<NativeLibraryInitializationException>().having(
            (e) => e.message,
            'message',
            allOf([for (final symbol in abiV1Exports) contains(symbol)]),
          ),
        ),
      );
    });

    test('ABI version mismatch (2)', () {
      final wrong = image(version: 2);
      final platform = FakePlatform({good: wrong, other: image()});
      final loader = NativeLibraryLoader(platform);
      expectPermanent(
        platform,
        loader,
        wrong,
        NativeLoadFailure.abiVersionMismatch,
      );
      expect(
        () => loader.load(good),
        throwsA(
          isA<NativeLibraryInitializationException>().having(
            (e) => e.message,
            'message',
            contains('expected = 1, actual = 2'),
          ),
        ),
      );
    });

    test('ABI version 0 (the version query failed) is not "an old ABI"', () {
      final zero = image(version: 0);
      final platform = FakePlatform({good: zero, other: image()});
      final loader = NativeLibraryLoader(platform);
      expectPermanent(
        platform,
        loader,
        zero,
        NativeLoadFailure.abiVersionQueryFailed,
      );
    });

    test('an unexpected error while binding', () {
      final broken = image(bindFails: true);
      final platform = FakePlatform({good: broken, other: image()});
      final loader = NativeLibraryLoader(platform);
      expectPermanent(
        platform,
        loader,
        broken,
        NativeLoadFailure.verificationFailed,
      );
    });
  });

  group('ProcessNativePlatform (no native library is loaded)', () {
    const platform = ProcessNativePlatform();
    final absoluteMissing = File(
      '${Directory.systemTemp.path}/sas_pairing_does_not_exist.bin',
    ).absolute.path;

    test('reports the 64-bit pointer width of this process', () {
      expect(platform.pointerSize, 8);
    });

    for (final (why, path) in [
      ('empty', ''),
      ('a bare name the OS loader would search for', 'sas_pairing_core.dll'),
      ('relative', 'lib/sas_pairing.dart'),
      ('missing', absoluteMissing),
      ('a directory', Directory.current.absolute.path),
    ]) {
      test('rejects a path that is $why, before opening', () {
        expect(
          () => platform.resolveLibraryPath(path),
          failsWith(NativeLoadFailure.invalidLibraryPath),
        );
      });
    }

    test('canonicalizes an existing absolute file', () {
      final file = File('pubspec.yaml').absolute;
      expect(
        platform.resolveLibraryPath(file.path),
        file.resolveSymbolicLinksSync(),
      );
    });

    test('a file the OS cannot load is a retryable pre-load failure', () {
      final loader = NativeLibraryLoader(platform);
      expect(
        () => loader.load(File('pubspec.yaml').absolute.path),
        failsWith(NativeLoadFailure.openFailed),
      );
      expect(loader.retainedImage, isNull);
    });
  });

  test('test loaders never initialize this isolate\'s process loader', () {
    expect(() => NativeLibraryLoader.instance, throwsStateError);
  });
}
