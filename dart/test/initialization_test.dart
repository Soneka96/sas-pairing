// P8.2.1 public initialization errors (P8-D-002 M): every private loader failure reaching
// SasPairingRuntime.create is translated, at one package-private boundary, into the public
// SasPairingInitializationException with the matching public category and restart class. The
// loader's own state machine is unchanged: a pre-load failure leaves it retryable, a post-load
// failure poisons it for the process. Driven through the fake loader seam; nothing is loaded.
import 'package:sas_pairing/src/exceptions.dart';
import 'package:sas_pairing/src/lifecycle.dart';
import 'package:sas_pairing/src/native/native_library_loader.dart';
import 'package:sas_pairing/src/native/native_process_context.dart';
import 'package:test/test.dart';

import 'support/fake_lifecycle.dart';
import 'support/fake_native.dart';

const good = '/fake/sas_pairing';
const other = '/fake/other';

/// The expected public category and restart class of each private loader failure.
const expected = {
  NativeLoadFailure.unsupportedPointerWidth: (
    SasPairingInitializationFailure.unsupportedPointerWidth,
    false,
  ),
  NativeLoadFailure.invalidLibraryPath: (
    SasPairingInitializationFailure.invalidLibraryPath,
    false,
  ),
  NativeLoadFailure.openFailed: (
    SasPairingInitializationFailure.openFailed,
    false,
  ),
  NativeLoadFailure.missingSymbol: (
    SasPairingInitializationFailure.missingSymbol,
    true,
  ),
  NativeLoadFailure.abiVersionQueryFailed: (
    SasPairingInitializationFailure.abiVersionQueryFailed,
    true,
  ),
  NativeLoadFailure.abiVersionMismatch: (
    SasPairingInitializationFailure.abiVersionMismatch,
    true,
  ),
  NativeLoadFailure.verificationFailed: (
    SasPairingInitializationFailure.verificationFailed,
    true,
  ),
};

Matcher initializationFailure(
  SasPairingInitializationFailure failure, {
  required bool restart,
  required String detail,
}) => isA<SasPairingInitializationException>()
    .having(
      (e) => e.runtimeType,
      'runtimeType',
      SasPairingInitializationException,
    )
    .having((e) => e.failure, 'failure', failure)
    .having((e) => e.processRestartRequired, 'processRestartRequired', restart)
    .having((e) => e.message, 'message', contains(detail))
    .having(
      (e) => e.toString(),
      'toString',
      allOf(
        startsWith('SasPairingInitializationException(${failure.name}): '),
        restart
            ? contains('Restart the OS process')
            : isNot(contains('Restart')),
        isNot(contains('NativeLibraryInitializationException')),
        isNot(contains('NativeLoadFailure')),
      ),
    );

/// A fake process loader over [platform] and the context initialization of
/// SasPairingRuntime.create, with the public translation boundary.
final class FakeProcess {
  FakeProcess(this.platform) : loader = NativeLibraryLoader(platform);

  final FakePlatform platform;
  final NativeLibraryLoader loader;
  final FakeLifecycleApi api = FakeLifecycleApi();
  int services = 0;

  NativeProcessContext initialize(String path) => initializeProcessContext(
    () => NativeProcessContext.forLibrary(
      path,
      load: loader.load,
      apiFor: (_) {
        services++;
        return api;
      },
    ),
  );
}

FakeImage image({
  int version = 1,
  Set<String>? symbols,
  bool bindFails = false,
}) {
  final image = FakeImage(
    version: version,
    symbols: symbols,
    bindFails: bindFails,
  );
  addTearDown(image.close);
  return image;
}

void main() {
  test('the public category set mirrors the private one, case by case', () {
    expect(SasPairingInitializationFailure.values, hasLength(7));
    expect(expected.keys.toSet(), NativeLoadFailure.values.toSet());
    for (final private in NativeLoadFailure.values) {
      final (public, restart) = expected[private]!;
      expect(public.name, private.name);
      expect(restart, private.processRestartRequired, reason: private.name);
      expect(
        () => initializeProcessContext(
          () => throw NativeLibraryInitializationException(private, 'detail'),
        ),
        throwsA(
          initializationFailure(public, restart: restart, detail: 'detail'),
        ),
        reason: private.name,
      );
    }
  });

  group('each loader failure reaching create is translated', () {
    final cases =
        <String, (FakePlatform Function(), String, NativeLoadFailure, String)>{
          'unsupported pointer width': (
            () => FakePlatform({good: image()}, pointerSize: 4),
            good,
            NativeLoadFailure.unsupportedPointerWidth,
            '4-byte pointers',
          ),
          'invalid library path': (
            () => FakePlatform({good: image()}),
            '/fake/missing',
            NativeLoadFailure.invalidLibraryPath,
            'fake: no such file /fake/missing',
          ),
          'OS load failure': (
            () => FakePlatform({good: null}),
            good,
            NativeLoadFailure.openFailed,
            'fake: cannot load $good',
          ),
          'missing export': (
            () => FakePlatform({good: image(symbols: {})}),
            good,
            NativeLoadFailure.missingSymbol,
            'lacks 25 of the 25 frozen ABI v1 exports',
          ),
          'ABI version query returned 0': (
            () => FakePlatform({good: image(version: 0)}),
            good,
            NativeLoadFailure.abiVersionQueryFailed,
            'expected = 1, actual = 0',
          ),
          'ABI version mismatch': (
            () => FakePlatform({good: image(version: 2)}),
            good,
            NativeLoadFailure.abiVersionMismatch,
            'expected = 1, actual = 2',
          ),
          'verification failure': (
            () => FakePlatform({good: image(bindFails: true)}),
            good,
            NativeLoadFailure.verificationFailed,
            'fake bind failure',
          ),
        };
    for (final MapEntry(key: name, value: (platform, path, private, detail))
        in cases.entries) {
      test(name, () {
        final process = FakeProcess(platform());
        final (public, restart) = expected[private]!;
        expect(
          () => process.initialize(path),
          throwsA(
            initializationFailure(public, restart: restart, detail: detail),
          ),
        );
        expect(process.services, 0, reason: 'no lifecycle service, no runtime');
        expect(process.api.calls, isEmpty);
        expect(
          process.loader.retainedImage,
          restart ? isNotNull : isNull,
          reason: 'restart is required exactly when an image was loaded',
        );
      });
    }
  });

  test('a pre-load failure (invalid path) leaves create retryable', () {
    final loaded = image();
    final process = FakeProcess(FakePlatform({good: loaded}));
    expect(
      () => process.initialize('/fake/missing'),
      throwsA(
        initializationFailure(
          SasPairingInitializationFailure.invalidLibraryPath,
          restart: false,
          detail: '/fake/missing',
        ),
      ),
    );
    expect(process.platform.opened, isEmpty);

    final runtime = createRuntime(process.initialize(good));
    expect(process.platform.opened, [good]);
    expect(identical(process.loader.retainedImage, loaded), isTrue);
    expect(process.api.count('runtimeCreate'), 1);
    runtime.close();
  });

  test(
    'a post-load failure (ABI mismatch) stays permanent; nothing else opens',
    () {
      final wrong = image(version: 2);
      final process = FakeProcess(FakePlatform({good: wrong, other: image()}));
      final mismatch = initializationFailure(
        SasPairingInitializationFailure.abiVersionMismatch,
        restart: true,
        detail: 'expected = 1, actual = 2',
      );
      expect(() => process.initialize(good), throwsA(mismatch));
      expect(() => process.initialize(other), throwsA(mismatch));
      expect(() => process.initialize(good), throwsA(mismatch));
      expect(process.platform.opened, [
        good,
      ], reason: 'no second image is opened');
      expect(identical(process.loader.retainedImage, wrong), isTrue);
      expect(process.services, 0);
      expect(process.api.calls, isEmpty);
    },
  );

  test('other failures pass the boundary untranslated', () {
    final error = StateError('not a loader failure');
    expect(
      () => initializeProcessContext(() => throw error),
      throwsA(same(error)),
    );
  });
}
