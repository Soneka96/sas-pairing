/// Process-lifetime loading of the one sas-pairing native library image (P8-D-001,
/// P7-D-002, ABI contract §14 and §21).
///
/// Private to the package. The loader opens exactly one native image from an explicit,
/// absolute path, checks it against the frozen ABI v1 (all 25 exports present,
/// `sas_pairing_abi_version() == 1`), and then keeps the `DynamicLibrary` and the generated
/// bindings strongly referenced. There is deliberately no close, dispose, unload, reload, reset,
/// or replace operation: the native state is module state of the loaded image, so unloading or
/// loading another copy would leave the supported contract, and the only recovery from
/// `SAS_PAIRING_FATAL` is an OS process restart.
///
/// ISOLATE LIMITATION: Dart statics are isolate-local. The process loader below is a singleton
/// for the isolate that uses it, not for the OS process. The supported model is one Dart owner
/// isolate per OS process for all direct native access; other isolates must not use this
/// library directly or open another image. Nothing here can enforce that across isolates.
library;

import 'dart:ffi';
import 'dart:io';

import 'abi_v1.dart';
import 'generated/sas_pairing_bindings.g.dart';

/// Why native initialization failed.
enum NativeLoadFailure {
  /// The process pointer width is not the supported 64-bit width. Nothing was opened.
  unsupportedPointerWidth(processRestartRequired: false),

  /// The library path is empty, relative, or not an existing file. Nothing was opened.
  invalidLibraryPath(processRestartRequired: false),

  /// The operating system could not load the file. No image is owned by the package.
  openFailed(processRestartRequired: false),

  /// The loaded image lacks one or more of the 25 frozen exports.
  missingSymbol(processRestartRequired: true),

  /// `sas_pairing_abi_version()` returned 0: the version query itself caught a panic.
  abiVersionQueryFailed(processRestartRequired: true),

  /// `sas_pairing_abi_version()` returned a version other than 1.
  abiVersionMismatch(processRestartRequired: true),

  /// Binding or verifying the loaded image threw unexpectedly.
  verificationFailed(processRestartRequired: true);

  const NativeLoadFailure({required this.processRestartRequired});

  /// True once an image was loaded: it cannot be unloaded, so the loader is unusable for the
  /// rest of the process (P7-D-002).
  final bool processRestartRequired;
}

/// Native initialization failed. When [processRestartRequired] is true, a native image was
/// already loaded and the loader is permanently failed for this process: correct the native
/// library, then restart the OS process.
final class NativeLibraryInitializationException implements Exception {
  NativeLibraryInitializationException(this.failure, this.message);

  final NativeLoadFailure failure;
  final String message;

  bool get processRestartRequired => failure.processRestartRequired;

  @override
  String toString() =>
      'NativeLibraryInitializationException(${failure.name}): '
      '$message${processRestartRequired ? ' Restart the OS process after correcting '
                'the native library; the loaded image cannot be unloaded or replaced.' : ''}';
}

/// One opened native image, as the loader sees it.
abstract interface class NativeImage {
  /// Whether the image exports [symbol]. A lookup only: nothing is called.
  bool providesSymbol(String symbol);

  /// Builds the generated bindings over this image. Called only after the symbol preflight.
  SasPairingNativeBindings bind();
}

/// What the loader needs from the platform. Production uses [ProcessNativePlatform]; tests
/// supply a fake to drive the state machine without loading anything.
abstract interface class NativePlatform {
  /// The process pointer width in bytes.
  int get pointerSize;

  /// Validates [libraryPath] (absolute, an existing file) and returns its canonical form, or
  /// throws [NativeLibraryInitializationException] with [NativeLoadFailure.invalidLibraryPath].
  String resolveLibraryPath(String libraryPath);

  /// Opens the image at the canonical [path], or throws if the OS cannot load it.
  NativeImage open(String path);
}

/// The ready, verified native library: retained for the rest of the process.
final class LoadedNativeLibrary {
  LoadedNativeLibrary._(
    this.libraryPath,
    this.image,
    this.bindings,
    this.abiVersion,
  );

  /// The canonical path the image was opened from.
  final String libraryPath;

  /// The retained image. Never closed.
  final NativeImage image;

  /// The one raw binding object. Never replaced.
  final SasPairingNativeBindings bindings;

  /// The version the image reported: always [requiredAbiVersion].
  final int abiVersion;
}

/// The loader state machine: uninitialized → ready, or uninitialized → permanently failed.
/// A failure before an image is loaded leaves it uninitialized, so a later attempt may try
/// again; a failure after an image is loaded is permanent for the process.
final class NativeLibraryLoader {
  /// A loader over [platform]. Production code uses only the process loader through the static
  /// [initialize] and [instance]; tests create their own loaders, which never touch it.
  NativeLibraryLoader(this._platform);

  static final NativeLibraryLoader _process = NativeLibraryLoader(
    const ProcessNativePlatform(),
  );

  /// Initializes this isolate's process loader from the explicit [libraryPath] (no search
  /// path, no fallback names, no discovery). Once ready, every later call returns the same
  /// [LoadedNativeLibrary] without inspecting [libraryPath] or opening anything.
  static LoadedNativeLibrary initialize({required String libraryPath}) =>
      _process.load(libraryPath);

  /// The ready process loader's library; throws [StateError] before a successful [initialize]
  /// and [NativeLibraryInitializationException] after a permanent failure.
  static LoadedNativeLibrary get instance => _process.loaded;

  final NativePlatform _platform;
  LoadedNativeLibrary? _ready;
  NativeLibraryInitializationException? _permanentFailure;

  // A loaded image that failed verification. Kept only so it is strongly referenced for the
  // rest of the process: it is never used, closed, or replaced.
  NativeImage? _failedImage;

  /// The image this loader holds for the rest of the process: the ready one, or one that failed
  /// verification after it was loaded; null while no image was ever loaded.
  NativeImage? get retainedImage => _ready?.image ?? _failedImage;

  /// The ready library, or the reason there is none.
  LoadedNativeLibrary get loaded {
    final failure = _permanentFailure;
    if (failure != null) throw failure;
    final ready = _ready;
    if (ready == null) {
      throw StateError('The sas-pairing native library is not initialized.');
    }
    return ready;
  }

  /// Loads and verifies the image at [libraryPath] once; see [initialize].
  LoadedNativeLibrary load(String libraryPath) {
    final ready = _ready;
    if (ready != null) return ready;
    final failure = _permanentFailure;
    if (failure != null) throw failure;

    // Before any image is loaded: these failures leave the loader uninitialized.
    final pointerSize = _platform.pointerSize;
    if (pointerSize != supportedPointerSize) {
      throw NativeLibraryInitializationException(
        NativeLoadFailure.unsupportedPointerWidth,
        'sas-pairing native ABI v1 supports only $supportedPointerSize-byte pointers; this '
        'process has $pointerSize-byte pointers. No library was opened.',
      );
    }
    final path = _platform.resolveLibraryPath(libraryPath);
    final NativeImage image;
    try {
      image = _platform.open(path);
    } on Object catch (error) {
      throw NativeLibraryInitializationException(
        NativeLoadFailure.openFailed,
        'Could not load the native library at "$path": $error',
      );
    }

    // An image is now loaded and can never be unloaded: every failure from here on is
    // permanent, and the image stays referenced.
    try {
      final missing = <String>[
        for (final symbol in abiV1Exports)
          if (!image.providesSymbol(symbol)) symbol,
      ];
      if (missing.isNotEmpty) {
        throw _poison(
          image,
          NativeLoadFailure.missingSymbol,
          'The native library at "$path" lacks ${missing.length} of the '
          '${abiV1Exports.length} frozen ABI v1 exports: ${missing.join(', ')}.',
        );
      }
      final bindings = image.bind();
      final version = bindings.sas_pairing_abi_version();
      if (version == 0) {
        throw _poison(
          image,
          NativeLoadFailure.abiVersionQueryFailed,
          'sas_pairing_abi_version() returned 0 (the version query failed inside the native '
          'library) for "$path"; expected = $requiredAbiVersion, actual = 0.',
        );
      }
      if (version != requiredAbiVersion) {
        throw _poison(
          image,
          NativeLoadFailure.abiVersionMismatch,
          'The native library at "$path" implements ABI version $version; '
          'expected = $requiredAbiVersion, actual = $version.',
        );
      }
      return _ready = LoadedNativeLibrary._(path, image, bindings, version);
    } on NativeLibraryInitializationException {
      rethrow;
    } on Object catch (error) {
      throw _poison(
        image,
        NativeLoadFailure.verificationFailed,
        'Verifying the native library at "$path" failed: $error',
      );
    }
  }

  NativeLibraryInitializationException _poison(
    NativeImage image,
    NativeLoadFailure failure,
    String message,
  ) {
    _failedImage = image;
    return _permanentFailure = NativeLibraryInitializationException(
      failure,
      message,
    );
  }
}

/// The real platform: `dart:ffi` and `dart:io`.
final class ProcessNativePlatform implements NativePlatform {
  const ProcessNativePlatform();

  @override
  int get pointerSize => sizeOf<IntPtr>();

  @override
  String resolveLibraryPath(String libraryPath) {
    NativeLibraryInitializationException invalid(String why) =>
        NativeLibraryInitializationException(
          NativeLoadFailure.invalidLibraryPath,
          'Invalid sas-pairing native library path "$libraryPath": $why. '
          'No library was opened.',
        );
    if (libraryPath.isEmpty) throw invalid('the path is empty');
    final file = File(libraryPath);
    // A bare name or relative path would make the OS loader search for the library.
    if (!file.isAbsolute) throw invalid('the path must be absolute');
    if (FileSystemEntity.typeSync(libraryPath) != FileSystemEntityType.file) {
      throw invalid('no such file');
    }
    try {
      return file.resolveSymbolicLinksSync();
    } on FileSystemException catch (error) {
      throw invalid(error.message);
    }
  }

  @override
  NativeImage open(String path) =>
      _DynamicLibraryImage(DynamicLibrary.open(path));
}

final class _DynamicLibraryImage implements NativeImage {
  _DynamicLibraryImage(this._library);

  // Strongly referenced for the rest of the process; never closed.
  final DynamicLibrary _library;

  @override
  bool providesSymbol(String symbol) => _library.providesSymbol(symbol);

  @override
  SasPairingNativeBindings bind() => SasPairingNativeBindings(_library);
}
