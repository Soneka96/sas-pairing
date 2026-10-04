// Fakes for the loader state machine: no native library is ever loaded. A fake image answers the
// symbol preflight from a set and serves sas_pairing_abi_version through a Dart callback, so the
// version check still runs through the generated binding.
import 'dart:ffi';

import 'package:sas_pairing/src/native/abi_v1.dart';
import 'package:sas_pairing/src/native/generated/sas_pairing_bindings.g.dart';
import 'package:sas_pairing/src/native/native_library_loader.dart';

final class FakeImage implements NativeImage {
  FakeImage({this.version = 1, Set<String>? symbols, this.bindFails = false})
    : symbols = symbols ?? abiV1Exports.toSet();

  final int version;
  final Set<String> symbols;
  final bool bindFails;
  final List<String> preflighted = [];
  final List<String> lookedUp = [];
  int binds = 0;
  NativeCallable<Uint32 Function()>? _version;

  @override
  bool providesSymbol(String symbol) {
    preflighted.add(symbol);
    return symbols.contains(symbol);
  }

  @override
  SasPairingNativeBindings bind() {
    binds++;
    if (bindFails) throw StateError('fake bind failure');
    return SasPairingNativeBindings.fromLookup(<T extends NativeType>(
      String symbol,
    ) {
      lookedUp.add(symbol);
      if (symbol != 'sas_pairing_abi_version') {
        throw StateError('fake image: unexpected lookup of $symbol');
      }
      final callable = _version ??=
          NativeCallable<Uint32 Function()>.isolateLocal(
            () => version,
            exceptionalReturn: 0,
          );
      return callable.nativeFunction.cast<T>();
    });
  }

  void close() => _version?.close();
}

final class FakePlatform implements NativePlatform {
  FakePlatform(this.images, {this.pointerSize = 8});

  /// Valid paths. A null image means the OS fails to load that file.
  final Map<String, FakeImage?> images;

  @override
  int pointerSize;

  final List<String> resolved = [];
  final List<String> opened = [];

  @override
  String resolveLibraryPath(String libraryPath) {
    resolved.add(libraryPath);
    if (!images.containsKey(libraryPath)) {
      throw NativeLibraryInitializationException(
        NativeLoadFailure.invalidLibraryPath,
        'fake: no such file $libraryPath',
      );
    }
    return libraryPath;
  }

  @override
  NativeImage open(String path) {
    opened.add(path);
    return images[path] ?? (throw ArgumentError('fake: cannot load $path'));
  }
}
