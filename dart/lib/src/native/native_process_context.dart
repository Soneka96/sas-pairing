/// The package-private process context of the loaded native image (P8-D-002 B, G, H).
///
/// Private to the package. One context belongs to each loaded image, so for the one process
/// loader there is one per owner isolate (P8-D-001 N). It holds the native lifecycle, network,
/// and ceremony services (P8-D-002 L, P8-D-003 Q, P8-D-004 rule 8), all built over the same
/// generated bindings of that image, and the two latches that live below every runtime: the
/// native FATAL latch and the contract-violation latch. Neither latch can be cleared: closing or recreating a runtime and
/// closing wrappers leave them set, and the only recovery is an OS process restart.
library;

import '../exceptions.dart';
import '../status.dart';
import 'native_ceremony_api.dart';
import 'native_library_loader.dart';
import 'native_lifecycle_api.dart';
import 'native_network_api.dart';

LoadedNativeLibrary _processLoad(String libraryPath) =>
    NativeLibraryLoader.initialize(libraryPath: libraryPath);

NativeLifecycleApi _ffiApi(LoadedNativeLibrary library) =>
    FfiNativeLifecycleApi(library.bindings);

NativeNetworkApi _ffiNetwork(LoadedNativeLibrary library) =>
    FfiNativeNetworkApi(library.bindings);

NativeCeremonyApi _ffiCeremony(LoadedNativeLibrary library) =>
    FfiNativeCeremonyApi(library.bindings);

final class NativeProcessContext {
  NativeProcessContext(this.api, this.network, this.ceremony);

  // One context per loaded image; the process loader returns the identical image every time.
  static final Expando<NativeProcessContext> _contexts = Expando(
    'sas_pairing native process context',
  );

  /// The context of the image at [libraryPath]: [load] initializes the loader (production: the
  /// P8.1 process loader, which opens nothing once ready), and the context is created once per
  /// loaded image. Tests pass their own [load], [apiFor], [networkFor], and [ceremonyFor].
  static NativeProcessContext forLibrary(
    String libraryPath, {
    LoadedNativeLibrary Function(String libraryPath) load = _processLoad,
    NativeLifecycleApi Function(LoadedNativeLibrary library) apiFor = _ffiApi,
    NativeNetworkApi Function(LoadedNativeLibrary library) networkFor =
        _ffiNetwork,
    NativeCeremonyApi Function(LoadedNativeLibrary library) ceremonyFor =
        _ffiCeremony,
  }) {
    final library = load(libraryPath);
    return _contexts[library] ??= NativeProcessContext(
      apiFor(library),
      networkFor(library),
      ceremonyFor(library),
    );
  }

  /// The lifecycle exports (P8.2).
  final NativeLifecycleApi api;

  /// The network exports (P8.3).
  final NativeNetworkApi network;

  /// The trusted-local ceremony exports (P8.4).
  final NativeCeremonyApi ceremony;

  bool _fatal = false;
  String? _contractViolation;

  /// Whether a native call returned `SAS_PAIRING_FATAL`. Never cleared.
  bool get isFatal => _fatal;

  /// Whether a native success output broke the frozen contract. Never cleared.
  bool get isContractViolated => _contractViolation != null;

  /// Refuses a normal operation, without a native call, once a latch is set. Cleanup
  /// operations never call this.
  void admitNormal(String operation) {
    if (_fatal) {
      throw SasPairingNativeException(
        operation,
        SasPairingStatus.fatal.code,
        detail:
            'refused locally without a native call: SAS_PAIRING_FATAL was already '
            'observed in this process',
      );
    }
    final violation = _contractViolation;
    if (violation != null) {
      throw SasPairingContractException(
        operation,
        'refused locally without a native call after an earlier violation '
        '($violation)',
      );
    }
  }

  /// Accepts `SAS_PAIRING_OK`; otherwise latches FATAL (status 900 only) and throws the exact
  /// status, known or unknown.
  void check(String operation, int status) {
    if (status == SasPairingStatus.ok.code) return;
    if (status == SasPairingStatus.fatal.code) _fatal = true;
    throw SasPairingNativeException(operation, status);
  }

  /// Records [status] without throwing: latches FATAL for status 900 and does nothing else. For
  /// a status that is reported as data rather than thrown (a drive's `out_failure`).
  void observe(int status) {
    if (status == SasPairingStatus.fatal.code) _fatal = true;
  }

  /// Latches a contract violation and returns the exception to throw.
  SasPairingContractException violation(String operation, String what) {
    _contractViolation ??= '$operation: $what';
    return SasPairingContractException(operation, what);
  }

  /// The handle of a successful creation, which ABI v1 guarantees is nonzero.
  int requireHandle(String operation, int handle) {
    if (handle == 0) {
      throw violation(operation, 'SAS_PAIRING_OK with a zero handle');
    }
    return handle;
  }
}
