/// `package:sas_pairing`: experimental, pre-alpha Dart binding of the sas-pairing native core.
///
/// **No pairing API is available yet.** P8 is in progress: P8.1 adds only the private
/// foundation (the generated raw bindings of the frozen native ABI v1 and the process-lifetime
/// native-library loader under `lib/src/native/`). This entrypoint intentionally exports
/// nothing: raw FFI types, pointers, the `DynamicLibrary`, and the generated bindings stay
/// private, and the high-level API begins in a later P8 increment.
///
/// Not production-security approved, not audited, and not formally verified. The protocol is
/// implemented only by the native Rust core; this package implements no protocol or
/// cryptography. Pairing networking is supported on Windows only.
library;
