# Project context for AI agents

- This is a security library; make no production cryptography claims without evidence.
- Specify and review the protocol before implementing production behavior. Research is not a selected architecture.
- Keep the core reusable and application-neutral. DovahLink is the original consumer, not the architectural owner; application trust semantics stay in consumers.
- Dart and .NET are intended wrappers around one core, not parallel production crypto implementations.
- No production-readiness claim before independent external review.
- Every security behavior needs tests. Deterministic vectors will become authoritative interoperability artifacts after protocol selection.
- Compatibility is not required before the first stable release unless explicitly approved. Breaking pre-1.0 security changes are acceptable when necessary.
- Fail closed on ambiguous security state.
