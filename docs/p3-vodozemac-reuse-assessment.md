# P3 vodozemac reuse assessment

**Research snapshot: 2026-09-28.** This is an architecture and security research assessment, not a protocol freeze, implementation approval, audit, or legal opinion. No source from the AGPL-licensed Dart packages is reproduced here.

## 1. Executive decision question

Should `sas-pairing` stop preparing Candidate B for production and instead build one application-neutral Rust ceremony around the maintained Apache-2.0 `vodozemac::sas` implementation, exposed to Dart and .NET through thin wrappers?

**Outcome: B — promising but review required.** The primitive API and the specified Matrix decimal SAS fit the numeric-only constraint. The SAS methods accept caller-selected context and caller-supplied MAC input. This makes authenticating canonical bootstrap bytes technically feasible without changing the underlying DH, HKDF, SAS, or HMAC algorithms. But `vodozemac::sas` is not the Matrix ceremony, and Matrix's documented identity, transcript, and state assumptions cannot simply be claimed for an application-neutral profile. Before selecting this architecture, an independent protocol reviewer must examine the generic ceremony mapping, canonical encoding, transcript binding, attempt policy, and terminal-state contract.

Classification:

- Rust `vodozemac` SAS primitive: **CANDIDATE** for the shared cryptographic dependency; pin an exact reviewed version if later selected.
- Matrix decimal SAS: **CANDIDATE** (specified and directly exposed by vodozemac; 39 bits).
- MAC of canonical generic bootstrap data: **CANDIDATE — safe generic adaptation at the API level; review required for the profile and its security claim**.
- Shared Rust ceremony and Dart/.NET wrappers: **CANDIDATE**, not selected for implementation yet.
- Candidate B: **CANDIDATE / RESEARCH REFERENCE** until the reuse mapping passes review; do not delete or rewrite its research.
- AGPL Dart/Flutter bindings: **RESEARCH ONLY** as prior art.
- Independent Dart and .NET cryptographic implementations: **STOP** under the one-security-core requirement.

## 2. Existing project requirements

The current repository is pre-alpha and has no production protocol implementation. P1 requires a remote, active-attacker-resistant ceremony that authenticates exact bootstrap bytes for one ceremony, explicit roles, and security-relevant context. Authenticated public-key bytes mean only that a peer supplied those bytes; the pairing result must not claim possession of the corresponding private key. A reusable pairing key is optional. Both parties compare the complete SAS and complete the same ceremony. Retry limits and durable state must follow the chosen construction's security argument. Dart and .NET are intended to wrap one shared security core. See [P1 threat model](threat-model.md), [architecture](architecture.md), and [protocol status](protocol-status.md).

The current protocol status selects Candidate B for the remote profile and identifies vodozemac/Matrix SAS as insufficient to select without generic-profile analysis. This document evaluates whether that assessment should change; it does not silently supersede it.

## 3. What Rust vodozemac SAS owns

The current `vodozemac` release is 0.11.0. Its public `sas` module provides:

- `Sas::new()`: random ephemeral Curve25519/X25519 keypair generation.
- `public_key()`: the ephemeral public key.
- `diffie_hellman(...)`: consumes the `Sas`, parses/checks the peer key, performs DH, and rejects a non-contributory result.
- `EstablishedSas::bytes(info)`: HKDF-SHA-256 over the DH shared secret, with no salt and caller-provided `info`; returns six bytes.
- `SasBytes::decimals()`: Matrix's specified three-number decimal encoding. `emoji_indices()` is also present but is not required here.
- `calculate_mac(input, info)` / `verify_mac(input, info, tag)`: HKDF derives a 32-byte HMAC-SHA-256 key from the shared secret and caller-provided info; HMAC covers the supplied input. Current API returns/verifies the full 32-byte tag.
- `bytes_raw(info, count)`: raw HKDF output, capped at `32 * 255` bytes and fallible when out of range.

The Rust SAS object does **not** own the commit/reveal exchange, negotiation, message serialization, roles, session identifier, confirmation UI, cancellation, timeout, replay database, bilateral completion, or application identity policy. It has no ceremony state machine. `EstablishedSas` can generate display bytes and MACs; the caller decides when those operations are legal and which exact context they cover. The crate's own documentation describes the higher-level verification use as verifying an account identity key, but the primitive accepts generic input strings.

The ephemeral secret is consumed by DH. The established DH shared secret remains inside `EstablishedSas` while SAS bytes or MACs may still be needed. It can be dropped after the terminal ceremony step, normally after the required MACs and completion checks. The underlying X25519 secret types use zeroization support; this is best-effort memory hygiene, not a guarantee against swap, dumps, hardware side channels, or copies outside Rust. The protocol does not require turning the SAS DH secret into an application's long-term or transport secret.

**Boundary:** vodozemac supplies cryptographic operations and validation. A Rust `sas-pairing` layer would still own all ceremony logic and must make its security contract explicit.

## 4. Matrix `m.sas.v1` ceremony

The normative reference is the [Matrix Client-Server specification v1.18, SAS verification section](https://spec.matrix.org/v1.18/client-server-api/#short-authentication-string-sas-verification). At a high level:

1. The initiator sends `m.key.verification.start`, including offered key-agreement, hash, MAC, and SAS methods, plus a transaction identifier when using to-device messages.
2. The responder selects compatible methods, creates its ephemeral X25519 pair, and sends `m.key.verification.accept` with a SHA-256 commitment. The commitment is the hash of the responder public key's unpadded Base64 representation concatenated with the canonical JSON representation of the initiator's start content. The responder has therefore committed to its ephemeral public key and the exact negotiation start content before seeing the initiator's ephemeral public key.
3. The initiator sends its ephemeral public key. The responder then reveals its committed public key. The initiator verifies the commitment; both compute X25519 DH and reject invalid/non-contributory inputs.
4. Both derive the SAS with HKDF-SHA-256. For `curve25519-hkdf-sha256`, the context includes a Matrix domain string, the initiator's Matrix user/device IDs and SAS public key, the responder's Matrix user/device IDs and SAS public key, and the transaction ID. Roles are ordered, not treated as interchangeable.
5. Both display the selected SAS representation. The user compares the values and each client receives a local match/mismatch decision.
6. After a match, both calculate MACs over their selected device/cross-signing public-key strings and over the sorted, comma-separated key-ID list. The MAC info binds Matrix identities, direction, transaction ID, and key ID (or `KEY_IDS`). The peer verifies the MACs against the expected keys/key list. The protocol then exchanges `m.key.verification.done` messages.
7. A party can cancel. The spec requires rejecting unexpected/out-of-order messages, mismatched commitments, mismatched SAS, and incompatible negotiated methods. It calls for timeouts (10 minutes in the framework) and transaction separation; request/event relationships and transaction IDs associate messages with a flow. This is flow separation, not a general persistent replay database or a generic cross-process restart policy.

The commit is specifically a hash commitment to the responder's ephemeral public key and the initiator's canonical start content. It does not commit the responder to arbitrary application bootstrap data, long-term private-key possession, or a final application trust decision. It prevents the committing responder from choosing that committed ephemeral key after receiving the initiator's reveal, assuming the selected hash commitment behaves as required. The SAS is still the active MITM check; the code library alone does not implement this argument.

### Context and transcript fields

Matrix SAS HKDF context contains both ordered roles' user IDs, device IDs, and ephemeral SAS public keys, plus transaction ID and the protocol domain. Negotiation choices are carried in `start`/`accept`, with the start content included in the responder's commitment. The MAC context separately binds the transaction, sending/receiving Matrix identities, and the specific key or key list being authenticated. Generic adaptation must keep equivalent domain separation, direction, roles, session uniqueness, exact canonical transcript, and negotiated-profile checks. A shared `info` string needs unambiguous framing; concatenating fields without delimiters or length framing is not a safe generic profile design.

### Confirmation and result

Matching SAS values alone is not the full Matrix verification result: the keys to verify still need valid reciprocal MACs and the flow needs its completion messages. A generic bootstrap adaptation should likewise require local approval, the peer's MAC over the expected canonical message, all profile checks, and terminal agreement before returning success. The Matrix protocol's done events do not by themselves prove a consumer's durable trust write or a later transport's key possession.

## 5. Numeric SAS and Skyrim compatibility

Matrix's decimal SAS is already in both the specification and `vodozemac::sas::SasBytes::decimals()`; no new representation is needed. The spec generates five HKDF bytes, divides them into three independent 13-bit integers, and adds 1000 to each. Each integer is in the range 1000–9191. The effective exact-equality work factor is **39 bits** (`3 × 13`), or a random-match probability of `2^-39` for one independent attempt. Matrix's broader security discussion sometimes uses 40 bits as an illustrative value; the actual decimal representation is 39 bits.

The display can use three digit groups with spaces, e.g. `4821 7314 2057`. The values remain the specified Matrix decimal SAS. This uses ASCII digits and whitespace only; no emoji, Unicode, punctuation, or arbitrary letters. It fits the stated Skyrim constraint, subject to validating actual font/display size and a full-string human comparison. Since the number is visible, it is not a secret, password, or typed code.

The 39-bit value does not by itself bound aggregate attacker success across unlimited ceremonies. The project must choose and enforce an attempt budget/cooldown/lifetime policy consistent with its security objective. Matrix's one-guess rationale relies on commitment plus the user noticing a mismatch; it is not permission for unlimited retries.

## 6. Audit and security evidence

Least Authority's final report is dated 2022-03-30. It reviewed vodozemac repository revision `7c11a501bc316a0bf92a5fe06fee8582aad24897`, then verified remediations at `57d8d87a747653d6d7b7a53acb9a8d8f8de48285`. The Rust repository was in scope; language bindings and third-party code were explicitly out of scope unless named. Matrix's high-level interactions with the library and the cryptographic design of Olm/Megolm were also out of scope. The report contains SAS-specific review findings: incorrect secret zeroing in `src/sas.rs` (resolved), insufficient `bytes_raw` validation (resolved), and a requested test case for `calculate_mac` (added). So it is accurate to say **some vodozemac SAS implementation code was examined**. It is inaccurate to say the Matrix SAS ceremony, a generic extracted ceremony, this project's use, or today's crate has been audited.

The audit marked two issues unresolved: memory protection against swap/side-channel access, and a truncated 64-bit MAC in `src/cipher/mod.rs` used by the then-reviewed cipher path. Do not conflate that older Olm/cipher tag finding with today's `sas::EstablishedSas` MAC: current SAS source uses full HMAC-SHA-256 output. Most other listed issues and suggestions were marked resolved during the audit process. Least Authority's report itself cautions that it makes no warranties.

Today's upstream crate is 0.11.0 (released 2026-09-11), four years and many releases after the audited revisions. Its dependencies, Rust edition/MSRV, and code have changed. I did not find a later public audit covering the current 0.11.0 tree or a line-by-line mapping from the audit commits to that release. Do not describe the current version as “audited”; say “the project received a 2022 audit that included some SAS code, at specific older revisions, with the listed scope and limits.”

The current repository has a GitHub security policy directing vulnerability reports to `security@matrix.org` and the Matrix disclosure policy. In its [2026 response to reported vodozemac issues](https://matrix.org/blog/2026/02/analysis-of-reported-issues-in-vodozemac/), Matrix confirmed that one Olm 3DH path did not reject all-zero X25519 outputs, while disputing the claimed Matrix confidentiality impact under Matrix's signed-key distribution assumptions. The same response says the SAS/ECIES paths explicitly reject non-contributory outputs and commits to adding the Olm-path check as defense in depth. This is evidence of active security response and also evidence that security claims depend on the surrounding protocol assumptions; it is not a SAS finding or independent audit.

## 7. Mapping to generic bootstrap authentication

`EstablishedSas::calculate_mac` authenticates an arbitrary UTF-8 string `input` under an HMAC key derived from the shared SAS secret and an arbitrary `info` string. The API does not enforce “device-key-only” inputs. Therefore, a canonical bootstrap structure can be encoded injectively (for example, canonical bytes encoded as Base64 text) and MACed unchanged at the cryptographic primitive level. A binary API would be convenient, but is not required to authenticate exact bytes if the text encoding is canonical and checked on both sides.

**Classification:** **safe generic adaptation at the API/construction level, with independent protocol review required before selection.** The transformation preserves the existing DH, HKDF, numeric SAS, and HMAC construction. It changes Matrix-specific identities and key strings to project-specific canonical bootstrap messages, so it must define and validate the exact domain, profile/version, fixed role mapping, ceremony ID, peer identity/key bytes, and security-relevant context. Both participants must know what values they expect; authenticating an asserted identity string does not prove it is true.

If the same DH-derived secret and a properly domain-separated, role- and ceremony-bound MAC authenticate the exact canonical bootstrap bytes on each side, then successful full SAS comparison plus reciprocal MAC verification can authenticate the exact bytes supplied by the other live participant for that ceremony. It does not prove private-key possession, external identity truth, authorization, or durable trust. No long-term secret must be derived from the DH result. After successful bootstrap authentication, the application may discard `EstablishedSas` and establish a different authenticated transport that proves possession of the exact pinned key, such as TLS 1.3 certificate validation and `CertificateVerify`.

This assessment does not claim that Matrix itself specified arbitrary bootstrap profiles or proved their application semantics. A reviewer must verify that generic values replace Matrix context without weakening the transcript binding, role separation, one-attempt rationale, or expected-key validation. The resulting profile's unknown-key-share, downgrade, replay, retry, and partial-human-comparison behavior must be stated and reviewed.

## 8. Required security questions

1. **Does it prevent an active MITM from adaptively choosing its ephemeral key after learning the peer's key?** The Matrix handshake's committing responder cannot choose the committed ephemeral public key after seeing the initiator's revealed key. Commitment binding and the exact message order must be preserved. The vodozemac primitive does not perform the commitment; reuse of just `Sas` does not establish this property.
2. **What is committed before the other ephemeral key is revealed?** SHA-256 of the responder's unpadded-Base64 ephemeral public key concatenated with canonical JSON for the initiator's SAS `start` content. Not an application bootstrap record or a long-term key.
3. **What enters SAS derivation?** The X25519 shared secret is HKDF-SHA-256 input key material, no salt. Matrix's context string includes a domain, ordered initiator and responder Matrix user/device IDs and SAS public keys, plus transaction ID. Generic replacement must specify equivalent exact fields and framing.
4. **What enters the MAC step?** The shared SAS secret derives an HMAC-SHA-256 key via HKDF using an info string. HMAC covers a key string or sorted key-ID list; info binds domain, key owner/sender/receiver identities, transaction, and key identifier/purpose. Generic bootstrap bytes can replace the key string, with reviewed canonical encoding and context.
5. **Can the MAC authenticate arbitrary canonical bootstrap bytes?** Yes at the API level: the Rust API authenticates caller-supplied string bytes and caller-supplied info. Exact binary bytes need an injective canonical text encoding or a small byte-slice wrapper. The profile framing/context still requires review.
6. **Does full SAS comparison plus MAC verification authenticate exact identity/key/context?** It can authenticate the exact bytes supplied by the peer in this session if the full byte sequence is MACed, peer/session/role/domain are bound, expected fields are validated, and both sides complete. It authenticates a claim as supplied, not its external truth.
7. **Is private-key possession established?** No. The SAS DH keys are ephemeral; a MAC over a supplied long-term public key only authenticates that byte string as supplied. A later transport must prove possession if required.
8. **Can the ephemeral DH secret be discarded after pairing?** Yes, after all required reciprocal MAC checks and completion decisions. The ceremony must not retain or export it as an application key.
9. **Must the secret become the application's long-term secret?** No. Matrix SAS verification does not output a reusable shared key; `EstablishedSas` is a temporary verification object.
10. **Can one-shot bootstrap authentication precede a different authenticated transport?** Yes, conceptually. Bind and validate the exact bootstrap data, finish pairing, drop SAS state, then independently establish the selected transport and verify proof of possession of any pinned key.
11. **How are retries, replays, and ceremony separation handled?** Matrix transaction/request IDs, event ordering, timeouts, cancel events, and rejection of unknown/out-of-sequence messages separate a flow. These do not supply project-wide durable retry counters, restart semantics, or protection if consumers reuse IDs. The generic profile needs fresh unique ceremony IDs, terminal-state invalidation, expiry, concurrency/replay rules, and any security-required attempt limits.
12. **Which P1/P2 requirements must change?** None need be weakened. P1's exact authenticated-bootstrap result and explicit no-proof-of-possession limit align with this use. P1 still needs an adopted numeric target (39 bits if choosing Matrix decimal), an aggregate attempt policy and durable enforcement where required, canonical generic context/SID/transcript rules, and a reviewed restart/replay lifecycle. P2's Candidate B selection can change only after the generic vodozemac ceremony passes independent review and these profile gates are answered; preserve all Candidate B findings.

## 9. Dart/Flutter prior art

The Famedly repository has separate `rust/`, `dart/`, and `flutter/` packages plus scripts. Its flow is handwritten Rust wrapper API in `rust/src/bindings.rs`, generated Rust/Dart glue under `dart/lib/generated/` via `flutter_rust_bridge`, then a documented handwritten Dart API in `dart/lib/api.dart`. The public Dart package exposes broad Olm/Megolm operations and SAS primitives. Initialization is explicit; native callers provide a Rust library path as needed. The current Flutter plugin advertises Android, iOS, Linux, macOS, and Windows. Flutter web is not listed; the pure Dart package has web support with a separate WASM build path.

As of the research date, pub.dev lists `vodozemac` 0.8.0 and `flutter_vodozemac` 0.8.1, both AGPL-3.0. The Rust binding crate currently pins `vodozemac` 0.10.0 and `flutter_rust_bridge` 2.13.0 while upstream vodozemac is 0.11.0. This is an observable version lag, not evidence of a defect; it is a supply-chain/release synchronization item consumers would need to track.

Native loading and packaging are deliberate per-platform choices. CocoaPods builds from source through cargokit. Swift Package Manager uses committed iOS XCFramework binaries; macOS uses a `.dylib` because pub.dev packaging does not preserve framework symlinks. The repo requires rebuilding and committing these binaries with the matching Rust change. Web is built separately into a WASM package. This is useful prior art, but too many platform-specific moving parts for an initial SDK that does not need web.

Tests include Dart/native tests on the developer's macOS/Linux/Windows platform and a separate web test script; this does not prove every platform build runs in every PR. The repository contribution notes require regeneration, hand-written wrapper updates, XCFramework rebuilds where relevant, tests, and release synchronization.

## 10. Lessons from dart-vodozemac history

These are documented changelog events, not inferred criticisms.

### Decision / problem

They split pure Dart bindings and a Flutter plugin, generate FFI code from Rust, and keep a handwritten Dart API above generated glue.

### Why it made sense

It lets Dart consumers use the Rust backend without exposing its internal Rust types as the intended Dart surface; the Flutter plugin owns native loading/platform setup.

### What happened

The repo documents regeneration and wrapper editing as separate steps, and binary rebuilding as an additional step for Apple SPM artifacts.

### Lesson for sas-pairing

Keep ceremony/security types and logic in Rust. Generate only the binding glue; manually keep the Dart and C# APIs small and concept-oriented. Avoid publishing a general Olm API that this SDK does not need.

### Decision / problem

Linux and Windows CMake integration initially named the plugin incorrectly; the `0.2.1` changelog fixes it.

### Why it made sense

Flutter plugins need platform registration and library-loading configuration in addition to a Rust library.

### What happened

The wrong plugin name broke those native platform integrations. The following `0.2.2` release also fixes forwarding the WASM path through `init()`.

### Lesson for sas-pairing

Add a minimal consumer smoke test for each shipped target and test explicit library-path/WASM-path behavior if those paths exist. Keep web out of the first release unless a real consumer requires it.

### Decision / problem

Version `0.4.1` was published as a repair because it did not contain `0.4.0`'s changes.

### Why it made sense

The packages have separate Dart and Flutter release metadata and multiple generated/native artifacts to synchronize.

### What happened

The changelog explicitly identifies the broken release and the follow-up correction.

### Lesson for sas-pairing

Build release artifacts from a pinned Rust revision, test the packed packages (not only the working tree), and automate version/source/hash synchronization before publishing.

### Decision / problem

The Flutter package added Swift Package Manager support with prebuilt XCFrameworks while retaining CocoaPods source builds.

### Why it made sense

SwiftPM plugin builds cannot run Cargo; prebuilding avoids making each consumer install Rust and speeds clean builds, while the source path preserves reproducibility/inspection options.

### What happened

Maintainers must commit XCFrameworks in sync with Rust source. The docs warn that mixing old notification-extension CocoaPods configuration with SPM causes duplicate framework embedding. A macOS `.dylib` is needed because pub publishing drops framework symlinks.

### Lesson for sas-pairing

For Apple packages, choose one default packaging path and document one escape hatch. If distributing prebuilt binaries, verify the Rust source revision and binary checksums in CI and test actual SPM and CocoaPods consumers. Do not assume a framework directory survives package publishing intact.

### Decision / problem

Android builds had to adapt to Gradle 9 removing `Project.exec`, and compile against SDK 36 because current AndroidX embeddings require SDK 34 or later.

### Why it made sense

The plugin's source-build path uses Gradle/Cargokit, while Flutter and AndroidX platform baselines move independently.

### What happened

The 0.6.0 changelog records both fixes alongside SPM support.

### Lesson for sas-pairing

Pin/test Rust, Flutter, Gradle, Android Gradle Plugin, NDK, and compile SDK as a compatibility matrix. Keep the native build script small and run an Android sample-app build when these inputs change.

### Decision / problem

The latest package line raises the required Dart/Flutter versions in preparation for Native Assets; the 0.8.1 Flutter release records a macOS fix and adds an optional `libraryPath` to initialization.

### Why it made sense

Native Assets may simplify Dart-managed native library build/load behavior, while explicit paths help applications that package or load the library outside the default plugin path.

### What happened

The package's current metadata requires Dart 3.10 and Flutter 3.38; the 0.8.0/0.8.1 changelogs show the SDK floor and macOS follow-up.

### Lesson for sas-pairing

Treat the Dart toolchain floor and native loading contract as public compatibility policy. Do not adopt Native Assets merely because they exist; first prove that the same package works in required Dart CLI and Flutter apps across target platforms.

### Decision / problem

The pure Dart package supports web by manually building and copying generated WASM assets; Flutter's native plugin targets do not list web.

### Why it made sense

The same Rust source can compile to WASM for a browser, but the loading and packaging pipeline differs from native FFI.

### What happened

Consumers must install the matching Flutter package version, install the matching FRB code generator, build WASM, and copy output into their app. The pure Dart package changelog records a web-worker WASM initialization fix in the FRB upgrade.

### Lesson for sas-pairing

Do not optimize for web in the first release. If demand appears, add it as a separately tested distribution target while retaining the same Rust ceremony and vectors.

## 11. .NET ecosystem assessment

Focused searches found no maintained direct vodozemac C# binding or small maintained .NET SAS package that provides a reusable implementation of the required ceremony. The old Matrix `MatrixAPI` C# repository has no releases and is an API client, not a cryptographic SAS library. Baking Bad's `Matrix.Sdk` 1.0.9 is a Matrix client library for a limited API subset; its repository documents password login and messaging and does not document reusable SAS or E2EE. Matrix's SDK directory marks other older .NET Matrix SDKs obsolete. Rory&::LibMatrix is an active-looking .NET 10 Matrix SDK but AGPL-3.0-only and not evidenced as a reusable SAS implementation. A full client SDK is not an equivalent.

For .NET, wrap the shared Rust ceremony; do not port its cryptography or state machine to C#. `csbindgen` can generate C# declarations for a deliberately small C ABI. UniFFI has a third-party C# generator (`uniffi-bindgen-cs`), but it is version-coupled to UniFFI, currently version 0.x, and its maintainers explicitly say binding stability is still uncertain. Keep it as a prototype candidate, not an assumed stable production boundary.

## 12. Binding architecture alternatives

### A — Famedly Dart bindings plus a separate .NET implementation

**STOP.** Reusing one Rust library for Dart while implementing the ceremony independently in C# creates two protocol/security owners and separate bug, review, and vector maintenance. It also introduces the AGPL binding dependency for Dart while not solving .NET.

### B — full Matrix SDK per language

**RESEARCH ONLY.** A Matrix client SDK supplies useful state-machine prior art but brings Matrix identities, event types, client/network/state dependencies, and unnecessary surface. Different SDKs would likely have different implementation maturity and release/security cadence. It does not create a shared security core unless both bind to one Rust ceremony; the AGPL Dart binding also creates a license boundary the project does not need. Do not import a full client SDK to reuse one verification primitive.

### C — shared Rust `sas-pairing` ceremony on vodozemac

**CANDIDATE.** A Rust crate owns canonical profile bytes, commit/reveal state, negotiation policy, exact SAS derivation context, the MAC message/data contract, lifecycle and errors. It calls vodozemac SAS primitives. Dart and .NET wrap `PairingSession`, `start`, `receive`, outbound messages, SAS display, `confirmMatch`, `reject`, `finish`, and `abort`. This preserves one security/protocol implementation. It still needs independent protocol review before being selected.

### D — separate Dart and .NET bindings to the same Rust ceremony

**CANDIDATE; preferred shape within C.** Each language may have its own idiomatic generated/native binding glue, provided both expose the same Rust ceremony and no protocol decision is reimplemented in either wrapper. Dart may use FRB while .NET uses generated C ABI declarations, or both can use one small explicit C ABI. The language binding choice does not change security ownership.

### Other alternative

No stronger focused cross-language SAS implementation was found. The Matrix Rust SDK crypto state machine is a substantial alternative when an application needs Matrix E2EE, but is not application-neutral and should not be treated as a small SAS SDK.

## 13. Binding technology assessment

| Boundary/tool | Fit here | Main cost/risk |
|---|---|---|
| Explicit stable C ABI | Strong candidate for a small concept API shared by Dart and .NET. Keep opaque session handles and byte buffers/errors narrow; publish ownership rules. | We own the ABI and native library loading; manual API design must avoid unsafe lifetime/ownership mistakes. |
| `flutter_rust_bridge` | Mature, high-level Dart/Rust generation and async support; prior art exists. Good if Flutter is the main consumer. | Flutter/Dart-specific and brings generator/version coupling; .NET still needs another boundary. Avoid exposing vodozemac or Rust implementation types directly. |
| Dart Native Assets | Potential build/load/package mechanism for Rust native code in Dart/Flutter. Not itself a shared Dart/.NET binding interface. | Toolchain and platform support must be demonstrated at the project's minimum SDK versions; it does not solve .NET packaging. |
| Generated Dart FFI | `dart:ffi`/`ffigen` can bind a narrow stable C API and avoid handwritten call marshalling. | Rust library build, symbols, allocation ownership, and target packaging remain ours. |
| Generated C# P/Invoke | Standard .NET P/Invoke over C ABI; `csbindgen` can generate declarations. | Generated signature stability and RID-specific native assets still need release validation. |
| UniFFI + C# generator | Useful alternative if its higher-level type mapping materially simplifies the public boundary. Official UniFFI supports several languages; C# is a third-party external generator. | C# generator is 0.x, version-coupled to UniFFI, and documented as not yet stable. Additional toolchain/IDL surface may not pay for this small API. |

**Recommendation:** prototype one small explicit C ABI with generated Dart and C# declarations before production packaging is frozen. Compare it to the current stable FRB path for Dart and UniFFI C# only if the prototype reveals a concrete ergonomic or maintenance advantage. Keep the public API in Rust concept-level. Generated language glue is acceptable; duplicated ceremony logic is not. Do not design around web.

## 14. Packaging strategy

Start with a Dart package plus a thin Flutter companion only if Flutter plugin metadata/native platform build integration requires it. A single pure Dart package is simpler for Dart-native consumers; the Famedly split shows that platform registration, Apple packaging, and Flutter-specific loading can justify a companion. Choose after a sample consumer build, not by copying package layout.

Publish one .NET managed package with RID-specific native Rust binaries (or a small native runtime package plus a managed facade only if NuGet packaging requires that split). For Apple/Android/Windows/Linux support, build reproducible platform artifacts in CI from the same tagged Rust source. Prefer prebuilt binaries for consumer simplicity; offer source-build instructions for audit/reproducibility and emergency platform support. Never accept unverified binary/source drift. Pin toolchains and record checksums/source commit in release metadata.

| Target | Recommended first-release stance | Cost to own |
|---|---|---|
| Windows | Required consumer target; package native runtime and test both Dart and .NET loads. | MSVC/Rust target, DLL search path and NuGet RID behavior. |
| Android | Required for Flutter mobile; build/ship `.so` per ABI and test Gradle/NDK sample. | ABI matrix, Gradle/AGP/NDK and Android page-size/toolchain changes. |
| iOS | Required if mobile Dart/Flutter is in scope; choose SPM prebuilt framework or source build and test on Xcode. | Apple signing/architectures, XCFramework/source sync, framework layout. |
| macOS | Ship/test dynamic library and loader path; preserve required architectures. | dylib/framework layout, notarization/load paths if applicable. |
| Linux | Ship/test shared library and CMake integration where Flutter uses it. | glibc baseline, CMake/loader search paths and distribution matrix. |
| Web/WASM | Defer. | Distinct build/runtime/security review path, not needed for Skyrim clients. |

## 15. Licensing implications

The Rust `vodozemac` crate is Apache-2.0. The `famedly/dart-vodozemac` Dart and Flutter packages are AGPL-3.0. The project can depend on the Apache crate through its own Rust wrapper and distribute the resulting library subject to its dependency notices; that is a materially different dependency boundary from depending on or copying the AGPL Dart bindings. Do not copy, paste, translate, or derive implementation code from those bindings. Their public API, build outcomes, changelogs, packaging decisions, and documented bugs are useful prior art only.

Relevant binding tool licenses checked: `flutter_rust_bridge` is MIT; `csbindgen` is MIT; Mozilla UniFFI and the NordSecurity `uniffi-bindgen-cs` generator are MPL-2.0. Confirm the exact pinned version's license and generated-output terms before packaging. This records architecture consequences, not legal advice.

## 16. Maintenance ownership comparison

Qualitative ongoing burden (low / medium / high):

| Architecture | Cryptographic maintenance | Protocol maintenance | Native build | Dart | .NET | Security review | Release |
|---|---:|---:|---:|---:|---:|---:|---:|
| Candidate B own implementation | High | High | Medium | Medium | Medium | Very high | High |
| Existing Dart vodozemac + separate .NET | Medium | High in two cores | Medium | Medium | High | Very high | High |
| Full Matrix SDK per language | Medium | Medium but Matrix-coupled | High | High | High | High | High |
| Shared Rust core + vodozemac + wrappers | Low–medium (upstream dependency review and updates) | Medium–high (our generic ceremony remains ours) | High | Medium | Medium | High before selection, then ongoing focused review | High |

Ownership detail for the candidate shared-core architecture:

- **Cryptographic maintenance:** upstream owns vodozemac primitives; sas-pairing tracks releases, audits dependency changes, configures the required features, handles advisories, and reviews any API/algorithm changes.
- **Protocol maintenance:** sas-pairing owns the full generic ceremony, transcript encoding, roles/SID, negotiation policy, confirmation, cancellation, expiry, retry policy, and its security argument.
- **Native build maintenance:** sas-pairing owns cross-target Rust builds, C ABI, symbols, memory ownership, ABI compatibility, and source/binary synchronization.
- **Dart maintenance:** own the idiomatic API, packaging, supported SDK floor, native library loading, async/error mapping, and tests; do not own cryptography.
- **.NET maintenance:** own the idiomatic API, P/Invoke/native asset packaging, RID resolution, exception/lifetime mapping, and tests; do not own cryptography.
- **Security review burden:** reviewers still need to review the new generic ceremony and FFI boundary. Upstream primitive reuse narrows but does not remove that burden.
- **Release burden:** synchronize Rust crate, generated wrappers, native binaries, package metadata, supported target matrix, and security advisories.

## 17. Candidate B comparison and decision matrix

Candidate B remains valuable: it has a project-specific formal result for authenticating exact role-positioned messages and a clearer connection to the current selected profile. Reuse is attractive only if it reduces cryptographic implementation ownership without importing incompatible Matrix assumptions. Keep Candidate B as research reference and fallback until the reviewer accepts the generic SAS mapping. Do not mark it obsolete merely because vodozemac is easier to bind.

| Option | Security ownership | Dart | .NET | Skyrim UX | License | Maintenance | Recommendation |
|---|---|---|---|---|---|---|---|
| Candidate B own implementation | We own commitment, SAS, MAC, and ceremony construction | Wrapper | Wrapper | Numeric form still a profile decision | Project MIT OR Apache; dependencies depend on instantiation | Highest crypto/review burden | **CANDIDATE / fallback** while current selection remains; do not implement without its open instantiation/review gates |
| Existing Dart vodozemac + separate .NET | Two security/protocol paths | Existing AGPL binding | Separate/no direct equivalent | Can display Matrix numeric SAS | Apache Rust underneath, AGPL Dart package | Duplicated behavior and review | **STOP** |
| Full Matrix SDK per language | Matrix-specific SDKs own different ceremony layers | Famedly binding/client SDK | Matrix C# SDKs exist, no focused reusable core verified | Matrix decimal can fit | Varies; Famedly AGPL, some C# SDKs MIT/AGPL | Large API surface, skew, matrix stack coupling | **RESEARCH ONLY** |
| Shared Rust core + vodozemac | Upstream primitive plus our single Rust ceremony | Thin generated wrapper | Thin generated wrapper | Specified numeric SAS, 39 bits | Apache dependency compatible with project choices; own wrappers | Concentrated protocol + multi-target native builds | **CANDIDATE; review required** |
| Matrix `matrix-sdk-crypto` Rust state machine | Matrix code owns full Matrix ceremony; extraction would still be ours | Bind to Rust | Bind to Rust | Numeric SAS supported | Apache-2.0 | Large Matrix-specific dependencies and behavior | **RESEARCH ONLY** unless consumer needs Matrix E2EE |

## 18. Recommendation and remaining unknowns

**Recommendation: B — promising but review required.** Continue research toward a single Rust pairing core that calls vodozemac. Prefer Matrix's existing decimal SAS unchanged. The generic MAC input is supported by the API and can cover exact canonical bootstrap bytes without changing the crypto construction. However, do not select the final architecture or begin production ceremony code until an independent reviewer confirms the generic transcript/identity mapping and the project resolves its P1 attempt, replay, and lifecycle gates.

The next design review should answer:

- Exact canonical bootstrap format and validation rules for identity, key, profile/version, ceremony ID, roles, and application context.
- Exact commit input and hash behavior for generic start/transcript data; the Matrix primitive API does not supply the commit state machine.
- Whether 39 bits satisfies the project's justified numeric comparison target, and the required global/peer attempt budget, cooldown, and persistence behavior.
- Exact uniqueness/entropy and restart/replay rules for ceremony IDs, concurrent flows, expiration, cancellation, late messages, and terminal handles.
- Whether P1's bilateral done/completion language should be implemented as a generic explicit final message rather than inferred from two local UI confirmations and MAC exchange.
- Current 0.11.0 audit/release evidence and supported-upstream policy; current Matrix security context includes the 2026 Olm-path report.
- Small stable C ABI prototype, Dart/Flutter Native Assets support floor, C# generator maturity, and supported runtime identifier matrix.
- Binary reproducibility, signing/checksum and vulnerability-response process for native package releases.

## 19. Sources

Primary sources, checked 2026-09-28 unless a dated report/release is noted:

### Project requirements

- [`docs/threat-model.md`](threat-model.md), [`docs/protocol-status.md`](protocol-status.md), [`docs/architecture.md`](architecture.md), and [`docs/construction-selection.md`](construction-selection.md) in this repository.

### Rust vodozemac and Matrix protocol

- [vodozemac SAS API](https://docs.rs/vodozemac/latest/vodozemac/sas/index.html), [`Sas`](https://docs.rs/vodozemac/latest/vodozemac/sas/struct.Sas.html), [`EstablishedSas`](https://docs.rs/vodozemac/latest/vodozemac/sas/struct.EstablishedSas.html), and [`SasBytes`](https://docs.rs/vodozemac/latest/vodozemac/sas/struct.SasBytes.html).
- [vodozemac 0.11.0 SAS source](https://github.com/matrix-org/vodozemac/blob/main/src/sas.rs), [Cargo.toml](https://github.com/matrix-org/vodozemac/blob/main/Cargo.toml), and [release history](https://github.com/matrix-org/vodozemac/releases).
- [Matrix Client-Server spec v1.18: SAS ceremony](https://spec.matrix.org/v1.18/client-server-api/#short-authentication-string-sas-verification), [decimal SAS](https://spec.matrix.org/v1.18/client-server-api/#sas-method-decimal), [MAC calculation](https://spec.matrix.org/v1.18/client-server-api/#mac-calculation), and [SAS HKDF](https://spec.matrix.org/v1.18/client-server-api/#sas-hkdf-calculation).
- [Matrix Rust SDK SAS state machine source](https://matrix-org.github.io/matrix-rust-sdk/src/matrix_sdk_crypto/verification/sas/sas_state.rs.html).

### Audit and security

- [Least Authority, vodozemac Security Audit Report (2022-03-30)](https://leastauthority.com/static/publications/LeastAuthority-Matrix_vodozemac_Final_Audit_Report.pdf), including target revisions, scope, issues, remediation, and unresolved findings.
- [Matrix announcement of the independent audit](https://matrix.org/blog/2022/05/16/independent-public-audit-of-vodozemac-a-native-rust-reference-implementation-of-matrix-end-to-end-encryption/).
- [vodozemac GitHub security policy](https://github.com/matrix-org/vodozemac/security/policy), [Matrix security disclosure policy](https://www.matrix.org/security-disclosure-policy/), and [Matrix's 2026 analysis of reported vodozemac issues](https://matrix.org/blog/2026/02/analysis-of-reported-issues-in-vodozemac/).

### Dart prior art and history

- [famedly/dart-vodozemac repository and contribution/build instructions](https://github.com/famedly/dart-vodozemac), [Dart changelog](https://github.com/famedly/dart-vodozemac/blob/main/dart/CHANGELOG.md), [Flutter changelog](https://github.com/famedly/dart-vodozemac/blob/main/flutter/CHANGELOG.md), [Flutter packaging guide](https://github.com/famedly/dart-vodozemac/blob/main/flutter/README.md), and [Rust Cargo manifest](https://github.com/famedly/dart-vodozemac/blob/main/rust/Cargo.toml).
- [pub.dev `vodozemac` 0.8.0](https://pub.dev/packages/vodozemac) and [pub.dev `flutter_vodozemac` 0.8.1](https://pub.dev/packages/flutter_vodozemac).

### .NET and binding generators

- [Matrix.org SDK directory](https://www.matrix.org/ecosystem/sdks/), [Baking Bad Matrix .NET SDK](https://github.com/baking-bad/matrix-dotnet-sdk), [Matrix.Sdk on NuGet](https://www.nuget.org/packages/Matrix.Sdk), and [VRocker MatrixAPI](https://github.com/VRocker/MatrixAPI).
- [flutter_rust_bridge](https://github.com/fzyzcjy/flutter_rust_bridge) and [its Dart Native Assets quickstart](https://cjycode.com/flutter_rust_bridge/guides/integrate/binary-dependencies/native-assets.html).
- [Dart FFI](https://dart.dev/interop/c-interop), [Dart Native Assets](https://dart.dev/tools/hooks), [`ffigen`](https://pub.dev/packages/ffigen), [`csbindgen`](https://github.com/Cysharp/csbindgen), [UniFFI](https://github.com/mozilla/uniffi-rs), and [NordSecurity `uniffi-bindgen-cs`](https://github.com/NordSecurity/uniffi-bindgen-cs).
