# P10 — Consumer Integration

## Status

🔵 **In progress — P10.1 complete.** P10 runs on the one branch `feature/p10-consumer-integration`, started from `main` `b938016` (the merge of the P9 pull request #15). P10.1 (consumer boundary and ABI-v1 / portability assessment, owner decision [P10-D-001](../docs/p10-consumer-integration/decisions.md#p10-d-001--consumer-boundary-platform-boundary-and-portability-discipline)) is complete and awaits independent review; **P10.2 starts only after that review accepts P10.1.** One P10 pull request is opened only after P10 closes. DovahLink changes, when they start, follow DovahLink's own branch and pull-request workflow in its own repository. The P10 package is [docs/p10-consumer-integration](../docs/p10-consumer-integration/README.md).

| Increment | Title | State |
|---|---|---|
| P10.1 | Consumer Boundary + ABI-v1 / Portability Assessment | ✅ Complete (awaiting independent review) |
| P10.2 | Canonical DovahLink Bootstrap Mapping + Current Authentication / Trust Audit | 🔵 Next, after P10.1 is accepted |
| P10.3 | Host Integration (.NET, Windows) | 🟡 Planned |
| P10.4 | Dart / Flutter Client Integration (Windows) | 🟡 Planned |
| P10.5 | SAS Comparison + Ceremony-Bound Approval | 🟡 Planned |
| P10.6 | DovahLink Authorization + Durable Trust | 🟡 Planned |
| P10.7 | Normal Trusted Reconnect | 🟡 Planned |
| P10.8 | Integration Closure + Android Portability Report | 🟡 Planned |

## Goal

Integrate the experimental `sas-pairing` packages into their original consumer, DovahLink, on Windows, with a consumer and domain boundary that stays platform-neutral where reasonably possible, and end with evidence-based answers about Android portability.

## Why this phase exists

The library is meant to be reused without making one application's policy part of the protocol. A real consumer is the test of that boundary: it shows whether the frozen ABI and the wrappers are usable as built, and where the line between protocol evidence and application trust actually falls.

## Inputs / prerequisites

The frozen native ABI v1 ([P7](P7-native-abi.md)), the Dart package ([P8](P8-dart-package.md)) and the .NET package ([P9](P9-dotnet-package.md)), with Windows x64 as the only pairing platform; DovahLink's current Host, SDK, and app, read at `main` `4a69ee5057029878200b6e16614f67a136e3e032` for P10.1.

## Phase rules (P10-D-001)

- **Windows implementation now.** P10 implements and claims Windows x64 only. No Android code, packaging, carrier, or platform channel.
- **Platform-neutral consumer boundary where practical.** DovahLink domain and trust services see consumer-level pairing concepts, never WinSock, `SafeSocketHandle`, listener tokens, native handles, FFI pointers, or DLL paths.
- **Concrete Android blockers recorded; speculative portability work deferred.** No ABI v2, new export, or platform abstraction from speculation; an ABI change needs a concrete P10 gap and an owner decision.
- **Library / consumer split.** `sas-pairing` owns the protocol, its cryptography, SAS, transcript, `ceremony_identity`, authenticated Bootstrap and result data, accounting, and failure semantics. DovahLink owns identities and keys, proof of possession, pending authorization, Pair / Reject / Block, KnownHost / KnownDevice, reconnect, sessions, discovery, and UX.
- **Rolling horizon.** P10.1 and P10.2 are planned to execute; P10.3–P10.8 stay milestone-level enough for P10.2's findings to refine them. P11 is a milestone only ([roadmap](README.md#p11--android--cross-platform-native-support-milestone-only)); nothing beyond it is planned.

## Increments

### P10.1 — Consumer Boundary + ABI-v1 / Portability Assessment

1. **Goal.** Decide the consumer boundary and the platform boundary before integration, assess whether ABI v1 is sufficient for the real Windows integration, classify every integration dependency as PN / WE / AB, and plan P10.
2. **Why it exists.** Integrating around the current Windows implementation without a boundary would leak Windows mechanics into DovahLink's domain, or DovahLink policy into the library.
3. **Scope.** Read the actual `sas-pairing` sources and decisions (P6–P9) and DovahLink (read only); record P10-D-001; the [consumer boundary](../docs/p10-consumer-integration/consumer-boundary.md); the [portability assessment](../docs/p10-consumer-integration/portability-assessment.md) with the ABI-v1 verdict, experiments, Android blocker register, and closure questions; this roadmap; current-state documents.
4. **Out of scope.** Any production code (core, Dart, .NET); any DovahLink change; Bootstrap encoding; the DovahLink authentication verdict; Android; ABI changes; a P10 pull request.
5. **Security invariants.** PairingResult is local completion only; `ceremony_identity` binds the exact attempt and is not identity; MATCH is not Pair; proof of possession, Pair / Reject / Block, durable trust, and reconnect stay with DovahLink; network location is never identity.
6. **Main areas / files.** `docs/p10-consumer-integration/` (README, decisions, consumer boundary, portability assessment); this file; `roadmap/README.md`; `README.md`; `docs/protocol-status.md`; `ai/context/project.md`; the status guard `tooling/tests/test_p9_distribution_contract.py`.
7. **Tests / evidence.** Source and document inspection with citations; diff gates (`core`, `dart/lib`, `dotnet/src`, the header) empty; repository consistency (required files, Markdown links and anchors, tooling tests); the full CI on the pushed head.
8. **Exit criteria.** P10-D-001 recorded; ABI-v1 verdict selected (**ABI-V1-P10-B**); PN / WE / AB classification, experiments, Android register, closure questions, owner-decision register, and this plan written; diff gates empty; CI green; branch pushed, not behind `main`, no pull request.
9. **STOP conditions.** A DovahLink Windows requirement that ABI v1 cannot express safely; a boundary that needs DovahLink policy in the library; result data insufficient for authorization; `ceremony_identity` unable to bind an attempt; a needed capability reachable only through private FFI; a DovahLink domain that inherently needs native objects; a materially different repository state. None was hit ([portability §17](../docs/p10-consumer-integration/portability-assessment.md#17-stop-conditions-review)).
10. **Dependencies.** P9 merged (PR #15, `main` `b938016`).

### P10.2 — Canonical DovahLink Bootstrap Mapping + Current Authentication / Trust Audit

1. **Goal.** Audit DovahLink's **current** authentication and trust and issue exactly one verdict (✅ WORKS AS-IS, 🟡 WORKS WITH TARGETED CHANGES, or 🔴 DOES NOT PROVIDE ADEQUATE AUTHENTICATION — REPLACEMENT REQUIRED); freeze the deterministic canonical Bootstrap encoding for the Host and the Client; freeze the proof-of-possession boundary.
2. **Why it exists.** The Bootstrap must carry the identity material DovahLink later proves possession of, and no integration should be built on an authentication model nobody has audited.
3. **Scope.** Answer audit questions A–W and X–AB of [consumer boundary §14](../docs/p10-consumer-integration/consumer-boundary.md#14-p102-authentication-audit-contract) from DovahLink source and tests; specify `applicationIdentity`, `keyAlgorithm`, `publicKey`, and `sharedContext` bytes with worked vectors; decide or bring to the owner P10-OD-04, -05, -06 (model), -10, -13, -14 ([register](../docs/p10-consumer-integration/decisions.md#pending-owner-decisions)); test the chosen peer-Bootstrap access (decode or exact compare) against the frozen vector (E-13); refine P10.3–P10.8.
4. **Out of scope.** Implementing adapters, keys, proof of possession, UI, or trust changes; changing `sas-pairing` code or the ABI; any DovahLink change unless the owner separately authorizes a documentation change there.
5. **Security invariants.** No JSON or other convenience serializer chosen without analysis; exact bytes, never normalized; `sharedContext` independently supplied by each side and never copied from the peer; no secrets in Bootstrap fields; the verdict is not presumed.
6. **Main areas / files.** `docs/p10-consumer-integration/` (an authentication audit, the Bootstrap mapping, new P10 decisions); DovahLink read only: `host/DovahLink.Host/{Pairing,Trust,Identity,Client/Authentication}`, `sdk/dart/dovahlink_client/lib/src/internal/{authentication,pairing,reconnect}`, `…/persistence`, `ai/context/security/`, `ai/context/protocol/security.md`.
7. **Tests / evidence.** Every audit answer cited to source or tests; the encoding specified byte by byte with vectors; E-05, E-06, E-07, E-13 results; consistency checks.
8. **Exit criteria.** The verdict recorded; the encoding and the proof-of-possession boundary frozen by owner decision; the listed owner decisions made or explicitly re-scheduled; P10.3–P10.8 refined from the findings.
9. **STOP conditions.** DovahLink identity material cannot be represented within the Bootstrap bounds; proof of possession cannot be placed outside `sas-pairing`; the verdict is REPLACEMENT REQUIRED with a scope the owner has not accepted into P10; E-13 shows no safe way to read peer fields (then report an ABI-V1-P10-C candidate, design nothing).
10. **Dependencies.** P10.1 accepted by independent review.

### P10.3 — Host Integration (.NET, Windows)

1. **Goal.** Integrate the .NET `SasPairing` package into the DovahLink Host behind a Windows infrastructure adapter that owns native loading, runtime / authority / host lifetime, the pairing listener's creation and handoff, drive scheduling, event translation, and deterministic cleanup, and hands translated evidence to DovahLink services.
2. **Why it exists.** The Host is the trust authority; its adapter is the first real consumer of the .NET package.
3. **Scope.** The adapter and its owner service (P10-OD-01, -02); the pairing listener's exposure and endpoint (P10-OD-11); artifact consumption (P10-OD-12); authority scope behaviour (E-11); experiments E-03 and E-08.
4. **Out of scope.** The comparison UX and Skyrim decision path (P10.5); Pair / Reject / Block and trust persistence (P10.6); the client.
5. **Security invariants.** No Windows or native type in Host domain or trust services; one logical owner of the runtime tree; `FATAL` → supervised Host process restart, never a library reload; every result read once into evidence and disposed; statuses never become trust verdicts; no endpoint becomes identity.
6. **Main areas / files.** DovahLink `host/DovahLink.Host` (a new infrastructure area chosen by P10-OD-01; `Composition/`; `Program.cs`), `host/DovahLink.Host.Tests`, DovahLink packaging tooling for the native DLL; `docs/p10-consumer-integration/` here for the record.
7. **Tests / evidence.** Real-DLL Host tests: register, attach, drive, ceremony against a test peer, detach, shutdown while driving, `FATAL` path; lock-contention and cadence measurements (E-03); architecture tests (E-08); two Host processes with one scope (E-11).
8. **Exit criteria.** The adapter runs a real ceremony to a local result inside the Host and translates it into evidence; E-03, E-08, E-11 pass; owner decisions -01, -02, -11, -12 made.
9. **STOP conditions.** The owner model cannot keep the Host responsive; any domain service needs a native or socket type; artifact consumption cannot meet DovahLink's repository rules.
10. **Dependencies.** P10.2 verdict and mapping.

### P10.4 — Dart / Flutter Client Integration (Windows)

1. **Goal.** Integrate the Dart `sas_pairing` package into the DovahLink client (Windows desktop) with one integration owner (runtime, authority, host, drive, runs, presentation, results) that translates into SDK and Flutter state; UI gets domain pairing state, never FFI resources.
2. **Why it exists.** The client is the other endpoint; its owner-isolate and connection-topology questions have no evidence yet.
3. **Scope.** Experiment E-02 first (the in-process loopback relay for outbound reachability, P10-OD-09); the WinSock listener creation in the Windows adapter; the owner isolate and message façade (P10-OD-03, E-04); placement in the SDK (P10-OD-01); E-08 architecture tests.
4. **Out of scope.** Android; the final comparison UX (P10.5); Pair and trust (P10.6).
5. **Security invariants.** No `SasPairing*`, socket, handle, pointer, or DLL path above the SDK adapter; one native image, initialized by one isolate; the relay never parses, builds, or alters a frame; no frame parsing except the P10.2-approved Bootstrap access.
6. **Main areas / files.** DovahLink `sdk/dart/dovahlink_client` (its Windows entry library and platform ports), `app/lib/features/pairing` (state mapping only), `app/windows` packaging.
7. **Tests / evidence.** E-02 report (foreign local connections, deadlines, failures); E-04 UI timing during drives; a real ceremony between the real client and the real Host through both adapters; architecture tests.
8. **Exit criteria.** E-02 and E-04 pass; the client reaches a local result against the real Host; no FFI type above the adapter.
9. **STOP conditions.** E-02 fails with no safe adapter (report an ABI-V1-P10-C candidate with its five required elements, design nothing); the owner isolate cannot be kept off the UI isolate.
10. **Dependencies.** P10.2; the Host pairing endpoint from P10.3.

### P10.5 — SAS Comparison + Ceremony-Bound Approval

1. **Goal.** Replace the six-digit code UX with compare-SAS on both sides and bind MATCH, MISMATCH, and CANCEL (and rejection) to the exact `ceremony_identity`; never `approveClient(clientId)` as attempt authority.
2. **Why it exists.** The SAS is compared, not typed; the human decision is part of the security system and must target the ceremony that was shown.
3. **Scope.** The Skyrim display and decision path through the adapter IPC (P10-OD-08, E-14); the Flutter comparison screen; the "completed locally" and "pending Pair" states (P10-OD-06); the legacy cutover (P10-OD-07); truthful `BUSY` / `EXHAUSTED` UX (E-12); the first full end-to-end ceremony (E-01).
4. **Out of scope.** Pair / Reject / Block persistence (P10.6); reconnect (P10.7).
5. **Security invariants.** The full SAS is shown on both sides; no automatic or partial comparison; MATCH is not Pair; a decision for one attempt never authorizes another; the SAS is not treated as a secret or a code.
6. **Main areas / files.** DovahLink `adapter/ipc`, `host/DovahLink.Host/Adapter/Ipc`, Papyrus or console glue as decided, `app/lib/features/pairing`, the SDK pairing API.
7. **Tests / evidence.** Stale and foreign identity decisions refused; mismatch, cancel, timeout, and lost-final-ACK paths; both screens show the same SAS for the same ceremony; accessibility and display checks.
8. **Exit criteria.** A real Skyrim + Flutter ceremony with human comparison on both sides; E-01, E-12, E-14 pass; the six-digit flow handled as the owner decided.
9. **STOP conditions.** No safe Skyrim decision path; a UX that would let MATCH imply Pair.
10. **Dependencies.** P10.3, P10.4.

### P10.6 — DovahLink Authorization + Durable Trust

1. **Goal.** After `sas-pairing` evidence: perform the proof of possession P10.2 requires, create a pending DovahLink authorization for the exact attempt, let Pair / Reject / Block decide it, and let Pair alone establish durable KnownHost / KnownDevice trust.
2. **Why it exists.** A `PairingResult` is local evidence, never the trust verdict; DovahLink's selected architecture puts the trust decision here.
3. **Scope.** Pending authorization model and storage; Pair / Reject / Block (including Block before completed trust, as DovahLink decides); KnownHost and KnownDevice bound to the authenticated key; asymmetric completion handling; administrative fences (revoke, block, reset during a pending attempt).
4. **Out of scope.** Normal reconnect (P10.7); `sas-pairing` changes.
5. **Security invariants.** No trust from a result alone; either side may be the only result holder and DovahLink must tolerate it; trust binds the key the ceremony authenticated and the identity whose possession was proved; stale approvals rejected.
6. **Main areas / files.** DovahLink `host/DovahLink.Host/{Pairing,Trust}`, SDK persistence and pairing services, app pairing state.
7. **Tests / evidence.** Initiator-only and Responder-only completion; stale approval; Reject and Block; revoke or reset during pending; crash and restart between evidence and Pair; E-10.
8. **Exit criteria.** Durable trust only after Pair and the required proof; every asymmetric case handled; E-10 passes.
9. **STOP conditions.** Trust would need to be written before proof of possession or Pair; asymmetric completion cannot be handled without a bilateral-commit assumption.
10. **Dependencies.** P10.2 verdict; P10.5.

### P10.7 — Normal Trusted Reconnect

1. **Goal.** Prove that already-trusted peers reconnect without SAS, through DovahLink authentication with proof of possession, into a fresh runtime session, with revoke and block preserved and network location never used as identity.
2. **Why it exists.** SAS establishes trust; it must not become the reconnect mechanism.
3. **Scope.** The reconnect path P10.2 settled (unchanged, targeted change, or replacement); E-09.
4. **Out of scope.** New pairing behaviour; `sas-pairing` changes.
5. **Security invariants.** No `sas-pairing` runtime, authority, or listener in reconnect; a fresh session per connection; revoked and blocked peers rejected with their typed outcomes; endpoint changes do not change identity.
6. **Main areas / files.** DovahLink Host hello and authentication, SDK reconnect and authentication services.
7. **Tests / evidence.** Reconnect with the pairing stack absent; endpoint and port change; revoked, blocked, stale credential; Host, client, and Skyrim restarts.
8. **Exit criteria.** E-09 passes and every case above is evidenced.
9. **STOP conditions.** Reconnect would require SAS or `sas-pairing` state; trust would depend on address or port.
10. **Dependencies.** P10.6.

### P10.8 — Integration Closure + Android Portability Report

1. **Goal.** Close P10 with end-to-end integration evidence, a security and readiness assessment of the integration, answers to the frozen closure questions, and the Android portability classification.
2. **Why it exists.** P10's evidence is the input to P11 and to any later readiness decision.
3. **Scope.** End-to-end evidence; answers to [portability §13](../docs/p10-consumer-integration/portability-assessment.md#13-p10-closure-portability-questions-p108) questions A–N; exactly one classification (A, B, or C); the Android blocker register updated from evidence; P10-OD-15 (generic examples) decided; the final P10 closure and the one P10 pull request (opened by the owner after review).
4. **Out of scope.** Android implementation; ABI changes (a C classification triggers an owner decision, not a design).
5. **Security invariants.** Claims stay within the evidence: experimental, not production-approved; no Android support claimed.
6. **Main areas / files.** `docs/p10-consumer-integration/` (final closure), roadmap and status documents.
7. **Tests / evidence.** Every experiment E-01–E-14 resolved; full CI on the final head; DovahLink evidence referenced by exact commit.
8. **Exit criteria.** Classification selected with evidence; closure documents complete; CI green; branch ready for the owner's pull request.
9. **STOP conditions.** An experiment unresolved; a contradiction between the integration and P10-D-001.
10. **Dependencies.** P10.1–P10.7.

## Out of scope (whole phase)

Moving DovahLink-specific trust, reconnect, discovery, authorization, or application policy into `sas-pairing`; Android or any non-Windows implementation; ABI evolution from speculation; production-security or release approval.

## Security invariants (whole phase)

Human comparison remains part of the security system. Pairing never silently grants durable trust or application authorization. A `PairingResult` is local completion only. Network location is never identity.

## Exit criteria (whole phase)

P10.1–P10.8 complete; the integration uses the reviewed packages without weakening protocol-required constraints or implying unsupported identity or context guarantees; P10.8's portability classification recorded.

## STOP conditions (whole phase)

Stop if integration requires weakening a security requirement, moving consumer policy into the protocol boundary, or an ABI change that has not been decided by the owner.

## What this unlocks

The P11 milestone (Android / cross-platform native support), informed by P10.8's evidence, and later a separate readiness assessment. P10 completion alone does not authorize 1.0.
