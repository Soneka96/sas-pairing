# P7 Owner Decisions

Stable owner decisions taken during P7. IDs `P7-D-NNN` are never reused. A decision records policy and its rationale; the [ABI contract](abi-contract.md) states the resulting normative ABI rules, and the [P7 package README](README.md) tracks implementation and evidence.

| Decision | State |
|---|---|
| [P7-D-001 — Native runtime, handle, and fatal containment unit](#p7-d-001--native-runtime-handle-and-fatal-containment-unit) | Decided P7.1; implemented in P7.1 |

## P7-D-001 — Native Runtime, Handle, and Fatal Containment Unit

- **Inputs:** [P6-D-004](../p6-remediation/decisions.md#p6-d-004--native-panic-containment-policy) (native panic containment, including the P6.4.1 payload-disposal rule, item 14) leaves the exact containment unit to P7's handle design; [P6-D-002](../p6-remediation/decisions.md#p6-d-002--f-003-owner-session-policy) forbids any same-process accounting reset; the [P7 roadmap](../../roadmap/P7-native-abi.md) lists the mandatory handoff.
- **Decision (owner-selected):**
  1. **One runtime per OS process.** At most one sas-pairing native runtime is active per OS process. A second create while one is active returns `SAS_PAIRING_ALREADY_INITIALIZED` and does not replace it. Later increments may place several pairing authorities inside the runtime; P7.1 implements none.
  2. **The runtime is the fatal-containment unit,** and its fatal state is process-wide native ABI state. P6-D-004's "affected native context" is therefore the whole native ABI of the process.
  3. **Normal lifecycle:** process → `sas_pairing_runtime_create` → runtime handle → later P7 operations → `sas_pairing_runtime_destroy`. After a normal destroy a new runtime may be created in the same process, and it receives a new handle.
  4. **Caught panic → permanent fatal.** When the ABI's containment boundary catches a Rust panic, the process's native ABI state becomes permanently fatal: no new runtime or normal core operation can start (they return `SAS_PAIRING_FATAL` without entering the core), destroy stays allowed, and recovery requires restarting the OS process. There is no "clear fatal", "reset runtime", or registry-clearing API, in production or in tests.
  5. **Destroy is the cleanup path.** Fatal state does not prevent destroy. Destroy invalidates the handle first, then performs best-effort runtime destruction. It never clears fatal state, starts protocol work, creates fresh accounting, or re-registers an authority. After fatal + destroy, create still returns `SAS_PAIRING_FATAL` until process restart.
  6. **Opaque `uint64_t` handles.** `sas_pairing_runtime_t` is `uint64_t`; `0` is never valid. Handles are process-local and opaque: not pointers, network identities, security secrets, authority identities, or protocol identifiers. They come from one monotonic, process-lifetime counter and are never reused within one OS process, so a destroyed handle can never alias a later runtime. If the counter would wrap, creation fails closed (`SAS_PAIRING_HANDLES_EXHAUSTED`) instead of reusing a value. There is no generation-reset API.
  7. **Runtime creation is infrastructure only.** It does not call `TrustedAuthority::register`, consume an opportunity, acquire the authority OS lock, start a listener, create a ceremony, or generate protocol randomness. Authority lifecycle belongs to P7.2.
- **Why conservative:** P6-D-004 requires a caught panic to poison the context that owns the panicking core state, and P6-D-002 forbids any same-process reset of authority accounting. A process-wide fatal unit satisfies both directly: no handle juggling (destroy and re-create, a second runtime, re-registration) can reach fresh accounting after a panic, and no partially updated Rust state is used again. The cost (one fatal event disables the native ABI for the rest of the process) is accepted because a caught panic is a catastrophic internal failure, never an ordinary error.
- **Wire, cryptography, ceremony authentication, result semantics, deadlines, and accounting:** unchanged. P7 wraps the frozen candidate.
- **Status:** decided by the owner for P7.1, 2026-10-02; implemented in P7.1 (`core/src/abi`). The P6-D-004 exit test through a real core-entering ABI operation remains open until later P7 increments add one ([README](README.md#mandatory-p6-handoff)).
