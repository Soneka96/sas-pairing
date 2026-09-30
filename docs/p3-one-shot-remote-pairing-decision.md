# Owner-selected remote pairing session safety policy

**OWNER-SELECTED SESSION POLICY — 10 EXPOSED OPPORTUNITIES PER PROCESS/SESSION PER CORE. PAIR-COUNTING REMEDIATION DOCUMENTED — PER-PAIR `2^-39` PREMISE STILL REQUIRES VERIFICATION. VODOZEMAC FAVORED, NOT SELECTED. P4 BLOCKED.**

This is the current owner decision for generic remote pairing safety. It does not select a cryptographic construction, establish its security, or authorize implementation. The larger durable-epoch and eight-Responder-slot rules retained in the vodozemac candidate are historical candidate text and do not describe the current owner policy.

## Remote ceremony policy

- **One live exposed ceremony:** At most one exposed remote pairing ceremony is active per pairing authority in total, across Initiator and Responder roles, connections, and relevant instances sharing that authority. A competing request receives no second SAS candidate and is refused before exposure.
- **Explicit retry only:** There is no automatic retry, resume, or reconnect continuation. Every new exposed opportunity requires a fresh explicit local user pairing action.
- **Terminal irreversibility (I1):** A terminated ceremony cannot later succeed. Release the active-ceremony guard only after irrevocable terminal state. Delayed messages, callbacks, reconnects, duplicate or reordered packets, and delayed acknowledgements cannot revive it.
- **SAS lifetime (I2):** A SAS is valid/comparable only while its ceremony is live. Termination immediately invalidates the SAS and consumer/UI state; stale approval cannot target it.
- **Network locality is not trust:** LAN, Wi-Fi, Ethernet, private IP addresses, discovery proximity, and loopback remain remote/untrusted. Successful pairing trusts the peer identity, not the LAN. Any future SAS-free local profile requires an independently approved OS-authenticated local IPC mechanism.

## Owner-selected process/session ceiling

`MAX_REMOTE_SAS_OPPORTUNITIES_PER_PROCESS_SESSION = 10`

This is a conservative owner-selected abuse/safety ceiling, not a lifetime counter or a cryptographic constant. It applies per core, across both roles and all network connections handled by that pairing authority, to exposed remote SAS opportunities only.

An opportunity counts when the ceremony crosses the current profile's SAS-enabling exposure boundary. The current profile's exposure semantics are unchanged. Once exposed, count the opportunity regardless of success, mismatch, rejection, cancellation, timeout, disconnect, MAC/authentication failure, or protocol error. Malformed pre-exposure input, rejected pre-exposure admission, BUSY/PAIRING_IN_PROGRESS, and connections that never cross the boundary do not count.

At 10 consumed opportunities, the core exposes a local limit-exhausted state/result and prevents any further remote ceremony from crossing the exposure boundary for the rest of that process/session. Any peer response is generic unavailable/busy-style behavior. A process restart creates a new local budget; there is no persistent cryptographic accounting or lifetime claim. Consumer applications choose any notification text.

## Pair-count model

For two honest endpoints A and B within one **joint window**, let `n_A` and `n_B` be their exposed opportunities. Under one live exposed ceremony per core, I1, I2, and explicit retries only, the maximum total number of security-relevant tested candidate pairs is:

`n_A + n_B - 1` when both are at least 1; otherwise `0`.

A held candidate may take part in several sequential comparisons. Do not claim that one local action equals one global comparison. The bound is on the total number of security-relevant candidate pairs.

With `n_A <= 10` and `n_B <= 10` in one joint window:

`10 + 10 - 1 = 19`

Thus 19 is the maximum pair-count result for the owner-selected 10/10 joint-window policy. It applies only while both endpoints remain within their current process/session budgets. Restart resets that endpoint's local 10-opportunity budget; 19 is not a lifetime, per-device-forever, or one-endpoint-process bound when the other endpoint repeatedly restarts. For arbitrary exposure counts, the structural formula remains `pairs <= N_A + N_B - 1`, subject to the same one-live-ceremony invariants.

## Conditional probability wording

> If each security-relevant tested candidate pair has conditional ideal full-SAS match probability at most `2^-39`, then a 10/10 joint window containing at most 19 tested pairs has a union-bound random-match term of at most `19 × 2^-39`.

`19 × 2^-39 ≈ 3.456 × 10^-11`. This is conditional on the per-pair premise; independence is not required for the union bound. It is an ideal random-SAS-match term, not a real-human error probability, not a lifetime bound, and not a complete proof of the vodozemac construction. The per-tested-pair `2^-39` premise remains OPEN for independent verification. Do not describe the protocol as having established `3.456 × 10^-11` MITM security.

## CR-01 and construction status

**CR-01 PAIR-COUNTING REMEDIATION DOCUMENTED — PER-PAIR `2^-39` PREMISE STILL REQUIRES VERIFICATION.** The owner policy and previously reviewed `n_A + n_B - 1` model resolve the unbounded candidate-pair accounting flaw for the stated scope. Keep the parent CR-01 item OPEN until independent review verifies whether each security-relevant tested candidate pair in the corrected composition has conditional ideal full-SAS match probability at most `2^-39` under active MITM scheduling and the stated cryptographic assumptions. This does not establish the construction's security.

`VODOZEMAC = FAVORED, NOT SELECTED`

`P4 = BLOCKED`

The transcript framing correction remains `u32be(len(domain)) || domain || ...`, consistent with deterministic vectors. It is unchanged by this policy decision. This document is generic library policy; consumer-specific warning text is outside its scope.
