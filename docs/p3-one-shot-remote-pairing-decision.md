# Owner-selected remote pairing session safety policy

**OWNER-SELECTED — ONE LIVE EXPOSED CEREMONY PER PAIRING AUTHORITY; 10 EXPOSED OPPORTUNITIES PER PROCESS/SESSION. CR-01 REMAINS OPEN. VODOZEMAC FAVORED, NOT SELECTED. P4 BLOCKED.**

This policy does not select a cryptographic construction, establish security, or authorize implementation. The normative vodozemac candidate profile must conform to it.

## Remote ceremony policy

- **Single live exposure:** At most one exposed remote ceremony may be live for a pairing authority, across Initiator and Responder roles, all remote connections, and all relevant instances. A process-local mutex alone does not satisfy this scope. Instances sharing an authority must coordinate the guard; if they cannot, they must fail closed before exposure.
- **Atomic admission:** The active-ceremony guard and the process/session opportunity reservation are acquired atomically before the role-specific ephemeral public contribution is released. A competing ceremony cannot cross exposure while the guard is occupied.
- **Explicit retry only:** There is no automatic retry, resume, or reconnect continuation. Every new exposed ceremony requires fresh explicit local user authorization. A continuously listening Responder may reject pre-exposure traffic, but continuous listening or admission is not authorization for an exposed ceremony.
- **Exposure accounting:** The successful atomic reservation is the exposure-boundary operation and occurs immediately before release of the role-specific ephemeral public contribution. It consumes exactly one opportunity and is never refunded if the following release outcome is ambiguous or fails. A refusal before reservation, including BUSY, consumes none. Count success and failure alike.
- **Terminal irreversibility (I1):** A terminated ceremony can never later succeed. Release the active guard only after terminal state is irrevocable. Delayed messages, callbacks, reconnects, duplicate/reordered packets, and acknowledgements cannot revive it.
- **SAS lifetime (I2):** A SAS is valid for human comparison only while its ceremony is live. Termination invalidates and withdraws it from the active comparison interface and rejects callbacks for that ceremony.
- **Human comparison:** The security argument assumes people compare the currently live SAS values. Software cannot prevent users from remembering or verbally reusing old values.
- **Network locality is not trust:** LAN, Wi-Fi, Ethernet, private IP addresses, discovery proximity, and loopback remain remote/untrusted.

## Owner-selected process/session ceiling

`MAX_REMOTE_SAS_OPPORTUNITIES_PER_PROCESS_SESSION = 10`

This is a conservative owner-selected session safety ceiling, not a lifetime counter or mathematically derived cryptographic constant. It applies across both roles for the local process/session. Once consumed, remote pairing cannot cross exposure again during that session. A process restart creates a new local session budget; no persistent lifetime accounting is selected.

The guard is scoped to the pairing authority and may span multiple processes or instances. The 10-opportunity budget is scoped to each process/session. An implementation must coordinate guard acquisition and reservation so that a ceremony cannot expose a key without holding the authority-wide guard and consuming exactly one available local opportunity. It must not assume that a process-local lock coordinates other instances.

## Pair-count model

For two honest endpoints A and B with overlapping live-ceremony intervals, let `n_A` and `n_B` be their actual exposed opportunities. Under one live exposed ceremony per pairing authority and I1/I2, the maximum number of security-relevant tested candidate pairs is:

`n_A + n_B - 1` when both are at least 1; otherwise `0`.

A held SAS may be compared against several sequentially authorized ceremonies at the other endpoint. Do not claim that one local action participates in only one global comparison.

For a joint window in which both endpoints remain within their respective 10-opportunity process/session budgets:

`maximum tested candidate pairs = 10 + 10 - 1 = 19`

This 19-pair maximum is not a lifetime bound. Restarts reset the local budget. Over longer periods, the structural result uses actual total exposure counts; no fixed lifetime numeric bound is established.

## Conditional probability wording

The proposed corrected per-pair statement is conditional:

`P_per_pair ≤ 2^-39 + δ`

Here `δ` represents applicable computational and cryptographic-assumption error terms. The review found no concrete attack exceeding the ideal term but concluded **PREVIOUS PROOF NOT ESTABLISHED**; it did not establish concrete standard-model security. Under the stated assumptions, a 10/10 joint window has:

`P_joint ≤ 19 × 2^-39 + ε`

where `ε` covers applicable computational and randomness terms. `19 × 2^-39 ≈ 3.456 × 10^-11`. No numeric value for `δ` or `ε` is asserted without a supported derivation. These are idealized SAS random-match bounds, not human-error probabilities, lifetime bounds, complete authentication guarantees, or formal proofs of the concrete implementation.

The proposed argument assumes random-oracle-style behavior for the relevant commitment and HKDF-SHA256 constructions, SHA-256 collision resistance for commitment binding, fresh unpredictable ephemeral keys, correct exposure ordering, atomic single-ceremony enforcement, and suitable treatment of adaptive scheduling/selective aborts. Ordinary HKDF PRF security alone is not asserted sufficient when the attacker knows the derived secret on its own protocol leg. Real SHA-256 and HKDF-SHA256 have not been proven to be random oracles.

## CR-01 and construction status

Pair counting is documented for the stated scope. The second independent adversarial AI review found no concrete attack above the ideal `2^-39` term but gave the verdict **PREVIOUS PROOF NOT ESTABLISHED** because assumptions and reasoning were incomplete. A corrected conditional argument is recorded in the normative candidate profile. CR-01 is **not fully closed**: the corrected argument and its assumptions require focused independent verification.

The reviews were AI reviews, not qualified human audits or formal verification. Documentation reconciliation is not independent verification.

`VODOZEMAC = FAVORED, NOT SELECTED`

`P4 = BLOCKED`

The transcript framing remains `u32be(len(domain)) || domain || ...`, consistent with the deterministic vector. No construction or message format is changed by this policy.
