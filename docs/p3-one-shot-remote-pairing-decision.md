# Owner-selected remote pairing session safety policy

**OWNER-SELECTED POLICY — ONE OWNING PROCESS PER PAIRING AUTHORITY; ONE LIVE EXPOSED CEREMONY; 10 SHARED EXPOSED OPPORTUNITIES PER PROCESS/SESSION. VODOZEMAC SELECTED FOR EXPERIMENTAL IMPLEMENTATION. P4 AUTHORIZED, NOT COMPLETE. CR-01 RETAINS CONDITIONAL ASSUMPTIONS AND VERIFICATION LIMITATIONS.** See [owner selection decision](decisions/0002-experimental-vodozemac-selection.md).

This policy is the selected vodozemac experimental baseline. It does not establish production security or authorize production use. The vodozemac profile must conform to it.

## Remote ceremony policy

- **Single owner:** Exactly one active owning process may use a pairing authority. It owns that authority's active remote pairing state, single shared remote-ceremony guard, process/session opportunity budget, and all Initiator and Responder ceremonies. Threads and connections in that process share this state. Processes using different authorities are unaffected.
- **Exclusive ownership before exposure:** The process must atomically establish exclusive ownership before it may expose any remote pairing ceremony. If another process already owns the authority, a second process cannot initiate or accept an exposed ceremony for it. An uncertain ownership result fails closed. A process-local mutex alone does not prevent another process from using the same authority.
- **Single live exposure:** At most one exposed remote ceremony may be live for the pairing authority across both roles and all remote connections in its owning process.
- **Atomic admission:** The active-ceremony guard and the process/session opportunity reservation are acquired atomically before the role-specific ephemeral public contribution is released. A competing ceremony cannot cross exposure while the guard is occupied.
- **Explicit retry only:** There is no automatic retry, resume, or reconnect continuation. Every new exposed ceremony requires fresh explicit local user authorization. A continuously listening Responder may reject pre-exposure traffic, but continuous listening or admission is not authorization for an exposed ceremony.
- **Exposure accounting:** The successful atomic reservation is the exposure-boundary operation and occurs immediately before release of the role-specific ephemeral public contribution. It consumes exactly one opportunity and is never refunded if the following release outcome is ambiguous or fails. A refusal before reservation, including BUSY, consumes none. Count success and failure alike.
- **Terminal irreversibility (I1):** A terminated ceremony can never later succeed. Release the active guard only after terminal state is irrevocable. Delayed messages, callbacks, reconnects, duplicate/reordered packets, and acknowledgements cannot revive it.
- **SAS lifetime (I2):** A SAS is valid for human comparison only while its ceremony is live. Termination invalidates and withdraws it from the active comparison interface and rejects callbacks for that ceremony.
- **Human comparison:** The security argument assumes people compare the currently live SAS values. Software cannot prevent users from remembering or verbally reusing old values.
- **Network locality is not trust:** LAN, Wi-Fi, Ethernet, private IP addresses, discovery proximity, and loopback remain remote/untrusted.

## Owner-selected process/session ceiling

`MAX_REMOTE_SAS_OPPORTUNITIES_PER_PROCESS_SESSION = 10`

This is a conservative owner-selected session safety ceiling, not a lifetime counter or mathematically derived cryptographic constant. Each authority's one owning process has one shared budget across both roles and all connections. Once consumed, remote pairing cannot cross exposure again during that owning process's session. A legitimate process restart starts a new budget only after the previous owner has terminated and exclusive ownership has been safely established; restart alone does not establish ownership. If ownership is uncertain, remote pairing remains disabled. No persistent accounting is selected.

The authority is owned by one process at a time in v1. The process must own the active guard and budget shared by its threads, roles, and connections. Ownership acquisition is atomic and precedes any exposure; uncertain acquisition fails closed. Concurrent ownership by multiple processes for the same authority is unsupported. Do not add a distributed counter or multi-process coordinator. A copied identity used simultaneously on another machine, restored snapshots, or duplicated authority state are not made safe by local process exclusivity; their behavior remains outside this policy's guarantee.

P4 must specify and verify exclusive ownership enforcement, safe handling of owner crashes/termination, and ownership-release verification. No platform-specific locking mechanism is selected here. A replacement process must not expose while prior ownership is active or uncertain, and cannot resume or revive an old ceremony.

## Pair-count model

For two honest endpoints A and B with overlapping live-ceremony intervals, let `n_A` and `n_B` be their actual exposed opportunities. Under one live exposed ceremony per pairing authority and I1/I2, the maximum number of security-relevant tested candidate pairs is:

`n_A + n_B - 1` when both are at least 1; otherwise `0`.

A held SAS may be compared against several sequentially authorized ceremonies at the other endpoint. Do not claim that one local action participates in only one global comparison.

For a joint window in which both endpoints remain within their respective 10-opportunity process/session budgets:

`maximum tested candidate pairs = 10 + 10 - 1 = 19`

This 19-pair maximum is not a lifetime bound. Restarts reset the local budget. Over longer periods, the structural result uses actual total exposure counts; no fixed lifetime numeric bound is established.

The numeric 19-pair bound applies only while both endpoints stay within their respective process sessions for that joint window. It does not extend across arbitrary restarts. In particular, if one endpoint restarts while the other has a live ceremony, the 19-pair numeric bound cannot automatically be extended across those sessions. Single-process ownership is not lifetime protection against repeated pairing attempts.

## Conditional probability wording

The proposed corrected per-pair statement is conditional:

`P_per_pair ≤ 2^-39 + δ`

Here `δ` represents applicable computational and cryptographic-assumption error terms. The review found no concrete attack exceeding the ideal term but concluded **PREVIOUS PROOF NOT ESTABLISHED**; it did not establish concrete standard-model security. Under the stated assumptions, a 10/10 joint window has:

`P_joint ≤ 19 × 2^-39 + ε`

where `ε` covers applicable computational and randomness terms. `19 × 2^-39 ≈ 3.456 × 10^-11`. No numeric value for `δ` or `ε` is asserted without a supported derivation. These are idealized SAS random-match bounds, not human-error probabilities, lifetime bounds, complete authentication guarantees, or formal proofs of the concrete implementation.

The proposed argument assumes random-oracle-style behavior for the relevant commitment and HKDF-SHA256 constructions, SHA-256 collision resistance for commitment binding, fresh unpredictable ephemeral keys, correct exposure ordering, atomic single-ceremony enforcement, and suitable treatment of adaptive scheduling/selective aborts. Ordinary HKDF PRF security alone is not asserted sufficient when the attacker knows the derived secret on its own protocol leg. Real SHA-256 and HKDF-SHA256 have not been proven to be random oracles.

**F-02 = FALSE POSITIVE UNDER THE STATED IDEALIZED ASSUMPTIONS.** A participating attacker normally calculates its own Diffie–Hellman shared secret after the honest public contribution is revealed, and the SAS argument does not require that secret to remain hidden after exposure. It requires the target SAS to remain unpredictable before the attacker fixes the relevant contribution. Under this model, the focused AI-assisted review found no additional X25519 hardness assumption necessary for that disputed property. The reasoning is conditional on fresh unpredictable honest ephemeral contributions, correct commitment timing and binding/hiding assumptions, correct role-specific ordering, the full injectively encoded SAS context, random-oracle-style assumptions for the relevant derivation, and correct exposure accounting. This disposition does not establish the complete per-pair argument or protocol security.

## CR-01 and construction status

Pair counting is documented for the stated scope and addresses the original structural comparison-accounting defect. The complete per-pair argument remains conditional and not formally verified. CR-01 status is: **STRUCTURAL REMEDIATION DOCUMENTED; RESIDUAL ASSUMPTIONS AND VERIFICATION REQUIREMENTS ACCEPTED FOR EXPERIMENTAL DEVELOPMENT.**

The reviews were AI-assisted, not qualified human audits or formal verification. The owner explicitly waived the qualified-human-review gate for experimental development; the audit was not completed. This does not authorize production use or release.

`VODOZEMAC = SELECTED FOR EXPERIMENTAL IMPLEMENTATION`

`P4 = EXPERIMENTAL DEVELOPMENT AUTHORIZED; NOT STARTED OR COMPLETE BY THIS DECISION`

The transcript framing remains `u32be(len(domain)) || domain || ...`, consistent with the deterministic vector. No construction or message format is changed by this policy.
