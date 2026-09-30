# P3 conformance cases

> These are documented conformance cases for experimental implementation work, not executable tests or production approval. The owner selected the remote vodozemac profile for experimental implementation. “Reject before exposure” means before release of the role's SAS-enabling ephemeral public contribution.

> **CASE STATUS:** `R-OWNER-*`, `R-WIRE-*`, and `R-MAC-*` describe current experimental requirements where they agree with the authoritative profile. `R-STATE-*` and `R-ACCOUNT-*` preserve historical candidate scenarios and are non-normative. In `R-RESOURCE-*`, cases `006`–`009` remain applicable timeout checks; all other cases preserve the historical candidate unless independently restated by a current `R-OWNER-*` case. No historical row may reinstate multi-ceremony exposure, eight simultaneous responders, persistent `5,497` accounting, epoch reset, or the old SAS rate-control policy. Local-profile and adapter cases remain candidate-only. The per-pair argument remains conditional; no implementation verification has occurred.

Each row supplies a stable ID, precondition/input, expected outcome, and relevant accounting/resource boundary. `—` means the property does not apply. “Terminal” describes the active ceremony. For current behavior, use the authoritative profile and the applicable rows named above; historical rows are retained as decision evidence only.

## Current owner-policy cases (documentation only)

| ID | Precondition; input or mutation | Expected outcome |
|---|---|---|
| R-OWNER-001 | Initiator receives valid `ACCEPT` | Validate all required fields, obtain fresh local authorization, atomically reserve the shared guard and one opportunity, then generate a fresh Initiator ephemeral key and send `I_pub`. Validation/authorization/reservation failure spends nothing; key-generation or send failure after reservation sends no usable contribution and never refunds the opportunity. |
| R-OWNER-002 | A live exposed ceremony holds the pairing-authority guard; a competing request arrives through another role, connection, or instance | Refuse before second exposure. No second SAS candidate and no additional opportunity consumed for pre-exposure refusal. |
| R-OWNER-003 | Concurrent requests/callbacks race to cross the exposure boundary | Authority-wide guard acquisition and process/session opportunity reservation have one atomic outcome; at most one succeeds. No unguarded or uncharged public contribution is released. |
| R-OWNER-004 | Responder has received `I_pub` but refuses its own exposure because authorization, guard, or budget admission fails | Responder MUST NOT release its own `R_pub` and MUST NOT consume a local opportunity. The Initiator may already have released `I_pub` and consumed its opportunity; do not report that neither endpoint exposed material. |
| R-OWNER-005 | Either role successfully reserves immediately before releasing its SAS-enabling ephemeral public contribution; the ceremony later fails or succeeds | Consume exactly one opportunity at the atomic exposure boundary; never refund it for an ambiguous/failed write or later success, mismatch, rejection, timeout, disconnect, cancellation, or protocol failure. |
| R-OWNER-006 | Ten opportunities have been exposed across both roles in one process/session | Refuse further remote exposure for the remainder of that session. A process restart starts a new local session budget; no lifetime bound is claimed. |
| R-OWNER-007 | Terminal ceremony receives a delayed message, acknowledgement, reconnect, or callback | Preserve terminal state; never transition to success after termination (I1). |
| R-OWNER-008 | Approval callback targets a terminated ceremony or a different transcript identity | Reject callback; it cannot approve any live or later ceremony (I1/I2). |
| R-OWNER-009 | Ceremony terminates while its SAS is displayed | Invalidate SAS and withdraw it from the active comparison interface; reject later approval for that ceremony (I2). |
| R-OWNER-010 | Terminal cleanup begins while the pairing-authority guard is held | Keep guard occupied until terminal state and SAS/callback invalidation are irrevocable; only then release it. |
| R-OWNER-011 | User retries or a connection reconnects after termination | Do not resume or automatically retry. Require fresh explicit local authorization and a new ceremony with new ephemeral material. |
| R-OWNER-012 | A second process attempts to use a pairing authority already owned by another process | Refuse Initiation and Responder exposure before any local contribution is released. Ownership must be acquired atomically before exposure; uncertain ownership fails closed. A process-local mutex alone does not prevent another process from using the authority. |
| R-OWNER-013 | Fork, VM snapshot, restored process state, RNG failure, or duplicated cryptographic state may repeat key material | Do not expose a key unless freshness and unpredictability are restored by a verified mechanism; make no unverified snapshot/rollback-resistance claim. |
| R-OWNER-014 | Responder continuously listens for `START` | Listening and pre-exposure validation may continue, but each fresh exposure still requires explicit local user authorization. |
| R-OWNER-015 | Initiator and Responder roles and multiple connections run in one owning process | All opportunities consume the same `MAX_REMOTE_SAS_OPPORTUNITIES_PER_PROCESS_SESSION = 10` budget and share one active-ceremony guard; no role-specific counters exist. |
| R-OWNER-016 | Responder prepared a committed contribution before exposure while another ceremony held the guard; that ceremony then terminates | Do not automatically reveal the prepared `R_pub`. Obtain fresh ceremony-specific authorization and successfully reserve the guard and shared opportunity after it becomes available; otherwise refuse/discard without exposure or charge. |
| R-OWNER-017 | Replacement process starts while prior ownership is active or ownership state is uncertain | Keep remote pairing disabled; do not expose. Start a new volatile budget only after the prior owner has terminated and exclusive ownership is safely established. No old ceremony, result, or approval resumes. |
| R-OWNER-018 | Two processes use the same identity on different machines, or authority state is copied/restored | Do not claim local process exclusivity makes duplicated authority state safe; behavior is unsupported and no synchronization mechanism is implied. |
| R-OWNER-019 | A peer varies request IDs, addresses, or other wire labels to reach another budget/owner | Keep those peer-controlled values out of pairing-authority identity and authority-wide accounting; refuse attempts to select/create an alternate local authority through network input. |
| R-OWNER-020 | Two local instances present colliding, aliased, malformed, or inconsistently scoped authority identities | Reject registration/acquisition and fail closed; do not partition ownership, limits, guard, or budget. |
| R-OWNER-021 | Another process owns the authority, or acquisition/release status is ambiguous | Refuse pairing before exposure. Do not use a process-local mutex as cross-process proof; do not enable replacement until the OS mechanism establishes prior-owner termination and exclusive acquisition. |
| R-OWNER-022 | Frontend restarts while native owning process remains alive | Preserve the process-owned budget, guard, pending-state controls, and ownership lease. Frontend restart is not a session replacement. |
| R-OWNER-023 | Responder reaches 16 unauthenticated connections, accept queue 4, or incomplete-frame limits/deadlines with fragmented/slow input | Enforce adapter connection/frame caps, at most 4 incomplete frames per authority and 1 per connection, 10-second whole-frame and 2-second idle deadlines, and no unbounded accept tasks; close/reject generically before semantic processing. No `ACCEPT`, no state leak, no SAS charge. |
| R-OWNER-024 | Four pending pre-exposure runs already exist for the authority | Refuse additional START generically and clean temporary state; no exposed guard or SAS opportunity is consumed. |
| R-OWNER-025 | Two expensive preliminary operations already run, or the authority START limiter is exhausted | Enforce at most 2 concurrent expensive operations authority-wide and burst 4 / 12 complete START frames per rolling 60 seconds before semantic validation. Acquire an operation permit before ephemeral generation, commitment hashing, or pre-exposure DH/contributory validation; do not queue unbounded work. Release each permit on every success or failure path. These controls are separate from the SAS budget; no opportunity is consumed or reset. |
| R-OWNER-026 | Pre-exposure run is refused, reaches its 60-second pending deadline, cancelled, disconnected, malformed, or transport fails | Release its state and resource reservations exactly once. Preserve any prior exposure charge; do not create an SAS charge for the pre-exposure failure itself. |
| R-OWNER-027 | Unsolicited START flood, pre-exposure admission limit, or resource cap is reached | Report resource/admission status distinct from the ten-exposure limit, SAS mismatch, authentication failure, and compromise. Network traffic alone cannot trigger the exhausted-opportunity warning. |
| R-OWNER-029 | `INITIATOR_KEY` is contributory; R authorizes and reserves, then reveals `RESPONDER_KEY` | R sends only after successful DH/contributory validation, fresh authorization, and atomic reservation. Keep charge if the send is ambiguous or later processing fails. |
| R-OWNER-030 | I's post-`ACCEPT` ephemeral generation fails after successful authorization and reservation | Send no `INITIATOR_KEY`; fail the run; retain the consumed opportunity and guard until terminal cleanup is irrevocable. |
| R-OWNER-031 | Ownership lease is released on clean shutdown or recovered after process crash | Terminate all ceremony/approval state first; replacement acquires only after OS-backed exclusivity and prior-owner incapability are established. Never resume prior state. |
| R-OWNER-032 | Ten locally authorized exposures have been reserved in this owner session | Return `OpportunityLimitReached` to the local consumer; only DovahLink may choose warning text. Do not claim compromise, authentication failure, or lifetime exhaustion; verified replacement is a distinct `SessionReplaced` status. |
| R-OWNER-033 | I validates a committed but non-contributory `R_pub` after previously authorizing, reserving, and exposing `I_pub` | I rejects the key and does not refund its consumed opportunity. I cannot determine whether R consumed an opportunity; no result is allowed. |
| R-OWNER-034 | START traffic is below and above the configured default admission boundary | Enforce both burst 4 and at most 12 syntactically framed STARTs in any rolling 60 seconds; malformed semantic fields count. Limit state is authority-wide, bounded, and independent of the SAS budget. |

These cases describe requirements only. They are not executable tests or evidence that the implementation conforms.

## Remote encoding

| ID | Precondition; input or mutation | Expected outcome | SAS charge; slot; prompt; terminal |
|---|---|---|---|
| R-WIRE-001 | Positive vector: canonical bootstrap, START, ACCEPT, both key frames, approval MAC frames, three finish frames, and both authenticated `CANCEL / 0x09` frames | Accept exact canonical bytes; consume each frame fully | Per exposure rules; slot follows state; prompt only at SAS approval; no failure |
| R-WIRE-002 | Replace `SASPAIR` magic | Reject before state transition | No new charge; no new slot; no prompt; terminal if active |
| R-WIRE-003 | Unsupported u16be version | Reject unsupported version | No new charge; no new slot; no prompt; terminal if active |
| R-WIRE-004 | Unknown message type | Reject unknown type | No new charge; no new slot; no prompt; terminal if active |
| R-WIRE-005 | Omit a required field | Reject missing field | No new charge; no new slot; no prompt; terminal if active |
| R-WIRE-006 | Add a duplicate field | Reject duplicate field | No new charge; no new slot; no prompt; terminal if active |
| R-WIRE-007 | Swap ordered fields | Reject noncanonical order | No new charge; no new slot; no prompt; terminal if active |
| R-WIRE-008 | Append a byte after the final field | Reject trailing bytes | No new charge; no new slot; no prompt; terminal if active |
| R-WIRE-009 | Complete wire frame is 65,537 bytes | Reject over profile maximum before unbounded allocation | No new charge; no new slot; no prompt; terminal if active |
| R-WIRE-010 | Complete nested bootstrap is 16,385 bytes | Reject over bootstrap maximum | No new charge; no new slot; no prompt; terminal if active |
| R-WIRE-011 | `key_algorithm` contains non-ASCII or violates `[a-z0-9][a-z0-9.-]*` | Reject malformed bootstrap | No new charge; no new slot; no prompt; terminal if active |
| R-WIRE-012 | X25519 public-key field length differs from 32 bytes | Reject before key construction | No new charge; no new slot; no prompt; terminal if active |
| R-WIRE-013 | 32-byte non-contributory X25519 peer key | **Responder rejects `I_pub`:** validate before local authorization, reservation, or revealing `R_pub`; terminate without revealing `R_pub`. **Initiator rejects `R_pub`:** validate after its prior authorization, reservation, and `I_pub` exposure; reject without refund. I cannot infer whether remote R consumed an opportunity. | On R rejection: R consumes none; an honest I already consumed its opportunity. On I rejection: I's prior charge remains; remote R's charge is unknown. No prompt; terminal. |
| R-WIRE-014 | Change START bytes after ACCEPT was constructed | Commitment/transcript checks fail; no SAS or result | No result; exposure charge only if already crossed; terminal |
| R-WIRE-015 | Flip one bit of committed `R_pub` | Commitment verification fails | Initiator has already reserved before `I_pub`; no refund; terminal |
| R-WIRE-016 | Later message carries another request ID | Reject routing/correlation mismatch | No new charge; active slot released on terminal cleanup; terminal |
| R-WIRE-017 | For bidirectional `BOOTSTRAP_MAC` or `CANCEL`, mutate the explicit length-prefixed one-byte role (`0x01` Initiator, `0x02` Responder) to the non-peer role | Receiver checks the encoded role against the expected peer role and rejects mismatch as protocol error | No new charge; terminal |
| R-WIRE-018 | Bootstrap `shared_context` differs from independent local context | Reject before exposure | No charge; responder slot not allocated for START mismatch; no prompt; terminal |
| R-WIRE-019 | Received bootstrap violates a supplied expected-peer constraint | Fail closed before exposure; no downgrade to open mode | No charge; no prompt; terminal |
| R-WIRE-020 | Approval or completion names another ceremony identity | Reject stale/wrong ceremony evidence | Existing charge is not refunded; terminal |
| R-WIRE-021 | MAC context uses wrong sender/receiver role direction | MAC verification fails | Existing charge is not refunded; terminal |
| R-WIRE-022 | Exact duplicate of an accepted frame on the same run/sender | Ignore idempotently without output, prompt, or cryptographic work | No additional charge/slot/prompt; remains active |
| R-WIRE-023 | Same accepted message type arrives with changed bytes | Fail active run closed | No refund; release owned slot; terminal |
| R-WIRE-024 | Message arrives before its legal state or out of order | Fail active run closed; no future-message queue | No refund; release owned slot; terminal |
| R-WIRE-025 | Fragment a valid frame across reads without exceeding its cap | Bounded parser reconstructs and accepts one complete canonical frame | Follow message boundary; no extra slot/prompt |
| R-WIRE-026 | Initiator receives ACCEPT whose bootstrap context or expected-peer value mismatches local input | Reject before Initiator SAS-attempt reservation and before INITIATOR_KEY | No charge; no prompt; terminal |

## Remote commitment/SAS/MAC

| ID | Precondition; input or mutation | Expected outcome | SAS charge; slot; prompt; terminal |
|---|---|---|---|
| R-MAC-001 | Positive remote JSON vector | Both roles obtain equal DH secret, commitment, transcript identity, six SAS bytes, decimals, and valid tags | Each attempt charged at its key-release boundary; prompt after SAS established |
| R-MAC-002 | Recompute SHA-256 commitment over fixed prefix, length-framed START, and raw `R_pub` | Match recorded commitment; ACCEPT contains that value | As R profile flow |
| R-MAC-003 | Flip one `R_pub` bit after ACCEPT | Commitment open fails | I attempt already charged before I_pub; no refund; terminal |
| R-MAC-004 | Mutate SAS context field (request ID, START, ACCEPT, or key) at one endpoint | SAS differs or subsequent authentication fails; no successful result | Attempts already charged; terminal |
| R-MAC-005 | Mutate one role byte in a bootstrap approval frame/context | Direction binding or MAC verification fails | No refund; terminal |
| R-MAC-006 | Change peer bootstrap in approval reconstruction | MAC verification fails | No refund; terminal |
| R-MAC-007 | Change ceremony identity in approval reconstruction | MAC verification fails | No refund; terminal |
| R-MAC-008 | Flip one bit of approval MAC | Reject malformed/invalid tag; no result | No refund; terminal |
| R-MAC-009 | Verify tag using opposite role direction | Verification fails | No refund; terminal |
| R-MAC-010 | Positive `INITIATOR_FINISH` authentication | Receiver reconstructs type `0x35` auth frame/context and verifies its 32-byte MAC | No refund; state advances |
| R-MAC-011 | Positive `RESPONDER_FINISH_ACK` authentication | Receiver reconstructs type `0x36` auth frame/context and verifies its 32-byte MAC | No refund; state advances |
| R-MAC-012 | Positive `INITIATOR_FINISH_ACK` authentication | Receiver reconstructs type `0x37` auth frame/context and verifies its 32-byte MAC | No refund; state advances to local success |
| R-MAC-013 | Finish carries a wrong transcript digest or finish type/MAC | Reject before state transition/result | No refund; terminal |
| R-MAC-014 | Add `=` padding or noncanonical characters to context Base64url | Reject noncanonical context encoding | No charge before exposure; otherwise no refund; terminal |
| R-MAC-015 | Positive authenticated `CANCEL` after shared SAS establishment, I → R (`0x02` user cancellation) and R → I (`0x03` timeout) JSON vectors | After canonical codec validation and expected-peer sender check, receiver reconstructs `CancelAuthFrame / 0x34` input and `CancelMacContext / 0x38` under outer purpose `cancel` with the received reason, verifies the 32-byte tag, and terminates only that exact ceremony: no `PairingResult`; SAS, approval, and session state invalidated; guard released only after invalidation is irrevocable | Consumed opportunity never refunded; terminal |
| R-MAC-016 | Verify a valid `CANCEL` tag with sender/receiver roles swapped in the reconstructed `0x34` frame and `0x38` context, or accept an I → R tag as R → I | MAC verification fails; not authenticated peer cancellation (wire sender-role mismatch is `R-WIRE-017`) | No refund; terminal protocol failure |
| R-MAC-017 | Reconstruct `CANCEL` frame/context with a different `ceremony_identity` | MAC verification fails; not authenticated peer cancellation | No refund; terminal protocol failure |
| R-MAC-018 | Replay a valid `CANCEL` from another ceremony with the same request ID, reason, and roles | Verification fails because `ceremony_identity` differs; request ID is not authentication; the other ceremony is unaffected | No refund; terminal protocol failure for the receiving active run |
| R-MAC-019 | Change the wire `CANCEL` reason code to another defined reason while keeping the tag | Receiver reconstructs both non-wire structures with the received reason; verification fails; a tag cannot be reused under another reason. An undefined reason code is rejected by the codec before MAC work | No refund; terminal protocol failure |
| R-MAC-020 | Flip one bit of the `CANCEL` MAC, or supply a tag that is not exactly 32 bytes | Reject; not authenticated peer cancellation | No refund; terminal protocol failure |
| R-MAC-021 | Compute or verify `CANCEL` with outer purpose `mac`, an inner `cancel` purpose field, or any context type other than `0x38` (for example `0x31`, `0x32`, or `0x34`) | Not the frozen encoding; MAC verification fails | No refund; terminal protocol failure |
| R-MAC-022 | Wire `CANCEL` arrives while active but before shared SAS establishment | Invalid protocol input, never authenticated peer cancellation; no MAC is computed | No charge if before exposure; otherwise no refund; terminal |
| R-MAC-023 | Exact duplicate or any `CANCEL` arrives after the ceremony is terminal (including after a verified `CANCEL`); or the local endpoint cancels | Terminal state and absence of result are immutable; nothing is revived. Local cancellation is terminal immediately; best-effort authenticated `CANCEL` send does not wait for peer receipt | No refund; no second outcome; no retry or resume |

## Remote state machine

| ID | Precondition; input or mutation | Expected outcome | SAS charge; slot; prompt; terminal |
|---|---|---|---|
| R-STATE-001 | START passes bounded parsing, admission, and D14 validation | Responder reserves a slot before ephemeral generation/ACCEPT | No SAS charge yet; slot yes; prompt no; active |
| R-STATE-002 | Initiator accepts valid ACCEPT and reserves before sending I_pub | Charge is durable immediately before key exposure | Charge yes; active slot; no prompt until SAS ready |
| R-STATE-003 | Responder accepts valid I_pub and reserves before revealing R_pub | Charge is durable immediately before key exposure | Charge yes; slot held; no prompt until SAS ready |
| R-STATE-004 | Responder local admission closes before exposure boundary | Fail without releasing R_pub | No new charge; release slot; no prompt; terminal |
| R-STATE-005 | Initiator and responder each approve their exact displayed SAS | Send/verify each role-bound BOOTSTRAP_MAC | No refund; active; prompt completed |
| R-STATE-006 | Valid completion messages arrive in specified order | Follow I/R state machine; emit only role-local result at specified point | No refund; release slot on terminal completion |
| R-STATE-007 | Peer rejects/mismatches SAS | Fail exact ceremony; no result | No refund; terminal |
| R-STATE-008 | Authenticated CANCEL before shared SAS establishment | Reject as peer-cancellation evidence; fail active run | No charge if before boundary; otherwise no refund; terminal |
| R-STATE-009 | Valid authenticated CANCEL after SAS establishment | Terminate only named active ceremony | No refund; release slot; terminal |
| R-STATE-010 | Wire CANCEL has a sender-role field different from expected peer | Reject protocol error | No refund; release slot; terminal |
| R-STATE-011 | Disconnect, timeout, or process restart | Abort volatile ceremony; discard approval and secrets | Preserve any durable charged count; terminal |
| R-STATE-012 | Terminal success or failure receives any later frame | Ignore/reject at boundary without changing result | No second charge or result; terminal immutable |

## Remote accounting/resource controls

| ID | Precondition; input or mutation | Expected outcome | SAS charge; slot; prompt; terminal |
|---|---|---|---|
| R-ACCOUNT-001 | Immediately before Initiator releases I_pub | Atomically/durably reserve shared epoch count | Charge before exposure; slot held; no prompt yet |
| R-ACCOUNT-002 | Immediately before Responder releases R_pub | Recheck admission/limiter, then atomically/durably reserve | Charge before exposure; slot held; no prompt yet |
| R-ACCOUNT-003 | 5,496 attempts already consumed; reserve attempt 5,497 | Permit exactly one concurrent winner for final slot | Charge 5,497 before exposure; active |
| R-ACCOUNT-004 | 5,497 attempts already consumed; request attempt 5,498 | Fail closed before key release | No extra charge/release; slot cleanup; no prompt; terminal |
| R-ACCOUNT-005 | Abort, reject, timeout, malformed later frame, success, or MAC failure after exposure | Keep charged attempt; never refund | Charge remains; terminal as applicable |
| R-ACCOUNT-006 | Successful ceremony | Do not reset or refund counter | Count unchanged; slot released at terminal success |
| R-ACCOUNT-007 | Process restart/reboot/update | Discard active runs; preserve durable epoch/count | No reset; no active slot after restart |
| R-ACCOUNT-008 | Explicit locally authorized epoch reset succeeds atomically | Create exactly one new epoch with zero count | Reset only after authorized completed transaction |
| R-ACCOUNT-009 | Reset storage result is ambiguous/fails | Fail closed; retain exhausted-state protection | No exposure; no new slot/prompt |
| R-ACCOUNT-010 | Local-profile activity while remote counter has value N | Leave remote counter/epoch unchanged | No remote charge/reset/refund |
| R-ACCOUNT-011 | Concurrent reservations race for final counter slot | At most one reservation succeeds | One charge; other blocked before exposure |
| R-ACCOUNT-012 | Storage unavailable, corrupt, or ambiguous at reservation | Fail closed before key release | No exposure; clean up slot; terminal |
| R-RESOURCE-001 | Eight active remote Responder ceremonies already allocated | Reject ninth before state/key generation/ACCEPT | No charge; no new slot; no prompt; not admitted |
| R-RESOURCE-002 | Active remote slot reaches terminal cleanup | Release slot exactly once and permit later eligible attempt | No refund of any charge; no stale state |
| R-RESOURCE-003 | START limiter refuses serial admission work | Generic refusal before expensive work where specified | No SAS charge/slot/prompt |
| R-RESOURCE-004 | SAS-opportunity limiter refuses before exposure | Fail before key release | No charge unless a conservative reservation was already persisted; no prompt |
| R-RESOURCE-005 | Disabled local remote-pairing admission receives START | Refuse before slot, key generation, ACCEPT, prompt, or SAS reservation | No charge/slot/prompt |
| R-RESOURCE-006 | Remote absolute deadline reaches five minutes | Terminal failure; no extension | Keep prior charge; release slot; no success |
| R-RESOURCE-007 | Machine inactivity reaches 60 seconds during protocol wait | Terminal failure | Keep prior charge; release slot; terminal |
| R-RESOURCE-008 | Complete SAS is awaiting deliberate human action | Suspend 60-second inactivity timer; 5-minute absolute continues | No timer-driven refund; prompt remains ceremony-scoped |
| R-RESOURCE-009 | Duplicate, junk, keepalive, replay, or UI activity occurs | Does not refresh inactivity/absolute timer | No new charge; no slot/prompt extension |

## Local encoding

| ID | Precondition; input or mutation | Expected outcome | SAS charge; slot; prompt; terminal |
|---|---|---|---|
| L-WIRE-001 | Positive local JSON vector for START, ACCEPT, APPROVE, REJECT, ACK | Parse each exact payload; both decisions/ACK carry exact 32-byte identity | No SAS charge; slot per lifecycle; prompt only on Responder decision |
| L-WIRE-002 | Each outer record's prefix equals canonical payload length | Accept and consume exactly one record | No SAS charge; active slot as applicable |
| L-WIRE-003 | Bad magic, unsupported version, remote-profile identifier, or remote message type | Reject wrong local frame/profile | No charge; no success; terminal if active |
| L-WIRE-004 | Unknown local message type | Reject | No charge; terminal |
| L-WIRE-005 | Mutate initiator or responder nonce | Reject expected nonce/transcript mismatch | No charge; terminal |
| L-WIRE-006 | Mutate bootstrap or shared context | Reject before Host approval/success | No charge; no Host prompt; terminal |
| L-WIRE-007 | Wrong sender or receiver role byte | Reject role mismatch | No charge; terminal |
| L-WIRE-008 | Flip transcript/ceremony identity in APPROVE | Reject wrong ceremony identity | No charge; no success; terminal |
| L-WIRE-009 | Flip transcript/ceremony identity in ACK | Reject wrong identity | No charge; terminal |
| L-WIRE-010 | APPROVE or ACK arrives on another authenticated connection | Reject connection-state mismatch | No charge; terminal |
| L-WIRE-011 | Host callback is delivered after connection replacement | Invalidate stale approval; no result | No charge; no prompt reuse; terminal |
| L-WIRE-012 | Exact duplicate accepted message on same active connection | Ignore with no repeated transition/output/result | No charge; no extra slot/prompt |
| L-WIRE-013 | Changed duplicate, illegal-next message, or reordered message | Fail closed | No charge; release owned slots; terminal |
| L-WIRE-014 | Unknown, missing, duplicate, reordered field, or trailing payload byte | Reject noncanonical payload | No charge; terminal |
| L-WIRE-015 | Outer record declares zero/invalid payload length | Reject before allocation | No charge; no slot/prompt |
| L-WIRE-016 | Declared payload is 65,533 bytes | Reject; maximum payload is 65,532 | No charge; no slot/prompt |
| L-WIRE-017 | Truncated record | Reject active ceremony | No charge; release slots; terminal |
| L-WIRE-018 | Valid record arrives in fragments | Bounded parser reassembles one record | No charge; lifecycle unchanged |

## Local state machine

| ID | Precondition; input or mutation | Expected outcome | SAS charge; slot; prompt; terminal |
|---|---|---|---|
| L-STATE-001 | Valid LOCAL_START on authorized connection | Responder validates context/expected peer, reserves active+Host slot, then sends ACCEPT | No remote SAS charge; slots yes; prompt on decision phase |
| L-STATE-002 | Exact Host approval in AwaitHostDecision | Send LOCAL_APPROVE; transition to AwaitAck; release Host slot, keep active slot | No charge; no second prompt; active |
| L-STATE-003 | Exact Host rejection | Send LOCAL_REJECT if possible; terminal failure | No charge; release slots; prompt consumed |
| L-STATE-004 | Initiator validates APPROVE and completes full ACK write | Initiator succeeds locally at the defined point | No charge; release Initiator active slot; terminal success |
| L-STATE-005 | Responder receives matching ACK on same connection | Responder succeeds locally | No charge; release slots; terminal success |
| L-STATE-006 | ACK receipt is lost after full write | Initiator may succeed; Responder has no success absent ACK | No charge; local terminal observations may differ |
| L-STATE-007 | REJECT followed by APPROVE or ACK | REJECT remains terminal | No charge; no success |
| L-STATE-008 | Second LOCAL_START on same authenticated connection | Refuse/fail; no retry or replacement | No charge; no second slot/prompt |
| L-STATE-009 | Second ceremony begins after new authenticated connection | Treat as a new ceremony with new nonces/identity/auth | No charge; allocate only if capacity allows |
| L-STATE-010 | Admission disabled or closes during active ceremony | Reject new work; terminally fail existing active ceremonies | No remote charge; release slots; no prompt after close |
| L-STATE-011 | Always require SAS policy selects transport-local pairing | Keep remote SAS profile; no SAS-free local path | Remote counter only if remote reaches exposure |
| L-STATE-012 | Local failure followed by caller-allowed remote pairing | Start a NEW remote ceremony; never transform local state | Normal remote accounting; separate state |
| L-STATE-013 | Automatic policy without separately approved adapter | Local predicate false; remote SAS or caller failure policy | No local success/prompt |

## Local resource/timeouts

| ID | Precondition; input or mutation | Expected outcome | SAS charge; slot; prompt; terminal |
|---|---|---|---|
| L-RESOURCE-001 | Four active local ceremonies occupy global shared cap | Reject fifth before responder state, nonce, ACCEPT, or prompt | No remote charge; no slot; no prompt |
| L-RESOURCE-002 | One ceremony already in AwaitHostDecision | Reject another before ACCEPT/prompt; no queue | No remote charge; no new slots/prompt |
| L-RESOURCE-003 | Initiator active-slot reservation unavailable | Fail before sending LOCAL_START | No charge; no new slot |
| L-RESOURCE-004 | Responder active or Host slot unavailable | Refuse before state/nonce/ACCEPT/prompt | No charge; no slot/prompt |
| L-RESOURCE-005 | START limiter refuses authenticated local request | Reject before expensive semantic/state work where practical | No charge; no new slot/prompt |
| L-RESOURCE-006 | Host-prompt limiter refuses after validation | Do not reserve/surface Host decision | No charge; no Host slot/prompt |
| L-RESOURCE-007 | Rotate PID, SID, connection, or identity labels under same endpoint scope | Global coordinated limiter/cap still applies | No charge; no bypass slot/prompt |
| L-RESOURCE-008 | Machine inactivity reaches 60 seconds | Terminal failure | No remote charge; release owned slot; invalidate prompt |
| L-RESOURCE-009 | Host decision reaches two minutes | Terminal failure | No charge; release active+Host slots; invalidate prompt |
| L-RESOURCE-010 | Absolute deadline reaches five minutes | Terminal failure regardless of phase | No charge; release slots; invalidate prompt |
| L-RESOURCE-011 | Duplicate arrives during wait | Do not refresh any timeout | No charge; slot held only until fixed deadline |
| L-RESOURCE-012 | Valid expected protocol progress occurs | Refresh 60-second machine timer only where defined | No charge; slot remains |
| L-RESOURCE-013 | UI activity, junk, keepalive, or adapter noise occurs | Do not refresh inactivity or absolute deadline | No charge; no prompt extension |
| L-RESOURCE-014 | System resume cannot establish elapsed time safely | Fail active ceremonies conservatively | No charge; release slots |
| L-RESOURCE-015 | Process restart | Destroy active ceremony/approval; may start fresh operational rate windows | No remote charge/reset; release volatile slots |
| L-RESOURCE-016 | Any local ceremony/activity | Remote 10-opportunity process/session budget stays unchanged | No remote charge/reset/refund |

## Windows adapter candidate

No SID/token binary vectors are defined. These are OS-backed conformance cases only.

| ID | Precondition; input or mutation | Expected outcome | Local success; terminal |
|---|---|---|---|
| W-ADAPTER-001 | Server omits `PIPE_REJECT_REMOTE_CLIENTS` on any instance | Local predicate false | No local SAS-free success |
| W-ADAPTER-002 | Client connects through remote UNC/SMB path | Reject | No local success |
| W-ADAPTER-003 | Pipe name is outside `LOCAL\` namespace | Reject | No local success |
| W-ADAPTER-004 | Pipe uses default/null security descriptor | Invalid configuration; reject | No local success |
| W-ADAPTER-005 | DACL includes Everyone, anonymous, or broad generic-user ACE | Reject | No local success |
| W-ADAPTER-006 | Connected pipe owner SID differs from expected Host SID | Reject | No local success |
| W-ADAPTER-007 | Owner or DACL cannot be read/validated | Fail closed | No local success |
| W-ADAPTER-008 | Client User SID differs from expected | Reject | No local success |
| W-ADAPTER-009 | Same User SID but different logon SID/session | Reject ordinary desktop policy | No local success |
| W-ADAPTER-010 | Expected User SID and expected logon SID/session both match | Continue to consumer authorization and other predicates | Candidate predicate only; approval still required |
| W-ADAPTER-011 | `ImpersonateNamedPipeClient` fails | Fail closed | No local success |
| W-ADAPTER-012 | Thread-token open/query/evidence validation fails | Fail closed | No local success |
| W-ADAPTER-013 | `RevertToSelf` fails | Fail closed and shut down per adapter policy | No local success |
| W-ADAPTER-014 | First-instance creation loses a squatting/startup race | Fail closed; do not use existing pipe or fallback name | No local success |
| W-ADAPTER-015 | Squatter is authorized within the exact configured same-principal/session boundary | Treat as inside declared boundary, not as a distinct executable | Candidate scope limitation remains |
| W-ADAPTER-016 | Inherited or duplicated handle is outside candidate assumptions | Reject configuration/operation or require separate review | No inferred identity from handle |
| W-ADAPTER-017 | Service/session-0 deployment uses ordinary interactive policy | Do not automatically accept | No local success |
| W-ADAPTER-018 | AppContainer/package mode presented without separate design/review | Do not automatically accept | No local success |
| W-ADAPTER-019 | `Always require SAS` is active | Bypass local adapter selection; use remote SAS | No SAS-free success |
| W-ADAPTER-020 | Adapter pre-auth resource cap, partial-read deadline, or connection limit fails | Fail before generic ceremony state | No local success; no generic prompt |

## Cross-profile separation

| ID | Precondition; input or mutation | Expected outcome | Boundary |
|---|---|---|---|
| X-PROFILE-001 | Remote START type `0x01` arrives on local state | Reject; never reinterpret as LOCAL_START | No local result |
| X-PROFILE-002 | Local LOCAL_START type `0x40` arrives on remote state | Reject; never reinterpret as START | No remote result |
| X-PROFILE-003 | Remote profile identifier appears in local message | Reject wrong profile | No local success |
| X-PROFILE-004 | Local profile identifier appears in remote message | Reject wrong profile | No remote success |
| X-PROFILE-005 | Same bytes are reused as request ID and nonce-like value | Keep profiles and state objects distinct | No merge/alias |
| X-PROFILE-006 | Local ceremony fails while remote ceremony exists | Local failure does not transform or relabel either active ceremony | No cross-profile state reuse |
| X-PROFILE-007 | Caller policy permits fallback after local failure | Start a NEW remote ceremony with remote bootstrap/accounting | Remote SAS charge at its boundary |
| X-PROFILE-008 | `Always require SAS` on same device | Never select SAS-free local path | Remote profile remains active |
