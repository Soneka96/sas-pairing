# P3 conformance cases

> These are documented conformance cases for future implementation work, not executable tests, profile selection, or production approval. “Reject before exposure” means before release of the role's SAS-enabling ephemeral public contribution.

> **HISTORICAL CANDIDATE CASES:** The existing remote state/accounting/resource cases below preserve the pre-owner multi-ceremony, eight-slot, persistent `5,497`-epoch candidate. They are historical and non-normative where they conflict with the current owner-selected policy. Current owner-policy cases are listed separately below. The per-pair security argument remains conditional and CR-01 remains open.

Each row supplies a stable ID, precondition/input, expected outcome, and relevant accounting/resource boundary. `—` means the property does not apply. “Terminal” describes the active ceremony. Existing remote cases below the current owner-policy section preserve historical candidate accounting/admission behavior where stated; consult the current owner-policy cases above for current remote exposure rules.

## Current owner-policy cases (documentation only)

| ID | Precondition; input or mutation | Expected outcome |
|---|---|---|
| R-OWNER-001 | Initiator receives valid `ACCEPT` | Validate all required fields first; only then generate a fresh Initiator ephemeral key; do not send `I_pub` until explicit local authorization and atomic guard/opportunity reservation succeed. |
| R-OWNER-002 | A live exposed ceremony holds the pairing-authority guard; a competing request arrives through another role, connection, or instance | Refuse before second exposure. No second SAS candidate and no additional opportunity consumed for pre-exposure refusal. |
| R-OWNER-003 | Concurrent requests/callbacks race to cross the exposure boundary | Authority-wide guard acquisition and process/session opportunity reservation have one atomic outcome; at most one succeeds. No unguarded or uncharged public contribution is released. |
| R-OWNER-004 | Malformed/pre-exposure traffic, failed local authorization, or BUSY refusal | No public contribution is released and no exposed opportunity is consumed. |
| R-OWNER-005 | Either role successfully reserves immediately before releasing its SAS-enabling ephemeral public contribution; the ceremony later fails or succeeds | Consume exactly one opportunity at the atomic exposure boundary; never refund it for an ambiguous/failed write or later success, mismatch, rejection, timeout, disconnect, cancellation, or protocol failure. |
| R-OWNER-006 | Ten opportunities have been exposed across both roles in one process/session | Refuse further remote exposure for the remainder of that session. A process restart starts a new local session budget; no lifetime bound is claimed. |
| R-OWNER-007 | Terminal ceremony receives a delayed message, acknowledgement, reconnect, or callback | Preserve terminal state; never transition to success after termination (I1). |
| R-OWNER-008 | Approval callback targets a terminated ceremony or a different transcript identity | Reject callback; it cannot approve any live or later ceremony (I1/I2). |
| R-OWNER-009 | Ceremony terminates while its SAS is displayed | Invalidate SAS and withdraw it from the active comparison interface; reject later approval for that ceremony (I2). |
| R-OWNER-010 | Terminal cleanup begins while the pairing-authority guard is held | Keep guard occupied until terminal state and SAS/callback invalidation are irrevocable; only then release it. |
| R-OWNER-011 | User retries or a connection reconnects after termination | Do not resume or automatically retry. Require fresh explicit local authorization and a new ceremony with new ephemeral material. |
| R-OWNER-012 | Another process/instance shares the pairing authority | Enforce the same active guard across instances; a process-local mutex is insufficient. If coordination cannot be verified, fail closed before exposure. |
| R-OWNER-013 | Fork, VM snapshot, restored process state, RNG failure, or duplicated cryptographic state may repeat key material | Do not expose a key unless freshness and unpredictability are restored by a verified mechanism; make no unverified snapshot/rollback-resistance claim. |
| R-OWNER-014 | Responder continuously listens for `START` | Listening and pre-exposure validation may continue, but each fresh exposure still requires explicit local user authorization. |

These cases describe requirements only. They are not executable tests or evidence that the implementation conforms.

## Remote encoding

| ID | Precondition; input or mutation | Expected outcome | SAS charge; slot; prompt; terminal |
|---|---|---|---|
| R-WIRE-001 | Positive vector: canonical bootstrap, START, ACCEPT, both key frames, approval MAC frames, and three finish frames | Accept exact canonical bytes; consume each frame fully | Per exposure rules; slot follows state; prompt only at SAS approval; no failure |
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
| R-WIRE-013 | 32-byte non-contributory X25519 peer key | Reject `NonContributoryKey` result. If R rejects `I_pub` before revealing `R_pub`, I's attempt was charged before `I_pub` and R's was not. If I rejects `R_pub`, both attempts were charged before their respective key releases. | Charge is role/state-specific; never refund an already charged attempt; no prompt; terminal |
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
