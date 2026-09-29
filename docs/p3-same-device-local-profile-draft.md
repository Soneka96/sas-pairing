# Same-device authenticated-local profile — Draft 01

> **CANDIDATE PROFILE — NO PLATFORM ADAPTER APPROVED — REQUIRES INDEPENDENT SECURITY REVIEW**
>
> Profile identifier: `sas-pairing-local-authenticated-profile-draft-01`
> Version: `1`

## 1. Purpose and status

This document defines an abstract candidate contract for a separate same-device authenticated-local pairing profile. It does not implement the profile, select or approve a platform adapter, or make a production-readiness claim. Candidate B remains the **SELECTED P2 remote construction**. The vodozemac ceremony remains **CANDIDATE — NOT SELECTED** for remote pairing. The local profile is independent of both remote constructions and does not reuse remote SAS or Diffie–Hellman messages.

There are **zero approved platform adapters**. Until a concrete adapter is independently reviewed and approved for a deployment, the SAS-free local path is unavailable in that deployment. Independent external security review remains mandatory.

Normative words (**MUST**, **MUST NOT**, **SHOULD**) state this abstract candidate contract only. They do not approve an operating-system mechanism.

## 2. Architecture and responsibility split

```text
generic authenticated-local ceremony
                ↑
      approved platform adapter
```

The generic core defines the required security predicate, ceremony lifecycle, bootstrap and context semantics, approval binding, state machine, profile selection, and result semantics. A platform adapter must separately establish and document genuine local-kernel IPC, remote-peer exclusion, authenticated peer credentials, connection integrity and binding, mutual endpoint authentication, and its configuration and permission assumptions.

The adapter supplies authenticated evidence about the actual connected endpoint; the core applies the consumer's authorization decision and the generic ceremony rules. Platform credentials and other adapter evidence stay outside the generic protocol wire and bootstrap. No adapter or platform credential format is selected here.

## 3. Local-profile selection predicate

SAS-free local pairing is permitted only if **all** of the following hold for the deployment and this ceremony:

1. A direct local OS/kernel IPC boundary is established.
2. Remote network peers are excluded by the selected adapter.
3. OS-authenticated peer evidence is bound to the actual connected endpoint.
4. Each endpoint authenticates the opposite endpoint on that same connection.
5. Consumer authorization accepts the authenticated principal/evidence at each endpoint.
6. The connection preserves integrity and endpoint binding for the entire ceremony.
7. The local profile identifier and version are unambiguous.
8. Consumer policy permits this local profile.
9. The Host obtains ceremony-specific approval before success.

If any condition is absent, ambiguous, revoked, or ceases to hold:

```text
NO LOCAL SAS-FREE SUCCESS
```

Use the remote SAS profile or fail according to caller/product policy. Remote failure, SAS-budget exhaustion, or a user preference cannot silently become local SAS-free success.

## 4. Locality is not a label

None of the following alone establishes the local predicate: `localhost`, `127.0.0.1`, `::1`, an IP address, hostname, LAN proximity, discovery name, process name, executable filename/path, PID, or a peer-supplied “same machine” claim. These may be diagnostic metadata only. A setting such as “Never require SAS” cannot turn them into authentication evidence.

## 5. Threat boundary

The candidate aims to resist remote network substitution, an unauthorized local principal using another OS credential, peer-supplied fake process/application labels, stale ceremony state, stale or replayed approval, connection replacement, and unauthorized profile downgrade.

It does **not** claim resistance to root/SYSTEM/administrator authority able to defeat the trusted OS boundary; a compromised kernel; a compromised authorized-user boundary; code injected into an authorized process; a stolen or inherited authenticated IPC handle where the OS treats possession as authorization; or a malicious same-principal process when policy deliberately authorizes every process under that principal.

## 6. Principal and application identity

An OS SID, UID, GID, package credential, or comparable OS principal is not automatically application identity. If consumer policy authorizes every process authenticated as principal `P`, then `P` is the authorization boundary. The profile MUST NOT describe that rule as authenticating a specific application binary.

A deployment requiring narrower application identity needs a separately reviewed adapter and policy based on authenticated platform evidence, which may include package, signing, service, or other platform-specific identity. This abstract profile standardizes none of those mechanisms.

## 7. Mutual endpoint authentication and authorization

Both directions are mandatory:

- **Responder/Host:** authenticates and consumer-authorizes the connected Initiator endpoint before showing an approval request.
- **Initiator:** authenticates and consumer-authorizes the Host/server endpoint on the same connection before trusting `LOCAL_ACCEPT`, Responder bootstrap bytes, Host approval, or success.

Authentication must be bound to the actual connection used by the ceremony. A named endpoint, pipe/socket path, or successful connection alone is insufficient. This requirement prevents a malicious local listener/server from impersonating the intended Host. The exact authentication mechanisms and evidence are adapter-specific and remain unselected.

## 8. Bootstrap, context, and expected peer

Reuse the remote canonical bootstrap record and its existing field/resource maxima:

```text
application_identity
key_algorithm
public_key
shared_context
```

Local success authenticates only that the authorized local ceremony endpoint supplied these exact bootstrap bytes. It does not establish external identity truth, private-key possession, application authorization beyond the separate local authorization decision, or durable trust.

Apply the existing D14 context and expected-peer semantics:

- each side supplies `shared_context` independently and compares exact bytes;
- the consumer explicitly selects open/first-contact or expected-peer intent;
- partial expected fields are allowed;
- expected key material is compared as the pair `(key_algorithm, public_key)`;
- an expected-peer check never falls back to open mode;
- authenticated key bytes are never silently substituted, including directory K1 → K2 replacement.

OS-principal authorization is additional local-profile evidence; it does not replace bootstrap or context validation. Successful pairing does not prove possession of the long-term bootstrap private key. Later proof-of-possession or reconnect remains separate and is out of scope.

## 9. Ceremony identity and authoritative state

Each new locally initiated ceremony uses an `initiator_nonce` of exactly 16 raw bytes, generated by the Initiator security core with an OS-backed CSPRNG. Before releasing an honestly generated nonce, the core MUST ensure it does not collide with an active locally generated nonce in the applicable local namespace; on collision it regenerates before sending. This nonce is public and non-secret, is sent in `LOCAL_START`, and provides pre-establishment correlation and freshness. A receiving Responder treats it as peer-controlled input and MUST NOT rely on attacker-supplied randomness.

After receiving a valid, authenticated, and authorized `LOCAL_START`, the Responder security core generates a `responder_nonce` of exactly 16 raw bytes using its OS-backed CSPRNG. It applies the same active locally generated nonce collision check before releasing the value. The Responder nonce is public and non-secret, is sent in `LOCAL_ACCEPT`, and contributes independent Responder freshness. Neither nonce is the authoritative `ceremony_identity`. No persistent historical nonce database is required solely for this active-collision check.

The one authoritative identity is:

```text
ceremony_identity = SHA-256(transcript)  // exactly 32 raw bytes
```

The transcript domain is the exact ASCII byte string below, with no Unicode normalization:

```text
D = ASCII("sas-pairing-local-authenticated-profile-draft-01/transcript/v1")
```

Let `START` and `ACCEPT` be the exact canonical `LOCAL_START` and `LOCAL_ACCEPT` payload bytes, including their `SASPAIR` headers, version, type, and all length-prefixed fields, but excluding the outer record prefixes. Then:

```text
transcript = u32be(len(D)) || D
          || u32be(len(START)) || START
          || u32be(len(ACCEPT)) || ACCEPT
ceremony_identity = SHA-256(transcript)
```

The order is fixed. The identity MUST be fixed before Host approval and MUST NOT include approval or ACK. `LOCAL_START` and `LOCAL_ACCEPT` bind the profile, version, message types, roles, both nonces, and both bootstrap records including each side's shared context. Fixing identity before approval lets Host approval refer to an already-fixed ceremony identity instead of creating a circular ordering.

This digest identifies and binds canonical protocol bytes. It is not a MAC, peer authentication, OS-connection authentication, or a replacement for adapter evidence. Distinct accepted canonical transcripts with the same digest imply a SHA-256 collision. An approved adapter remains responsible for authenticated endpoint binding and message integrity.

Authoritative state MUST also bind the exact authenticated adapter connection, adapter-authenticated endpoint evidence, consumer authorization decision, and whatever current authorization state/version is needed to invalidate stale authorization. The representation is implementation-specific; no particular token type is required. Revocation or replacement invalidates the active ceremony. Two authenticated connections remain different state objects even when all transcript bytes, nonces, and the digest match. Messages or approval from one connection MUST NOT enter another connection's state. Raw OS credentials and OS-specific principal structures are not serialized into the generic transcript.

## 10. Draft semantic message flow

Every payload has this header:

```text
ASCII("SASPAIR")  // exactly 7 bytes
u16be(1)
u8(message_type)
```

Every field is `u32be(byte_length) || exact_bytes`. V1 requires exact field order, with no missing, repeated, reordered, unknown, or trailing fields. Length and aggregate arithmetic MUST be checked before allocation. Every local message includes the exact ASCII profile identifier `sas-pairing-local-authenticated-profile-draft-01` as its first field using this encoding. The version is exactly `u16be(1)`; an unsupported version fails the local profile, with no negotiation during an active ceremony. Roles are one-byte values `Initiator = 0x01` and `Responder = 0x02`; every message carries sender role then receiver role, including messages whose type already indicates direction.

Local message types are fixed and do not overlap remote message types `0x01..0x09`:

| Message | Type |
|---|---:|
| `LOCAL_START` | `0x40` |
| `LOCAL_ACCEPT` | `0x41` |
| `LOCAL_APPROVE` | `0x42` |
| `LOCAL_REJECT` | `0x43` |
| `LOCAL_ACK` | `0x44` |

The schemas below list fields after the header, in wire order. `field(x)` means the ordinary length-prefixed field encoding. Bootstrap bytes reuse the existing canonical bootstrap representation and validation exactly: `application_identity`, `key_algorithm`, `public_key`, and `shared_context`, with the existing 16,384-byte bootstrap maximum. No local near-copy is defined.

```text
LOCAL_START (0x40):
  field(profile_identifier), field(initiator_nonce),
  field(sender_role), field(receiver_role), field(initiator_bootstrap)
  initiator_nonce = 16 bytes; roles = 0x01, 0x02

LOCAL_ACCEPT (0x41):
  field(profile_identifier), field(initiator_nonce), field(responder_nonce),
  field(sender_role), field(receiver_role), field(responder_bootstrap)
  initiator_nonce = exact nonce accepted in START; responder_nonce = 16 bytes
  roles = 0x02, 0x01

LOCAL_APPROVE (0x42), LOCAL_REJECT (0x43), LOCAL_ACK (0x44):
  field(profile_identifier), field(ceremony_identity),
  field(sender_role), field(receiver_role)
  ceremony_identity = 32 bytes
  APPROVE/REJECT roles = 0x02, 0x01; ACK roles = 0x01, 0x02
```

`LOCAL_START`'s bootstrap already includes `shared_context`; context MUST NOT be repeated as a top-level field. `LOCAL_ACCEPT` does not repeat the Initiator bootstrap because the exact `LOCAL_START` bytes are in the transcript. Message type itself expresses APPROVE or REJECT; there is no extra decision byte or required rejection reason.

Before sending `LOCAL_ACCEPT`, the Responder compares the received Initiator `shared_context` byte-for-byte with its independently supplied local context. Before accepting `LOCAL_ACCEPT`, the Initiator compares the Responder bootstrap's `shared_context` byte-for-byte with its independently supplied local context. Each endpoint also applies its selected expected-peer checks to the received canonical bootstrap. Any mismatch fails before Host approval or success.

An outer transport-independent record is `u32be(payload_length) || canonical_payload`; the length excludes the four-byte prefix. Fragmented transport reads are allowed and one OS read need not equal one message. The parser obtains exactly four length bytes, validates the length before allocation, reads exactly the payload (possibly fragmented), parses it canonically, and treats subsequent bytes as the next record. Closing before a complete record is terminal for an active ceremony. No alternate magic is defined. Profile identifier, type range, version, state machine, transcript domain, and explicit profile selection keep local and remote profiles separate; ambiguous or unsupported profile/version fails closed.

The local ceremony adds no HMAC, signature, Diffie–Hellman exchange, or shared pairing secret. Those are not substitutes for the mutually authenticated, integrity-protected channel required from an approved adapter. A local ceremony never transforms into a remote ceremony; higher-level caller policy may start a new remote SAS ceremony after local failure if allowed.

## 11. State, disconnect, and restart

The local state machine is:

| Role/state | Legal action or message | Transition |
|---|---|---|
| Initiator `Idle` | Deliberate Start on authenticated local connection; generate nonce and send `LOCAL_START` | `AwaitAccept` |
| Responder `Idle` | Valid `LOCAL_START`; authenticate and authorize Initiator; validate profile, bootstrap, context, and expected peer; generate responder nonce; construct canonical ACCEPT and fix identity; send `LOCAL_ACCEPT` | `AwaitHostDecision` |
| Initiator `AwaitAccept` | Valid `LOCAL_ACCEPT`; authenticate and authorize Host; validate nonce, bootstrap, context, and expected peer; fix identity | `AwaitApproval` |
| Responder `AwaitHostDecision` | Exact Host approval; send `LOCAL_APPROVE` | `AwaitAck` |
| Responder `AwaitHostDecision` | Host rejection; send `LOCAL_REJECT` if possible | `Failed` |
| Initiator `AwaitApproval` | Valid exact `LOCAL_APPROVE`; revalidate connection and authorization; fully write `LOCAL_ACK` | `Succeeded` after complete write |
| Initiator `AwaitApproval` | Valid exact `LOCAL_REJECT` | `Failed` |
| Responder `AwaitAck` | Valid matching `LOCAL_ACK` on same authenticated connection | `Succeeded` |
| Any nonterminal state | Disconnect, restart, authorization revocation, adapter predicate loss, malformed input, changed duplicate, or illegal next message | `Failed` |
| Any terminal state | Any later event | No state or result change |

Host approval is accepted only after identity is fixed and applies to that exact ceremony state. Before identity establishment, route state by exact authenticated adapter connection instance and `initiator_nonce`; afterward the same state object also records `ceremony_identity`. Connection identifiers are internal state and are not serialized. No reordering buffer exists.

On the same active connection and ceremony, an exact byte-for-byte duplicate of an already accepted message is ignored idempotently: no transition, repeated prompt, repeated ACCEPT/APPROVE/ACK, or repeated result. A changed duplicate or illegal-next/out-of-order message fails the ceremony. A duplicate `LOCAL_APPROVE` after the Initiator issued ACK MUST NOT trigger a second ACK. Terminal state is immutable. V1 defines no application-level retransmission or recovery semantics.

Disconnect before local success is terminal. There is no reconnect/resume: a new connection is a new ceremony with fresh nonces, endpoint authentication, authorization, and Host approval. Process restart destroys active ceremonies and pending approvals. Historical nonce/identity storage is not required solely for active freshness under this no-resume rule. Authorization revocation/replacement or loss of any required adapter predicate invalidates the active ceremony. Durable consumer trust remains consumer-owned.

## 12. Completion and result semantics

The Initiator succeeds only after deliberate Start, adapter mutual authentication and authorization, peer bootstrap/context/expected-peer validation, fixed identity, valid matching Host `LOCAL_APPROVE`, a live connection/authorization recheck, and successful complete write of the exact `LOCAL_ACK` on that still-valid authenticated connection. The write proves neither receipt, Responder success, nor durable trust storage.

The Responder succeeds only after authenticating and authorizing the Initiator, validating exact bootstrap/context/expected-peer state, fixing identity, receiving explicit exact Host approval, sending `LOCAL_APPROVE`, and receiving a valid matching `LOCAL_ACK` on the same authenticated connection. Sending approval alone is not success.

Neither result proves durable trust storage. Message loss or disconnect may let one endpoint meet its local success condition while the other returns no success. If both return success, their local profile/version, ceremony identity, opposite roles, peer bootstrap, and shared context MUST be compatible; conflicting successful results are forbidden. Atomic bilateral success and atomic durable trust persistence are not claimed. In particular: before ACCEPT, after ACCEPT but before Host decision, after APPROVE but before Initiator receipt, and after receipt but before ACK issuance, neither may report success; after a successful ACK write whose receipt is lost, Initiator may succeed while Responder does not; once Responder verifies ACK it succeeds. REJECT is terminal despite any later APPROVE or ACK.

The language-neutral result should preserve the common contract conceptually:

```text
ceremony_identity
peer_role
authenticated_peer_bootstrap
authenticated_shared_context
profile_identifier
profile_version
```

`ceremony_identity` is the exact 32-byte transcript digest above. Neither nonce is an alternate identity or an added PairingResult field. The local result need not contain the remote profile's `request_id`.

It MUST NOT add generic `identity_verified` or `os_principal` fields. The narrow claim is:

> An approved local-profile adapter established and maintained the configured authenticated-local OS boundary for both endpoints; the consumer authorized the connection-bound endpoint evidence; the exact bootstrap/context for this exact local ceremony was accepted under that authorization; and the Host explicitly approved that ceremony.

This does not mean the peer is a particular human or application executable, owns the bootstrap private key, or cannot be impersonated by privileged malware.

## 13. Selection policy and remote SAS accounting

**Automatic:** choose the local profile only if an adapter is separately approved for the deployment, its complete authenticated-local predicate succeeds, consumer authorization succeeds, and policy permits it. Otherwise choose the remote SAS profile or fail according to caller/product policy. Because zero adapters are approved, this abstract profile alone cannot activate SAS-free production pairing.

**Always require SAS:** use the remote SAS ceremony, even if an approved authenticated-local adapter could otherwise succeed. The transport may physically be local, but the security profile remains remote SAS. No hybrid local-without-SAS mode exists.

Local attempts MUST NOT consume, reset, or refund the remote 5,497 SAS opportunities. They cannot bypass remote budget exhaustion by being relabeled local. If the local predicate fails, local SAS-free success is impossible; a separately selected remote SAS attempt follows the ordinary remote accounting rules.

## 14. Resource bounds

Local messages carrying the existing canonical bootstrap reuse its exact field and bootstrap maxima and MUST NOT enlarge them. A complete local record is at most 65,536 bytes including the four-byte outer prefix, so `payload_length` is at most 65,532 bytes. Reject zero/invalid length, payloads above 65,532, checked-arithmetic overflow, truncation, and malformed payload before unbounded allocation. Do not modify the remote frame cap. Partial reads follow §10; bytes after one complete record belong to the next record.

The profile requires bounded input sizes, bounded active local ceremonies, finite rate/resource controls, prompt/fatigue protection, and finite ceremony timeouts. The local candidate values and enforcement rules are defined in §15. These controls protect availability and human attention; they do not count or limit remote SAS attempts.

Raw OS token/SID structures, PID, Linux `ucred`, UID/GID triples, Android Binder structures, and similar platform credentials MUST NOT be placed in generic wire/bootstrap data. An adapter or consumer may retain evidence separately for audit under its own rules.

## 15. Local admission, capacity, rate, and timeout policy

### 15.1 Admission and connection scope

The applicable local security core MUST maintain an independently locally controlled state:

```text
local_pairing_admission = enabled | disabled
```

Network or peer input MUST NOT enable admission. General interactive/reference integrations SHOULD default to disabled and enable only after deliberate local action. A service/deployment MAY deliberately keep admission continuously enabled, subject to every resource limit, ceremony-specific Host approval, authorization, rate control, and timeout in this section.

Disabling admission immediately prevents new ceremonies and terminally fails all existing nonterminal local ceremonies, invalidating pending approval and releasing owned slots. Re-enabling admission never resumes an old ceremony. Admission is neither durable trust, peer identity, SAS accounting, nor an authorization result.

Host approval authorizes one exact accepted ceremony. Admission determines whether local pairing may be admitted at all. Host approval occurs after request work and state already exist, so it does not replace admission or prevent request-processing and prompt abuse.

One authenticated local IPC connection MUST carry at most one local pairing ceremony during its lifetime. A second `LOCAL_START` on that connection MUST NOT start a retry, replace prior state, or create another concurrent ceremony; it is refused or fails according to state. A new attempt requires a new authenticated connection, new nonces and ceremony identity, fresh endpoint authentication, authorization, and Host approval. This rule is separate from duplicate-message handling.

### 15.2 Active ceremony and Host-decision capacity

The maximum is exactly **4 active local ceremonies globally** across the applicable local security-core/logical-endpoint scope, shared by Initiator and Responder ceremonies and all workers serving that scope. It is not four per worker, connection, PID, SID/UID, application identity, or bootstrap identity. Optional narrower limits MAY supplement this global cap.

An Initiator atomically reserves one active slot when local Start creates ceremony state, before sending `LOCAL_START`; if unavailable, it fails before sending. A Responder does not consume a ceremony slot for raw unauthenticated transport activity. After bounded intake, adapter endpoint authentication, local admission, the applicable START limiter, canonical/semantic `START` validation, consumer authorization, and context/expected-peer validation, it MUST atomically reserve both an active slot and the single Host-decision slot before creating active state, generating/releasing `responder_nonce`, or sending `LOCAL_ACCEPT`. If either reservation is unavailable, it refuses before state, nonce, ACCEPT, or Host prompt.

The separate maximum for ceremonies in `AwaitHostDecision` is exactly **1**. This slot is held only while a ceremony is in `AwaitHostDecision`; it is released when that state ends. On approval, `AwaitHostDecision → AwaitAck` releases the Host-decision slot but retains the ordinary active slot. Another ceremony may then enter `AwaitHostDecision`, subject to the limiters and available active slot. Rejection and every other terminal path release all slots owned by the ceremony.

There is no Host-approval queue. A Responder must have both slots before `LOCAL_ACCEPT`; authenticated peers do not bypass this rule. With all four active slots occupied or the Host-decision slot occupied, refuse the new ceremony without evicting/replacing an existing one, creating a prompt, or generating/releasing ACCEPT merely to report capacity. Slot release occurs exactly once on success, rejection, timeout, disconnect, cancellation, authorization revocation, adapter-predicate loss, admission closure, or process restart.

### 15.3 Mandatory global rate controls

Every deployment MUST configure explicit finite rate and burst/capacity values for both of these distinct global controls:

1. **START/resource admission limiter:** bounds serial local request-processing work. Apply it after bounded transport intake and sufficient adapter endpoint authentication to identify an eligible local connection, and before expensive semantic/state work where practical.
2. **Host-approval request limiter:** bounds prompt flooding, approval fatigue, and habituation. Apply only after local admission, authorization, structural validation, and context/expected-peer validation, and before reserving or surfacing the Host-decision interaction.

Missing or unbounded values fail closed for new local ceremony admission/prompts. Exact numeric rates and burst capacities are deployment-selected and MUST NOT be invented as universal profile values. Optional per-principal, per-app, per-connection, or per-user limits MAY be stricter, but do not replace either global control.

Global enforcement MUST be coordinated across all workers serving the same applicable endpoint scope and MUST NOT rely solely on PID, UID/SID, public key, application identity, bootstrap, connection, or ceremony nonce. Authenticated or previously known peers do not bypass capacity, rate controls, or deadlines. Uncertain/missing live shared limiter state fails closed for new admissions/prompts. Durable rate-window state is not required across an ordinary restart; a process/device restart MAY initialize a fresh operational rate window because these limits are not a cryptographic cumulative-attempt counter. A deployment claiming a bound across restart within a time interval MUST persist/coordinate enough state to support that claim. There is no generic rollback/reinstall continuity guarantee.

### 15.4 Deadlines and terminal behavior

The candidate uses three finite deadlines:

```text
machine/protocol inactivity = 60 seconds
Host decision deadline       = 2 minutes
absolute ceremony deadline   = 5 minutes
```

The machine inactivity deadline applies while waiting for machine/protocol progress, including Initiator `AwaitAccept` and Responder `AwaitAck`; it does not run during deliberate Host-decision wait. It starts when Initiator Start creates active state or when an accepted Responder `START` becomes active after required admission and slot reservations. Only a valid, expected, state-advancing protocol event refreshes it. Duplicates, malformed or illegal messages, keepalives, unrelated traffic, UI activity, and adapter noise do not.

The non-extendable 2-minute Host-decision deadline applies while the Responder is in `AwaitHostDecision` and while the Initiator waits in `AwaitApproval` for that same Host decision after validating `LOCAL_ACCEPT`. It starts for the Responder when ceremony identity is fixed, `LOCAL_ACCEPT` is issued, and the state enters `AwaitHostDecision`; for the Initiator it starts when valid `LOCAL_ACCEPT` is validated, identity is fixed, and the state enters `AwaitApproval`. The 60-second machine deadline is suspended in this phase; the absolute deadline continues.

The non-extendable 5-minute absolute deadline starts at Initiator active-state creation or Responder acceptance into active state, and continues through machine waits, Host decision, approval, and final ACK wait. No event extends it; it overrides any remaining phase-specific time.

Any deadline expiry terminally fails the ceremony, invalidates Host approval/callbacks, releases each owned slot exactly once, drops volatile ceremony evidence, and prevents later messages from resurrecting it. Retries require a new authenticated connection and a new ceremony. Deadlines use monotonic elapsed time; wall-clock changes MUST NOT extend them. After suspend/resume, deadlines are re-evaluated conservatively; if elapsed time cannot be established reliably enough, active ceremonies fail. Process restart destroys all active state and pending approvals and does not resume ceremonies.

These values are candidate engineering/resource limits, not cryptographic-strength claims. The local controls bound memory, CPU, state, IPC churn, stale authorization, prompt flooding, human fatigue, and availability. Local ceremonies contain no 39-bit SAS random guess, consume none of remote `N = 5,497`, do not affect remote `ε = 10^-8`, and require no local statistical attempt counter. Resource-cap, rate, or timeout refusal affects availability; it does not weaken a completed ceremony when its required predicates hold, and it never changes remote SAS accounting.

### 15.5 Future coverage (not implemented here)

Future vectors/tests MUST cover: fifth active ceremony refusal before responder state, nonce, ACCEPT, or prompt; shared cap across roles/workers; second `LOCAL_START` on one connection; unavailable Host slot causing no state/nonce/ACCEPT/prompt; Host slot release at approval transition to `AwaitAck` while active slot remains; another ceremony entering Host decision; no queue; START-rate and Host-prompt-rate rejection; rotating PID/identity/connection not bypassing live global limiters; exact 60-second, 2-minute, and 5-minute timeout behavior and absolute-deadline precedence; duplicate does not refresh; valid transition selects the next timer; timeout/admission closure releases slots once; conservative suspend expiry; restart destroys active state and may start fresh operational rate windows; and no local control changes remote 5,497 accounting. No tests or vectors are implemented by this document.

## 16. Platform research status (non-normative)

These are research notes, not profile guarantees or adapter approvals.

| Platform | Current research status |
|---|---|
| Windows | Needs more adapter research/review. |
| Linux | Sufficient evidence to draft a future adapter candidate; **not approved**. |
| macOS | Needs more adapter research/review. |
| Android | Sufficient evidence to draft a future adapter candidate; **not approved**. |
| iOS | No generic unrelated-app adapter established. |

`Ready to draft candidate adapter` does not mean `approved adapter`. There are zero approved adapters after this task.

### Windows research note

Windows named pipes are not inherently local-only. A future candidate would need explicit remote rejection such as `PIPE_REJECT_REMOTE_CLIENTS`, a restrictive security descriptor/DACL, authenticated client token, consumer authorization, server authentication by the client, and squatting/race handling. PID, process name, and executable path alone are insufficient. This is research direction only; no Windows adapter is approved.

### Unix and mobile research notes

- **Linux:** a filesystem Unix-domain socket with peer credentials is promising. Endpoint directory/socket ownership, namespaces/containers, and mutual principal authorization still need review. An abstract namespace is not filesystem authorization.
- **macOS:** Unix-domain peer credentials or managed IPC appear possible; assumptions remain unapproved.
- **Android:** LocalSocket/Binder authenticated OS UID evidence appears promising; package/signature authorization is deployment-specific.
- **iOS:** no generic unrelated-app authenticated-local adapter is selected.

These notes do not standardize the APIs or turn research into profile guarantees.

## 17. Adapter approval gate

An adapter may be called **APPROVED** only after a separate security review records its exact OS primitive and version scope; endpoint creation semantics; remote exclusion; peer credential mechanism; mutual endpoint authentication; namespace/path/name ownership; permissions/ACLs; race handling; process/PID lifecycle if used; handle inheritance/transfer assumptions; authorization semantics; integrity assumptions; pre-authentication bounds for listener/backlog, credential-query, and partial-read resources; and known limits. Every approved adapter must bound those adapter-level resources separately. The generic four-slot cap does not claim to bound all adapter-level denial of service. Approval is deployment-scoped. No adapter meets this gate in this task.

Future adapter specifications may be separate documents, for example `docs/p3-local-adapter-windows-draft.md`, `docs/p3-local-adapter-linux-draft.md`, and `docs/p3-local-adapter-android-draft.md`; no placeholders are created here.

## 18. Future conformance coverage

Future deterministic vectors should include positive canonical `LOCAL_START`, `LOCAL_ACCEPT`, exact transcript bytes, 32-byte identity, `LOCAL_APPROVE`, `LOCAL_REJECT`, and `LOCAL_ACK`. Mutation cases should cover profile, version, type, either nonce, roles, either bootstrap/context, wrong identity, reordered/unknown/missing fields, duplicates and changed duplicates, trailing/truncated data, overflow, oversized and zero-invalid records, fragmented valid records, cross-profile messages, wrong-connection approval/ACK, and replayed START yielding a fresh Responder nonce and new identity. Resource/lifecycle coverage is listed in §15.5. Also retain adapter/selection cases: no approved adapter blocks Automatic local selection; loopback is insufficient; authorization and mutual-authentication failures block success; changed connection is distinct; Always require SAS stays remote; and local activity does not affect the remote 5,497 budget. Do not generate vectors now.

No vectors or implementation tests are produced by this draft.

## 19. Open same-device gates

1. Concrete deployment-selected finite rates and burst/capacity values for both global limiters.
2. Windows adapter.
3. Linux adapter.
4. macOS adapter.
5. Android adapter.
6. iOS/support policy.
7. Deterministic vectors.
8. Independent external security review.

These remaining rate configuration, vector, adapter, and review gates do not reopen the candidate's selected cap, connection rule, admission, prompt serialization, or timeout values. They do not imply any platform adapter is approved. The local profile is a candidate foundation only.
