# P3 same-device authenticated-local — security decisions and review log

This document is the audit trail for the separate same-device authenticated-local profile: its architecture, threat boundary, adapter model, authorization semantics, ceremony mechanics, and future adapter decisions. The normative abstract candidate is [the local profile draft](p3-same-device-local-profile-draft.md). This log does not replace it or the separate [vodozemac candidate log](p3-vodozemac-security-decisions.md).

## Status and evidence boundaries

Candidate B remains the **SELECTED P2 remote construction**. The vodozemac ceremony remains **CANDIDATE — NOT SELECTED** for remote pairing. This authenticated-local profile is separate from either remote construction. The Windows principal-bound named-pipe adapter is documented as a candidate only; no platform adapter is approved. Independent external security review remains mandatory. This is a candidate decision record, not external review or production approval.

Keep four evidence levels distinct:

1. **Platform research evidence:** APIs and their documented behavior inform possible future adapters; research does not itself approve one.
2. **Abstract candidate decision:** this log and profile define generic requirements.
3. **Future adapter decision:** each concrete OS adapter and deployment scope remains undecided.
4. **Independent external review:** still required for the complete profile and each adapter before use.

## L1 — Abstract authenticated-local profile and approved-adapter architecture

**Status:** Abstract candidate architecture selected for specification; no production adapter approved.

**Decision:** Define a generic authenticated-local ceremony above separately approved platform adapters. The core owns the predicate, lifecycle, bootstrap/context binding, approval, state machine, selection, and result semantics. An adapter must establish genuine local-kernel IPC, remote exclusion, endpoint-bound peer authentication, integrity, and mutual endpoint authentication under documented configuration and permission assumptions.

**Rationale:** OS mechanisms, permissions, namespaces, endpoint naming, and remote-exclusion behavior differ by platform and deployment. Encoding those differences as generic protocol guarantees would overstate what the core can establish. Loopback, hostnames, discovery metadata, process names, paths, and PIDs are not authenticated locality evidence by themselves. Separating adapter review keeps the generic claim dependent on evidence the adapter actually supplies.

**Alternatives considered:** Treat localhost or same-machine detection as sufficient; standardize one platform primitive generically; or treat the remote vodozemac SAS ceremony as the local profile. These do not establish the required OS boundary and would conflate separate profiles.

**Evidence boundary:** P1 permits a distinct same-device OS-authenticated profile subject to locality, authorization, remote exclusion, ceremony-specific approval, and threat-boundary requirements. Current platform observations in the local profile are non-normative research only.

**Does not establish:** Any Windows/Linux/macOS/Android/iOS adapter, production readiness, or resistance beyond the actual trusted OS/user boundary.

**Independent-review status:** Generic contract and every future adapter require independent review.

## L2 — Mutual endpoint OS authentication and consumer authorization

**Status:** Abstract candidate requirement.

**Decision:** Both endpoints authenticate and authorize the opposite endpoint on the exact connected channel. The Responder/Host authenticates and authorizes the Initiator before presenting approval. The Initiator authenticates and authorizes the Host/server before accepting its bootstrap, approval, or success. Adapter evidence must be bound to the actual connection; endpoint names alone are insufficient.

An OS SID/UID/GID/package credential is a principal credential, not automatically application identity. If consumer policy authorizes every process under principal `P`, then that principal is the actual security boundary. The profile makes no specific-binary claim. Narrower application identity requires a separately reviewed adapter/policy using authenticated platform evidence.

**Rationale:** One-way client authentication leaves a malicious local listener able to impersonate the intended Host. Mutual endpoint authentication closes that gap only to the extent of the adapter's OS evidence and consumer authorization. Explicitly stating same-principal semantics prevents an OS user credential from being mistaken for binary identity.

**Alternatives considered:** Authenticate only the connecting client; treat a named endpoint/path as Host identity; or equate a user credential with application identity. Each overstates evidence available to the generic core.

**Does not establish:** Identity beyond the authenticated principal/evidence and authorization policy; it does not resist privileged OS compromise, injected code in an authorized process, or malicious same-principal processes when all such processes are authorized.

**Independent-review status:** Adapter evidence, connection binding, and deployment authorization policy remain unreviewed.

## L3 — Local ceremony, approval, and result lifecycle

**Status:** Historical abstract candidate decision. Its original single-nonce framing is superseded by L5's two-nonce and canonical-identity mechanics; its lifecycle and approval principles are further specified by L6.

**Decision:** The core generates a fresh public, non-secret 128-bit nonce for every local attempt. Ceremony state also binds profile/version, exact roles, the exact authenticated connection, endpoint evidence and authorization decisions, both canonical bootstrap records, shared context, and approval state. Host approval applies only to that complete state. Initiator's deliberate Start is its intent; no second confirmation is required solely for symmetry. A valid Host approval is followed by `LOCAL_ACK`; Responder reports success only after receiving the matching ACK. Disconnect, changed state, revoked authorization, adapter-predicate loss, or restart terminates the attempt. There is no resume; a new connection/retry gets new state and new approval.

At the time L3 was recorded, the nonce by itself was not claimed to authenticate the complete ceremony, and the exported identity and canonical framing were open; L5 now defines those mechanics. Results may be asymmetric under final message loss; if both sides succeed, results must be compatible. Durable trust remains consumer-owned.

**Rationale:** Complete-state binding prevents stale approval from transferring across changed connections or inputs. No-resume semantics avoid requiring durable active-ceremony replay state. Local verified completion states what each side knows without promising atomic bilateral success or durable persistence.

**Alternatives considered:** Reuse a nonce/approval after reconnect or restart; let a global “always approve” switch stand in for per-ceremony Host approval; claim the nonce alone is a cryptographic transcript identity; or promise atomic completion. Those choices either reuse stale authority or exceed the specified evidence.

**Does not establish:** A reviewed canonical transcript, a final `ceremony_identity` encoding, durable trust writes, or simultaneous success.

**Independent-review status:** Lifecycle semantics are candidate only; identity/framing mechanics and complete-state binding require focused review.

## L4 — Remote-profile separation and selection policy

**Status:** Candidate decision.

**Decision:** Keep the local profile independent of Candidate B and the vodozemac remote candidate. **Automatic** may choose local only when a deployment-approved adapter and the complete predicate both succeed and policy permits it; otherwise use remote SAS or fail by caller/product policy. Because zero adapters are approved, this abstract profile cannot currently activate SAS-free production pairing. **Always require SAS** uses the remote SAS ceremony, even over physically local transport. No user preference can establish locality or authorize a silent downgrade.

Local attempts neither consume nor reset/refund the remote `N = 5,497` SAS opportunities. If the local predicate fails, local SAS-free success is impossible; any remote SAS attempt uses normal remote accounting.

**Rationale:** Remote Candidate B decisions and their aggregate SAS budget remain unchanged. Mixing profiles or letting remote failure fall through to a local shortcut would violate the distinct trust boundaries and could bypass remote accounting.

**Alternatives considered:** Treat the local profile as Candidate B without SAS; use the vodozemac ceremony as a local shortcut; infer local eligibility from user preference or address labels; or let local attempts alter the remote epoch. None preserves the defined profile and budget boundaries.

**Does not establish:** A production selection policy implementation, adapter approval, or a change to Candidate B, its `5,497` budget, or the unselected vodozemac candidate.

**Future coverage:** Verify that absent/unapproved adapter blocks Automatic local selection; loopback never satisfies the predicate; mutual authentication and authorization failures block success; Always require SAS stays on the remote SAS profile; remote failure cannot become local success; and local attempts do not affect remote accounting.

**Independent-review status:** Generic selection and separation rules require review with the complete local profile. Future adapter decisions require separate scoped evidence and review.

## L5 — Canonical local framing and transcript identity

**Status:** Candidate mechanics defined; requires independent review.

**Decision:** Retain profile identifier `sas-pairing-local-authenticated-profile-draft-01`, version `1`, and define two distinct public, non-secret 16-byte nonces. The Initiator security core generates `initiator_nonce` with an OS-backed CSPRNG for each new locally initiated ceremony and sends it in `LOCAL_START`. The Responder security core generates `responder_nonce` with an OS-backed CSPRNG only after valid/authenticated/authorized `LOCAL_START` and sends it in `LOCAL_ACCEPT`. Before release, each core checks against active locally generated nonces in its applicable local namespace and regenerates on collision. A receiver treats a peer-provided nonce as untrusted input; security does not depend on attacker-supplied randomness. No persistent historical nonce database is required solely for active collision avoidance.

Reuse the seven-byte ASCII `SASPAIR` payload header, `u16be(1)` version, fixed local message types `0x40..0x44`, and field encoding `u32be(length) || exact_bytes`. V1 field order is exact and forbids missing, repeated, reordered, unknown, or trailing fields; length arithmetic is checked before allocation. Every local message carries the exact ASCII profile identifier. Roles are one byte (`Initiator=0x01`, `Responder=0x02`) and every message explicitly encodes sender then receiver. Local schemas and bootstrap reuse are normatively listed in the profile. The transport-independent outer record is `u32be(payload_length) || payload`; fragmentation is allowed and the declared length excludes the four-byte prefix.

The sole authoritative ceremony identity is exactly 32 raw bytes:

```text
D = ASCII("sas-pairing-local-authenticated-profile-draft-01/transcript/v1")
transcript = u32be(len(D)) || D
          || u32be(len(START)) || START
          || u32be(len(ACCEPT)) || ACCEPT
ceremony_identity = SHA-256(transcript)
```

`START` and `ACCEPT` are their exact canonical payloads, including header and fields but excluding outer record prefixes. This identity is fixed after canonical ACCEPT exists and before Host approval. START+ACCEPT bind profile/version/types/roles, both nonces, and both canonical bootstraps including contexts. Excluding approval lets Host approval refer to an already-fixed identity and avoids circular ordering. The digest identifies/binds canonical protocol bytes; it is not a MAC, peer authentication, OS connection authentication, or adapter evidence. Distinct accepted canonical transcripts with the same digest imply a SHA-256 collision. No HMAC, signature, Diffie–Hellman, or shared pairing secret is added to the local ceremony.

The complete local record cap is 65,536 bytes including its four-byte prefix, hence payload maximum 65,532 bytes. OS credential structures and platform-specific principal evidence are excluded from the generic transcript. The local state separately binds the exact authenticated connection, adapter-authenticated endpoint evidence, consumer authorization decision, and current authorization state/version sufficient to invalidate stale authorization. This is a security property, not a mandated token/API type; revocation or replacement invalidates the active ceremony.

**Rationale:** The Responder nonce contributes independent freshness after an authenticated and authorized request; replaying START therefore produces a different transcript and identity except for the negligible chance of a repeated 128-bit nonce or a SHA-256 collision. Exact canonical framing and a transcript digest provide one deterministic local identity without treating either nonce as the result identity. Keeping connection and authorization evidence in local state preserves adapter binding without making OS-specific structures part of generic bytes.

**Alternatives considered:** Nonce-only identity; approval-inclusive transcript identity; nonce plus digest as competing identities; transport-specific record boundaries; a new local magic; or a local MAC/HMAC. Nonce-only does not bind both accepted bootstrap records; approval-inclusive identity cannot be fixed before approval; multiple identity values make result semantics ambiguous; transport-specific framing harms consistency; new magic duplicates the existing envelope; and a local MAC would imply a key/authentication mechanism absent from this channel-based profile.

**Does not establish:** SHA-256 authentication, endpoint authentication, any adapter approval, or production readiness.

**Independent-review status:** The exact transcript, SHA-256 collision assumption, parser bounds, and adapter boundary remain subject to independent review.

## L6 — Local state machine, duplicate, and completion semantics

**Status:** Candidate mechanics defined; requires independent review.

**Decision:** The Initiator moves `Idle → AwaitAccept` when it deliberately sends START on an authenticated connection. The Responder accepts START only after authenticating/authorizing the Initiator and validating profile, bootstrap, context, and expected-peer state; it generates its nonce, constructs canonical ACCEPT and fixes identity, sends ACCEPT, and enters `AwaitHostDecision`. The Initiator accepts canonical ACCEPT only after authenticating/authorizing the Host and validating nonce/bootstrap/context/expected-peer state; it fixes the same identity and enters `AwaitApproval`. Exact Host approval causes the Responder to send APPROVE and enter `AwaitAck`; Host rejection sends REJECT when possible and is terminal. A valid APPROVE causes the Initiator to recheck connection/authorization, write one complete ACK, and succeed after the write. The Responder succeeds only after receiving and validating the matching ACK on the same authenticated connection.

Before establishment, route local state by exact authenticated connection instance and initiator nonce; after establishment, that same state object also records the digest. Connection identity is not serialized. Different connections are distinct even when transcript, nonces, and digest match. The state binds adapter-authenticated evidence, consumer authorization, and current authorization state/version sufficient to invalidate stale authorization; revocation/replacement terminates the active ceremony. No reordering buffer exists.

On the same active connection/ceremony, an exact byte-for-byte duplicate of an accepted message is ignored idempotently without another transition, prompt, ACCEPT, APPROVE, ACK, or result. A changed duplicate, illegal-next message, or out-of-order message is terminal failure. In particular, a duplicate APPROVE after ACK issuance cannot produce a second ACK. Terminal states are immutable. V1 adds no retransmission/recovery behavior.

Initiator success occurs only after deliberate Start; mutual endpoint authentication/authorization; peer bootstrap/context/expected-peer validation; fixed identity; matching Host APPROVE; live connection/authorization recheck; and successful complete ACK write on the still-valid connection. This does not prove ACK receipt, Responder success, or durable trust. Responder success requires authentication/authorization and validation, fixed identity, exact Host approval, APPROVE sent, and matching ACK actually received on the same connection. Thus after ACK write but before receipt, Initiator may succeed while Responder does not. Other pre-ACK disconnect points yield no success; REJECT remains terminal despite later messages. New connection/restart means fresh nonces, authentication, authorization, approval, and ceremony; resume is unsupported.

**Rationale:** State-object and connection binding prevents equal wire bytes or digest values from crossing authenticated channels. Idempotent duplicate ignore prevents accidental repeated side effects while ensuring lost final ACK does not hide an unapproved retry protocol. The selected local completion contract makes each endpoint's result depend only on evidence it actually observed and does not claim distributed atomicity.

**Alternatives considered:** Duplicate-triggered retransmission; a second final ACK; reconnect/resume; and an atomic/common-success claim. Retransmission and a second ACK create additional delivery semantics without common knowledge; resume would require new persistent replay/approval machinery; and network loss makes simultaneous common success unclaimable.

**Does not establish:** Simultaneous success, ACK delivery from a successful write, durable trust persistence, or adapter security.

**Independent-review status:** State transitions, duplicate semantics, result points, and connection/authorization invalidation remain subject to review.

## L7 — Local resource, timeout, and approval-flood policy

**Status:** Candidate policy selected for the abstract same-device profile; requires independent security review. It does not approve a platform adapter.

**Decision:** Require a separately and locally controlled `local_pairing_admission = enabled | disabled` state. Network/peer input cannot enable it. General interactive/reference integrations SHOULD default to disabled and require deliberate local action to enable; a service/deployment MAY deliberately keep it continuously enabled under all limits, authorization, ceremony-specific Host approval, rate controls, and timeouts. Closing admission immediately rejects new ceremonies and terminally fails existing nonterminal ceremonies.

One authenticated local IPC connection carries at most one ceremony for its lifetime. A second `LOCAL_START` cannot retry, replace state, or create another ceremony. A new attempt requires a new authenticated connection, nonces, ceremony identity, endpoint authentication, authorization, and Host approval.

Set the maximum to **4 active local ceremonies globally** across the applicable local security-core/logical-endpoint scope, counting Initiator and Responder roles together across all workers. It is not a per-worker, connection, PID, SID/UID, application, or bootstrap limit. The Initiator reserves a slot when Start creates state and before sending START. The Responder reserves atomically only after bounded intake, endpoint authentication, admission, the START limiter, canonical/semantic START validation, authorization, and context/expected-peer validation, but before active state, responder-nonce generation/release, or ACCEPT. Capacity refusal happens before ACCEPT and creates no Host prompt.

Add a separate maximum of **1 ceremony in `AwaitHostDecision`**. Host approval authorizes one exact accepted ceremony; admission determines whether any local ceremony may be admitted. Approval follows prior processing/state and does not replace admission. The Host-decision slot is held only while the state is `AwaitHostDecision`. Approval releases it on `AwaitHostDecision → AwaitAck`, while the ordinary active slot remains held. Rejection or another terminal outcome releases all applicable slots. There is no approval queue. If either the active or Host-decision slot is unavailable, refuse before creating responder state, generating/releasing a responder nonce, ACCEPT, or prompt. Never evict/replace an active ceremony. Release each slot exactly once on terminal outcome or restart.

Require two distinct finite global rate controls, each configured with explicit deployment-selected rate and burst/capacity values: (1) a START/resource-admission limiter after bounded intake and sufficient endpoint authentication, before expensive semantic/state work where practical; (2) a Host-approval request limiter after admission, authorization, structural validation, and context/expected-peer validation, before reserving/surfacing the Host interaction. Missing/unbounded configuration fails closed. No universal numeric rates are selected. Optional narrower limits may supplement but not replace either global control. All workers serving the logical endpoint share live limiter state; enforcement MUST NOT rely solely on rotatable PID, UID/SID, public key, application identity, bootstrap, connection, or nonce. Missing or uncertain live shared state fails closed. Ordinary restart MAY initialize a fresh operational rate window; there is no generic cross-restart guarantee. A deployment claiming a time-bounded limit across restart must persist/coordinate enough state to support that claim. These are not durable SAS-style counters.

Freeze three non-extendable candidate deadlines: **60 seconds** for machine/protocol inactivity, **2 minutes** for Host decision, and **5 minutes** absolute ceremony lifetime. The machine timer starts when local Initiator state is created or accepted Responder state becomes active, and applies during machine waits but not Host-decision wait. Only valid, expected, state-advancing protocol events refresh it; duplicates, malformed/illegal input, keepalives, unrelated traffic, UI activity, and adapter noise do not. The Host timer starts when Responder identity is fixed, ACCEPT is issued, and `AwaitHostDecision` begins; on Initiator it starts after validating ACCEPT, fixing identity, and entering `AwaitApproval`. The absolute timer starts at active-state creation and continues through Host decision and ACK wait; it overrides any remaining phase deadline. Deadlines use monotonic elapsed time; suspend/resume is evaluated conservatively and uncertain elapsed time fails the active ceremony. Restart destroys active ceremonies and approvals.

Resource limits protect memory, CPU, state, IPC churn, stale authorization, prompt flooding, human fatigue, and availability. They are not analogous to remote SAS attempt accounting: local ceremonies contain no 39-bit SAS random guess, consume none of remote `N = 5,497`, do not affect remote `ε = 10^-8`, and require no local statistical attempt counter. Availability refusal does not weaken a completed ceremony whose security predicates hold.

**Rationale:** An authenticated or authorized local peer need not be benign. A local admission switch bounds whether work may start; one ceremony per connection prevents retries from inheriting connection state; the shared active cap bounds memory/CPU/state across roles and workers; and the separate Host slot limits simultaneous human attention without holding that slot through final ACK. A queueless policy avoids hidden approval backlog. Independent global limiters bound serial request work and prompt fatigue despite identity/connection rotation. Finite deadlines bound stale authorization and abandoned state. Treating these as availability controls avoids confusing them with the remote cryptographic SAS budget.

**Alternatives considered:** No explicit admission; unlimited or deployment-only active cap; caps of 1, 2, 8, or 16; multiple ceremonies per connection; multiple simultaneous Host prompts; bounded or unbounded approval queues; holding the Host slot through terminal success after approval; reusing remote timeout values without a local Host timer; fully deployment-selected timeout values; omitting either global limiter; universal rate values; or durable rate state across every restart. These either leave local work/human attention unbounded, allow stale connection authority, hold the prompt slot longer than its state, create hidden backlog, or impose availability/persistence claims unrelated to a cryptographic attempt bound.

**Security boundary:** These are availability/resource/human-factors controls, not cryptographic attempt accounting. They do not strengthen SHA-256, OS authentication, or authorization. Admission is not trust, identity, SAS accounting, or authorization. Host approval remains ceremony-specific. Capacity/rate/timeout refusal changes availability only and never modifies remote `N = 5,497` or `ε = 10^-8`. Adapter-level pre-authentication IPC resources remain a separate adapter responsibility; the four-slot cap does not claim to bound them.

**Future vector/test implications:** Cover fifth global active ceremony refused; cap shared by roles/workers; second START on one connection rejected; unavailable Host slot causes no state/nonce/ACCEPT/prompt; Host slot releases on approval transition to AwaitAck while active slot remains and another ceremony can enter Host decision; no queue; START and prompt rate rejection; PID/identity/connection rotation cannot bypass live global limiters; 60-second machine timeout; 2-minute Host timeout; 5-minute absolute timeout and precedence; duplicates do not refresh; valid transitions select the proper next timer; timeout releases exact slots once; admission closure releases state; conservative suspend expiry; restart destroys active state and may start a fresh operational rate window; deployment claims across restart have supporting persistence; and no local control changes remote 5,497 accounting. No vectors or tests are implemented here.

**Independent-review status:** The abstract policy is recorded but remains subject to independent external security review. Exact deployment rates, cross-process coordination/storage, concrete adapters, vectors, and final P3 review remain open.

## Unresolved local mechanics and future decisions

Keep open: concrete deployment-selected values for both mandatory global limiters; deterministic vectors; Windows adapter conformance and per-release validation; Linux, macOS, Android, and iOS adapter/support decisions; and independent external security review. Future platform decisions must be added to this log with their OS/version scope, primitive, peer evidence, mutual authentication, remote exclusion, endpoint/permission/race assumptions, authorization semantics, integrity, limits, and review status. L5/L6 supersede L3's earlier open framing/identity mechanics; L7 closes the abstract candidate resource/timeout policy without selecting any platform adapter or exact limiter values. L8 records a Windows principal-bound adapter candidate only and does not approve it. No remote-profile decision changes.

The local profile reuses the remote bootstrap and D14 semantics but does not alter the remote profile or remote security decision log. Platform credential structures remain adapter evidence and are excluded from generic wire/bootstrap/result claims.

## L8 — Windows principal-bound authenticated-local adapter candidate

**Status:** Candidate adapter documented; **NOT APPROVED**; requires independent external security review. This decision preserves zero production-approved platform adapters.

### Decision

Document a Windows authenticated-local candidate using duplex byte-mode named pipes at `\\.\pipe\LOCAL\<deployment-defined-name>`, scoped to currently serviced Windows 11 desktop builds with validation per supported release. Require `LOCAL\` namespace use, `PIPE_REJECT_REMOTE_CLIENTS` on every server instance, an explicit owner/DACL, non-inheritable handles, finite adapter-level pre-auth resources and pipe-instance bounds, and `FILE_FLAG_FIRST_PIPE_INSTANCE` for the initial Host instance.

For ordinary interactive desktop mode, require the expected Host `TokenUser` SID and an authorization policy restricted to the intended user plus logon SID/session. The Host authenticates the Initiator using `ImpersonateNamedPipeClient`, `OpenThreadToken`, and required token queries after exactly one bounded first record and before admitting `LOCAL_START` to generic ceremony processing. It always reverts impersonation; failed `RevertToSelf` takes the worker/process out of service following Microsoft's fail-safe guidance.

The Initiator authenticates the Host before generic Start or `LOCAL_START` using the owner SID from `GetSecurityInfo` on the actual connected pipe handle, plus the expected `LOCAL\` login-session boundary, restrictive DACL, and consumer authorization. The owner SID is normative Host-principal evidence for the permitted Windows ownership boundary; the DACL is access-control evidence, not identity. Every client open uses `SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION`. Pipes use duplex byte mode; generic local framing remains authoritative. The pipe name and connection bind the adapter evidence to that one pipe instance. Windows SIDs, tokens, PIDs, and session evidence remain outside generic wire, transcript, and result data.

The security claim is principal-bound only. It does not identify an executable, process name, path, PID, file hash, Authenticode signer, window, human, or bootstrap private-key possessor. Same-account different-session peers are not automatically authorized. Service/session-0 and packaged/AppContainer modes need separate policy and review. All failures of remote exclusion, namespace/session checks, descriptor/owner validation, either endpoint authentication, authorization, pre-auth resources, or generic admission fail closed with no local SAS-free success.

### Alternatives considered

One-way client authentication only; PID or process-name server identity; executable-path identity; default pipe security descriptor; DACL-only Host identity; pipe-name secrecy; SSPI/Negotiate; service/broker-only architecture; and application-signature identity. These either leave the Host unauthenticated to the Initiator, rely on mutable or name-based metadata, exceed the minimum principal-bound mode, or require a separate identity mechanism and review.

### Evidence boundary

- **Microsoft API semantics:** Microsoft documentation describes `LOCAL\` login-session scope, named-pipe modes and per-instance behavior, remote-client rejection, first-instance creation, owner/DACL access, token inspection and impersonation, SQOS impersonation levels, handle inheritance, and owner-assignment privileges. References are collected in [the Windows adapter draft](p3-local-adapter-windows-draft.md).
- **Internal candidate design:** this log selects the above API combination and principal/session authorization as a project candidate. The pipe owner SID is normative Host-principal evidence only within the stated owner-creation contract; the DACL is not identity evidence.
- **Application identity:** unsolved. No executable, signer, package, or service identity is claimed by this minimum adapter.
- **Review:** source documentation is not a complete threat analysis or approval. Independent external review, supported-release validation, concrete pre-auth and deployment rate values, deterministic adapter/conformance tests, deterministic generic P3 vectors, and whole-P3 review remain required.

**Does not establish:** A particular executable or human, private-key possession, security beyond the configured principal/logon-session boundary, any Windows production approval, or production readiness.

**Independent-review status:** Not reviewed or approved. The candidate must be revalidated on each currently serviced Windows 11 desktop release in scope. Service, package, and AppContainer modes are outside this decision.
