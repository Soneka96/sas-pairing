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

For every local attempt, the core generates a fresh 128-bit nonce from its CSPRNG, independently of prior attempts. The nonce is public, non-secret, and scoped to one ceremony. A retry or reconnect receives a new nonce. The nonce alone is not claimed to cryptographically authenticate the entire ceremony.

Authoritative local ceremony state consists of the local profile and version, nonce, exact roles, exact authenticated connection, authenticated and authorized endpoint evidence, both canonical bootstrap records, shared context, and approval state. Approval and result MUST bind to that complete state. If later review selects a canonical transcript digest as the exported `ceremony_identity`, it may refine the representation without weakening this binding.

**Open mechanical gate:** final exported `ceremony_identity` may be the nonce, a canonical transcript digest including it, or another reviewed deterministic representation. Canonical local framing and transcript hashing have not received focused review; none is frozen or externally approved here.

## 10. Draft semantic message flow

The local profile has its own semantic messages: `LOCAL_START`, `LOCAL_ACCEPT`, `LOCAL_APPROVE`, `LOCAL_REJECT`, and `LOCAL_ACK`. They are local-profile messages only. Each transition binds the local profile identifier and version, ceremony nonce/identity handle, appropriate sender/receiver roles, and the relevant canonical bootstrap/context state. Remote-profile frames cannot be accepted as local frames, and local frames cannot advance remote-profile state. These names define semantic roles only; canonical encoding and numeric type assignments remain open.

1. **`LOCAL_START` — Initiator:** after deliberate local Start and adapter establishment of the authenticated local transport, the core creates a fresh nonce and sends profile/version, nonce, Initiator role, Initiator bootstrap, and shared context. This action expresses Initiator intent, not Host approval.
2. **Pre-approval validation — Responder:** verify the adapter predicate and actual connected Initiator; authorize its evidence; validate profile/version, canonical START/bootstrap/context, and expected-peer constraints; then create state bound to this connection. Any failure is terminal, with no SAS-free fallback success.
3. **`LOCAL_ACCEPT` — Responder:** send only after all preceding checks pass. Bind profile/version, the same nonce, roles, Responder bootstrap, exact matched context, and local ceremony state. Before trusting it, Initiator must authenticate and authorize the Host/server endpoint on this same connection.
4. **Host approval:** after all required endpoint and bootstrap/context checks, the Host presents this exact active ceremony for explicit approval or rejection. Approval binds profile/version, nonce/final identity, roles, exact connection, authorized endpoint evidence and decision, both bootstrap records, and context. A global “always approve local peers” setting is not ceremony-specific approval; no unattended bypass is defined here.
5. **`LOCAL_APPROVE` / `LOCAL_REJECT`:** transmit or terminate the Host action, bound to the exact active connection, ceremony, profile/version, roles, and canonical bootstrap/context. Initiator Start is sufficient Initiator intent; no extra Initiator confirmation is required solely for symmetry.
6. **`LOCAL_ACK` and completion:** on a valid approval, Initiator revalidates current connection, identity, ceremony, roles, bootstrap/context, and active state, then sends ACK. Responder returns local success only after the matching valid ACK. Initiator may return success after issuing ACK on the still-valid authenticated connection. A successful write does not prove durable peer trust.

The complete local state—not the nonce alone—binds approval and result. Every missing, changed, ambiguous, or unauthenticated value fails closed.

## 11. State, disconnect, and restart

Each local attempt has isolated state. Changed connection, OS principal, authorization decision, role, profile/version, bootstrap, or context invalidates pending approval and requires a new ceremony and approval. Authorization revocation, closure of local admission, or loss of the adapter predicate during an active ceremony terminates it.

Disconnect before local success is terminal. There is no reconnect/resume: a new connection is a new ceremony with a new nonce, reauthentication, reauthorization, and new Host approval. Process restart destroys active local ceremonies and pending approvals; none resumes. Durable consumer trust remains consumer-owned. No historical replay database is required solely for active-ceremony replay under this no-resume rule.

## 12. Completion and result semantics

Neither result proves durable trust storage. Message loss or disconnect may let one endpoint meet its local success condition while the other returns no success. If both return success, their local profile/version, ceremony identity, opposite roles, peer bootstrap, and shared context MUST be compatible; conflicting successful results are forbidden. Atomic bilateral success and atomic durable trust persistence are not claimed.

The language-neutral result should preserve the common contract conceptually:

```text
ceremony_identity
peer_role
authenticated_peer_bootstrap
authenticated_shared_context
profile_identifier
profile_version
```

It MUST NOT add generic `identity_verified` or `os_principal` fields. The narrow claim is:

> An approved local-profile adapter established and maintained the configured authenticated-local OS boundary for both endpoints; the consumer authorized the connection-bound endpoint evidence; the exact bootstrap/context for this exact local ceremony was accepted under that authorization; and the Host explicitly approved that ceremony.

This does not mean the peer is a particular human or application executable, owns the bootstrap private key, or cannot be impersonated by privileged malware.

## 13. Selection policy and remote SAS accounting

**Automatic:** choose the local profile only if an adapter is separately approved for the deployment, its complete authenticated-local predicate succeeds, consumer authorization succeeds, and policy permits it. Otherwise choose the remote SAS profile or fail according to caller/product policy. Because zero adapters are approved, this abstract profile alone cannot activate SAS-free production pairing.

**Always require SAS:** use the remote SAS ceremony, even if an approved authenticated-local adapter could otherwise succeed. The transport may physically be local, but the security profile remains remote SAS. No hybrid local-without-SAS mode exists.

Local attempts MUST NOT consume, reset, or refund the remote 5,497 SAS opportunities. They cannot bypass remote budget exhaustion by being relabeled local. If the local predicate fails, local SAS-free success is impossible; a separately selected remote SAS attempt follows the ordinary remote accounting rules.

## 14. Resource bounds

Local messages carrying the existing canonical bootstrap reuse its exact field and bootstrap maxima and MUST NOT enlarge them. Any local envelope is bounded and parsed using checked length/aggregate arithmetic before allocation. If the complete local-frame maximum is separate from the remote frame cap, its exact value remains open.

The profile requires bounded input sizes, bounded active local ceremonies, finite rate/resource controls, prompt/fatigue protection, and finite ceremony timeouts. Exact active-ceremony maximum, rate thresholds, timeout values, and any separate complete-frame cap remain open same-device candidate gates. Remote five-minute/60-second timeout values are precedent only and are not inherited here.

Raw OS token/SID structures, PID, Linux `ucred`, UID/GID triples, Android Binder structures, and similar platform credentials MUST NOT be placed in generic wire/bootstrap data. An adapter or consumer may retain evidence separately for audit under its own rules.

## 15. Platform research status (non-normative)

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

## 16. Adapter approval gate

An adapter may be called **APPROVED** only after a separate security review records its exact OS primitive and version scope; endpoint creation semantics; remote exclusion; peer credential mechanism; mutual endpoint authentication; namespace/path/name ownership; permissions/ACLs; race handling; process/PID lifecycle if used; handle inheritance/transfer assumptions; authorization semantics; integrity assumptions; and known limits. Approval is deployment-scoped. No adapter meets this gate in this task.

Future adapter specifications may be separate documents, for example `docs/p3-local-adapter-windows-draft.md`, `docs/p3-local-adapter-linux-draft.md`, and `docs/p3-local-adapter-android-draft.md`; no placeholders are created here.

## 17. Future conformance coverage

Future tests/vectors should cover: no approved adapter means Automatic cannot choose local; loopback cannot satisfy the predicate; unauthorized principal rejection; behavior under same-principal policy exactly as declared; a squatter/incorrect server rejection by the adapter; mutual-authentication failure blocks success; changed connection creates new ceremony; stale approval rejection; changed bootstrap/context rejection; expected-peer downgrade prohibition; Host approval bound to exact ceremony; disconnect before completion is terminal; asymmetric final ACK handling; profile confusion rejection; Always require SAS never takes the SAS-free path; and local activity leaves the remote 5,497 budget unchanged.

No vectors or implementation tests are produced by this draft.

## 18. Open same-device gates

1. Exported `ceremony_identity`: nonce versus canonical transcript digest or another reviewed representation.
2. Canonical local message encoding and type numbers.
3. Complete local-frame maximum if separate from remote framing.
4. Exact active local-ceremony cap.
5. Exact local rate limits.
6. Exact local timeout policy.
7. Windows adapter.
8. Linux adapter.
9. macOS adapter.
10. Android adapter.
11. iOS/support policy.
12. Independent external security review.

These are open mechanics and approval gates, not reasons to infer a platform adapter is approved. The local profile is a candidate foundation only.
