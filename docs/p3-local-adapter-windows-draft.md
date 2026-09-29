# Windows authenticated-local adapter — Draft 01

> **CANDIDATE ADAPTER — PRINCIPAL-BOUND ONLY — NOT APPROVED — REQUIRES INDEPENDENT SECURITY REVIEW**
>
> This document proposes one Windows adapter for the separate authenticated-local candidate profile. It is a design draft, not an implementation, platform approval, or production-readiness decision. There remain **zero production-approved platform adapters**.

## 1. Purpose, scope, and claim

This adapter candidate uses Windows named pipes to authenticate a Windows **principal and logon-session boundary** on the exact connected pipe instance. It does not authenticate a particular executable, process name, path, PID, Authenticode signer, human, or possession of the bootstrap private key.

The ordinary deployment mode described here is an interactive desktop Host and Initiator authorized as the same expected user SID and expected logon SID/session. A deployment must define its expected principal and authorization policy. Authorization to a principal intentionally includes every process in that principal/session boundary that can satisfy the policy; it does not distinguish the intended Host executable from another process inside that boundary.

The candidate scope is **currently serviced Windows 11 desktop builds**, with validation for each supported release and relevant edition/configuration. The supported release set must be recorded and revalidated as servicing changes. Older API minimum-version tables do not establish general Windows 10, Windows Server, or historical Windows support. Platform behavior and security assumptions must be revalidated for every release in the supported set. Microsoft documents changing release servicing windows; see [Windows 11 lifecycle](https://learn.microsoft.com/en-us/lifecycle/faq/windows) and [Windows 11 release information](https://learn.microsoft.com/en-us/windows/release-health/windows11-release-information).

The abstract same-device profile remains candidate-defined. Candidate B remains the **prior P2 abstract remote construction selection**, with its concrete instantiation unresolved; vodozemac remains an unselected remote candidate. No remote construction is ready for final selection. This Windows adapter is **CANDIDATE — NOT APPROVED**. Independent external security review remains mandatory, and the abstract local profile alone does not enable SAS-free production pairing.

## 2. Source behavior and project decisions

The Microsoft references in §18 describe Windows API behavior. The policy choices in this document—expected SID/session, owner as Host-principal evidence, authorization rules, resource bounds, and fail-closed behavior—are project candidate decisions built on that behavior. Microsoft API documentation does not approve this adapter or establish the project's complete security claim.

## 3. IPC primitive and framing

The candidate endpoint is:

```text
\\.\pipe\LOCAL\<deployment-defined-name>
```

Use a duplex named pipe configured as byte type and byte read mode. Use the frozen generic local record framing unchanged:

```text
u32be(payload_length) || canonical_payload
```

The generic framing is authoritative. Pipe message mode is not protocol framing. Fragmented reads are normal; a read boundary is not a record boundary. Overlapped versus synchronous I/O is implementation-selected, subject to the deadlines and finite resource rules in §12.

`LOCAL\` contributes login-session scoping and cross-session separation. It is one part of the boundary, not complete endpoint authentication. The exact expected local pipe name is deployment-defined and fixed by policy. The Initiator must form a local pipe path itself; it must not accept an arbitrary server name or remote UNC path from discovery or peer input.

## 4. Remote exclusion

Both conditions are mandatory:

```text
\\.\pipe\LOCAL\<name>
PIPE_REJECT_REMOTE_CLIENTS on every server instance
```

The Host applies `PIPE_REJECT_REMOTE_CLIENTS` to every instance it creates. No instance may use the remote-accepting mode. A missing or mixed setting makes the Windows authenticated-local predicate false, so the local path cannot proceed and cannot produce SAS-free success. `NT AUTHORITY\NETWORK` denial and a restrictive DACL alone are not proof of locality.

The Initiator uses only the local `.` server form and the configured `LOCAL\` pipe name. It must not connect using arbitrary remote UNC syntax. The name or its secrecy is not authentication.

## 5. Explicit owner and DACL policy

The Host must supply an explicit security descriptor when creating every pipe instance. Default named-pipe security is prohibited, including `lpSecurityDescriptor = NULL` or equivalent default ACL behavior. Microsoft's documented default pipe descriptor grants read access to Everyone and anonymous in addition to broader principals, which exceeds this candidate policy.

Ordinary interactive desktop candidate policy:

- Owner is the expected Host `TokenUser` SID.
- The DACL is restrictive and explicitly names the intended Host and authorized login-session principal using a logon-SID-aware policy.
- No Everyone, anonymous, or broad generic-user ACE is allowed.
- The Initiator receives only the exact read, write, and `READ_CONTROL` rights needed for this duplex protocol and descriptor inspection.
- Do not grant broad `FILE_GENERIC_WRITE` to the client: named-pipe generic write includes `FILE_CREATE_PIPE_INSTANCE`.
- SYSTEM and Administrators are not added automatically for convenience. A deployment needing them must document and separately authorize that broader policy.

The Initiator's client handle must request `READ_CONTROL` so it can read the owner and DACL from the connected pipe handle. An unreadable, absent, null, malformed, or broader-than-policy descriptor fails closed. The DACL is mandatory access-control/configuration evidence; it is not Host identity evidence.

### Owner assignment contract

The normative desktop candidate requires the Host to create the pipe while running under its own expected security context, with no unrelated impersonation token active. The descriptor explicitly sets owner to the expected Host `TokenUser` SID, and the owner/DACL remain unchanged for the pipe instance lifetime.

The security argument relies on Windows ownership rules and excludes an actor with sufficiently powerful ownership/restore privileges. Microsoft documents that `SeRestorePrivilege` or `WRITE_OWNER` can set an arbitrary valid owner SID, and that the owner can modify the DACL. This privileged capability is outside the ordinary principal-bound claim. Any detected or expected owner/DACL mutation requires separate review; the Initiator checks the descriptor on the actual connected handle.

## 6. Mutual endpoint authentication

Both endpoints authenticate and authorize the peer on the exact connected pipe instance. `LOCAL\`, the pipe name, a DACL, or a successful connection alone does not satisfy this requirement.

### Host authenticates Initiator

`ImpersonateNamedPipeClient` authenticates the security context associated with the last message read. Therefore, before generic ceremony processing, the Host performs this adapter pre-authentication sequence on the same pipe instance and worker:

```text
accept connection
↓
read exactly one bounded first generic record
↓
ImpersonateNamedPipeClient
↓
OpenThreadToken
↓
GetTokenInformation
↓
snapshot TokenUser + logon SID + TokenSessionId evidence
↓
RevertToSelf
↓
consumer authorization
↓
only then admit LOCAL_START into generic ceremony processing
```

The first record is adapter pre-authentication work. It must obey the generic 65,536-byte complete-record maximum, use an adapter-level partial-read deadline, and consume finite pre-auth resources. It must not create generic ceremony state before authentication and authorization succeed. No further pipe read may occur between completing this first record and obtaining the impersonation token. The implementation and independent review must verify the documented “last message read” semantics for the selected byte-mode/framing implementation on every supported Windows release; unresolved semantics fail closed.

After successful impersonation, every path—including token-query and evidence-validation failures—must call `RevertToSelf` before worker reuse. Failure of `ImpersonateNamedPipeClient`, `OpenThreadToken`, any required `GetTokenInformation`, or evidence validation fails closed. If `RevertToSelf` fails, Microsoft says the process continues in the client's context and should shut down; the worker/process must be taken out of service using a reviewed fail-safe, with no further local pairing. It must never return normally to the worker pool.

### Initiator authenticates Host

Before generic local Start is invoked or `LOCAL_START` is sent, the Initiator authenticates and authorizes the Host on the actual connected pipe handle:

```text
CreateFile(local LOCAL\\ path, exact duplex rights + READ_CONTROL,
           SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION)
↓
GetSecurityInfo(actual connected pipe handle, owner + DACL)
↓
validate owner SID == expected authorized Host principal
↓
validate LOCAL\\ login-session boundary and restrictive expected DACL
↓
consumer authorizes Host evidence
↓
ONLY THEN invoke generic local Start and send LOCAL_START
```

Failure to read or validate the owner, DACL, namespace/session policy, or consumer authorization fails closed. The pipe owner SID is the normative generic Host-principal evidence: it supports the claim that the pipe object was created under the permitted Windows ownership boundary defined here. It does not prove a particular process image, executable, signer, or current PID. The DACL is access-control evidence, not identity evidence. The check is against the descriptor of the actual connected handle, not a separate name lookup.

## 7. Principal and cross-session authorization

Ordinary desktop authorization requires both:

```text
expected User SID AND expected login-session boundary
```

Host-side evidence snapshots `TokenUser`, the token logon SID, and `TokenSessionId`. Session ID is supporting session evidence; consumer policy must require the expected logon SID/session and the configured `LOCAL\` boundary. Authorization by User SID alone is insufficient because one account may have multiple independent logon sessions.

Ordinary interactive mode does not span another Remote Desktop logon, fast-user-switching logon, simultaneous logon by the same account, or service/session 0. A deployment that intentionally supports one of these cases requires a separately specified authorization mode and review. `LOCAL\` alone is not treated as complete mutual authentication.

Integrity level is authorization/access-control metadata, not identity. Host policy may inspect integrity or AppContainer state, but must not weaken mandatory integrity controls to permit pairing. The minimum candidate makes no Host application, package, or integrity identity claim from the pipe owner.

## 8. Security QoS

Every client pipe `CreateFile` must include:

```text
SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION
```

The candidate does not rely on a Windows default impersonation level and does not request `SecurityImpersonation` or `SecurityDelegation`. `SecurityIdentification` permits the server to inspect client identity without granting unnecessary ability to act as that client. Any alternate QoS level is outside this candidate and requires separate review.

## 9. Squatting and startup races

Initial Host pipe creation must include `FILE_FLAG_FIRST_PIPE_INSTANCE`. If creation fails because the name already exists or the initial-instance race is lost, the Host fails closed. It must not use the existing pipe, silently choose a fallback name, or treat another instance as the intended Host.

Subsequent legitimate Host instances use the same explicit security descriptor and remote-rejection configuration, without the first-instance flag. First-instance creation protects startup/name squatting; it is not client-side Host authentication. A malicious process within the exact authorized principal/session boundary may create a pipe satisfying the same principal-bound policy and is inside this candidate's declared trust boundary.

## 10. Handle inheritance and transfer

All pipe handles must be non-inheritable by default. Accidental child-process inheritance is not permitted. Unreviewed `DuplicateHandle`, brokered handle transfer, and intentional inherited server handles are outside the candidate and require explicit review. Sufficiently privileged handle theft or duplication is outside the threat claim.

## 11. Pipe mode, rights, and channel binding

The server instance uses:

```text
PIPE_ACCESS_DUPLEX
PIPE_TYPE_BYTE
PIPE_READMODE_BYTE
```

The client requests compatible read/write access and `READ_CONTROL`. Exact client rights must not include unneeded generic rights, especially rights that permit creation of another pipe instance. Overlapped versus synchronous I/O remains implementation-selected.

Each named-pipe instance has its own buffers and endpoint handles and is a separate conduit. An unauthorized ordinary process that only knows the public pipe name cannot inject bytes into the already-established connection. An allowed process may open another connection if policy permits, but that is a different pipe instance/connection and therefore a different local ceremony. No additional confidentiality guarantee is claimed. This argument excludes stolen/duplicated endpoint handles, process injection, Administrator/SYSTEM authority, and kernel compromise.

Windows owner/DACL state is assumed established at creation and immutable during a connected instance. A descriptor mutation/change detected or expected by deployment behavior requires separate review. The generic local transcript, wire messages, and `PairingResult` remain unchanged: no Windows SID, token, session ID, PID, or other Windows evidence is serialized into them.

## 12. Adapter-level pre-authentication resources

The generic four-active-ceremony cap begins only after adapter authentication, consumer authorization, and generic admission. It does not bound unauthenticated Windows pipe work. Every deployment/implementation must configure finite limits for:

- pipe instances (`nMaxInstances` must be finite; never `PIPE_UNLIMITED_INSTANCES`);
- unauthenticated connected peers and pre-auth workers;
- partial first-record buffering, size, and read deadline;
- credential-query operations and associated memory;
- connection-attempt churn and other pre-auth CPU/resource use.

Do not set `nMaxInstances = 4` merely because the generic active ceremony cap is four; they govern different resource layers. Concrete adapter numeric values and deployment rate values remain open gates until justified and recorded. Resource exhaustion, an incomplete first record, or deadline expiry fails closed before generic state or SAS-free success.

## 13. Application identity, service, and package modes

### Application identity limitation

This Windows candidate does not authenticate a process executable, executable path, file hash, Authenticode signer, window identity, or a particular human. Do not add Authenticode verification to this minimum adapter. A malicious process within a principal/session that policy intentionally authorizes is inside the trust boundary. Future stronger modes may investigate service SID, MSIX/package identity, AppContainer, a trusted broker, or code-signing policy, but none is selected or approved here.

### Service mode

A Windows service Host may need a separate deployment policy using a service SID, service token, and service/session-specific ACL rules. Ordinary interactive same-logon policy is not automatically valid for session-0 or service deployments. Service mode is future scoped work.

### Packaged and AppContainer modes

MSIX/AppContainer identity may support stronger app-bound policy, but requires a distinct design and review. This candidate does not claim packaged-app identity and does not approve that mode.

## 14. Failure behavior and privileged boundary

The Windows local predicate is false on any of the following:

- missing `PIPE_REJECT_REMOTE_CLIENTS` on any server instance;
- non-`LOCAL\` or unexpected pipe namespace, or an Initiator remote UNC connection;
- missing, invalid, unreadable, default, null, or overbroad security descriptor/DACL;
- owner SID mismatch or unexpected owner/DACL mutation;
- first-instance creation race/failure;
- client impersonation, thread-token open, token query, or evidence-validation failure;
- failure to `RevertToSelf`;
- failed consumer authorization or unexpected user/logon SID/session evidence;
- pre-auth resource exhaustion, partial-read deadline, or connection loss;
- generic admission, global rate limit, active-cap, or timeout failure;
- inability to establish either direction of mutual authentication and authorization.

Every failure yields **NO LOCAL SAS-FREE SUCCESS**. Higher-level policy may start a completely new remote SAS ceremony if permitted; the failed local connection cannot be relabeled or resumed as remote.

The candidate excludes Administrator/SYSTEM authority able to defeat object or process security, kernel compromise, code injection into an authorized process, sufficiently privileged handle duplication, and any malicious process deliberately included by a policy that authorizes all processes in its principal/session boundary. No claim extends beyond the configured Windows principal and logon-session boundary.

## 15. Candidate-specific future conformance cases

No tests or vectors are implemented by this draft. Future deterministic adapter/conformance coverage must include:

- remote UNC/SMB rejected; missing per-instance `PIPE_REJECT_REMOTE_CLIENTS`; non-`LOCAL\` path rejected;
- default/null descriptor, Everyone, anonymous, and broad ACL rejected;
- wrong Host owner SID; unreadable owner/DACL; descriptor mutation;
- unauthorized client user SID; same account with a different logon SID/session; valid same-user/same-session peer;
- unauthorized-principal pipe squatter; authorized same-boundary squatter explicitly treated as inside the boundary; first-instance race failure;
- failed client impersonation; token query failure; `RevertToSelf` failure; SecurityIdentification behavior;
- inherited-handle configuration failure and unreviewed handle-transfer rejection;
- service/AppContainer mismatch;
- partial read and pre-auth timeout; finite pipe-instance exhaustion; second ceremony on one pipe; connection drop;
- generic four-slot limit and one-Host-decision limit;
- Always require SAS never selects the local path.

Coverage also remains required for all frozen generic local deterministic vectors and lifecycle/resource cases. Conformance tests do not replace independent security review.

## 16. Approval status and remaining gates

```text
Windows principal-bound named-pipe adapter:
CANDIDATE — NOT APPROVED — REQUIRES INDEPENDENT SECURITY REVIEW
```

No Windows implementation or other OS adapter is approved. Automatic SAS-free production selection remains blocked. Open Windows/local gates are: deterministic adapter-specific conformance tests; concrete adapter-level pre-auth resource values; concrete deployment rate values; validation on each supported serviced Windows 11 release; separate service/package modes if needed; broader generic P3 conformance coverage beyond the existing deterministic fixtures; and independent external review of the adapter and whole P3 profile. The local profile is not complete or production-ready solely because this draft exists.

## 17. Evidence boundary

The following Microsoft sources describe relevant API semantics. The candidate policies above are project choices and must be checked against the exact supported Windows release set and deployment configuration:

- [IPC and named-pipe `LOCAL\` login-session scope](https://learn.microsoft.com/en-us/windows/apps/develop/communication/interprocess-communication), [named-pipe namespaces and behavior](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipes), and [pipe-name forms](https://learn.microsoft.com/en-us/windows/win32/ipc/pipe-names).
- [Named Pipe Security and Access Rights](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights) documents default-pipe ACL behavior, `GetSecurityInfo`, `READ_CONTROL`, and named-pipe access rights, including the additional `FILE_CREATE_PIPE_INSTANCE` right implicated by generic write.
- [CreateNamedPipe](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createnamedpipea) documents duplex access, byte/message/read modes, remote-client modes, security attributes, `FILE_FLAG_FIRST_PIPE_INSTANCE`, and finite instance configuration. [Named Pipe Open Modes](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-open-modes), [Named Pipe Type, Read, and Wait Modes](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-type-read-and-wait-modes), and [Pipe Handle Inheritance](https://learn.microsoft.com/en-us/windows/win32/ipc/pipe-handle-inheritance) document access, mode, inheritance, and duplication behavior.
- [Impersonating a Named Pipe Client](https://learn.microsoft.com/en-us/windows/win32/ipc/impersonating-a-named-pipe-client) and [ImpersonateNamedPipeClient](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient) document last-message-read context and failure behavior. [OpenThreadToken](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openthreadtoken) and [GetTokenInformation](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-gettokeninformation) provide token access/query behavior; [Access Tokens](https://learn.microsoft.com/en-us/windows/win32/secauthz/access-tokens) describes user, logon SID, owner, and token information.
- [RevertToSelf](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-reverttoself) says a process should shut down if reverting fails. [Impersonation Levels](https://learn.microsoft.com/en-us/windows/win32/secauthz/impersonation-levels) and [CreateFile](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew) document `SECURITY_IDENTIFICATION` and SQOS selection.
- [GetSecurityInfo](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-getsecurityinfo) retrieves owner/DACL from a handle and requires `READ_CONTROL`; [Owner of a New Object](https://learn.microsoft.com/en-us/windows/win32/secauthz/owner-of-a-new-object) documents owner assignment, owner DACL control, and the `SeRestorePrivilege`/`WRITE_OWNER` boundary.
- [GetNamedPipeClientSessionId](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getnamedpipeclientsessionid) documents pipe-client session evidence. It and related session APIs are evidence inputs, not replacements for the selected logon-SID authorization contract.

These sources establish API behavior only. They do not establish a particular executable's identity, select consumer authorization, validate this candidate's complete threat argument, or provide independent security approval.
