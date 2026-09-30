# 0003 — Windows account-scoped pairing authority ownership

**Status:** Accepted for the experimental P4 implementation.

## Context

The P3 canonical pairing-authority identity is application-neutral and remains encoded as `sas-pairing-authority-v1 || u32be(scope_length) || scope`. Windows ownership must be shared across processes and logon sessions of one authenticated account, while genuinely independent authorities under different accounts may operate separately.

## Decision

Windows derives the ownership key from the unchanged canonical identity and the current process token's `TokenUser` SID. It obtains the profile root from `GetUserProfileDirectoryW`, never from caller input or an environment variable. The resulting lock file is held with the existing exclusive `LockFileEx` lease.

The trusted application registry identifies the underlying pairing capability and supplies one stable logical scope for it across process and frontend restarts. It must reject aliases and conflicting mappings. A capability shared across Windows accounts is unsupported; accounts may have separate authorities only when their pairing capability and state are genuinely independent. Separate machines are not coordinated.

The generic core does not infer capability identity or expose a Windows account selector. The application must not accept a caller-provided SID, username, profile path, or authority scope from untrusted ceremony input. Failure to obtain token identity or profile location fails closed.

## Consequences

Different logon sessions for the same account resolve the same SID-bound lock identity and profile-based lock location. Different accounts have separate lock namespaces. This decision is an experimental P4 platform policy; it does not revise the normative P3 identity encoding or approve production security. Cross-session execution remains required evidence before cryptographic contribution exposure is enabled.
