# 0003 — Windows account-scoped pairing authority ownership

**Status:** Accepted for the experimental P4 implementation.

## Context

The P3 canonical pairing-authority identity is application-neutral and remains encoded as `sas-pairing-authority-v1 || u32be(scope_length) || scope`. Windows ownership must be shared across processes and logon sessions of one authenticated account, while genuinely independent authorities under different accounts may operate separately.

## Decision

Windows derives the ownership key from the unchanged canonical identity and the current process token's `TokenUser` SID. It obtains the profile root from `GetUserProfileDirectoryW`, never from caller input or an environment variable. The resulting lock file is held with the existing exclusive `LockFileEx` lease.

The trusted application registry identifies the underlying pairing capability and supplies one stable logical scope for it across process and frontend restarts. It must reject aliases and conflicting mappings. A capability shared across Windows accounts is unsupported; accounts may have separate authorities only when their pairing capability and state are genuinely independent. Separate machines are not coordinated.

The generic core does not infer capability identity or expose a Windows account selector. The application must not accept a caller-provided SID, username, profile path, or authority scope from untrusted ceremony input. Failure to obtain token identity or profile location fails closed.

## Consequences

Different logon sessions for the same account resolve the same SID-bound lock identity and profile-based lock location. Owner-run manual verification on 2026-09-30 confirmed contention in both directions and replacement after release across actual Windows process session IDs 0 and 1, using the same account identity and canonical authority identity. This verifies the exercised Windows 11 Pro/S4U configuration; it does not establish cross-machine coordination, same-profile attacker resistance, administrator/SYSTEM isolation, or cryptographic security. This decision remains the approved experimental P4 Windows account-scoped policy; it does not revise the normative P3 identity encoding or approve production security. The evidence was manually executed and is not an automated CI result, formal proof, or professional audit.
