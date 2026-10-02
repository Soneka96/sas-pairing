# P5 Analysis — Parser, Commitment, SAS, MAC Domains, Completion, CANCEL

Reviewed source: `core/src/protocol.rs`, `core/src/crypto.rs`, and the ceremony entry points in `core/src/ceremony.rs` at `e21ff0b`, plus the cached vodozemac 0.11.0 `src/sas.rs`. The goal is to review the project's **composition** of vodozemac, not to prove vodozemac.

## 1. Canonical parser and framing

| Attack | Code path | Result |
|---|---|---|
| Integer overflow in lengths | `parse`: `checked_add` on `pos + 4` and `end_len + len`. `wire_frame_extent`: `checked_add` plus the remaining-prefix invariant `pos + 4·later ≤ 65,536` | Rejected (`LengthOverflow`/`Oversized`) |
| Enormous declared length | `wire_frame_extent` rejects as soon as the declaration is read. The transport reserves at most `target − len` ≤ 65,536 | Nothing is allocated from an unvalidated length |
| Incomplete prefix | `header` checks magic and version on whatever bytes are present; `Extent::Need` | Accepted as incomplete; no state |
| Field count | `wire_field_count` per type (3/4/5); START via `StartCandidate::from_wire`; bootstrap exactly 4 | Exact |
| Field order or wrong type | Fixed positions and widths (`fixed_32`, one-byte role and reason enums, 1–64-byte request ID) | Only digest↔MAC and CANCEL role↔reason swaps decode. They become different messages, which the run rejects by digest, role, or MAC (P4 evidence) |
| Duplicate, missing, or trailing field | The parser walks to the exact end, then the count check | Rejected |
| Wrong profile or version | Profile compared byte-exactly as field 0; version `0x0001` | Rejected before dispatch |
| Malformed nested bootstrap | `Bootstrap::decode`: ≤ 16,384 bytes, its own header, type `0x20`, 4 fields, per-field bounds, `key_algorithm` grammar | Rejected. For START this happens after the limiter charge (P3 §11.1.1) |
| Request ID 0 bytes or more than 64 | `bounded(1, 64)` | Rejected. A request ID of all zero bytes is valid opaque data (P3 §4) |
| Concatenation and fragmentation | The transport returns one frame per call by `wire_frame_extent`. The TCP suffix keeps the remainder | Exact. P4 tests every split point |
| Partial-frame retention | One `Option<Partial>` per connection, 4 per authority, 10 s / 2 s deadlines | Bounded |

**Two byte strings, one semantic message?** For a given type, `parse` is a bijection between byte strings and ordered field lists: every field is `u32be(len) ‖ value`, there is no padding, and no varint. Each field's semantic decoding is injective: raw bytes, fixed 32 bytes, or a one-byte enum whose set is exactly {1,2} or {1..4}. `Bootstrap` keeps its raw canonical bytes, and every cryptographic input uses received or sent canonical bytes, never a re-serialization. **No non-canonical alias exists.** This is recorded as the false positive [P5-F-015](findings.md#p5-f-015).

Minor observation: `parse` builds a `Vec<&[u8]>` with one entry per field. Through the public `protocol::decode` on arbitrary bytes, that can reach about 16,384 entries (roughly 256 KiB, transient). Transport-delimited frames have at most 5 fields. No finding.

## 2. Commitment

Rebuilt from `crypto::commitment_input`:

```text
"sas-pairing-vodozemac-profile-draft-01/commit/v1" ‖ u32be(len(START)) ‖ START ‖ R_pub[32]
commitment = SHA-256(...)
```

- **Context:** a fixed domain. START is length-framed and R_pub is fixed-width, which matches P3 §5 exactly. Nothing is omitted.
- **START representation:** at R, the received canonical bytes. At I, the canonical bytes of I's own encoded START. A START changed in transit differs byte for byte.
- **Timing:** R generates its ephemeral and commits after pending admission and before `ACCEPT`. I verifies in `receive_responder_key` **before** DH, SAS, and transcript identity, and before any state other than `Terminal` is installed. A mismatch is terminal.
- **Substitution:** R cannot reveal a different `R_pub` after seeing `I_pub` without a SHA-256 collision.
- **Accounting:** I's opportunity is consumed at its own `I_pub` release, before the commitment opens. That is the P3 order (I exposes first), and a mismatch never refunds.
- **Independent changed-in-transit START scenario** (built independently of P4's test). A MITM rewrites the I bootstrap `application_identity` in START, keeping `shared_context`. R validates the context, is charged by the limiter, and commits over START′. I receives ACCEPT, validates R's bootstrap against its own context, authorizes, reserves, and sends `I_pub`. R performs DH, authorizes, reserves, and reveals `R_pub`. I computes SHA-256 over its own START, finds it differs from the commitment over START′, and fails terminally with no SAS. Both opportunities stay consumed and no result exists. If the MITM instead rewrites the request ID, I rejects ACCEPT (`RequestIdMismatch`) before any reservation.

## 3. Ephemeral keys and contributory checks

- `EphemeralSas::new()` → `Sas::new()` → `rand::rng()` (`ThreadRng`, ChaCha12 reseeding from `SysRng`/`getrandom` 0.4.3 → `ProcessPrng`). It is called exactly once per run: R at admission, I after `reserve`.
- Peer keys must be exactly 32 bytes (codec `fixed_32`). `Sas::diffie_hellman` consumes the `Sas` and rejects a shared secret that is the identity point (`was_contributory`). The core maps that to `NonContributory`, which is terminal.
- **Non-canonical and torsion encodings.** X25519 ignores bit 255, reduces `u ≥ p`, and clamped scalars kill small-order components. So several 32-byte strings can yield the same shared secret. Every key is bound as **exact bytes** in the SAS context, the transcript, and `ceremony_identity`. An equivalent re-encoding in transit therefore changes the SAS and identity, which is just a detectable MITM, and gives the attacker no equal-SAS pair. This is recorded as the false positive [P5-F-014](findings.md#p5-f-014).

## 4. Transcript and `ceremony_identity`

`SHA-256(u32be(len(D)) ‖ D ‖ u32be(len(START)) ‖ START ‖ … ‖ u32be(len(RESPONDER_KEY)) ‖ RESPONDER_KEY)` with `D = "…/transcript/v1"`. The request IDs of all four messages must be equal. I computes it after the commitment check. R computes it when its `RESPONDER_KEY` bytes are fixed, after `reserve`. Both hash the same canonical bytes. The digest is not included in itself.

## 5. SAS derivation and presentation

Context frame `0x30`: `org.sas-pairing`, profile ID, `u16be(1)`, request ID, START, ACCEPT, `I_pub`, `R_pub`. Info string: `…/sas/` ‖ unpadded Base64url(context), capped at 65,536 bytes. With maximal bootstraps the context is about 33 KiB, so the cap is not reachable for valid input.

vodozemac `bytes(info)` = HKDF-SHA-256(no salt, i.e. the RFC 5869 zero-filled default; IKM = X25519 shared secret).expand(info, 6). `decimals()` takes 13+13+13 bits from bytes 0–4 (byte 4's low bit and byte 5 unused) plus 1000, rendered `"{:04} {:04} {:04}"`. That is 39 bits, as P3 §7 states.

| Context component | Effect of a one-sided change | Evidence |
|---|---|---|
| Request ID (also inside START) | Different HKDF info → different SAS | `crypto::every_sas_context_field_is_bound_into_the_live_sas` |
| START (I bootstrap, `shared_context`) | Different SAS, and the commitment fails | same; §2 |
| ACCEPT (commitment, R bootstrap) | Different SAS | same |
| `I_pub`, `R_pub` (exact bytes) | Different SAS (and DH) | same |
| Role | Fixed key order: `I_pub` then `R_pub` | Structural |
| Domain, profile, version | Constants in the frame and prefix | Structural |

Presentation exists only in `AwaitLocalApproval` while the deadlines evaluate `Live` (read-only). Approval requires the exact 32-byte `ceremony_identity`, never the request ID. No human-error claim is made: UI rendering is external.

## 6. MAC domain separation (rebuilt from `crypto.rs`)

All MACs use vodozemac `calculate_mac`/`verify_mac`: HMAC-SHA-256 keyed by HKDF-expand(info, 32), with the tag checked by `verify_slice` from `digest` 0.11.3, which compares in constant time (`ctutils::CtEq`). Input is unpadded Base64url of the auth frame. Info is prefix ‖ unpadded Base64url of the context frame.

| Purpose | Wire type | Auth frame (MAC input) | Context type / outer prefix | Sender | Receiver | `ceremony_identity` | Other bound values |
|---|---|---|---|---|---|---|---|
| BOOTSTRAP_MAC | `0x05` | `0x33`: domain, profile, v1, sender, cid, 6 SAS bytes, **sender's** canonical bootstrap | `0x31`: domain, profile, v1, `match-approve-bootstrap`, sender, receiver, cid; `…/mac/` | I or R (wire role must equal the expected peer) | Other role | Yes, in both frames | Full SAS, sender bootstrap |
| INITIATOR_FINISH | `0x06` | `0x35`: domain, profile, v1, I, R, cid, `initiator-finish` | `0x32`: domain, profile, v1, `initiator-finish`, I, R, cid; `…/mac/` | I | R | Yes, plus the wire digest compared first | Purpose |
| RESPONDER_FINISH_ACK | `0x07` | `0x36`: …, R, I, cid, `responder-finish-ack` | `0x32` with `responder-finish-ack`, R, I | R | I | Yes | Purpose |
| INITIATOR_FINISH_ACK | `0x08` | `0x37`: …, I, R, cid, `initiator-finish-ack` | `0x32` with `initiator-finish-ack`, I, R | I | R | Yes | Purpose |
| CANCEL | `0x09` | `0x34`: domain, profile, v1, sender, receiver, cid, reason | `0x38` (same fields); **`…/cancel/`** | Wire role, checked against the expected peer | Local role | Yes | Reason |

**Reconstruction source.** Every receiver rebuilds both structures from **local trusted state**: its own role (so peer and direction), its own `ceremony_identity`, its own six SAS bytes, and the peer bootstrap retained from the transcript. The only wire-derived inputs are the CANCEL reason (itself MAC-bound) and the completion step. The step is selected by the wire type, but `receive_completion` accepts it only when it is the legal next step for the local state **and** the local role is that step's receiver.

| Attempt | Why it fails |
|---|---|
| Purpose relabel (finish ↔ ack ↔ approval) | Different context bytes, so a different HKDF MAC key, and a different auth frame |
| Direction swap (I→R tag presented as R→I) | Sender and receiver bytes swap in both frames |
| Role swap (wire sender role edited) | Wire role ≠ expected peer → `UnexpectedSenderRole` before MAC work |
| Frame-type substitution (`0x06` bytes sent as `0x07`) | The state and role check rejects out-of-order steps; the auth frame type differs anyway |
| Context-type substitution (`0x31`/`0x32`/`0x38`) | Distinct type byte; CANCEL also has a distinct outer prefix |
| Cross-ceremony replay | `ceremony_identity` differs |
| Same request-ID replay | `ceremony_identity` differs (fresh R ephemeral → different transcript) |
| Same SAS, different bootstrap | The approval frame includes the sender bootstrap, and cid includes both bootstraps |
| Bootstrap swap (I's bootstrap presented as R's) | The receiver uses the retained peer bootstrap from START or ACCEPT |
| Reflection of one's own message | Wire sender role = local role → rejected. Completion steps fail the state and role check (recorded as the false positive [P5-F-022](findings.md#p5-f-022)) |
| Request ID treated as authentication | Only checked for equality as routing data. Authentication comes from cid in every MAC |

Project-owned MAC or tag comparison code: none. `verify_mac` is vodozemac's.

## 7. Completion and `PairingResult`

- **R** reaches `Succeeded` only in `receive_completion` for `INITIATOR_FINISH_ACK`, in `AwaitInitiatorFinishAck`, after its own MAC was sent, I's approval MAC verified, `INITIATOR_FINISH` verified, and `RESPONDER_FINISH_ACK` produced.
- **I** reaches `Succeeded` only in `confirm_initiator_finish_ack_sent` with the exact pending bytes. The TCP adapter calls it only after the frame's last byte was written locally. Deadlines are checked first.
- `succeed` builds the result, drops the session (SAS, approval, `EstablishedSas`), releases the guard, and installs `Succeeded(result)` **only if** the release is certain. Uncertain release → no result even though the final ACK was sent.
- No path yields a result before peer MAC verification, before local approval, before completion, before the final-ACK write (I), twice, after uncertainty, after a failed write, or after timeout. Every later input is `Completed` or ignored. The Router removes a succeeded run under its lock, and the result goes to exactly one remover.
- **Intended asymmetry.** I can succeed while R does not (lost final ACK). That is P3 §9 behavior, not a vulnerability. Two related observations: the reverse outcome (R succeeds, I times out after fully writing its final ACK) is [P5-F-007](findings.md#p5-f-007), and the experimental owner loop can also turn a *delivered* final ACK into an R failure ([P5-F-001](findings.md#p5-f-001)).

## 8. Authenticated CANCEL

| Case | Behavior |
|---|---|
| Before SAS establishment (any state without `SasSession`) | Terminal protocol failure, no MAC work, never `PeerCancellation` |
| After SAS: valid tag, expected sender role, exact request ID | Terminal, no result. Session dropped before the guard is released. Reason returned as authenticated diagnostic |
| Wrong role, request ID, reason, or tag | Terminal protocol failure, not reported as peer cancellation |
| Undefined reason code | Codec rejection (run fails) |
| Exact or changed duplicate after terminal | No change. In the Router the run is gone, so the frame is a stale route → session-fatal (P3 §11.2 "unknown or stale"). Spec-conformant |
| Local reject or cancel | `live_session(cid)` first (wrong or stale cid → no effect). The CANCEL is built while `EstablishedSas` exists, then terminate, then the bytes are returned (best effort). Construction failure → `NotEmitted`, never an unauthenticated substitute |
| Timeout | Same order through `end_with_cancel(Timeout)`. Only after SAS establishment |
| Send failure or CANCEL lost | Local terminality never waits. The TCP adapter offers CANCEL only into a free slot and otherwise drops it |
| Unknown route | Session-fatal routing failure; no run touched |

No path reports an unauthenticated CANCEL as authenticated peer intent.

## 9. R-MAC-001 and R-MAC-015 partials

- **Uncertainty beyond reproducibility?** None found for the implementation. Every project-owned byte that feeds vodozemac (commitment input, transcript, SAS context and info string, every MAC input and info string, every wire frame) matches the fixture byte for byte. The remaining derivation (X25519 → HKDF-SHA-256 with no salt → expand(info) for 6 or 32 bytes → HMAC-SHA-256) happens entirely inside vodozemac, whose 0.11.0 source was read for this review (`bytes_raw`, `get_mac_key`, `calculate_mac`, `verify_mac`). Live two-party runs show both roles agree.
- **What the partial leaves unverified:** that the fixture's recorded fixed-secret values (DH secret, six SAS bytes, tags) are themselves internally consistent. That is a property of the **fixture**, not of the core's code path.
- **Possible review technique** (not used here because P5 adds no cryptographic library): an out-of-tree recomputation with any independent X25519/HKDF/HMAC implementation, or a review-only harness using the already-locked `x25519-dalek`, `hkdf`, and `hmac` versions with no new lockfile packages. Either would check the fixture's consistency, and an owner decision is needed. Neither would test the core more strongly than the existing byte-exact and live evidence.
- **Conclusion:** an evidence limitation only. Keep the `PARTIAL` verdicts unchanged.
