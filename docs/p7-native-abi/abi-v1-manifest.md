# sas-pairing Native ABI v1 Manifest

> Compact compatibility reference for the native ABI, version 1. Pre-alpha and experimental: not production approval, a professional audit, or formal verification. The normative prose is the [ABI contract](abi-contract.md); the declarations are [`core/include/sas_pairing.h`](../../core/include/sas_pairing.h); the freeze decision is [P7-D-013](decisions.md#p7-d-013--abi-v1-final-freeze-and-wrapper-handoff); the closure summary is the [P7 final closure](final-closure.md).

**State: FROZEN (P7-D-013, P7.7).** Every value below is the implemented, tested ABI v1 surface. Changing, removing, or renumbering any of it, or adding to it, needs an explicit owner decision on ABI version and compatibility (P7-D-013 item 14).

Machine-checked: every table row whose first cell names a `SAS_PAIRING_` constant, an export, a type, or a record is compared with the Rust implementation and the header by `abi::tests::freeze::the_abi_v1_manifest_matches_the_rust_abi_and_the_header` (feature `native-abi`), and the export table with the built library by [`tooling/check_abi_exports.py`](../../tooling/check_abi_exports.py) in CI. A difference fails the build.

## 1. Version

| Name | Value |
|---|---:|
| `SAS_PAIRING_ABI_VERSION` | 1 |
| `SAS_PAIRING_ABI_VERSION_INVALID` | 0 |

`sas_pairing_abi_version()` returns `1`, also after `SAS_PAIRING_FATAL`; `0` only if the query itself caught a panic. The ABI version is not the protocol profile version (`sas-pairing-vodozemac-profile-draft-01`, version `1`) and not the crate version (`0.1.0`).

## 2. Exports (25)

Exactly these symbols, and no other, are exported by the supported artifact built with the `native-abi` feature; an ordinary build exports none. Each is `extern "C"` (the platform's C calling convention; on Windows x64, the Microsoft x64 convention), never `C-unwind`, and enters Rust only through the one panic-containment dispatcher. Each returns `sas_pairing_status_t` (`int32_t`), except `sas_pairing_abi_version` (`uint32_t`). The header declarations are pinned verbatim by `abi::tests::header_matches_the_rust_abi`.

Fatal class after a contained panic: **normal**: refused with `SAS_PAIRING_FATAL` without entering the core (a Windows-only operation off Windows returns `SAS_PAIRING_UNSUPPORTED_PLATFORM` first); **cleanup**: still admitted, never clears fatal or restarts pairing; **data**: reads or drops an existing result, never entering the core; **constant**: reads a constant.

| # | Export | Fatal class |
|---:|---|---|
| 1 | `sas_pairing_abi_version` | constant |
| 2 | `sas_pairing_runtime_create` | normal |
| 3 | `sas_pairing_runtime_destroy` | cleanup |
| 4 | `sas_pairing_authority_register` | normal |
| 5 | `sas_pairing_authority_release` | cleanup |
| 6 | `sas_pairing_authority_status` | normal |
| 7 | `sas_pairing_host_create` | normal |
| 8 | `sas_pairing_host_destroy` | cleanup |
| 9 | `sas_pairing_host_attach_windows_listener` | normal |
| 10 | `sas_pairing_host_detach_listener` | cleanup |
| 11 | `sas_pairing_host_drive` | normal |
| 12 | `sas_pairing_host_recheck_after_resume` | normal |
| 13 | `sas_pairing_connection_close` | cleanup |
| 14 | `sas_pairing_result_info` | data |
| 15 | `sas_pairing_result_copy` | data |
| 16 | `sas_pairing_result_destroy` | data |
| 17 | `sas_pairing_connection_start_initiator` | normal |
| 18 | `sas_pairing_run_authorize_exposure` | normal |
| 19 | `sas_pairing_run_expose_key` | normal |
| 20 | `sas_pairing_run_presentation` | normal |
| 21 | `sas_pairing_run_approve_sas` | normal |
| 22 | `sas_pairing_run_emit_bootstrap_mac` | normal |
| 23 | `sas_pairing_run_reject_sas` | normal |
| 24 | `sas_pairing_run_cancel_sas` | normal |
| 25 | `sas_pairing_run_emit_initiator_finish` | normal |

## 3. Status codes (48)

`sas_pairing_status_t` is `int32_t`. Ranges: 1–99 ABI, lifecycle, and arguments; 100–199 authority, resource, and core; 200–299 ceremony and protocol; 300–399 buffers and data results; 400–499 host, listener, and transport-boundary lifecycle; 900–999 fatal. Wrappers treat every non-zero value, known or not, as failure. No status is a trust verdict.

| Name | Value |
|---|---:|
| `SAS_PAIRING_OK` | 0 |
| `SAS_PAIRING_INVALID_ARGUMENT` | 1 |
| `SAS_PAIRING_INVALID_HANDLE` | 2 |
| `SAS_PAIRING_ALREADY_INITIALIZED` | 3 |
| `SAS_PAIRING_HANDLES_EXHAUSTED` | 4 |
| `SAS_PAIRING_INVALID_SCOPE` | 100 |
| `SAS_PAIRING_ALREADY_REGISTERED` | 101 |
| `SAS_PAIRING_OWNERSHIP_UNAVAILABLE` | 102 |
| `SAS_PAIRING_UNSUPPORTED_PLATFORM` | 103 |
| `SAS_PAIRING_OWNERSHIP_UNCERTAIN` | 104 |
| `SAS_PAIRING_BUSY` | 105 |
| `SAS_PAIRING_EXHAUSTED` | 106 |
| `SAS_PAIRING_RESOURCE_LIMITED` | 107 |
| `SAS_PAIRING_MISSING_AUTHORIZATION` | 200 |
| `SAS_PAIRING_STALE_AUTHORIZATION` | 201 |
| `SAS_PAIRING_TERMINATED` | 202 |
| `SAS_PAIRING_INVALID_BOOTSTRAP` | 203 |
| `SAS_PAIRING_RUN_ENDED` | 204 |
| `SAS_PAIRING_WRITE_PENDING` | 205 |
| `SAS_PAIRING_CEREMONY_INVALID_STATE` | 206 |
| `SAS_PAIRING_NO_LIVE_SAS` | 207 |
| `SAS_PAIRING_CEREMONY_IDENTITY_MISMATCH` | 208 |
| `SAS_PAIRING_NOT_LOCALLY_APPROVED` | 209 |
| `SAS_PAIRING_UNEXPECTED_SENDER_ROLE` | 210 |
| `SAS_PAIRING_INVALID_REQUEST_ID` | 211 |
| `SAS_PAIRING_REQUEST_ID_GENERATION_FAILED` | 212 |
| `SAS_PAIRING_REQUEST_ID_MISMATCH` | 213 |
| `SAS_PAIRING_SHARED_CONTEXT_MISMATCH` | 214 |
| `SAS_PAIRING_EXPECTED_PEER_MISMATCH` | 215 |
| `SAS_PAIRING_APPROVALS_NOT_AUTHENTICATED` | 216 |
| `SAS_PAIRING_NOT_INITIATOR` | 217 |
| `SAS_PAIRING_TRANSCRIPT_MISMATCH` | 218 |
| `SAS_PAIRING_COMPLETED` | 219 |
| `SAS_PAIRING_NO_PENDING_FINAL_ACK` | 220 |
| `SAS_PAIRING_FINAL_ACK_MISMATCH` | 221 |
| `SAS_PAIRING_CEREMONY_TIMED_OUT` | 222 |
| `SAS_PAIRING_CEREMONY_CLOCK_UNAVAILABLE` | 223 |
| `SAS_PAIRING_PENDING_EXPIRED` | 224 |
| `SAS_PAIRING_CEREMONY_CODEC_ERROR` | 225 |
| `SAS_PAIRING_CEREMONY_CRYPTO_ERROR` | 226 |
| `SAS_PAIRING_BUFFER_TOO_SMALL` | 300 |
| `SAS_PAIRING_LISTENER_ALREADY_ATTACHED` | 400 |
| `SAS_PAIRING_LISTENER_SETUP_FAILED` | 401 |
| `SAS_PAIRING_LISTENER_NOT_ATTACHED` | 402 |
| `SAS_PAIRING_OWNER_LOOP_CLOSED` | 403 |
| `SAS_PAIRING_NETWORK_POLL_FAILED` | 404 |
| `SAS_PAIRING_CONNECTION_ENDED` | 405 |
| `SAS_PAIRING_FATAL` | 900 |

## 4. Integer namespaces (84 values)

Every namespace is a `uint32_t` typedef with explicit values; `0` is the invalid or none value of every enumeration (a result field `0` names no field). Flags are bit masks.

| Name | Type | Value |
|---|---|---:|
| `SAS_PAIRING_AUTHORITY_STATE_INVALID` | `sas_pairing_authority_state_t` | 0 |
| `SAS_PAIRING_AUTHORITY_READY` | `sas_pairing_authority_state_t` | 1 |
| `SAS_PAIRING_AUTHORITY_BUSY` | `sas_pairing_authority_state_t` | 2 |
| `SAS_PAIRING_AUTHORITY_EXHAUSTED` | `sas_pairing_authority_state_t` | 3 |
| `SAS_PAIRING_EVENT_INVALID` | `sas_pairing_event_kind_t` | 0 |
| `SAS_PAIRING_EVENT_CONNECTION_ACCEPTED` | `sas_pairing_event_kind_t` | 1 |
| `SAS_PAIRING_EVENT_ACCEPT_REFUSED` | `sas_pairing_event_kind_t` | 2 |
| `SAS_PAIRING_EVENT_LISTENER_DISABLED` | `sas_pairing_event_kind_t` | 3 |
| `SAS_PAIRING_EVENT_CONNECTION_STEP` | `sas_pairing_event_kind_t` | 4 |
| `SAS_PAIRING_EVENT_CONNECTION_CLOSED` | `sas_pairing_event_kind_t` | 5 |
| `SAS_PAIRING_STEP_NONE` | `sas_pairing_step_kind_t` | 0 |
| `SAS_PAIRING_STEP_INBOUND` | `sas_pairing_step_kind_t` | 1 |
| `SAS_PAIRING_STEP_REFUSED` | `sas_pairing_step_kind_t` | 2 |
| `SAS_PAIRING_STEP_DEADLINE` | `sas_pairing_step_kind_t` | 3 |
| `SAS_PAIRING_STEP_WRITTEN` | `sas_pairing_step_kind_t` | 4 |
| `SAS_PAIRING_STEP_CONFIRMED` | `sas_pairing_step_kind_t` | 5 |
| `SAS_PAIRING_STEP_UNCONFIRMED` | `sas_pairing_step_kind_t` | 6 |
| `SAS_PAIRING_STEP_DISCARDED` | `sas_pairing_step_kind_t` | 7 |
| `SAS_PAIRING_PROTOCOL_EVENT_NONE` | `sas_pairing_protocol_event_t` | 0 |
| `SAS_PAIRING_PROTOCOL_EVENT_START_ACCEPTED` | `sas_pairing_protocol_event_t` | 1 |
| `SAS_PAIRING_PROTOCOL_EVENT_START_DUPLICATE` | `sas_pairing_protocol_event_t` | 2 |
| `SAS_PAIRING_PROTOCOL_EVENT_ACCEPT` | `sas_pairing_protocol_event_t` | 3 |
| `SAS_PAIRING_PROTOCOL_EVENT_INITIATOR_KEY` | `sas_pairing_protocol_event_t` | 4 |
| `SAS_PAIRING_PROTOCOL_EVENT_RESPONDER_KEY` | `sas_pairing_protocol_event_t` | 5 |
| `SAS_PAIRING_PROTOCOL_EVENT_BOOTSTRAP_MAC_AUTHENTICATED` | `sas_pairing_protocol_event_t` | 6 |
| `SAS_PAIRING_PROTOCOL_EVENT_BOOTSTRAP_MAC_DUPLICATE` | `sas_pairing_protocol_event_t` | 7 |
| `SAS_PAIRING_PROTOCOL_EVENT_INITIATOR_FINISH` | `sas_pairing_protocol_event_t` | 8 |
| `SAS_PAIRING_PROTOCOL_EVENT_INITIATOR_FINISH_DUPLICATE` | `sas_pairing_protocol_event_t` | 9 |
| `SAS_PAIRING_PROTOCOL_EVENT_RESPONDER_FINISH_ACK` | `sas_pairing_protocol_event_t` | 10 |
| `SAS_PAIRING_PROTOCOL_EVENT_INITIATOR_FINISH_ACK` | `sas_pairing_protocol_event_t` | 11 |
| `SAS_PAIRING_PROTOCOL_EVENT_PEER_CANCEL` | `sas_pairing_protocol_event_t` | 12 |
| `SAS_PAIRING_EVENT_REASON_NONE` | `sas_pairing_event_reason_t` | 0 |
| `SAS_PAIRING_EVENT_REASON_RESOURCE_LIMITED` | `sas_pairing_event_reason_t` | 1 |
| `SAS_PAIRING_EVENT_REASON_PEER_CLOSED` | `sas_pairing_event_reason_t` | 2 |
| `SAS_PAIRING_EVENT_REASON_SOCKET_IO` | `sas_pairing_event_reason_t` | 3 |
| `SAS_PAIRING_EVENT_REASON_ABANDONED_PARTIAL_FRAME` | `sas_pairing_event_reason_t` | 4 |
| `SAS_PAIRING_EVENT_REASON_READINESS_FAILURE` | `sas_pairing_event_reason_t` | 5 |
| `SAS_PAIRING_EVENT_REASON_LISTENER_IO` | `sas_pairing_event_reason_t` | 6 |
| `SAS_PAIRING_EVENT_REASON_LISTENER_READINESS` | `sas_pairing_event_reason_t` | 7 |
| `SAS_PAIRING_EVENT_REASON_ROUTE_REFUSED` | `sas_pairing_event_reason_t` | 8 |
| `SAS_PAIRING_EVENT_REASON_OWNERSHIP_UNCERTAIN` | `sas_pairing_event_reason_t` | 9 |
| `SAS_PAIRING_EVENT_REASON_OTHER_HOST_FAILURE` | `sas_pairing_event_reason_t` | 10 |
| `SAS_PAIRING_EVENT_REASON_INVALID_FRAME` | `sas_pairing_event_reason_t` | 11 |
| `SAS_PAIRING_EVENT_REASON_TRANSPORT_DEADLINE` | `sas_pairing_event_reason_t` | 12 |
| `SAS_PAIRING_EVENT_REASON_CLOCK_UNAVAILABLE` | `sas_pairing_event_reason_t` | 13 |
| `SAS_PAIRING_EVENT_REASON_SESSION_PROTOCOL_FAILURE` | `sas_pairing_event_reason_t` | 14 |
| `SAS_PAIRING_EVENT_REASON_ALREADY_CLOSED` | `sas_pairing_event_reason_t` | 15 |
| `SAS_PAIRING_DEADLINE_NONE` | `sas_pairing_deadline_kind_t` | 0 |
| `SAS_PAIRING_DEADLINE_ABSOLUTE_TIMEOUT` | `sas_pairing_deadline_kind_t` | 1 |
| `SAS_PAIRING_DEADLINE_INACTIVITY_TIMEOUT` | `sas_pairing_deadline_kind_t` | 2 |
| `SAS_PAIRING_DEADLINE_PENDING_EXPIRED` | `sas_pairing_deadline_kind_t` | 3 |
| `SAS_PAIRING_DEADLINE_CLOCK_UNAVAILABLE` | `sas_pairing_deadline_kind_t` | 4 |
| `SAS_PAIRING_CANCEL_STATE_NONE` | `sas_pairing_cancel_state_t` | 0 |
| `SAS_PAIRING_CANCEL_STATE_NOT_BUILT` | `sas_pairing_cancel_state_t` | 1 |
| `SAS_PAIRING_CANCEL_STATE_PENDING` | `sas_pairing_cancel_state_t` | 2 |
| `SAS_PAIRING_CANCEL_STATE_DROPPED` | `sas_pairing_cancel_state_t` | 3 |
| `SAS_PAIRING_CANCEL_REASON_NONE` | `sas_pairing_cancel_reason_t` | 0 |
| `SAS_PAIRING_CANCEL_REASON_USER_REJECTION` | `sas_pairing_cancel_reason_t` | 1 |
| `SAS_PAIRING_CANCEL_REASON_USER_CANCELLATION` | `sas_pairing_cancel_reason_t` | 2 |
| `SAS_PAIRING_CANCEL_REASON_TIMEOUT` | `sas_pairing_cancel_reason_t` | 3 |
| `SAS_PAIRING_CANCEL_REASON_LOCAL_POLICY_FAILURE` | `sas_pairing_cancel_reason_t` | 4 |
| `SAS_PAIRING_EVENT_FLAG_WRITE_PENDING` | `sas_pairing_event_flags_t` | 0x1 |
| `SAS_PAIRING_EVENT_FLAG_RUN_UNTRACKED` | `sas_pairing_event_flags_t` | 0x2 |
| `SAS_PAIRING_ROLE_INVALID` | `sas_pairing_role_t` | 0 |
| `SAS_PAIRING_ROLE_INITIATOR` | `sas_pairing_role_t` | 1 |
| `SAS_PAIRING_ROLE_RESPONDER` | `sas_pairing_role_t` | 2 |
| `SAS_PAIRING_RESULT_FIELD_REQUEST_ID` | `sas_pairing_result_field_t` | 1 |
| `SAS_PAIRING_RESULT_FIELD_AUTHENTICATED_PEER_BOOTSTRAP` | `sas_pairing_result_field_t` | 2 |
| `SAS_PAIRING_RESULT_FIELD_AUTHENTICATED_SHARED_CONTEXT` | `sas_pairing_result_field_t` | 3 |
| `SAS_PAIRING_RESULT_FIELD_PROFILE_IDENTIFIER` | `sas_pairing_result_field_t` | 4 |
| `SAS_PAIRING_LOCAL_EVENT_INVALID` | `sas_pairing_local_event_t` | 0 |
| `SAS_PAIRING_LOCAL_EVENT_INITIATOR_STARTED` | `sas_pairing_local_event_t` | 1 |
| `SAS_PAIRING_LOCAL_EVENT_EXPOSURE_AUTHORIZED` | `sas_pairing_local_event_t` | 2 |
| `SAS_PAIRING_LOCAL_EVENT_KEY_EXPOSED` | `sas_pairing_local_event_t` | 3 |
| `SAS_PAIRING_LOCAL_EVENT_SAS_APPROVED` | `sas_pairing_local_event_t` | 4 |
| `SAS_PAIRING_LOCAL_EVENT_SAS_ALREADY_APPROVED` | `sas_pairing_local_event_t` | 5 |
| `SAS_PAIRING_LOCAL_EVENT_BOOTSTRAP_MAC_EMITTED` | `sas_pairing_local_event_t` | 6 |
| `SAS_PAIRING_LOCAL_EVENT_BOOTSTRAP_MAC_ALREADY_EMITTED` | `sas_pairing_local_event_t` | 7 |
| `SAS_PAIRING_LOCAL_EVENT_INITIATOR_FINISH_EMITTED` | `sas_pairing_local_event_t` | 8 |
| `SAS_PAIRING_LOCAL_EVENT_INITIATOR_FINISH_ALREADY_EMITTED` | `sas_pairing_local_event_t` | 9 |
| `SAS_PAIRING_LOCAL_EVENT_SAS_REJECTED` | `sas_pairing_local_event_t` | 10 |
| `SAS_PAIRING_LOCAL_EVENT_SAS_CANCELLED` | `sas_pairing_local_event_t` | 11 |
| `SAS_PAIRING_LOCAL_EVENT_DEADLINE` | `sas_pairing_local_event_t` | 12 |
| `SAS_PAIRING_ACTION_FLAG_WRITE_PENDING` | `sas_pairing_action_flags_t` | 0x1 |

## 5. Handle invalid values and scalar constants (11)

| Name | Type | Value |
|---|---|---:|
| `SAS_PAIRING_RUNTIME_INVALID` | `sas_pairing_runtime_t` | 0 |
| `SAS_PAIRING_AUTHORITY_INVALID` | `sas_pairing_authority_t` | 0 |
| `SAS_PAIRING_HOST_INVALID` | `sas_pairing_host_t` | 0 |
| `SAS_PAIRING_SOCKET_INVALID` | `sas_pairing_socket_t` | UINTPTR_MAX |
| `SAS_PAIRING_CONNECTION_INVALID` | `sas_pairing_connection_t` | 0 |
| `SAS_PAIRING_RUN_INVALID` | `sas_pairing_run_t` | 0 |
| `SAS_PAIRING_RESULT_INVALID` | `sas_pairing_result_t` | 0 |
| `SAS_PAIRING_MAX_DRIVE_EVENTS` | `size_t` | 17 |
| `SAS_PAIRING_MAX_REQUEST_ID_LEN` | `size_t` | 64 |
| `SAS_PAIRING_MAX_RUNS_PER_CONNECTION` | `size_t` | 32 |
| `SAS_PAIRING_SAS_DECIMAL_LEN` | `size_t` | 14 |

## 6. Types

Every handle (runtime, authority, host, connection, run, result) is an opaque `uint64_t` from one shared, monotonic, process-lifetime counter: `0` is never valid, a value is issued once to one kind and never reused, the counter never wraps or resets (exhaustion fails closed with `SAS_PAIRING_HANDLES_EXHAUSTED`), and a handle is never a pointer, socket, request ID, `ceremony_identity`, peer identity, or trust material. A socket is an OS resource handed in, not a handle.

| Type | C type |
|---|---|
| `sas_pairing_status_t` | `int32_t` |
| `sas_pairing_runtime_t` | `uint64_t` |
| `sas_pairing_authority_t` | `uint64_t` |
| `sas_pairing_host_t` | `uint64_t` |
| `sas_pairing_authority_state_t` | `uint32_t` |
| `sas_pairing_socket_t` | `uintptr_t` |
| `sas_pairing_connection_t` | `uint64_t` |
| `sas_pairing_run_t` | `uint64_t` |
| `sas_pairing_result_t` | `uint64_t` |
| `sas_pairing_event_kind_t` | `uint32_t` |
| `sas_pairing_step_kind_t` | `uint32_t` |
| `sas_pairing_protocol_event_t` | `uint32_t` |
| `sas_pairing_event_reason_t` | `uint32_t` |
| `sas_pairing_deadline_kind_t` | `uint32_t` |
| `sas_pairing_cancel_state_t` | `uint32_t` |
| `sas_pairing_cancel_reason_t` | `uint32_t` |
| `sas_pairing_event_flags_t` | `uint32_t` |
| `sas_pairing_role_t` | `uint32_t` |
| `sas_pairing_result_field_t` | `uint32_t` |
| `sas_pairing_local_event_t` | `uint32_t` |
| `sas_pairing_action_flags_t` | `uint32_t` |

## 7. Records

Sizes and offsets in bytes on 64-bit targets (the two views are made of pointer-sized words: on a 32-bit target they are 8 and 32 bytes, aligned to 4). No record has padding: its fields are contiguous and fill it. Output records (`sas_pairing_event_t`, `sas_pairing_result_info_t`, `sas_pairing_action_t`, `sas_pairing_sas_presentation_t`) are written whole from all-zero records, so no uninitialized byte crosses the ABI; reserved fields and request-ID bytes past `request_id_len` are always `0`. The views are input only; their pointers are borrowed for the call and never retained.

| Record | Size | Align |
|---|---:|---:|
| `sas_pairing_bytes_view_t` | 16 | 8 |
| `sas_pairing_bootstrap_view_t` | 64 | 8 |
| `sas_pairing_event_t` | 128 | 8 |
| `sas_pairing_result_info_t` | 56 | 4 |
| `sas_pairing_action_t` | 24 | 8 |
| `sas_pairing_sas_presentation_t` | 56 | 4 |

| Record | Field | Offset | Size |
|---|---|---:|---:|
| `sas_pairing_bytes_view_t` | `data` | 0 | 8 |
| `sas_pairing_bytes_view_t` | `len` | 8 | 8 |
| `sas_pairing_bootstrap_view_t` | `application_identity` | 0 | 16 |
| `sas_pairing_bootstrap_view_t` | `key_algorithm` | 16 | 16 |
| `sas_pairing_bootstrap_view_t` | `public_key` | 32 | 16 |
| `sas_pairing_bootstrap_view_t` | `shared_context` | 48 | 16 |
| `sas_pairing_event_t` | `kind` | 0 | 4 |
| `sas_pairing_event_t` | `step_kind` | 4 | 4 |
| `sas_pairing_event_t` | `protocol_event` | 8 | 4 |
| `sas_pairing_event_t` | `reason` | 12 | 4 |
| `sas_pairing_event_t` | `deadline_kind` | 16 | 4 |
| `sas_pairing_event_t` | `cancel_state` | 20 | 4 |
| `sas_pairing_event_t` | `cancel_reason` | 24 | 4 |
| `sas_pairing_event_t` | `flags` | 28 | 4 |
| `sas_pairing_event_t` | `connection` | 32 | 8 |
| `sas_pairing_event_t` | `run` | 40 | 8 |
| `sas_pairing_event_t` | `result` | 48 | 8 |
| `sas_pairing_event_t` | `request_id_len` | 56 | 4 |
| `sas_pairing_event_t` | `reserved` | 60 | 4 |
| `sas_pairing_event_t` | `request_id` | 64 | 64 |
| `sas_pairing_result_info_t` | `ceremony_identity` | 0 | 32 |
| `sas_pairing_result_info_t` | `peer_role` | 32 | 4 |
| `sas_pairing_result_info_t` | `profile_version` | 36 | 4 |
| `sas_pairing_result_info_t` | `request_id_len` | 40 | 4 |
| `sas_pairing_result_info_t` | `peer_bootstrap_len` | 44 | 4 |
| `sas_pairing_result_info_t` | `shared_context_len` | 48 | 4 |
| `sas_pairing_result_info_t` | `profile_identifier_len` | 52 | 4 |
| `sas_pairing_action_t` | `event` | 0 | 4 |
| `sas_pairing_action_t` | `deadline_kind` | 4 | 4 |
| `sas_pairing_action_t` | `flags` | 8 | 4 |
| `sas_pairing_action_t` | `reserved` | 12 | 4 |
| `sas_pairing_action_t` | `run` | 16 | 8 |
| `sas_pairing_sas_presentation_t` | `available` | 0 | 4 |
| `sas_pairing_sas_presentation_t` | `reserved` | 4 | 4 |
| `sas_pairing_sas_presentation_t` | `ceremony_identity` | 8 | 32 |
| `sas_pairing_sas_presentation_t` | `decimal` | 40 | 14 |
| `sas_pairing_sas_presentation_t` | `reserved_tail` | 54 | 2 |

## 8. Bounds

| Bound | Value |
|---|---|
| Events per drive or recheck (`SAS_PAIRING_MAX_DRIVE_EVENTS`, the owner loop's `MAX_STEP_EVENTS`) | 17 |
| Live connections per owner loop (the authority-wide cap) | 16 |
| Readiness waits per drive | at most one, of at most 250 ms |
| Socket operations per existing connection per drive | at most one |
| Accepts per drive | at most one |
| Handle values a drive may issue (checked before the owner loop runs, nothing burned) | 17 |
| Handle values a local Initiator start needs (checked before the owner loop runs) | 1 |
| Run handles kept per connection (`SAS_PAIRING_MAX_RUNS_PER_CONNECTION`; beyond it `RUN_UNTRACKED`, nothing evicted) | 32 |
| Request ID (`SAS_PAIRING_MAX_REQUEST_ID_LEN`) | 1–64 bytes |
| SAS decimal display (`SAS_PAIRING_SAS_DECIMAL_LEN`) | 14 ASCII bytes `NNNN NNNN NNNN` |
| `ceremony_identity` | exactly 32 bytes |

## 9. Loader invariant (P7-D-002)

Exactly one sas-pairing native library image per OS process, loaded no later than the first `sas_pairing_runtime_create` and kept resident until the process exits; never unloaded and reloaded, and never loaded again from a copied, renamed, or alternate path. The only recovery from `SAS_PAIRING_FATAL` is an OS process restart. Every process-lifetime guarantee (handle non-reuse, one runtime, permanent fatal, process-session accounting) holds only under this invariant.

## 10. Platform scope

| Platform | Native ABI | Pairing |
|---|---|---|
| Windows (MSVC, x86_64) | `sas_pairing_core.dll` with the 25 exports | Supported: authority ownership, the Windows TCP carrier (caller-bound listener, cooperative owner loop), ceremony control, results |
| Other platforms (Linux CI) | The library builds and exports the same 25 symbols | Fail closed: authority registration, listener attach, drive, recheck, connection close, and every ceremony action return `SAS_PAIRING_UNSUPPORTED_PLATFORM` with nothing faked; result access is platform-neutral data access, but no result can be produced |
