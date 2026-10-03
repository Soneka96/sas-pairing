/*
 * sas-pairing native ABI v1 consumer (P7.7 freeze check). Not part of the library.
 *
 * A real foreign consumer of core/include/sas_pairing.h, compiled as strict C11 and as C++17
 * (-Wall -Wextra -Werror -pedantic) and linked against the built release library. At compile time
 * it pins every type width, record size, alignment, and field offset, and every constant value
 * of docs/p7-native-abi/abi-v1-manifest.md, and binds each of the 25 exports to a function pointer
 * of its exact frozen signature (which also makes the link resolve every one). At run time it
 * makes a few platform-neutral calls through the library. Exit status 0 means every check held.
 */
#include "sas_pairing.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#ifdef __cplusplus
#define ABI_ASSERT(condition, what) static_assert(condition, what)
#define ABI_ALIGNOF(type) alignof(type)
#define ABI_LANGUAGE "C++17"
#else
#define ABI_ASSERT(condition, what) _Static_assert(condition, what)
#define ABI_ALIGNOF(type) _Alignof(type)
#define ABI_LANGUAGE "C11"
#endif

/* Type widths. */
ABI_ASSERT(sizeof(sas_pairing_status_t) == 4, "sas_pairing_status_t width");
ABI_ASSERT(sizeof(sas_pairing_runtime_t) == 8, "sas_pairing_runtime_t width");
ABI_ASSERT(sizeof(sas_pairing_authority_t) == 8, "sas_pairing_authority_t width");
ABI_ASSERT(sizeof(sas_pairing_host_t) == 8, "sas_pairing_host_t width");
ABI_ASSERT(sizeof(sas_pairing_authority_state_t) == 4, "sas_pairing_authority_state_t width");
ABI_ASSERT(sizeof(sas_pairing_socket_t) == sizeof(void *), "sas_pairing_socket_t width");
ABI_ASSERT(sizeof(sas_pairing_connection_t) == 8, "sas_pairing_connection_t width");
ABI_ASSERT(sizeof(sas_pairing_run_t) == 8, "sas_pairing_run_t width");
ABI_ASSERT(sizeof(sas_pairing_result_t) == 8, "sas_pairing_result_t width");
ABI_ASSERT(sizeof(sas_pairing_event_kind_t) == 4, "sas_pairing_event_kind_t width");
ABI_ASSERT(sizeof(sas_pairing_step_kind_t) == 4, "sas_pairing_step_kind_t width");
ABI_ASSERT(sizeof(sas_pairing_protocol_event_t) == 4, "sas_pairing_protocol_event_t width");
ABI_ASSERT(sizeof(sas_pairing_event_reason_t) == 4, "sas_pairing_event_reason_t width");
ABI_ASSERT(sizeof(sas_pairing_deadline_kind_t) == 4, "sas_pairing_deadline_kind_t width");
ABI_ASSERT(sizeof(sas_pairing_cancel_state_t) == 4, "sas_pairing_cancel_state_t width");
ABI_ASSERT(sizeof(sas_pairing_cancel_reason_t) == 4, "sas_pairing_cancel_reason_t width");
ABI_ASSERT(sizeof(sas_pairing_event_flags_t) == 4, "sas_pairing_event_flags_t width");
ABI_ASSERT(sizeof(sas_pairing_role_t) == 4, "sas_pairing_role_t width");
ABI_ASSERT(sizeof(sas_pairing_result_field_t) == 4, "sas_pairing_result_field_t width");
ABI_ASSERT(sizeof(sas_pairing_local_event_t) == 4, "sas_pairing_local_event_t width");
ABI_ASSERT(sizeof(sas_pairing_action_flags_t) == 4, "sas_pairing_action_flags_t width");
ABI_ASSERT((sas_pairing_status_t)-1 < 0, "sas_pairing_status_t is signed");
ABI_ASSERT((sas_pairing_runtime_t)-1 > 0, "handles are unsigned");

/* Record layouts (64-bit values; the two views are pointer-sized words). */
#define ABI_WORD (sizeof(void *))
ABI_ASSERT(sizeof(sas_pairing_bytes_view_t) == 2 * ABI_WORD, "sas_pairing_bytes_view_t size");
ABI_ASSERT(ABI_ALIGNOF(sas_pairing_bytes_view_t) == ABI_ALIGNOF(void *), "sas_pairing_bytes_view_t alignment");
ABI_ASSERT(sizeof(sas_pairing_bootstrap_view_t) == 8 * ABI_WORD, "sas_pairing_bootstrap_view_t size");
ABI_ASSERT(ABI_ALIGNOF(sas_pairing_bootstrap_view_t) == ABI_ALIGNOF(void *), "sas_pairing_bootstrap_view_t alignment");
ABI_ASSERT(sizeof(sas_pairing_event_t) == 128, "sas_pairing_event_t size");
ABI_ASSERT(ABI_ALIGNOF(sas_pairing_event_t) == 8, "sas_pairing_event_t alignment");
ABI_ASSERT(sizeof(sas_pairing_result_info_t) == 56, "sas_pairing_result_info_t size");
ABI_ASSERT(ABI_ALIGNOF(sas_pairing_result_info_t) == 4, "sas_pairing_result_info_t alignment");
ABI_ASSERT(sizeof(sas_pairing_action_t) == 24, "sas_pairing_action_t size");
ABI_ASSERT(ABI_ALIGNOF(sas_pairing_action_t) == 8, "sas_pairing_action_t alignment");
ABI_ASSERT(sizeof(sas_pairing_sas_presentation_t) == 56, "sas_pairing_sas_presentation_t size");
ABI_ASSERT(ABI_ALIGNOF(sas_pairing_sas_presentation_t) == 4, "sas_pairing_sas_presentation_t alignment");
ABI_ASSERT(offsetof(sas_pairing_bytes_view_t, data) == 0 * ABI_WORD, "sas_pairing_bytes_view_t.data offset");
ABI_ASSERT(offsetof(sas_pairing_bytes_view_t, len) == 1 * ABI_WORD, "sas_pairing_bytes_view_t.len offset");
ABI_ASSERT(offsetof(sas_pairing_bootstrap_view_t, application_identity) == 0 * ABI_WORD, "sas_pairing_bootstrap_view_t.application_identity offset");
ABI_ASSERT(offsetof(sas_pairing_bootstrap_view_t, key_algorithm) == 2 * ABI_WORD, "sas_pairing_bootstrap_view_t.key_algorithm offset");
ABI_ASSERT(offsetof(sas_pairing_bootstrap_view_t, public_key) == 4 * ABI_WORD, "sas_pairing_bootstrap_view_t.public_key offset");
ABI_ASSERT(offsetof(sas_pairing_bootstrap_view_t, shared_context) == 6 * ABI_WORD, "sas_pairing_bootstrap_view_t.shared_context offset");
ABI_ASSERT(offsetof(sas_pairing_event_t, kind) == 0, "sas_pairing_event_t.kind offset");
ABI_ASSERT(offsetof(sas_pairing_event_t, step_kind) == 4, "sas_pairing_event_t.step_kind offset");
ABI_ASSERT(offsetof(sas_pairing_event_t, protocol_event) == 8, "sas_pairing_event_t.protocol_event offset");
ABI_ASSERT(offsetof(sas_pairing_event_t, reason) == 12, "sas_pairing_event_t.reason offset");
ABI_ASSERT(offsetof(sas_pairing_event_t, deadline_kind) == 16, "sas_pairing_event_t.deadline_kind offset");
ABI_ASSERT(offsetof(sas_pairing_event_t, cancel_state) == 20, "sas_pairing_event_t.cancel_state offset");
ABI_ASSERT(offsetof(sas_pairing_event_t, cancel_reason) == 24, "sas_pairing_event_t.cancel_reason offset");
ABI_ASSERT(offsetof(sas_pairing_event_t, flags) == 28, "sas_pairing_event_t.flags offset");
ABI_ASSERT(offsetof(sas_pairing_event_t, connection) == 32, "sas_pairing_event_t.connection offset");
ABI_ASSERT(offsetof(sas_pairing_event_t, run) == 40, "sas_pairing_event_t.run offset");
ABI_ASSERT(offsetof(sas_pairing_event_t, result) == 48, "sas_pairing_event_t.result offset");
ABI_ASSERT(offsetof(sas_pairing_event_t, request_id_len) == 56, "sas_pairing_event_t.request_id_len offset");
ABI_ASSERT(offsetof(sas_pairing_event_t, reserved) == 60, "sas_pairing_event_t.reserved offset");
ABI_ASSERT(offsetof(sas_pairing_event_t, request_id) == 64, "sas_pairing_event_t.request_id offset");
ABI_ASSERT(offsetof(sas_pairing_result_info_t, ceremony_identity) == 0, "sas_pairing_result_info_t.ceremony_identity offset");
ABI_ASSERT(offsetof(sas_pairing_result_info_t, peer_role) == 32, "sas_pairing_result_info_t.peer_role offset");
ABI_ASSERT(offsetof(sas_pairing_result_info_t, profile_version) == 36, "sas_pairing_result_info_t.profile_version offset");
ABI_ASSERT(offsetof(sas_pairing_result_info_t, request_id_len) == 40, "sas_pairing_result_info_t.request_id_len offset");
ABI_ASSERT(offsetof(sas_pairing_result_info_t, peer_bootstrap_len) == 44, "sas_pairing_result_info_t.peer_bootstrap_len offset");
ABI_ASSERT(offsetof(sas_pairing_result_info_t, shared_context_len) == 48, "sas_pairing_result_info_t.shared_context_len offset");
ABI_ASSERT(offsetof(sas_pairing_result_info_t, profile_identifier_len) == 52, "sas_pairing_result_info_t.profile_identifier_len offset");
ABI_ASSERT(offsetof(sas_pairing_action_t, event) == 0, "sas_pairing_action_t.event offset");
ABI_ASSERT(offsetof(sas_pairing_action_t, deadline_kind) == 4, "sas_pairing_action_t.deadline_kind offset");
ABI_ASSERT(offsetof(sas_pairing_action_t, flags) == 8, "sas_pairing_action_t.flags offset");
ABI_ASSERT(offsetof(sas_pairing_action_t, reserved) == 12, "sas_pairing_action_t.reserved offset");
ABI_ASSERT(offsetof(sas_pairing_action_t, run) == 16, "sas_pairing_action_t.run offset");
ABI_ASSERT(offsetof(sas_pairing_sas_presentation_t, available) == 0, "sas_pairing_sas_presentation_t.available offset");
ABI_ASSERT(offsetof(sas_pairing_sas_presentation_t, reserved) == 4, "sas_pairing_sas_presentation_t.reserved offset");
ABI_ASSERT(offsetof(sas_pairing_sas_presentation_t, ceremony_identity) == 8, "sas_pairing_sas_presentation_t.ceremony_identity offset");
ABI_ASSERT(offsetof(sas_pairing_sas_presentation_t, decimal) == 40, "sas_pairing_sas_presentation_t.decimal offset");
ABI_ASSERT(offsetof(sas_pairing_sas_presentation_t, reserved_tail) == 54, "sas_pairing_sas_presentation_t.reserved_tail offset");

/* Every constant of the manifest. */
ABI_ASSERT(SAS_PAIRING_ABI_VERSION == 1, "SAS_PAIRING_ABI_VERSION");
ABI_ASSERT(SAS_PAIRING_ABI_VERSION_INVALID == 0, "SAS_PAIRING_ABI_VERSION_INVALID");
ABI_ASSERT(SAS_PAIRING_OK == 0, "SAS_PAIRING_OK");
ABI_ASSERT(SAS_PAIRING_INVALID_ARGUMENT == 1, "SAS_PAIRING_INVALID_ARGUMENT");
ABI_ASSERT(SAS_PAIRING_INVALID_HANDLE == 2, "SAS_PAIRING_INVALID_HANDLE");
ABI_ASSERT(SAS_PAIRING_ALREADY_INITIALIZED == 3, "SAS_PAIRING_ALREADY_INITIALIZED");
ABI_ASSERT(SAS_PAIRING_HANDLES_EXHAUSTED == 4, "SAS_PAIRING_HANDLES_EXHAUSTED");
ABI_ASSERT(SAS_PAIRING_INVALID_SCOPE == 100, "SAS_PAIRING_INVALID_SCOPE");
ABI_ASSERT(SAS_PAIRING_ALREADY_REGISTERED == 101, "SAS_PAIRING_ALREADY_REGISTERED");
ABI_ASSERT(SAS_PAIRING_OWNERSHIP_UNAVAILABLE == 102, "SAS_PAIRING_OWNERSHIP_UNAVAILABLE");
ABI_ASSERT(SAS_PAIRING_UNSUPPORTED_PLATFORM == 103, "SAS_PAIRING_UNSUPPORTED_PLATFORM");
ABI_ASSERT(SAS_PAIRING_OWNERSHIP_UNCERTAIN == 104, "SAS_PAIRING_OWNERSHIP_UNCERTAIN");
ABI_ASSERT(SAS_PAIRING_BUSY == 105, "SAS_PAIRING_BUSY");
ABI_ASSERT(SAS_PAIRING_EXHAUSTED == 106, "SAS_PAIRING_EXHAUSTED");
ABI_ASSERT(SAS_PAIRING_RESOURCE_LIMITED == 107, "SAS_PAIRING_RESOURCE_LIMITED");
ABI_ASSERT(SAS_PAIRING_MISSING_AUTHORIZATION == 200, "SAS_PAIRING_MISSING_AUTHORIZATION");
ABI_ASSERT(SAS_PAIRING_STALE_AUTHORIZATION == 201, "SAS_PAIRING_STALE_AUTHORIZATION");
ABI_ASSERT(SAS_PAIRING_TERMINATED == 202, "SAS_PAIRING_TERMINATED");
ABI_ASSERT(SAS_PAIRING_INVALID_BOOTSTRAP == 203, "SAS_PAIRING_INVALID_BOOTSTRAP");
ABI_ASSERT(SAS_PAIRING_RUN_ENDED == 204, "SAS_PAIRING_RUN_ENDED");
ABI_ASSERT(SAS_PAIRING_WRITE_PENDING == 205, "SAS_PAIRING_WRITE_PENDING");
ABI_ASSERT(SAS_PAIRING_CEREMONY_INVALID_STATE == 206, "SAS_PAIRING_CEREMONY_INVALID_STATE");
ABI_ASSERT(SAS_PAIRING_NO_LIVE_SAS == 207, "SAS_PAIRING_NO_LIVE_SAS");
ABI_ASSERT(SAS_PAIRING_CEREMONY_IDENTITY_MISMATCH == 208, "SAS_PAIRING_CEREMONY_IDENTITY_MISMATCH");
ABI_ASSERT(SAS_PAIRING_NOT_LOCALLY_APPROVED == 209, "SAS_PAIRING_NOT_LOCALLY_APPROVED");
ABI_ASSERT(SAS_PAIRING_UNEXPECTED_SENDER_ROLE == 210, "SAS_PAIRING_UNEXPECTED_SENDER_ROLE");
ABI_ASSERT(SAS_PAIRING_INVALID_REQUEST_ID == 211, "SAS_PAIRING_INVALID_REQUEST_ID");
ABI_ASSERT(SAS_PAIRING_REQUEST_ID_GENERATION_FAILED == 212, "SAS_PAIRING_REQUEST_ID_GENERATION_FAILED");
ABI_ASSERT(SAS_PAIRING_REQUEST_ID_MISMATCH == 213, "SAS_PAIRING_REQUEST_ID_MISMATCH");
ABI_ASSERT(SAS_PAIRING_SHARED_CONTEXT_MISMATCH == 214, "SAS_PAIRING_SHARED_CONTEXT_MISMATCH");
ABI_ASSERT(SAS_PAIRING_EXPECTED_PEER_MISMATCH == 215, "SAS_PAIRING_EXPECTED_PEER_MISMATCH");
ABI_ASSERT(SAS_PAIRING_APPROVALS_NOT_AUTHENTICATED == 216, "SAS_PAIRING_APPROVALS_NOT_AUTHENTICATED");
ABI_ASSERT(SAS_PAIRING_NOT_INITIATOR == 217, "SAS_PAIRING_NOT_INITIATOR");
ABI_ASSERT(SAS_PAIRING_TRANSCRIPT_MISMATCH == 218, "SAS_PAIRING_TRANSCRIPT_MISMATCH");
ABI_ASSERT(SAS_PAIRING_COMPLETED == 219, "SAS_PAIRING_COMPLETED");
ABI_ASSERT(SAS_PAIRING_NO_PENDING_FINAL_ACK == 220, "SAS_PAIRING_NO_PENDING_FINAL_ACK");
ABI_ASSERT(SAS_PAIRING_FINAL_ACK_MISMATCH == 221, "SAS_PAIRING_FINAL_ACK_MISMATCH");
ABI_ASSERT(SAS_PAIRING_CEREMONY_TIMED_OUT == 222, "SAS_PAIRING_CEREMONY_TIMED_OUT");
ABI_ASSERT(SAS_PAIRING_CEREMONY_CLOCK_UNAVAILABLE == 223, "SAS_PAIRING_CEREMONY_CLOCK_UNAVAILABLE");
ABI_ASSERT(SAS_PAIRING_PENDING_EXPIRED == 224, "SAS_PAIRING_PENDING_EXPIRED");
ABI_ASSERT(SAS_PAIRING_CEREMONY_CODEC_ERROR == 225, "SAS_PAIRING_CEREMONY_CODEC_ERROR");
ABI_ASSERT(SAS_PAIRING_CEREMONY_CRYPTO_ERROR == 226, "SAS_PAIRING_CEREMONY_CRYPTO_ERROR");
ABI_ASSERT(SAS_PAIRING_BUFFER_TOO_SMALL == 300, "SAS_PAIRING_BUFFER_TOO_SMALL");
ABI_ASSERT(SAS_PAIRING_LISTENER_ALREADY_ATTACHED == 400, "SAS_PAIRING_LISTENER_ALREADY_ATTACHED");
ABI_ASSERT(SAS_PAIRING_LISTENER_SETUP_FAILED == 401, "SAS_PAIRING_LISTENER_SETUP_FAILED");
ABI_ASSERT(SAS_PAIRING_LISTENER_NOT_ATTACHED == 402, "SAS_PAIRING_LISTENER_NOT_ATTACHED");
ABI_ASSERT(SAS_PAIRING_OWNER_LOOP_CLOSED == 403, "SAS_PAIRING_OWNER_LOOP_CLOSED");
ABI_ASSERT(SAS_PAIRING_NETWORK_POLL_FAILED == 404, "SAS_PAIRING_NETWORK_POLL_FAILED");
ABI_ASSERT(SAS_PAIRING_CONNECTION_ENDED == 405, "SAS_PAIRING_CONNECTION_ENDED");
ABI_ASSERT(SAS_PAIRING_FATAL == 900, "SAS_PAIRING_FATAL");
ABI_ASSERT(SAS_PAIRING_AUTHORITY_STATE_INVALID == 0, "SAS_PAIRING_AUTHORITY_STATE_INVALID");
ABI_ASSERT(SAS_PAIRING_AUTHORITY_READY == 1, "SAS_PAIRING_AUTHORITY_READY");
ABI_ASSERT(SAS_PAIRING_AUTHORITY_BUSY == 2, "SAS_PAIRING_AUTHORITY_BUSY");
ABI_ASSERT(SAS_PAIRING_AUTHORITY_EXHAUSTED == 3, "SAS_PAIRING_AUTHORITY_EXHAUSTED");
ABI_ASSERT(SAS_PAIRING_EVENT_INVALID == 0, "SAS_PAIRING_EVENT_INVALID");
ABI_ASSERT(SAS_PAIRING_EVENT_CONNECTION_ACCEPTED == 1, "SAS_PAIRING_EVENT_CONNECTION_ACCEPTED");
ABI_ASSERT(SAS_PAIRING_EVENT_ACCEPT_REFUSED == 2, "SAS_PAIRING_EVENT_ACCEPT_REFUSED");
ABI_ASSERT(SAS_PAIRING_EVENT_LISTENER_DISABLED == 3, "SAS_PAIRING_EVENT_LISTENER_DISABLED");
ABI_ASSERT(SAS_PAIRING_EVENT_CONNECTION_STEP == 4, "SAS_PAIRING_EVENT_CONNECTION_STEP");
ABI_ASSERT(SAS_PAIRING_EVENT_CONNECTION_CLOSED == 5, "SAS_PAIRING_EVENT_CONNECTION_CLOSED");
ABI_ASSERT(SAS_PAIRING_STEP_NONE == 0, "SAS_PAIRING_STEP_NONE");
ABI_ASSERT(SAS_PAIRING_STEP_INBOUND == 1, "SAS_PAIRING_STEP_INBOUND");
ABI_ASSERT(SAS_PAIRING_STEP_REFUSED == 2, "SAS_PAIRING_STEP_REFUSED");
ABI_ASSERT(SAS_PAIRING_STEP_DEADLINE == 3, "SAS_PAIRING_STEP_DEADLINE");
ABI_ASSERT(SAS_PAIRING_STEP_WRITTEN == 4, "SAS_PAIRING_STEP_WRITTEN");
ABI_ASSERT(SAS_PAIRING_STEP_CONFIRMED == 5, "SAS_PAIRING_STEP_CONFIRMED");
ABI_ASSERT(SAS_PAIRING_STEP_UNCONFIRMED == 6, "SAS_PAIRING_STEP_UNCONFIRMED");
ABI_ASSERT(SAS_PAIRING_STEP_DISCARDED == 7, "SAS_PAIRING_STEP_DISCARDED");
ABI_ASSERT(SAS_PAIRING_PROTOCOL_EVENT_NONE == 0, "SAS_PAIRING_PROTOCOL_EVENT_NONE");
ABI_ASSERT(SAS_PAIRING_PROTOCOL_EVENT_START_ACCEPTED == 1, "SAS_PAIRING_PROTOCOL_EVENT_START_ACCEPTED");
ABI_ASSERT(SAS_PAIRING_PROTOCOL_EVENT_START_DUPLICATE == 2, "SAS_PAIRING_PROTOCOL_EVENT_START_DUPLICATE");
ABI_ASSERT(SAS_PAIRING_PROTOCOL_EVENT_ACCEPT == 3, "SAS_PAIRING_PROTOCOL_EVENT_ACCEPT");
ABI_ASSERT(SAS_PAIRING_PROTOCOL_EVENT_INITIATOR_KEY == 4, "SAS_PAIRING_PROTOCOL_EVENT_INITIATOR_KEY");
ABI_ASSERT(SAS_PAIRING_PROTOCOL_EVENT_RESPONDER_KEY == 5, "SAS_PAIRING_PROTOCOL_EVENT_RESPONDER_KEY");
ABI_ASSERT(SAS_PAIRING_PROTOCOL_EVENT_BOOTSTRAP_MAC_AUTHENTICATED == 6, "SAS_PAIRING_PROTOCOL_EVENT_BOOTSTRAP_MAC_AUTHENTICATED");
ABI_ASSERT(SAS_PAIRING_PROTOCOL_EVENT_BOOTSTRAP_MAC_DUPLICATE == 7, "SAS_PAIRING_PROTOCOL_EVENT_BOOTSTRAP_MAC_DUPLICATE");
ABI_ASSERT(SAS_PAIRING_PROTOCOL_EVENT_INITIATOR_FINISH == 8, "SAS_PAIRING_PROTOCOL_EVENT_INITIATOR_FINISH");
ABI_ASSERT(SAS_PAIRING_PROTOCOL_EVENT_INITIATOR_FINISH_DUPLICATE == 9, "SAS_PAIRING_PROTOCOL_EVENT_INITIATOR_FINISH_DUPLICATE");
ABI_ASSERT(SAS_PAIRING_PROTOCOL_EVENT_RESPONDER_FINISH_ACK == 10, "SAS_PAIRING_PROTOCOL_EVENT_RESPONDER_FINISH_ACK");
ABI_ASSERT(SAS_PAIRING_PROTOCOL_EVENT_INITIATOR_FINISH_ACK == 11, "SAS_PAIRING_PROTOCOL_EVENT_INITIATOR_FINISH_ACK");
ABI_ASSERT(SAS_PAIRING_PROTOCOL_EVENT_PEER_CANCEL == 12, "SAS_PAIRING_PROTOCOL_EVENT_PEER_CANCEL");
ABI_ASSERT(SAS_PAIRING_EVENT_REASON_NONE == 0, "SAS_PAIRING_EVENT_REASON_NONE");
ABI_ASSERT(SAS_PAIRING_EVENT_REASON_RESOURCE_LIMITED == 1, "SAS_PAIRING_EVENT_REASON_RESOURCE_LIMITED");
ABI_ASSERT(SAS_PAIRING_EVENT_REASON_PEER_CLOSED == 2, "SAS_PAIRING_EVENT_REASON_PEER_CLOSED");
ABI_ASSERT(SAS_PAIRING_EVENT_REASON_SOCKET_IO == 3, "SAS_PAIRING_EVENT_REASON_SOCKET_IO");
ABI_ASSERT(SAS_PAIRING_EVENT_REASON_ABANDONED_PARTIAL_FRAME == 4, "SAS_PAIRING_EVENT_REASON_ABANDONED_PARTIAL_FRAME");
ABI_ASSERT(SAS_PAIRING_EVENT_REASON_READINESS_FAILURE == 5, "SAS_PAIRING_EVENT_REASON_READINESS_FAILURE");
ABI_ASSERT(SAS_PAIRING_EVENT_REASON_LISTENER_IO == 6, "SAS_PAIRING_EVENT_REASON_LISTENER_IO");
ABI_ASSERT(SAS_PAIRING_EVENT_REASON_LISTENER_READINESS == 7, "SAS_PAIRING_EVENT_REASON_LISTENER_READINESS");
ABI_ASSERT(SAS_PAIRING_EVENT_REASON_ROUTE_REFUSED == 8, "SAS_PAIRING_EVENT_REASON_ROUTE_REFUSED");
ABI_ASSERT(SAS_PAIRING_EVENT_REASON_OWNERSHIP_UNCERTAIN == 9, "SAS_PAIRING_EVENT_REASON_OWNERSHIP_UNCERTAIN");
ABI_ASSERT(SAS_PAIRING_EVENT_REASON_OTHER_HOST_FAILURE == 10, "SAS_PAIRING_EVENT_REASON_OTHER_HOST_FAILURE");
ABI_ASSERT(SAS_PAIRING_EVENT_REASON_INVALID_FRAME == 11, "SAS_PAIRING_EVENT_REASON_INVALID_FRAME");
ABI_ASSERT(SAS_PAIRING_EVENT_REASON_TRANSPORT_DEADLINE == 12, "SAS_PAIRING_EVENT_REASON_TRANSPORT_DEADLINE");
ABI_ASSERT(SAS_PAIRING_EVENT_REASON_CLOCK_UNAVAILABLE == 13, "SAS_PAIRING_EVENT_REASON_CLOCK_UNAVAILABLE");
ABI_ASSERT(SAS_PAIRING_EVENT_REASON_SESSION_PROTOCOL_FAILURE == 14, "SAS_PAIRING_EVENT_REASON_SESSION_PROTOCOL_FAILURE");
ABI_ASSERT(SAS_PAIRING_EVENT_REASON_ALREADY_CLOSED == 15, "SAS_PAIRING_EVENT_REASON_ALREADY_CLOSED");
ABI_ASSERT(SAS_PAIRING_DEADLINE_NONE == 0, "SAS_PAIRING_DEADLINE_NONE");
ABI_ASSERT(SAS_PAIRING_DEADLINE_ABSOLUTE_TIMEOUT == 1, "SAS_PAIRING_DEADLINE_ABSOLUTE_TIMEOUT");
ABI_ASSERT(SAS_PAIRING_DEADLINE_INACTIVITY_TIMEOUT == 2, "SAS_PAIRING_DEADLINE_INACTIVITY_TIMEOUT");
ABI_ASSERT(SAS_PAIRING_DEADLINE_PENDING_EXPIRED == 3, "SAS_PAIRING_DEADLINE_PENDING_EXPIRED");
ABI_ASSERT(SAS_PAIRING_DEADLINE_CLOCK_UNAVAILABLE == 4, "SAS_PAIRING_DEADLINE_CLOCK_UNAVAILABLE");
ABI_ASSERT(SAS_PAIRING_CANCEL_STATE_NONE == 0, "SAS_PAIRING_CANCEL_STATE_NONE");
ABI_ASSERT(SAS_PAIRING_CANCEL_STATE_NOT_BUILT == 1, "SAS_PAIRING_CANCEL_STATE_NOT_BUILT");
ABI_ASSERT(SAS_PAIRING_CANCEL_STATE_PENDING == 2, "SAS_PAIRING_CANCEL_STATE_PENDING");
ABI_ASSERT(SAS_PAIRING_CANCEL_STATE_DROPPED == 3, "SAS_PAIRING_CANCEL_STATE_DROPPED");
ABI_ASSERT(SAS_PAIRING_CANCEL_REASON_NONE == 0, "SAS_PAIRING_CANCEL_REASON_NONE");
ABI_ASSERT(SAS_PAIRING_CANCEL_REASON_USER_REJECTION == 1, "SAS_PAIRING_CANCEL_REASON_USER_REJECTION");
ABI_ASSERT(SAS_PAIRING_CANCEL_REASON_USER_CANCELLATION == 2, "SAS_PAIRING_CANCEL_REASON_USER_CANCELLATION");
ABI_ASSERT(SAS_PAIRING_CANCEL_REASON_TIMEOUT == 3, "SAS_PAIRING_CANCEL_REASON_TIMEOUT");
ABI_ASSERT(SAS_PAIRING_CANCEL_REASON_LOCAL_POLICY_FAILURE == 4, "SAS_PAIRING_CANCEL_REASON_LOCAL_POLICY_FAILURE");
ABI_ASSERT(SAS_PAIRING_EVENT_FLAG_WRITE_PENDING == 0x1, "SAS_PAIRING_EVENT_FLAG_WRITE_PENDING");
ABI_ASSERT(SAS_PAIRING_EVENT_FLAG_RUN_UNTRACKED == 0x2, "SAS_PAIRING_EVENT_FLAG_RUN_UNTRACKED");
ABI_ASSERT(SAS_PAIRING_ROLE_INVALID == 0, "SAS_PAIRING_ROLE_INVALID");
ABI_ASSERT(SAS_PAIRING_ROLE_INITIATOR == 1, "SAS_PAIRING_ROLE_INITIATOR");
ABI_ASSERT(SAS_PAIRING_ROLE_RESPONDER == 2, "SAS_PAIRING_ROLE_RESPONDER");
ABI_ASSERT(SAS_PAIRING_RESULT_FIELD_REQUEST_ID == 1, "SAS_PAIRING_RESULT_FIELD_REQUEST_ID");
ABI_ASSERT(SAS_PAIRING_RESULT_FIELD_AUTHENTICATED_PEER_BOOTSTRAP == 2, "SAS_PAIRING_RESULT_FIELD_AUTHENTICATED_PEER_BOOTSTRAP");
ABI_ASSERT(SAS_PAIRING_RESULT_FIELD_AUTHENTICATED_SHARED_CONTEXT == 3, "SAS_PAIRING_RESULT_FIELD_AUTHENTICATED_SHARED_CONTEXT");
ABI_ASSERT(SAS_PAIRING_RESULT_FIELD_PROFILE_IDENTIFIER == 4, "SAS_PAIRING_RESULT_FIELD_PROFILE_IDENTIFIER");
ABI_ASSERT(SAS_PAIRING_LOCAL_EVENT_INVALID == 0, "SAS_PAIRING_LOCAL_EVENT_INVALID");
ABI_ASSERT(SAS_PAIRING_LOCAL_EVENT_INITIATOR_STARTED == 1, "SAS_PAIRING_LOCAL_EVENT_INITIATOR_STARTED");
ABI_ASSERT(SAS_PAIRING_LOCAL_EVENT_EXPOSURE_AUTHORIZED == 2, "SAS_PAIRING_LOCAL_EVENT_EXPOSURE_AUTHORIZED");
ABI_ASSERT(SAS_PAIRING_LOCAL_EVENT_KEY_EXPOSED == 3, "SAS_PAIRING_LOCAL_EVENT_KEY_EXPOSED");
ABI_ASSERT(SAS_PAIRING_LOCAL_EVENT_SAS_APPROVED == 4, "SAS_PAIRING_LOCAL_EVENT_SAS_APPROVED");
ABI_ASSERT(SAS_PAIRING_LOCAL_EVENT_SAS_ALREADY_APPROVED == 5, "SAS_PAIRING_LOCAL_EVENT_SAS_ALREADY_APPROVED");
ABI_ASSERT(SAS_PAIRING_LOCAL_EVENT_BOOTSTRAP_MAC_EMITTED == 6, "SAS_PAIRING_LOCAL_EVENT_BOOTSTRAP_MAC_EMITTED");
ABI_ASSERT(SAS_PAIRING_LOCAL_EVENT_BOOTSTRAP_MAC_ALREADY_EMITTED == 7, "SAS_PAIRING_LOCAL_EVENT_BOOTSTRAP_MAC_ALREADY_EMITTED");
ABI_ASSERT(SAS_PAIRING_LOCAL_EVENT_INITIATOR_FINISH_EMITTED == 8, "SAS_PAIRING_LOCAL_EVENT_INITIATOR_FINISH_EMITTED");
ABI_ASSERT(SAS_PAIRING_LOCAL_EVENT_INITIATOR_FINISH_ALREADY_EMITTED == 9, "SAS_PAIRING_LOCAL_EVENT_INITIATOR_FINISH_ALREADY_EMITTED");
ABI_ASSERT(SAS_PAIRING_LOCAL_EVENT_SAS_REJECTED == 10, "SAS_PAIRING_LOCAL_EVENT_SAS_REJECTED");
ABI_ASSERT(SAS_PAIRING_LOCAL_EVENT_SAS_CANCELLED == 11, "SAS_PAIRING_LOCAL_EVENT_SAS_CANCELLED");
ABI_ASSERT(SAS_PAIRING_LOCAL_EVENT_DEADLINE == 12, "SAS_PAIRING_LOCAL_EVENT_DEADLINE");
ABI_ASSERT(SAS_PAIRING_ACTION_FLAG_WRITE_PENDING == 0x1, "SAS_PAIRING_ACTION_FLAG_WRITE_PENDING");
ABI_ASSERT(SAS_PAIRING_RUNTIME_INVALID == 0, "SAS_PAIRING_RUNTIME_INVALID");
ABI_ASSERT(SAS_PAIRING_AUTHORITY_INVALID == 0, "SAS_PAIRING_AUTHORITY_INVALID");
ABI_ASSERT(SAS_PAIRING_HOST_INVALID == 0, "SAS_PAIRING_HOST_INVALID");
ABI_ASSERT(SAS_PAIRING_SOCKET_INVALID == UINTPTR_MAX, "SAS_PAIRING_SOCKET_INVALID");
ABI_ASSERT(SAS_PAIRING_CONNECTION_INVALID == 0, "SAS_PAIRING_CONNECTION_INVALID");
ABI_ASSERT(SAS_PAIRING_RUN_INVALID == 0, "SAS_PAIRING_RUN_INVALID");
ABI_ASSERT(SAS_PAIRING_RESULT_INVALID == 0, "SAS_PAIRING_RESULT_INVALID");
ABI_ASSERT(SAS_PAIRING_MAX_DRIVE_EVENTS == 17, "SAS_PAIRING_MAX_DRIVE_EVENTS");
ABI_ASSERT(SAS_PAIRING_MAX_REQUEST_ID_LEN == 64, "SAS_PAIRING_MAX_REQUEST_ID_LEN");
ABI_ASSERT(SAS_PAIRING_MAX_RUNS_PER_CONNECTION == 32, "SAS_PAIRING_MAX_RUNS_PER_CONNECTION");
ABI_ASSERT(SAS_PAIRING_SAS_DECIMAL_LEN == 14, "SAS_PAIRING_SAS_DECIMAL_LEN");

/* Each export bound to a pointer of its exact frozen signature. */
struct abi_exports {
    uint32_t (*abi_version)(void);
    sas_pairing_status_t (*runtime_create)(sas_pairing_runtime_t *);
    sas_pairing_status_t (*runtime_destroy)(sas_pairing_runtime_t);
    sas_pairing_status_t (*authority_register)(sas_pairing_runtime_t, const uint8_t *, size_t, sas_pairing_authority_t *);
    sas_pairing_status_t (*authority_release)(sas_pairing_runtime_t, sas_pairing_authority_t);
    sas_pairing_status_t (*authority_status)(sas_pairing_runtime_t, sas_pairing_authority_t, sas_pairing_authority_state_t *, uint32_t *);
    sas_pairing_status_t (*host_create)(sas_pairing_runtime_t, sas_pairing_authority_t, sas_pairing_host_t *);
    sas_pairing_status_t (*host_destroy)(sas_pairing_runtime_t, sas_pairing_host_t);
    sas_pairing_status_t (*host_attach_windows_listener)(sas_pairing_runtime_t, sas_pairing_host_t, sas_pairing_socket_t *, const sas_pairing_bootstrap_view_t *, const sas_pairing_bootstrap_view_t *);
    sas_pairing_status_t (*host_detach_listener)(sas_pairing_runtime_t, sas_pairing_host_t);
    sas_pairing_status_t (*host_drive)(sas_pairing_runtime_t, sas_pairing_host_t, sas_pairing_event_t *, size_t, size_t *, sas_pairing_status_t *);
    sas_pairing_status_t (*host_recheck_after_resume)(sas_pairing_runtime_t, sas_pairing_host_t, sas_pairing_event_t *, size_t, size_t *, sas_pairing_status_t *);
    sas_pairing_status_t (*connection_close)(sas_pairing_runtime_t, sas_pairing_host_t, sas_pairing_connection_t);
    sas_pairing_status_t (*result_info)(sas_pairing_runtime_t, sas_pairing_result_t, sas_pairing_result_info_t *);
    sas_pairing_status_t (*result_copy)(sas_pairing_runtime_t, sas_pairing_result_t, sas_pairing_result_field_t, uint8_t *, size_t, size_t *);
    sas_pairing_status_t (*result_destroy)(sas_pairing_runtime_t, sas_pairing_result_t);
    sas_pairing_status_t (*connection_start_initiator)(sas_pairing_runtime_t, sas_pairing_host_t, sas_pairing_connection_t, const sas_pairing_bootstrap_view_t *, const sas_pairing_bootstrap_view_t *, sas_pairing_action_t *);
    sas_pairing_status_t (*run_authorize_exposure)(sas_pairing_runtime_t, sas_pairing_host_t, sas_pairing_connection_t, sas_pairing_run_t, sas_pairing_action_t *);
    sas_pairing_status_t (*run_expose_key)(sas_pairing_runtime_t, sas_pairing_host_t, sas_pairing_connection_t, sas_pairing_run_t, sas_pairing_action_t *);
    sas_pairing_status_t (*run_presentation)(sas_pairing_runtime_t, sas_pairing_host_t, sas_pairing_connection_t, sas_pairing_run_t, sas_pairing_sas_presentation_t *);
    sas_pairing_status_t (*run_approve_sas)(sas_pairing_runtime_t, sas_pairing_host_t, sas_pairing_connection_t, sas_pairing_run_t, const uint8_t *, sas_pairing_action_t *);
    sas_pairing_status_t (*run_emit_bootstrap_mac)(sas_pairing_runtime_t, sas_pairing_host_t, sas_pairing_connection_t, sas_pairing_run_t, sas_pairing_action_t *);
    sas_pairing_status_t (*run_reject_sas)(sas_pairing_runtime_t, sas_pairing_host_t, sas_pairing_connection_t, sas_pairing_run_t, const uint8_t *, sas_pairing_action_t *);
    sas_pairing_status_t (*run_cancel_sas)(sas_pairing_runtime_t, sas_pairing_host_t, sas_pairing_connection_t, sas_pairing_run_t, const uint8_t *, sas_pairing_action_t *);
    sas_pairing_status_t (*run_emit_initiator_finish)(sas_pairing_runtime_t, sas_pairing_host_t, sas_pairing_connection_t, sas_pairing_run_t, sas_pairing_action_t *);
};

static const struct abi_exports EXPORTS = {
    sas_pairing_abi_version,
    sas_pairing_runtime_create,
    sas_pairing_runtime_destroy,
    sas_pairing_authority_register,
    sas_pairing_authority_release,
    sas_pairing_authority_status,
    sas_pairing_host_create,
    sas_pairing_host_destroy,
    sas_pairing_host_attach_windows_listener,
    sas_pairing_host_detach_listener,
    sas_pairing_host_drive,
    sas_pairing_host_recheck_after_resume,
    sas_pairing_connection_close,
    sas_pairing_result_info,
    sas_pairing_result_copy,
    sas_pairing_result_destroy,
    sas_pairing_connection_start_initiator,
    sas_pairing_run_authorize_exposure,
    sas_pairing_run_expose_key,
    sas_pairing_run_presentation,
    sas_pairing_run_approve_sas,
    sas_pairing_run_emit_bootstrap_mac,
    sas_pairing_run_reject_sas,
    sas_pairing_run_cancel_sas,
    sas_pairing_run_emit_initiator_finish
};

#define ABI_EXPORT_COUNT 25
ABI_ASSERT(sizeof(struct abi_exports) == ABI_EXPORT_COUNT * sizeof(EXPORTS.abi_version), "25 exports");

static int failures;

static void check(int condition, const char *what) {
    if (!condition) {
        failures++;
        printf("FAILED: %s\n", what);
    }
}

/* Whether all `size` bytes at `bytes` are zero. */
static int all_zero(const void *bytes, size_t size) {
    const unsigned char *at = (const unsigned char *)bytes;
    size_t index;
    for (index = 0; index < size; index++) {
        if (at[index] != 0) {
            return 0;
        }
    }
    return 1;
}

int main(void) {
    sas_pairing_runtime_t runtime = 99;
    sas_pairing_runtime_t second = 99;
    sas_pairing_authority_t authority = 99;
    sas_pairing_host_t host = 99;
    sas_pairing_authority_state_t state = 99;
    uint32_t remaining = 99;
    size_t count = 99;
    sas_pairing_status_t failure = 99;
    sas_pairing_status_t status;
    sas_pairing_event_t events[SAS_PAIRING_MAX_DRIVE_EVENTS];
    sas_pairing_action_t action;
    sas_pairing_sas_presentation_t presentation;
    sas_pairing_result_info_t info;
    static const uint8_t scope[] = "p7.7-c-abi-v1-consumer";
    static const uint8_t identity[32] = {0};

    /* Linking resolved all 25 exports into EXPORTS; call two through it. */
    check(EXPORTS.abi_version() == SAS_PAIRING_ABI_VERSION, "ABI version 1");
    check(EXPORTS.runtime_destroy(0) == SAS_PAIRING_INVALID_HANDLE, "0 is never a handle");
    check(sas_pairing_runtime_create(NULL) == SAS_PAIRING_INVALID_ARGUMENT, "null output");

    /* The drive's size query: structural checks, outputs set, then platform, then capacity. */
    status = sas_pairing_host_drive(0, 0, NULL, 0, &count, &failure);
#ifdef _WIN32
    check(status == SAS_PAIRING_BUFFER_TOO_SMALL, "drive size query");
    check(count == SAS_PAIRING_MAX_DRIVE_EVENTS, "required capacity 17");
#else
    check(status == SAS_PAIRING_UNSUPPORTED_PLATFORM, "drive fails closed");
    check(count == 0, "nothing driven");
#endif
    check(failure == SAS_PAIRING_OK, "no owner-loop failure");

    check(sas_pairing_runtime_create(&runtime) == SAS_PAIRING_OK, "runtime create");
    check(runtime != SAS_PAIRING_RUNTIME_INVALID, "runtime handle");
    check(sas_pairing_runtime_create(&second) == SAS_PAIRING_ALREADY_INITIALIZED, "one runtime");
    check(second == SAS_PAIRING_RUNTIME_INVALID, "no second handle");

    status = sas_pairing_authority_register(runtime, scope, sizeof scope - 1, &authority);
#ifdef _WIN32
    check(status == SAS_PAIRING_OK, "authority register");
    check(sas_pairing_authority_status(runtime, authority, &state, &remaining) == SAS_PAIRING_OK,
          "authority status");
    check(state == SAS_PAIRING_AUTHORITY_READY && remaining == 10, "ready, 10 opportunities");
    check(sas_pairing_host_create(runtime, authority, &host) == SAS_PAIRING_OK, "host create");
    status = sas_pairing_host_drive(runtime, host, events, SAS_PAIRING_MAX_DRIVE_EVENTS, &count,
                                    &failure);
    check(status == SAS_PAIRING_LISTENER_NOT_ATTACHED, "no listener, nothing driven");
#else
    check(status == SAS_PAIRING_UNSUPPORTED_PLATFORM, "authority registration fails closed");
    check(authority == SAS_PAIRING_AUTHORITY_INVALID, "no authority handle");
    (void)state;
    (void)remaining;
    (void)host;
    (void)events;
#endif

    /* Output records are zeroed on entry: no byte of the caller's old contents survives. */
    memset(&action, 0xEE, sizeof action);
    status = sas_pairing_run_approve_sas(runtime, host, 7, 8, identity, &action);
    check(status != SAS_PAIRING_OK, "no such run");
    check(all_zero(&action, sizeof action), "action record zeroed");
    memset(&presentation, 0xEE, sizeof presentation);
    status = sas_pairing_run_presentation(runtime, host, 7, 8, &presentation);
    check(status != SAS_PAIRING_OK, "no such run");
    check(all_zero(&presentation, sizeof presentation), "presentation zeroed");
    memset(&info, 0xEE, sizeof info);
    check(sas_pairing_result_info(runtime, 8, &info) == SAS_PAIRING_INVALID_HANDLE, "no result");
    check(all_zero(&info, sizeof info), "result info zeroed");

#ifdef _WIN32
    check(sas_pairing_host_destroy(runtime, host) == SAS_PAIRING_OK, "host destroy");
    check(sas_pairing_authority_release(runtime, authority) == SAS_PAIRING_OK, "release");
#endif
    check(sas_pairing_runtime_destroy(runtime) == SAS_PAIRING_OK, "runtime destroy");
    check(sas_pairing_runtime_destroy(runtime) == SAS_PAIRING_INVALID_HANDLE, "destroyed once");

    if (failures != 0) {
        printf("sas_pairing ABI v1 consumer (%s): %d check(s) FAILED\n", ABI_LANGUAGE, failures);
        return 1;
    }
    printf("sas_pairing ABI v1 consumer (%s): OK\n", ABI_LANGUAGE);
    return 0;
}
