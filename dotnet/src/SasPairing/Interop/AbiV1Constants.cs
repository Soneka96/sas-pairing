namespace SasPairing.Interop;

/// <summary>
/// Every frozen native ABI v1 constant (P7-D-013, manifest sections 1, 3, 4, and 5), spelled exactly as
/// <c>core/include/sas_pairing.h</c> spells it and typed by the P9-D-001 C to C# mapping. Private to the
/// assembly: the high-level API (P9.2 onwards) translates these values and never exposes them raw.
/// </summary>
/// <remarks>
/// The tests compare this class with the manifest and the header name by name, value by value, and type by
/// type, and require that no constant is missing or extra. Statuses are raw <c>int32_t</c> values: every
/// non-zero status, known or unknown, is a failure, and none is a trust verdict. Handles are opaque
/// <c>uint64_t</c> values, never pointers or identities.
/// </remarks>
internal static class AbiV1Constants
{
    // Manifest section 1: the native ABI version. A literal, not derived from the header, so that a header
    // that changed its version fails the consistency tests instead of being accepted.
    internal const uint SAS_PAIRING_ABI_VERSION = 1;
    internal const uint SAS_PAIRING_ABI_VERSION_INVALID = 0;

    // Manifest section 3: the 48 sas_pairing_status_t (int32_t) values.
    internal const int SAS_PAIRING_OK = 0;
    internal const int SAS_PAIRING_INVALID_ARGUMENT = 1;
    internal const int SAS_PAIRING_INVALID_HANDLE = 2;
    internal const int SAS_PAIRING_ALREADY_INITIALIZED = 3;
    internal const int SAS_PAIRING_HANDLES_EXHAUSTED = 4;
    internal const int SAS_PAIRING_INVALID_SCOPE = 100;
    internal const int SAS_PAIRING_ALREADY_REGISTERED = 101;
    internal const int SAS_PAIRING_OWNERSHIP_UNAVAILABLE = 102;
    internal const int SAS_PAIRING_UNSUPPORTED_PLATFORM = 103;
    internal const int SAS_PAIRING_OWNERSHIP_UNCERTAIN = 104;
    internal const int SAS_PAIRING_BUSY = 105;
    internal const int SAS_PAIRING_EXHAUSTED = 106;
    internal const int SAS_PAIRING_RESOURCE_LIMITED = 107;
    internal const int SAS_PAIRING_MISSING_AUTHORIZATION = 200;
    internal const int SAS_PAIRING_STALE_AUTHORIZATION = 201;
    internal const int SAS_PAIRING_TERMINATED = 202;
    internal const int SAS_PAIRING_INVALID_BOOTSTRAP = 203;
    internal const int SAS_PAIRING_RUN_ENDED = 204;
    internal const int SAS_PAIRING_WRITE_PENDING = 205;
    internal const int SAS_PAIRING_CEREMONY_INVALID_STATE = 206;
    internal const int SAS_PAIRING_NO_LIVE_SAS = 207;
    internal const int SAS_PAIRING_CEREMONY_IDENTITY_MISMATCH = 208;
    internal const int SAS_PAIRING_NOT_LOCALLY_APPROVED = 209;
    internal const int SAS_PAIRING_UNEXPECTED_SENDER_ROLE = 210;
    internal const int SAS_PAIRING_INVALID_REQUEST_ID = 211;
    internal const int SAS_PAIRING_REQUEST_ID_GENERATION_FAILED = 212;
    internal const int SAS_PAIRING_REQUEST_ID_MISMATCH = 213;
    internal const int SAS_PAIRING_SHARED_CONTEXT_MISMATCH = 214;
    internal const int SAS_PAIRING_EXPECTED_PEER_MISMATCH = 215;
    internal const int SAS_PAIRING_APPROVALS_NOT_AUTHENTICATED = 216;
    internal const int SAS_PAIRING_NOT_INITIATOR = 217;
    internal const int SAS_PAIRING_TRANSCRIPT_MISMATCH = 218;
    internal const int SAS_PAIRING_COMPLETED = 219;
    internal const int SAS_PAIRING_NO_PENDING_FINAL_ACK = 220;
    internal const int SAS_PAIRING_FINAL_ACK_MISMATCH = 221;
    internal const int SAS_PAIRING_CEREMONY_TIMED_OUT = 222;
    internal const int SAS_PAIRING_CEREMONY_CLOCK_UNAVAILABLE = 223;
    internal const int SAS_PAIRING_PENDING_EXPIRED = 224;
    internal const int SAS_PAIRING_CEREMONY_CODEC_ERROR = 225;
    internal const int SAS_PAIRING_CEREMONY_CRYPTO_ERROR = 226;
    internal const int SAS_PAIRING_BUFFER_TOO_SMALL = 300;
    internal const int SAS_PAIRING_LISTENER_ALREADY_ATTACHED = 400;
    internal const int SAS_PAIRING_LISTENER_SETUP_FAILED = 401;
    internal const int SAS_PAIRING_LISTENER_NOT_ATTACHED = 402;
    internal const int SAS_PAIRING_OWNER_LOOP_CLOSED = 403;
    internal const int SAS_PAIRING_NETWORK_POLL_FAILED = 404;
    internal const int SAS_PAIRING_CONNECTION_ENDED = 405;
    internal const int SAS_PAIRING_FATAL = 900;

    // Manifest section 5: handle invalid values (uint64_t handles; 0 is never valid).
    internal const ulong SAS_PAIRING_RUNTIME_INVALID = 0;
    internal const ulong SAS_PAIRING_AUTHORITY_INVALID = 0;
    internal const ulong SAS_PAIRING_HOST_INVALID = 0;
    internal const ulong SAS_PAIRING_CONNECTION_INVALID = 0;
    internal const ulong SAS_PAIRING_RUN_INVALID = 0;
    internal const ulong SAS_PAIRING_RESULT_INVALID = 0;

    /// <summary>
    /// <c>SAS_PAIRING_SOCKET_INVALID</c>: <c>UINTPTR_MAX</c> of the pointer-sized <c>sas_pairing_socket_t</c>
    /// (Windows <c>INVALID_SOCKET</c>). Pointer-width dependent, so not a C# constant.
    /// </summary>
    internal static nuint SAS_PAIRING_SOCKET_INVALID => nuint.MaxValue;

    // Manifest section 5: size_t scalar limits.
    internal const nuint SAS_PAIRING_MAX_DRIVE_EVENTS = 17;
    internal const nuint SAS_PAIRING_MAX_REQUEST_ID_LEN = 64;
    internal const nuint SAS_PAIRING_MAX_RUNS_PER_CONNECTION = 32;
    internal const nuint SAS_PAIRING_SAS_DECIMAL_LEN = 14;

    // Manifest section 4: the 84 values of the thirteen uint32_t namespaces.
    // sas_pairing_authority_state_t
    internal const uint SAS_PAIRING_AUTHORITY_STATE_INVALID = 0;
    internal const uint SAS_PAIRING_AUTHORITY_READY = 1;
    internal const uint SAS_PAIRING_AUTHORITY_BUSY = 2;
    internal const uint SAS_PAIRING_AUTHORITY_EXHAUSTED = 3;

    // sas_pairing_event_kind_t
    internal const uint SAS_PAIRING_EVENT_INVALID = 0;
    internal const uint SAS_PAIRING_EVENT_CONNECTION_ACCEPTED = 1;
    internal const uint SAS_PAIRING_EVENT_ACCEPT_REFUSED = 2;
    internal const uint SAS_PAIRING_EVENT_LISTENER_DISABLED = 3;
    internal const uint SAS_PAIRING_EVENT_CONNECTION_STEP = 4;
    internal const uint SAS_PAIRING_EVENT_CONNECTION_CLOSED = 5;

    // sas_pairing_step_kind_t
    internal const uint SAS_PAIRING_STEP_NONE = 0;
    internal const uint SAS_PAIRING_STEP_INBOUND = 1;
    internal const uint SAS_PAIRING_STEP_REFUSED = 2;
    internal const uint SAS_PAIRING_STEP_DEADLINE = 3;
    internal const uint SAS_PAIRING_STEP_WRITTEN = 4;
    internal const uint SAS_PAIRING_STEP_CONFIRMED = 5;
    internal const uint SAS_PAIRING_STEP_UNCONFIRMED = 6;
    internal const uint SAS_PAIRING_STEP_DISCARDED = 7;

    // sas_pairing_protocol_event_t
    internal const uint SAS_PAIRING_PROTOCOL_EVENT_NONE = 0;
    internal const uint SAS_PAIRING_PROTOCOL_EVENT_START_ACCEPTED = 1;
    internal const uint SAS_PAIRING_PROTOCOL_EVENT_START_DUPLICATE = 2;
    internal const uint SAS_PAIRING_PROTOCOL_EVENT_ACCEPT = 3;
    internal const uint SAS_PAIRING_PROTOCOL_EVENT_INITIATOR_KEY = 4;
    internal const uint SAS_PAIRING_PROTOCOL_EVENT_RESPONDER_KEY = 5;
    internal const uint SAS_PAIRING_PROTOCOL_EVENT_BOOTSTRAP_MAC_AUTHENTICATED = 6;
    internal const uint SAS_PAIRING_PROTOCOL_EVENT_BOOTSTRAP_MAC_DUPLICATE = 7;
    internal const uint SAS_PAIRING_PROTOCOL_EVENT_INITIATOR_FINISH = 8;
    internal const uint SAS_PAIRING_PROTOCOL_EVENT_INITIATOR_FINISH_DUPLICATE = 9;
    internal const uint SAS_PAIRING_PROTOCOL_EVENT_RESPONDER_FINISH_ACK = 10;
    internal const uint SAS_PAIRING_PROTOCOL_EVENT_INITIATOR_FINISH_ACK = 11;
    internal const uint SAS_PAIRING_PROTOCOL_EVENT_PEER_CANCEL = 12;

    // sas_pairing_event_reason_t
    internal const uint SAS_PAIRING_EVENT_REASON_NONE = 0;
    internal const uint SAS_PAIRING_EVENT_REASON_RESOURCE_LIMITED = 1;
    internal const uint SAS_PAIRING_EVENT_REASON_PEER_CLOSED = 2;
    internal const uint SAS_PAIRING_EVENT_REASON_SOCKET_IO = 3;
    internal const uint SAS_PAIRING_EVENT_REASON_ABANDONED_PARTIAL_FRAME = 4;
    internal const uint SAS_PAIRING_EVENT_REASON_READINESS_FAILURE = 5;
    internal const uint SAS_PAIRING_EVENT_REASON_LISTENER_IO = 6;
    internal const uint SAS_PAIRING_EVENT_REASON_LISTENER_READINESS = 7;
    internal const uint SAS_PAIRING_EVENT_REASON_ROUTE_REFUSED = 8;
    internal const uint SAS_PAIRING_EVENT_REASON_OWNERSHIP_UNCERTAIN = 9;
    internal const uint SAS_PAIRING_EVENT_REASON_OTHER_HOST_FAILURE = 10;
    internal const uint SAS_PAIRING_EVENT_REASON_INVALID_FRAME = 11;
    internal const uint SAS_PAIRING_EVENT_REASON_TRANSPORT_DEADLINE = 12;
    internal const uint SAS_PAIRING_EVENT_REASON_CLOCK_UNAVAILABLE = 13;
    internal const uint SAS_PAIRING_EVENT_REASON_SESSION_PROTOCOL_FAILURE = 14;
    internal const uint SAS_PAIRING_EVENT_REASON_ALREADY_CLOSED = 15;

    // sas_pairing_deadline_kind_t
    internal const uint SAS_PAIRING_DEADLINE_NONE = 0;
    internal const uint SAS_PAIRING_DEADLINE_ABSOLUTE_TIMEOUT = 1;
    internal const uint SAS_PAIRING_DEADLINE_INACTIVITY_TIMEOUT = 2;
    internal const uint SAS_PAIRING_DEADLINE_PENDING_EXPIRED = 3;
    internal const uint SAS_PAIRING_DEADLINE_CLOCK_UNAVAILABLE = 4;

    // sas_pairing_cancel_state_t
    internal const uint SAS_PAIRING_CANCEL_STATE_NONE = 0;
    internal const uint SAS_PAIRING_CANCEL_STATE_NOT_BUILT = 1;
    internal const uint SAS_PAIRING_CANCEL_STATE_PENDING = 2;
    internal const uint SAS_PAIRING_CANCEL_STATE_DROPPED = 3;

    // sas_pairing_cancel_reason_t
    internal const uint SAS_PAIRING_CANCEL_REASON_NONE = 0;
    internal const uint SAS_PAIRING_CANCEL_REASON_USER_REJECTION = 1;
    internal const uint SAS_PAIRING_CANCEL_REASON_USER_CANCELLATION = 2;
    internal const uint SAS_PAIRING_CANCEL_REASON_TIMEOUT = 3;
    internal const uint SAS_PAIRING_CANCEL_REASON_LOCAL_POLICY_FAILURE = 4;

    // sas_pairing_event_flags_t
    internal const uint SAS_PAIRING_EVENT_FLAG_WRITE_PENDING = 0x1;
    internal const uint SAS_PAIRING_EVENT_FLAG_RUN_UNTRACKED = 0x2;

    // sas_pairing_role_t
    internal const uint SAS_PAIRING_ROLE_INVALID = 0;
    internal const uint SAS_PAIRING_ROLE_INITIATOR = 1;
    internal const uint SAS_PAIRING_ROLE_RESPONDER = 2;

    // sas_pairing_result_field_t
    internal const uint SAS_PAIRING_RESULT_FIELD_REQUEST_ID = 1;
    internal const uint SAS_PAIRING_RESULT_FIELD_AUTHENTICATED_PEER_BOOTSTRAP = 2;
    internal const uint SAS_PAIRING_RESULT_FIELD_AUTHENTICATED_SHARED_CONTEXT = 3;
    internal const uint SAS_PAIRING_RESULT_FIELD_PROFILE_IDENTIFIER = 4;

    // sas_pairing_local_event_t
    internal const uint SAS_PAIRING_LOCAL_EVENT_INVALID = 0;
    internal const uint SAS_PAIRING_LOCAL_EVENT_INITIATOR_STARTED = 1;
    internal const uint SAS_PAIRING_LOCAL_EVENT_EXPOSURE_AUTHORIZED = 2;
    internal const uint SAS_PAIRING_LOCAL_EVENT_KEY_EXPOSED = 3;
    internal const uint SAS_PAIRING_LOCAL_EVENT_SAS_APPROVED = 4;
    internal const uint SAS_PAIRING_LOCAL_EVENT_SAS_ALREADY_APPROVED = 5;
    internal const uint SAS_PAIRING_LOCAL_EVENT_BOOTSTRAP_MAC_EMITTED = 6;
    internal const uint SAS_PAIRING_LOCAL_EVENT_BOOTSTRAP_MAC_ALREADY_EMITTED = 7;
    internal const uint SAS_PAIRING_LOCAL_EVENT_INITIATOR_FINISH_EMITTED = 8;
    internal const uint SAS_PAIRING_LOCAL_EVENT_INITIATOR_FINISH_ALREADY_EMITTED = 9;
    internal const uint SAS_PAIRING_LOCAL_EVENT_SAS_REJECTED = 10;
    internal const uint SAS_PAIRING_LOCAL_EVENT_SAS_CANCELLED = 11;
    internal const uint SAS_PAIRING_LOCAL_EVENT_DEADLINE = 12;

    // sas_pairing_action_flags_t
    internal const uint SAS_PAIRING_ACTION_FLAG_WRITE_PENDING = 0x1;
}
