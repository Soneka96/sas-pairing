/*
 * sas_pairing.h - native ABI of the sas-pairing core, ABI version 1.
 *
 * Experimental, pre-alpha, not production-security approved. Exposes the version query, the
 * runtime lifecycle, the authority lifecycle (P7.2), hosting contexts (P7.3), Windows listener
 * ownership for a host (P7.4), and the bounded network drive with its connection, run, event, and
 * result representation (P7.5). No local ceremony action (Initiator START, authorization, key
 * exposure, SAS presentation or decision, own MAC or finish) is exposed yet.
 *
 * Contract: docs/p7-native-abi/abi-contract.md. Decisions: docs/p7-native-abi/decisions.md
 * (P7-D-001 to P7-D-010). Kept in sync with core/src/abi by the abi::tests::header consistency
 * test.
 *
 * LIBRARY LIFETIME (P7-D-002): supported use loads exactly one image of this library per OS
 * process and keeps it loaded until the process exits once stateful use begins (no later than
 * sas_pairing_runtime_create). Do not unload/reload it or load an independent copy to reset
 * state: its state is module state, so that leaves the supported contract. The process-lifetime
 * guarantees below, including authority process-session accounting, hold under this rule.
 * Process restart is the only supported recovery from
 * SAS_PAIRING_FATAL.
 *
 * Build: cargo build --manifest-path core/Cargo.toml --release --features native-abi
 *
 * Trust boundary: the library rejects null or misaligned required pointers and zero, unknown,
 * or destroyed handles, and never lets a Rust panic cross this boundary. The caller guarantees
 * that every non-null pointer it passes references the documented amount of caller-owned,
 * accessible memory for the whole call and that no other thread mutates it meanwhile; other
 * invalid addresses cannot be detected. No function returns memory the caller must free.
 */
#ifndef SAS_PAIRING_H
#define SAS_PAIRING_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Native ABI version. Not the protocol profile version (sas-pairing-vodozemac-profile-draft-01
 * version 1) and not the crate version. 0 is never a valid ABI version. */
#define SAS_PAIRING_ABI_VERSION 1u
#define SAS_PAIRING_ABI_VERSION_INVALID 0u

/* Status codes. Values are frozen and never reused; treat every non-zero value, including
 * unknown ones, as failure. Reserved ranges: 1-99 ABI/lifecycle/argument, 100-199
 * authority/resource/core, 200-299 ceremony/protocol, 300-399 buffer/data result,
 * 400-499 host/listener/transport-boundary lifecycle, 900-999 fatal/internal. */
typedef int32_t sas_pairing_status_t;

#define SAS_PAIRING_OK 0
#define SAS_PAIRING_INVALID_ARGUMENT 1
#define SAS_PAIRING_INVALID_HANDLE 2
#define SAS_PAIRING_ALREADY_INITIALIZED 3
#define SAS_PAIRING_HANDLES_EXHAUSTED 4
/* Core errors, translated one-to-one from the reviewed core (P7-D-004); meanings are the
 * core's. 100-199: authority, resource, and core. */
#define SAS_PAIRING_INVALID_SCOPE 100
#define SAS_PAIRING_ALREADY_REGISTERED 101
#define SAS_PAIRING_OWNERSHIP_UNAVAILABLE 102
#define SAS_PAIRING_UNSUPPORTED_PLATFORM 103
#define SAS_PAIRING_OWNERSHIP_UNCERTAIN 104
#define SAS_PAIRING_BUSY 105
#define SAS_PAIRING_EXHAUSTED 106
#define SAS_PAIRING_RESOURCE_LIMITED 107
/* 200-299: ceremony and protocol. */
#define SAS_PAIRING_MISSING_AUTHORIZATION 200
#define SAS_PAIRING_STALE_AUTHORIZATION 201
#define SAS_PAIRING_TERMINATED 202
/* The supplied Bootstrap configuration failed the core's own Bootstrap validation. */
#define SAS_PAIRING_INVALID_BOOTSTRAP 203
/* 300-399: buffers and data results. A caller buffer is too small: nothing was copied or
 * driven, and the required size was reported. */
#define SAS_PAIRING_BUFFER_TOO_SMALL 300
/* 400-499: host, listener, and transport-boundary lifecycle. */
#define SAS_PAIRING_LISTENER_ALREADY_ATTACHED 400
#define SAS_PAIRING_LISTENER_SETUP_FAILED 401
#define SAS_PAIRING_LISTENER_NOT_ATTACHED 402
#define SAS_PAIRING_OWNER_LOOP_CLOSED 403
#define SAS_PAIRING_NETWORK_POLL_FAILED 404
/* A Rust panic was contained. The native ABI state of this process is permanently fatal:
 * every later create and normal operation (including drive and recheck) returns this without
 * entering the core; runtime destroy, authority release, host destroy, listener detach, and
 * connection close still work as cleanup, and existing results stay readable and destroyable;
 * only a new OS process recovers (a library reload is not recovery). */
#define SAS_PAIRING_FATAL 900

/* Opaque process-local handles. Never a pointer, secret, network identity, authority identity,
 * or protocol identifier. Runtime, authority, host, connection, run, and result handles come from
 * one counter, so a value is issued once, to one kind, and never reused within one OS process
 * (under the library-lifetime rule above). 0 is never valid. */
typedef uint64_t sas_pairing_runtime_t;
typedef uint64_t sas_pairing_authority_t;
/* A host is one hosting context of one authority: it owns one core router. Several hosts may
 * belong to one authority and share its opportunity budget and START limiter; a host is never a
 * new security session. Not a socket, connection, peer, or run. */
typedef uint64_t sas_pairing_host_t;

#define SAS_PAIRING_RUNTIME_INVALID ((sas_pairing_runtime_t)0)
#define SAS_PAIRING_AUTHORITY_INVALID ((sas_pairing_authority_t)0)
#define SAS_PAIRING_HOST_INVALID ((sas_pairing_host_t)0)

/* Authority state reported by sas_pairing_authority_status. */
typedef uint32_t sas_pairing_authority_state_t;

#define SAS_PAIRING_AUTHORITY_STATE_INVALID ((sas_pairing_authority_state_t)0)
#define SAS_PAIRING_AUTHORITY_READY ((sas_pairing_authority_state_t)1)
#define SAS_PAIRING_AUTHORITY_BUSY ((sas_pairing_authority_state_t)2)
#define SAS_PAIRING_AUTHORITY_EXHAUSTED ((sas_pairing_authority_state_t)3)

/* A Windows SOCKET handed to the library by sas_pairing_host_attach_windows_listener
 * (P7-D-006). An OS resource, not a handle of the library's counter, and never a peer,
 * connection, authority, or protocol identity. SAS_PAIRING_SOCKET_INVALID equals Windows
 * INVALID_SOCKET. */
typedef uintptr_t sas_pairing_socket_t;

#define SAS_PAIRING_SOCKET_INVALID ((sas_pairing_socket_t)UINTPTR_MAX)

/* Borrowed caller bytes, input only: data may be NULL only when len is 0. The library copies
 * the bytes during the call and keeps no pointer. */
typedef struct sas_pairing_bytes_view {
    const uint8_t *data;
    size_t len;
} sas_pairing_bytes_view_t;

/* One Bootstrap configuration, input only: four byte strings, copied during the call and
 * validated by the core's own Bootstrap rules (SAS_PAIRING_INVALID_BOOTSTRAP otherwise). */
typedef struct sas_pairing_bootstrap_view {
    sas_pairing_bytes_view_t application_identity;
    sas_pairing_bytes_view_t key_algorithm;
    sas_pairing_bytes_view_t public_key;
    sas_pairing_bytes_view_t shared_context;
} sas_pairing_bootstrap_view_t;

/* Opaque handles of the network drive (P7-D-009, P7-D-010), from the same counter as every other
 * handle: never reused, 0 never valid.
 * A connection is one live accepted connection of a host's current owner loop: local, volatile,
 * not a socket, peer identity, authentication, or trust. A run is one exact in-memory ceremony
 * run: not its request ID, ceremony identity, peer, authorization, or trust. A result owns one
 * immutable local verified completion (PairingResult): not bilateral success, not proof that the
 * peer completed or received the final message, and not durable trust. */
typedef uint64_t sas_pairing_connection_t;
typedef uint64_t sas_pairing_run_t;
typedef uint64_t sas_pairing_result_t;

#define SAS_PAIRING_CONNECTION_INVALID ((sas_pairing_connection_t)0)
#define SAS_PAIRING_RUN_INVALID ((sas_pairing_run_t)0)
#define SAS_PAIRING_RESULT_INVALID ((sas_pairing_result_t)0)

/* The most events one drive or recheck reports (the listener plus one per live connection): the
 * event array must hold at least this many. */
#define SAS_PAIRING_MAX_DRIVE_EVENTS ((size_t)17)
/* The frozen protocol request-ID bound (1-64 bytes). */
#define SAS_PAIRING_MAX_REQUEST_ID_LEN ((size_t)64)
/* Run references one connection keeps; a new run beyond it is reported without a handle, with
 * SAS_PAIRING_EVENT_FLAG_RUN_UNTRACKED. */
#define SAS_PAIRING_MAX_RUNS_PER_CONNECTION ((size_t)32)

/* Event kinds. */
typedef uint32_t sas_pairing_event_kind_t;

#define SAS_PAIRING_EVENT_INVALID ((sas_pairing_event_kind_t)0)
#define SAS_PAIRING_EVENT_CONNECTION_ACCEPTED ((sas_pairing_event_kind_t)1)
#define SAS_PAIRING_EVENT_ACCEPT_REFUSED ((sas_pairing_event_kind_t)2)
#define SAS_PAIRING_EVENT_LISTENER_DISABLED ((sas_pairing_event_kind_t)3)
#define SAS_PAIRING_EVENT_CONNECTION_STEP ((sas_pairing_event_kind_t)4)
#define SAS_PAIRING_EVENT_CONNECTION_CLOSED ((sas_pairing_event_kind_t)5)

/* What one CONNECTION_STEP's adapter call did. */
typedef uint32_t sas_pairing_step_kind_t;

#define SAS_PAIRING_STEP_NONE ((sas_pairing_step_kind_t)0)
#define SAS_PAIRING_STEP_INBOUND ((sas_pairing_step_kind_t)1)
#define SAS_PAIRING_STEP_REFUSED ((sas_pairing_step_kind_t)2)
#define SAS_PAIRING_STEP_DEADLINE ((sas_pairing_step_kind_t)3)
#define SAS_PAIRING_STEP_WRITTEN ((sas_pairing_step_kind_t)4)
#define SAS_PAIRING_STEP_CONFIRMED ((sas_pairing_step_kind_t)5)
#define SAS_PAIRING_STEP_UNCONFIRMED ((sas_pairing_step_kind_t)6)
#define SAS_PAIRING_STEP_DISCARDED ((sas_pairing_step_kind_t)7)

/* What one dispatched inbound frame did (STEP_INBOUND). */
typedef uint32_t sas_pairing_protocol_event_t;

#define SAS_PAIRING_PROTOCOL_EVENT_NONE ((sas_pairing_protocol_event_t)0)
#define SAS_PAIRING_PROTOCOL_EVENT_START_ACCEPTED ((sas_pairing_protocol_event_t)1)
#define SAS_PAIRING_PROTOCOL_EVENT_START_DUPLICATE ((sas_pairing_protocol_event_t)2)
#define SAS_PAIRING_PROTOCOL_EVENT_ACCEPT ((sas_pairing_protocol_event_t)3)
#define SAS_PAIRING_PROTOCOL_EVENT_INITIATOR_KEY ((sas_pairing_protocol_event_t)4)
#define SAS_PAIRING_PROTOCOL_EVENT_RESPONDER_KEY ((sas_pairing_protocol_event_t)5)
#define SAS_PAIRING_PROTOCOL_EVENT_BOOTSTRAP_MAC_AUTHENTICATED ((sas_pairing_protocol_event_t)6)
#define SAS_PAIRING_PROTOCOL_EVENT_BOOTSTRAP_MAC_DUPLICATE ((sas_pairing_protocol_event_t)7)
#define SAS_PAIRING_PROTOCOL_EVENT_INITIATOR_FINISH ((sas_pairing_protocol_event_t)8)
#define SAS_PAIRING_PROTOCOL_EVENT_INITIATOR_FINISH_DUPLICATE ((sas_pairing_protocol_event_t)9)
#define SAS_PAIRING_PROTOCOL_EVENT_RESPONDER_FINISH_ACK ((sas_pairing_protocol_event_t)10)
#define SAS_PAIRING_PROTOCOL_EVENT_INITIATOR_FINISH_ACK ((sas_pairing_protocol_event_t)11)
#define SAS_PAIRING_PROTOCOL_EVENT_PEER_CANCEL ((sas_pairing_protocol_event_t)12)

/* Operational reason of a refusal or ending. Never evidence about the peer, authentication, an
 * SAS, or compromise: an I/O error is not an attack, a peer close is not a rejection. */
typedef uint32_t sas_pairing_event_reason_t;

#define SAS_PAIRING_EVENT_REASON_NONE ((sas_pairing_event_reason_t)0)
#define SAS_PAIRING_EVENT_REASON_RESOURCE_LIMITED ((sas_pairing_event_reason_t)1)
#define SAS_PAIRING_EVENT_REASON_PEER_CLOSED ((sas_pairing_event_reason_t)2)
#define SAS_PAIRING_EVENT_REASON_SOCKET_IO ((sas_pairing_event_reason_t)3)
#define SAS_PAIRING_EVENT_REASON_ABANDONED_PARTIAL_FRAME ((sas_pairing_event_reason_t)4)
#define SAS_PAIRING_EVENT_REASON_READINESS_FAILURE ((sas_pairing_event_reason_t)5)
#define SAS_PAIRING_EVENT_REASON_LISTENER_IO ((sas_pairing_event_reason_t)6)
#define SAS_PAIRING_EVENT_REASON_LISTENER_READINESS ((sas_pairing_event_reason_t)7)
#define SAS_PAIRING_EVENT_REASON_ROUTE_REFUSED ((sas_pairing_event_reason_t)8)
#define SAS_PAIRING_EVENT_REASON_OWNERSHIP_UNCERTAIN ((sas_pairing_event_reason_t)9)
#define SAS_PAIRING_EVENT_REASON_OTHER_HOST_FAILURE ((sas_pairing_event_reason_t)10)
#define SAS_PAIRING_EVENT_REASON_INVALID_FRAME ((sas_pairing_event_reason_t)11)
#define SAS_PAIRING_EVENT_REASON_TRANSPORT_DEADLINE ((sas_pairing_event_reason_t)12)
#define SAS_PAIRING_EVENT_REASON_CLOCK_UNAVAILABLE ((sas_pairing_event_reason_t)13)
#define SAS_PAIRING_EVENT_REASON_SESSION_PROTOCOL_FAILURE ((sas_pairing_event_reason_t)14)
#define SAS_PAIRING_EVENT_REASON_ALREADY_CLOSED ((sas_pairing_event_reason_t)15)

/* How a run ended by its own deadline processing (STEP_DEADLINE). A timeout, the pending
 * pre-exposure resource expiry, and an unusable clock are different outcomes. */
typedef uint32_t sas_pairing_deadline_kind_t;

#define SAS_PAIRING_DEADLINE_NONE ((sas_pairing_deadline_kind_t)0)
#define SAS_PAIRING_DEADLINE_ABSOLUTE_TIMEOUT ((sas_pairing_deadline_kind_t)1)
#define SAS_PAIRING_DEADLINE_INACTIVITY_TIMEOUT ((sas_pairing_deadline_kind_t)2)
#define SAS_PAIRING_DEADLINE_PENDING_EXPIRED ((sas_pairing_deadline_kind_t)3)
#define SAS_PAIRING_DEADLINE_CLOCK_UNAVAILABLE ((sas_pairing_deadline_kind_t)4)

/* What became of a deadline's best-effort authenticated CANCEL locally; never whether the peer
 * received it. */
typedef uint32_t sas_pairing_cancel_state_t;

#define SAS_PAIRING_CANCEL_STATE_NONE ((sas_pairing_cancel_state_t)0)
#define SAS_PAIRING_CANCEL_STATE_NOT_BUILT ((sas_pairing_cancel_state_t)1)
#define SAS_PAIRING_CANCEL_STATE_PENDING ((sas_pairing_cancel_state_t)2)
#define SAS_PAIRING_CANCEL_STATE_DROPPED ((sas_pairing_cancel_state_t)3)

/* The reason a verified peer CANCEL carried (PROTOCOL_EVENT_PEER_CANCEL). */
typedef uint32_t sas_pairing_cancel_reason_t;

#define SAS_PAIRING_CANCEL_REASON_NONE ((sas_pairing_cancel_reason_t)0)
#define SAS_PAIRING_CANCEL_REASON_USER_REJECTION ((sas_pairing_cancel_reason_t)1)
#define SAS_PAIRING_CANCEL_REASON_USER_CANCELLATION ((sas_pairing_cancel_reason_t)2)
#define SAS_PAIRING_CANCEL_REASON_TIMEOUT ((sas_pairing_cancel_reason_t)3)
#define SAS_PAIRING_CANCEL_REASON_LOCAL_POLICY_FAILURE ((sas_pairing_cancel_reason_t)4)

/* Event flag bits. WRITE_PENDING: the connection's adapter still holds one outbound frame (it
 * writes it itself on a later drive). RUN_UNTRACKED: the event names a live run that got no run
 * handle because its connection already holds SAS_PAIRING_MAX_RUNS_PER_CONNECTION. */
typedef uint32_t sas_pairing_event_flags_t;

#define SAS_PAIRING_EVENT_FLAG_WRITE_PENDING ((sas_pairing_event_flags_t)0x1)
#define SAS_PAIRING_EVENT_FLAG_RUN_UNTRACKED ((sas_pairing_event_flags_t)0x2)

/* One drive event: 128 bytes, aligned to 8, no padding. Fields that do not apply are 0.
 * connection: the connection the event names (for CONNECTION_CLOSED, the handle that just became
 * invalid). run: the live exact run, 0 once terminal. result: a new result handle the caller now
 * owns. request_id: routing and correlation bytes only (never the run, ceremony identity, peer
 * identity, or authentication), request_id_len of them. reserved is always 0. */
typedef struct sas_pairing_event {
    sas_pairing_event_kind_t kind;
    sas_pairing_step_kind_t step_kind;
    sas_pairing_protocol_event_t protocol_event;
    sas_pairing_event_reason_t reason;
    sas_pairing_deadline_kind_t deadline_kind;
    sas_pairing_cancel_state_t cancel_state;
    sas_pairing_cancel_reason_t cancel_reason;
    sas_pairing_event_flags_t flags;
    sas_pairing_connection_t connection;
    sas_pairing_run_t run;
    sas_pairing_result_t result;
    uint32_t request_id_len;
    uint32_t reserved;
    uint8_t request_id[SAS_PAIRING_MAX_REQUEST_ID_LEN];
} sas_pairing_event_t;

/* A role, as reported in a result: the PEER's role in the ceremony. */
typedef uint32_t sas_pairing_role_t;

#define SAS_PAIRING_ROLE_INVALID ((sas_pairing_role_t)0)
#define SAS_PAIRING_ROLE_INITIATOR ((sas_pairing_role_t)1)
#define SAS_PAIRING_ROLE_RESPONDER ((sas_pairing_role_t)2)

/* The variable-length result fields sas_pairing_result_copy copies. */
typedef uint32_t sas_pairing_result_field_t;

#define SAS_PAIRING_RESULT_FIELD_REQUEST_ID ((sas_pairing_result_field_t)1)
#define SAS_PAIRING_RESULT_FIELD_AUTHENTICATED_PEER_BOOTSTRAP ((sas_pairing_result_field_t)2)
#define SAS_PAIRING_RESULT_FIELD_AUTHENTICATED_SHARED_CONTEXT ((sas_pairing_result_field_t)3)
#define SAS_PAIRING_RESULT_FIELD_PROFILE_IDENTIFIER ((sas_pairing_result_field_t)4)

/* The fixed fields of one result: 56 bytes, aligned to 4, no padding, no pointer.
 * ceremony_identity: exactly the core's 32-byte transcript-derived ceremony identity (not the
 * request ID, a connection or run handle, or peer identity). The *_len fields are the exact byte
 * lengths of the variable fields. */
typedef struct sas_pairing_result_info {
    uint8_t ceremony_identity[32];
    sas_pairing_role_t peer_role;
    uint32_t profile_version;
    uint32_t request_id_len;
    uint32_t peer_bootstrap_len;
    uint32_t shared_context_len;
    uint32_t profile_identifier_len;
} sas_pairing_result_info_t;

/* Returns SAS_PAIRING_ABI_VERSION. Returns 0 only if the query itself failed. */
uint32_t sas_pairing_abi_version(void);

/* Creates the one runtime of this process. out_runtime must point to one writable
 * sas_pairing_runtime_t; it is set to 0 on entry and receives the new handle only on
 * SAS_PAIRING_OK. Returns SAS_PAIRING_INVALID_ARGUMENT (null or misaligned out_runtime, not
 * written), SAS_PAIRING_ALREADY_INITIALIZED (a runtime is active; it is not replaced),
 * SAS_PAIRING_HANDLES_EXHAUSTED, or SAS_PAIRING_FATAL. */
sas_pairing_status_t sas_pairing_runtime_create(sas_pairing_runtime_t *out_runtime);

/* Destroys the runtime; its handle and every authority and host handle it owns are invalid
 * forever afterwards; its hosts' listeners are closed first, then its hosts destroyed, then its
 * authorities released. Allowed in the fatal state. Returns
 * SAS_PAIRING_OK, SAS_PAIRING_INVALID_HANDLE (0, unknown, or destroyed), or SAS_PAIRING_FATAL. */
sas_pairing_status_t sas_pairing_runtime_destroy(sas_pairing_runtime_t runtime);

/* Registers the authority named by scope (scope_len bytes, not a C string; copied, not kept)
 * and takes its OS ownership. out_authority is set to 0 on entry and receives a new handle only
 * on SAS_PAIRING_OK. scope may be NULL only when scope_len is 0 (giving
 * SAS_PAIRING_INVALID_SCOPE). Returns SAS_PAIRING_INVALID_ARGUMENT (bad out_authority or scope
 * pointer, nothing written), SAS_PAIRING_FATAL, SAS_PAIRING_INVALID_HANDLE (runtime),
 * SAS_PAIRING_HANDLES_EXHAUSTED, or a core error such as SAS_PAIRING_INVALID_SCOPE,
 * SAS_PAIRING_ALREADY_REGISTERED, SAS_PAIRING_OWNERSHIP_UNAVAILABLE,
 * SAS_PAIRING_OWNERSHIP_UNCERTAIN, or SAS_PAIRING_UNSUPPORTED_PLATFORM. The authority's
 * opportunity budget and START limiter belong to this process, not to the handle: registering
 * again after a release continues them, under a new handle. */
sas_pairing_status_t sas_pairing_authority_register(sas_pairing_runtime_t runtime, const uint8_t *scope, size_t scope_len, sas_pairing_authority_t *out_authority);

/* Releases the authority's registration (its OS ownership), after first destroying every host
 * of the authority (closing any attached listener before its host's router). The handle and all of its host handles are consumed: invalid forever once
 * this returns, even when a core error such as SAS_PAIRING_OWNERSHIP_UNCERTAIN is returned.
 * Process-session accounting is not reset.
 * Allowed in the fatal state. Returns SAS_PAIRING_OK, SAS_PAIRING_INVALID_HANDLE, a core error,
 * or SAS_PAIRING_FATAL. */
sas_pairing_status_t sas_pairing_authority_release(sas_pairing_runtime_t runtime, sas_pairing_authority_t authority);

/* Reports the authority's state: READY with the remaining opportunities, or BUSY or EXHAUSTED
 * with 0. Both outputs must be distinct writable slots; they are set to INVALID and 0 on entry
 * and filled only on SAS_PAIRING_OK. Returns SAS_PAIRING_INVALID_ARGUMENT (nothing written),
 * SAS_PAIRING_FATAL, SAS_PAIRING_INVALID_HANDLE, or a core error. */
sas_pairing_status_t sas_pairing_authority_status(sas_pairing_runtime_t runtime, sas_pairing_authority_t authority, sas_pairing_authority_state_t *out_state, uint32_t *out_remaining);

/* Creates a host (one core router) for the authority. out_host is set to 0 on entry and
 * receives a new handle only on SAS_PAIRING_OK. Does no networking (no listener, socket, or
 * connection; those arrive in a later P7 increment) and changes no accounting. Returns
 * SAS_PAIRING_INVALID_ARGUMENT (null or misaligned out_host, not written), SAS_PAIRING_FATAL,
 * SAS_PAIRING_INVALID_HANDLE (runtime or authority), SAS_PAIRING_HANDLES_EXHAUSTED, or
 * SAS_PAIRING_OWNERSHIP_UNCERTAIN. */
sas_pairing_status_t sas_pairing_host_create(sas_pairing_runtime_t runtime, sas_pairing_authority_t authority, sas_pairing_host_t *out_host);

/* Destroys the host: an attached listener and its owner loop are closed first, then the router;
 * the handle is invalid forever afterwards, whatever is returned. The authority is not released
 * and its other hosts stay valid. Releasing the authority or destroying the runtime also
 * destroys its hosts. Allowed in the fatal state. Returns SAS_PAIRING_OK,
 * SAS_PAIRING_INVALID_HANDLE, SAS_PAIRING_OWNERSHIP_UNCERTAIN (a connection's cleanup could not
 * be established), or SAS_PAIRING_FATAL. */
sas_pairing_status_t sas_pairing_host_destroy(sas_pairing_runtime_t runtime, sas_pairing_host_t host);

/* Attaches an ALREADY-BOUND Windows listening socket to the host (P7-D-006, P7-D-007). The
 * library never binds, chooses an address, interface, or port, or configures discovery or a
 * firewall: the caller does all of that before this call. local (required) is the host's
 * Responder Bootstrap; expected is the exact expected peer Bootstrap, or NULL for none. Both are
 * copied; no pointer is kept. Nothing is driven: no accept, connection, or event happens here.
 *
 * SOCKET OWNERSHIP: *inout_listener must hold the caller's socket on entry. If the call fails
 * before adoption, *inout_listener is unchanged and the socket is still the caller's (close it
 * yourself): SAS_PAIRING_INVALID_ARGUMENT, SAS_PAIRING_UNSUPPORTED_PLATFORM (not Windows),
 * SAS_PAIRING_INVALID_BOOTSTRAP, SAS_PAIRING_FATAL, SAS_PAIRING_INVALID_HANDLE, or
 * SAS_PAIRING_LISTENER_ALREADY_ATTACHED. Once the library adopts the socket it writes
 * SAS_PAIRING_SOCKET_INVALID to *inout_listener and owns and closes the socket, also when it then
 * returns SAS_PAIRING_LISTENER_SETUP_FAILED or SAS_PAIRING_FATAL. Whenever *inout_listener reads
 * SAS_PAIRING_SOCKET_INVALID after the call, never close, use, or hand on that socket again.
 *
 * Caller precondition (not checkable): a socket value other than SAS_PAIRING_SOCKET_INVALID is
 * one valid, already-bound Windows listening SOCKET that the caller owns exclusively and that
 * nobody closes or uses during the call. One listener per host: replace it with
 * sas_pairing_host_detach_listener, then attach again. Changes no accounting. */
sas_pairing_status_t sas_pairing_host_attach_windows_listener(sas_pairing_runtime_t runtime, sas_pairing_host_t host, sas_pairing_socket_t *inout_listener, const sas_pairing_bootstrap_view_t *local, const sas_pairing_bootstrap_view_t *expected);

/* Detaches the host's listener: its owner loop closes the listener and every connection it owns
 * while the host's router stays alive. The host, its router, its authority, and all accounting
 * stay. Idempotent: SAS_PAIRING_OK also when no listener is attached. Allowed in the fatal state
 * (it never clears it). Returns SAS_PAIRING_OK, SAS_PAIRING_INVALID_HANDLE,
 * SAS_PAIRING_OWNERSHIP_UNCERTAIN, or SAS_PAIRING_FATAL. */
sas_pairing_status_t sas_pairing_host_detach_listener(sas_pairing_runtime_t runtime, sas_pairing_host_t host);

/* Drives the host's owner loop once (P7-D-008): one bounded synchronous step (deadline sweeps,
 * at most one readiness wait of at most 250 ms, at most one socket operation per connection, at
 * most one accept), reported as at most SAS_PAIRING_MAX_DRIVE_EVENTS records in events. No
 * thread is created, and no outbound byte is returned: the library writes protocol frames itself.
 *
 * out_count and out_failure must be distinct writable slots; events may be NULL only with
 * event_capacity 0. Bad pointers give SAS_PAIRING_INVALID_ARGUMENT with nothing written.
 * Otherwise *out_count = 0 and *out_failure = SAS_PAIRING_OK on entry. An event_capacity below
 * SAS_PAIRING_MAX_DRIVE_EVENTS gives SAS_PAIRING_BUFFER_TOO_SMALL with *out_count set to the
 * required capacity, and drives nothing (pass NULL, 0 to query it). SAS_PAIRING_FATAL,
 * SAS_PAIRING_INVALID_HANDLE, SAS_PAIRING_LISTENER_NOT_ATTACHED, SAS_PAIRING_HANDLES_EXHAUSTED,
 * and SAS_PAIRING_UNSUPPORTED_PLATFORM also drive nothing.
 *
 * SAS_PAIRING_OK: *out_count events were written; consume every one of them, including when
 * *out_failure is not SAS_PAIRING_OK. *out_failure reports the owner loop's own failure during
 * this call: SAS_PAIRING_NETWORK_POLL_FAILED or SAS_PAIRING_OWNERSHIP_UNCERTAIN (it failed closed:
 * the listener and every connection are gone, every connection and run handle of the host is
 * invalid), SAS_PAIRING_OWNER_LOOP_CLOSED (it had already failed closed; nothing was driven), or
 * SAS_PAIRING_FATAL. Detach the listener or destroy the host after a failure. Every nonzero
 * result handle in an event is a new result the caller owns: destroy it with
 * sas_pairing_result_destroy. */
sas_pairing_status_t sas_pairing_host_drive(sas_pairing_runtime_t runtime, sas_pairing_host_t host, sas_pairing_event_t *events, size_t event_capacity, size_t *out_count, sas_pairing_status_t *out_failure);

/* For trusted outer code after an OS resume notification: one deadline sweep of the host's owner
 * loop and nothing else (no readiness wait, socket read or write, or accept), with exactly the
 * contract of sas_pairing_host_drive. */
sas_pairing_status_t sas_pairing_host_recheck_after_resume(sas_pairing_runtime_t runtime, sas_pairing_host_t host, sas_pairing_event_t *events, size_t event_capacity, size_t *out_count, sas_pairing_status_t *out_failure);

/* Closes one connection of the host (cleanup, P7-D-009): the connection handle and every run
 * handle of that connection are invalidated first, then the library closes the connection (no
 * CANCEL is sent, nothing is retried). Allowed in the fatal state. Returns SAS_PAIRING_OK,
 * SAS_PAIRING_INVALID_HANDLE, SAS_PAIRING_LISTENER_NOT_ATTACHED, SAS_PAIRING_OWNERSHIP_UNCERTAIN
 * (the cleanup could not be established, so the owner loop failed closed and every connection
 * handle of the host is invalid), SAS_PAIRING_UNSUPPORTED_PLATFORM, or SAS_PAIRING_FATAL. */
sas_pairing_status_t sas_pairing_connection_close(sas_pairing_runtime_t runtime, sas_pairing_host_t host, sas_pairing_connection_t connection);

/* Reads the fixed fields of a result (P7-D-010). *out_info is zeroed on entry and filled only on
 * SAS_PAIRING_OK. A result is local verified completion only: it does not mean the peer also
 * completed. Results survive connection close, listener detach, host destroy, and authority
 * release; result destroy and runtime destroy end them. Allowed in the fatal state (no core work).
 * Returns SAS_PAIRING_OK, SAS_PAIRING_INVALID_ARGUMENT (null or misaligned out_info, nothing
 * written), SAS_PAIRING_INVALID_HANDLE, or SAS_PAIRING_FATAL. */
sas_pairing_status_t sas_pairing_result_info(sas_pairing_runtime_t runtime, sas_pairing_result_t result, sas_pairing_result_info_t *out_info);

/* Copies one variable-length result field: exactly *out_required bytes, never truncated and never
 * NUL-terminated. out_required is required; buffer may be NULL only when capacity is 0. Bad
 * pointers or an unknown field give SAS_PAIRING_INVALID_ARGUMENT with nothing written. Otherwise
 * *out_required is set to 0 on entry and to the field's length once the result is found;
 * SAS_PAIRING_BUFFER_TOO_SMALL copies nothing. Allowed in the fatal state (no core work). Returns
 * SAS_PAIRING_OK, SAS_PAIRING_INVALID_ARGUMENT, SAS_PAIRING_INVALID_HANDLE,
 * SAS_PAIRING_BUFFER_TOO_SMALL, or SAS_PAIRING_FATAL. */
sas_pairing_status_t sas_pairing_result_copy(sas_pairing_runtime_t runtime, sas_pairing_result_t result, sas_pairing_result_field_t field, uint8_t *buffer, size_t capacity, size_t *out_required);

/* Destroys a result; its handle is invalid forever afterwards. Allowed in the fatal state (no core
 * work). Returns SAS_PAIRING_OK, SAS_PAIRING_INVALID_HANDLE, or SAS_PAIRING_FATAL. */
sas_pairing_status_t sas_pairing_result_destroy(sas_pairing_runtime_t runtime, sas_pairing_result_t result);

#ifdef __cplusplus
}
#endif

#endif /* SAS_PAIRING_H */
