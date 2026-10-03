/*
 * sas_pairing.h - native ABI of the sas-pairing core, ABI version 1.
 *
 * Experimental, pre-alpha, not production-security approved. Exposes the version query, the
 * runtime lifecycle, the authority lifecycle (P7.2), hosting contexts (P7.3), and Windows listener
 * ownership for a host (P7.4). No network driving, connection, run, event, result, or ceremony
 * operation is exposed yet: an attached listener is inert until a later increment adds driving.
 *
 * Contract: docs/p7-native-abi/abi-contract.md. Decisions: docs/p7-native-abi/decisions.md
 * (P7-D-001 to P7-D-007). Kept in sync with core/src/abi by the abi::tests::header consistency
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
/* 400-499: host, listener, and transport-boundary lifecycle. */
#define SAS_PAIRING_LISTENER_ALREADY_ATTACHED 400
#define SAS_PAIRING_LISTENER_SETUP_FAILED 401
/* A Rust panic was contained. The native ABI state of this process is permanently fatal:
 * every later create and normal operation returns this without entering the core; runtime
 * destroy, authority release, host destroy, and listener detach still work as cleanup; only a
 * new OS process recovers (a library reload is not recovery). */
#define SAS_PAIRING_FATAL 900

/* Opaque process-local handles. Never a pointer, secret, network identity, authority identity,
 * or protocol identifier. Runtime, authority, and host handles come from one counter, so a
 * value is issued once, to one kind, and never reused within one OS process (under the
 * library-lifetime rule above). 0 is never valid. */
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

#ifdef __cplusplus
}
#endif

#endif /* SAS_PAIRING_H */
