/*
 * sas_pairing.h - native ABI of the sas-pairing core, ABI version 1.
 *
 * Experimental, pre-alpha, not production-security approved. P7.1 foundation only: version
 * query and runtime lifecycle. No pairing operation is exposed yet.
 *
 * Contract: docs/p7-native-abi/abi-contract.md. Decisions: docs/p7-native-abi/decisions.md
 * (P7-D-001, P7-D-002). Kept in sync with core/src/abi by the abi::tests::header consistency
 * test.
 *
 * LIBRARY LIFETIME (P7-D-002): supported use loads exactly one image of this library per OS
 * process and keeps it loaded until the process exits once stateful use begins (no later than
 * sas_pairing_runtime_create). Do not unload/reload it or load an independent copy to reset
 * state: its state is module state, so that leaves the supported contract. The process-lifetime
 * guarantees below hold under this rule. Process restart is the only supported recovery from
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
 * 900-999 fatal/internal. */
typedef int32_t sas_pairing_status_t;

#define SAS_PAIRING_OK 0
#define SAS_PAIRING_INVALID_ARGUMENT 1
#define SAS_PAIRING_INVALID_HANDLE 2
#define SAS_PAIRING_ALREADY_INITIALIZED 3
#define SAS_PAIRING_HANDLES_EXHAUSTED 4
/* A Rust panic was contained. The native ABI state of this process is permanently fatal:
 * every later create returns this, destroy still works, and only a new OS process recovers
 * (a library reload is not recovery). */
#define SAS_PAIRING_FATAL 900

/* Opaque process-local runtime handle. Never a pointer, secret, network identity, or protocol
 * identifier. Never reused within one OS process (under the library-lifetime rule above). 0 is
 * never valid. */
typedef uint64_t sas_pairing_runtime_t;

#define SAS_PAIRING_RUNTIME_INVALID ((sas_pairing_runtime_t)0)

/* Returns SAS_PAIRING_ABI_VERSION. Returns 0 only if the query itself failed. */
uint32_t sas_pairing_abi_version(void);

/* Creates the one runtime of this process. out_runtime must point to one writable
 * sas_pairing_runtime_t; it is set to 0 on entry and receives the new handle only on
 * SAS_PAIRING_OK. Returns SAS_PAIRING_INVALID_ARGUMENT (null or misaligned out_runtime, not
 * written), SAS_PAIRING_ALREADY_INITIALIZED (a runtime is active; it is not replaced),
 * SAS_PAIRING_HANDLES_EXHAUSTED, or SAS_PAIRING_FATAL. */
sas_pairing_status_t sas_pairing_runtime_create(sas_pairing_runtime_t *out_runtime);

/* Destroys the runtime; its handle is invalid forever afterwards. Allowed in the fatal state.
 * Returns SAS_PAIRING_OK, SAS_PAIRING_INVALID_HANDLE (0, unknown, or destroyed), or
 * SAS_PAIRING_FATAL. */
sas_pairing_status_t sas_pairing_runtime_destroy(sas_pairing_runtime_t runtime);

#ifdef __cplusplus
}
#endif

#endif /* SAS_PAIRING_H */
