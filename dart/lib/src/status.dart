/// The frozen native ABI v1 status values as a public Dart enum (P8-D-002 I).
library;

import 'native/generated/sas_pairing_bindings.g.dart' as raw;

/// One known `sas_pairing_status_t` value of the frozen native ABI v1 (all 48 of them).
///
/// A status is the outcome of one native operation. It is never a trust verdict, a judgement
/// that a peer is malicious, authentication policy, or consumer authorization. Every value
/// other than [ok] is a failure, and so is every code this enum does not know:
/// [fromCode] returns `null` for those, and the wrapper keeps their integer value.
enum SasPairingStatus {
  ok(raw.SAS_PAIRING_OK),
  invalidArgument(raw.SAS_PAIRING_INVALID_ARGUMENT),
  invalidHandle(raw.SAS_PAIRING_INVALID_HANDLE),
  alreadyInitialized(raw.SAS_PAIRING_ALREADY_INITIALIZED),
  handlesExhausted(raw.SAS_PAIRING_HANDLES_EXHAUSTED),
  invalidScope(raw.SAS_PAIRING_INVALID_SCOPE),
  alreadyRegistered(raw.SAS_PAIRING_ALREADY_REGISTERED),
  ownershipUnavailable(raw.SAS_PAIRING_OWNERSHIP_UNAVAILABLE),
  unsupportedPlatform(raw.SAS_PAIRING_UNSUPPORTED_PLATFORM),
  ownershipUncertain(raw.SAS_PAIRING_OWNERSHIP_UNCERTAIN),

  /// The native failure status `SAS_PAIRING_BUSY` (105). Not the successful authority state
  /// `SasPairingAuthorityState.busy`.
  busy(raw.SAS_PAIRING_BUSY),
  exhausted(raw.SAS_PAIRING_EXHAUSTED),
  resourceLimited(raw.SAS_PAIRING_RESOURCE_LIMITED),
  missingAuthorization(raw.SAS_PAIRING_MISSING_AUTHORIZATION),
  staleAuthorization(raw.SAS_PAIRING_STALE_AUTHORIZATION),
  terminated(raw.SAS_PAIRING_TERMINATED),
  invalidBootstrap(raw.SAS_PAIRING_INVALID_BOOTSTRAP),
  runEnded(raw.SAS_PAIRING_RUN_ENDED),
  writePending(raw.SAS_PAIRING_WRITE_PENDING),
  ceremonyInvalidState(raw.SAS_PAIRING_CEREMONY_INVALID_STATE),
  noLiveSas(raw.SAS_PAIRING_NO_LIVE_SAS),
  ceremonyIdentityMismatch(raw.SAS_PAIRING_CEREMONY_IDENTITY_MISMATCH),
  notLocallyApproved(raw.SAS_PAIRING_NOT_LOCALLY_APPROVED),
  unexpectedSenderRole(raw.SAS_PAIRING_UNEXPECTED_SENDER_ROLE),
  invalidRequestId(raw.SAS_PAIRING_INVALID_REQUEST_ID),
  requestIdGenerationFailed(raw.SAS_PAIRING_REQUEST_ID_GENERATION_FAILED),
  requestIdMismatch(raw.SAS_PAIRING_REQUEST_ID_MISMATCH),
  sharedContextMismatch(raw.SAS_PAIRING_SHARED_CONTEXT_MISMATCH),
  expectedPeerMismatch(raw.SAS_PAIRING_EXPECTED_PEER_MISMATCH),
  approvalsNotAuthenticated(raw.SAS_PAIRING_APPROVALS_NOT_AUTHENTICATED),
  notInitiator(raw.SAS_PAIRING_NOT_INITIATOR),
  transcriptMismatch(raw.SAS_PAIRING_TRANSCRIPT_MISMATCH),
  completed(raw.SAS_PAIRING_COMPLETED),
  noPendingFinalAck(raw.SAS_PAIRING_NO_PENDING_FINAL_ACK),
  finalAckMismatch(raw.SAS_PAIRING_FINAL_ACK_MISMATCH),
  ceremonyTimedOut(raw.SAS_PAIRING_CEREMONY_TIMED_OUT),
  ceremonyClockUnavailable(raw.SAS_PAIRING_CEREMONY_CLOCK_UNAVAILABLE),
  pendingExpired(raw.SAS_PAIRING_PENDING_EXPIRED),
  ceremonyCodecError(raw.SAS_PAIRING_CEREMONY_CODEC_ERROR),
  ceremonyCryptoError(raw.SAS_PAIRING_CEREMONY_CRYPTO_ERROR),
  bufferTooSmall(raw.SAS_PAIRING_BUFFER_TOO_SMALL),
  listenerAlreadyAttached(raw.SAS_PAIRING_LISTENER_ALREADY_ATTACHED),
  listenerSetupFailed(raw.SAS_PAIRING_LISTENER_SETUP_FAILED),
  listenerNotAttached(raw.SAS_PAIRING_LISTENER_NOT_ATTACHED),
  ownerLoopClosed(raw.SAS_PAIRING_OWNER_LOOP_CLOSED),
  networkPollFailed(raw.SAS_PAIRING_NETWORK_POLL_FAILED),
  connectionEnded(raw.SAS_PAIRING_CONNECTION_ENDED),

  /// `SAS_PAIRING_FATAL` (900): the native state of this process is permanently fatal. The
  /// only recovery is an OS process restart.
  fatal(raw.SAS_PAIRING_FATAL);

  const SasPairingStatus(this.code);

  /// The frozen `sas_pairing_status_t` value.
  final int code;

  /// The known status with [code], or `null` for a code ABI v1 does not define (still a
  /// failure).
  static SasPairingStatus? fromCode(int code) {
    for (final status in values) {
      if (status.code == code) return status;
    }
    return null;
  }
}
