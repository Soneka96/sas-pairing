using SasPairing.Interop;

namespace SasPairing;

/// <summary>
/// One native PairingResult: the LOCAL verified completion of one ceremony by THIS endpoint (P9-D-005), delivered
/// by exactly one drive event (<see cref="SasPairingEvent.Result"/>).
/// </summary>
/// <remarks>
/// <para>
/// <b>Local completion only, never bilateral success.</b> A result does not mean that the peer completed, received
/// the final message, holds a result of its own, or stored anything, and it is not a committed pair, an established
/// session, or trust. Either endpoint may be the only one holding a result. The package trusts, persists, and
/// enrolls nothing: the application decides what, if anything, to do with <see cref="Read"/>'s data.
/// </para>
/// <para>
/// <b>Ownership.</b> A result belongs to its <see cref="SasPairingRuntime"/>, not to the connection, run, host, or
/// authority that produced it: it stays open across connection disposal, a connection close event, listener
/// detach, an owner-loop failure, host disposal, authority disposal, and <see cref="SasPairingStatus.Fatal"/>.
/// Only <see cref="Dispose"/> and <see cref="SasPairingRuntime.Dispose"/> end it. Dispose it deterministically when
/// it is no longer wanted; there is no finalizer.
/// </para>
/// <para>
/// <b>Reading.</b> <see cref="Read"/> returns an immutable, detached <see cref="SasPairingResultData"/> snapshot
/// and reads the native result again on every call. Reading is data access, not pairing work: it stays allowed
/// after <see cref="SasPairingStatus.Fatal"/> (which still requires an OS process restart for any new pairing
/// work), but is refused once the package observed a native contract violation. Disposing stays allowed in both
/// cases.
/// </para>
/// <para>
/// A result is a resource wrapper with reference identity: two results are never equal by their data.
/// </para>
/// </remarks>
public sealed class SasPairingResult : IDisposable
{
    /// <summary>
    /// The source-proven request-ID bound (P9-D-005): the frozen protocol request ID is 1 to 64 bytes
    /// (<c>SAS_PAIRING_MAX_REQUEST_ID_LEN</c>).
    /// </summary>
    internal const uint MaxRequestIdLength = (uint)AbiV1Constants.SAS_PAIRING_MAX_REQUEST_ID_LEN;

    /// <summary>
    /// The source-proven complete canonical Bootstrap frame bound (P9-D-005): <c>MAX_BOOTSTRAP_FRAME</c> of the
    /// frozen core profile (16,384 bytes). Not an ABI v1 header constant.
    /// </summary>
    internal const uint MaxPeerBootstrapLength = 16_384;

    /// <summary>
    /// The source-proven shared-context bound (P9-D-005): 0 to 8,192 bytes in the frozen core profile. Not an ABI
    /// v1 header constant.
    /// </summary>
    internal const uint MaxSharedContextLength = 8_192;

    /// <summary>
    /// The source-proven profile-identifier bound (P9-D-005): every result of the frozen core carries the one
    /// profile identifier constant of its protocol (38 bytes). Not an ABI v1 header constant.
    /// </summary>
    internal const uint MaxProfileIdentifierLength = 38;

    private const string ReadOperation = "SasPairingResult.Read";
    private const string DisposeOperation = "SasPairingResult.Dispose";

    private readonly SasPairingRuntime _runtime;

    internal SasPairingResult(SasPairingRuntime runtime, NativeResultRef reference)
    {
        _runtime = runtime;
        Ref = reference;
    }

    /// <summary>Whether this result was disposed, by <see cref="Dispose"/> or by disposing its runtime.</summary>
    public bool IsDisposed
    {
        get
        {
            lock (_runtime.Gate)
            {
                return !Ref.IsValid;
            }
        }
    }

    /// <summary>The exact native result reference. Internal only; its handle is never exposed or printed.</summary>
    internal NativeResultRef Ref { get; }

    private NativeProcessContext Context => _runtime.Context;

    /// <summary>
    /// Reads one coherent snapshot of the result, synchronously: its fixed fields once, then each byte field
    /// exactly once at the length the same immutable native result reported. Nothing partial is ever returned, and
    /// a failed read leaves the result open. Each call makes a fresh complete native read.
    /// </summary>
    /// <returns>The immutable, detached snapshot.</returns>
    /// <exception cref="ObjectDisposedException">The result or its runtime was disposed (no native call).</exception>
    /// <exception cref="SasPairingContractException">
    /// A native contract violation was observed in this process, earlier (no native call) or by this read.
    /// </exception>
    /// <exception cref="SasPairingNativeException">
    /// The native read failed, for example <see cref="SasPairingStatus.InvalidHandle"/>, or
    /// <see cref="SasPairingStatus.Fatal"/> (which is recorded; later reads are still allowed).
    /// </exception>
    public SasPairingResultData Read()
    {
        lock (_runtime.Gate)
        {
            ObjectDisposedException.ThrowIf(!Ref.IsValid, this);

            // Data access, not the normal-operation admission: native FATAL does not block reading an existing result.
            Context.AdmitData(ReadOperation);
            ulong runtime = _runtime.Handle;
            ulong result = Ref.Handle;
            NativeResultInfoOutcome answer = Context.Results.ResultInfo(runtime, result);
            Context.ThrowIfFailed(ReadOperation, answer.Status);
            NativeResultInfoRecord info = answer.Info ?? throw Context.ViolateContract(ReadOperation, "returned no result info");
            if (info.CeremonyIdentity.Length != SasPairingCeremonyIdentity.Length)
            {
                throw Context.ViolateContract(ReadOperation, $"returned a ceremony identity of {info.CeremonyIdentity.Length} bytes");
            }

            SasPairingPeerRole peerRole = info.PeerRole switch
            {
                AbiV1Constants.SAS_PAIRING_ROLE_INITIATOR => SasPairingPeerRole.Initiator,
                AbiV1Constants.SAS_PAIRING_ROLE_RESPONDER => SasPairingPeerRole.Responder,
                _ => throw Context.ViolateContract(ReadOperation, $"returned the peer role {info.PeerRole}"),
            };
            int requestIdLength = Bounded("request ID", info.RequestIdLength, MaxRequestIdLength);
            int peerBootstrapLength = Bounded("peer Bootstrap", info.PeerBootstrapLength, MaxPeerBootstrapLength);
            int sharedContextLength = Bounded("shared context", info.SharedContextLength, MaxSharedContextLength);
            int profileIdentifierLength = Bounded("profile identifier", info.ProfileIdentifierLength, MaxProfileIdentifierLength);

            // Every field is copied and checked before anything is built: a failure returns nothing partial.
            byte[] requestId = Copy("request ID", AbiV1Constants.SAS_PAIRING_RESULT_FIELD_REQUEST_ID, requestIdLength);
            byte[] peerBootstrap = Copy("peer Bootstrap", AbiV1Constants.SAS_PAIRING_RESULT_FIELD_AUTHENTICATED_PEER_BOOTSTRAP, peerBootstrapLength);
            byte[] sharedContext = Copy("shared context", AbiV1Constants.SAS_PAIRING_RESULT_FIELD_AUTHENTICATED_SHARED_CONTEXT, sharedContextLength);
            byte[] profileIdentifier = Copy("profile identifier", AbiV1Constants.SAS_PAIRING_RESULT_FIELD_PROFILE_IDENTIFIER, profileIdentifierLength);
            return new SasPairingResultData(
                new SasPairingCeremonyIdentity(info.CeremonyIdentity),
                peerRole,
                info.ProfileVersion,
                requestId,
                peerBootstrap,
                sharedContext,
                profileIdentifier);
        }
    }

    /// <summary>
    /// Destroys the native result with exactly one native call (cleanup: allowed after
    /// <see cref="SasPairingStatus.Fatal"/> and after a contract violation). Data already read stays usable. The
    /// result is disposed whatever the native result, and a failure is then thrown once; it is never retried.
    /// Later calls, and calls after the runtime was disposed (which already dropped the native result), do nothing.
    /// </summary>
    /// <exception cref="SasPairingNativeException">Native cleanup reported a failure (first call only).</exception>
    public void Dispose()
    {
        int status;
        lock (_runtime.Gate)
        {
            if (!Ref.IsValid)
            {
                return;
            }

            // Consuming: the result is disposed before the one native call, whatever it returns.
            Ref.Invalidate();
            _runtime.ResultStore.Forget(this);
            status = Context.Results.ResultDestroy(_runtime.Handle, Ref.Handle);
        }

        Context.ThrowIfFailed(DisposeOperation, status);
    }

    /// <summary>A length from a successful info within its source-proven <paramref name="max"/>, checked before any buffer exists.</summary>
    private int Bounded(string field, uint length, uint max) =>
        length <= max ? (int)length : throw Context.ViolateContract(ReadOperation, $"reported a {field} length of {length} (at most {max})");

    /// <summary>
    /// Exactly one copy of the native <paramref name="field"/> at exactly <paramref name="expected"/> bytes, the
    /// length the same immutable result reported in its info: never a size query, negotiation, or retry.
    /// </summary>
    private byte[] Copy(string name, uint field, int expected)
    {
        NativeResultCopyOutcome copy = Context.Results.ResultCopy(_runtime.Handle, Ref.Handle, field, expected);
        if (copy.Status == AbiV1Constants.SAS_PAIRING_BUFFER_TOO_SMALL)
        {
            throw Context.BreakContract(ReadOperation, $"returned SAS_PAIRING_BUFFER_TOO_SMALL for the {name} at the length {expected} its own info reported (required {copy.Required})");
        }

        Context.ThrowIfFailed(ReadOperation, copy.Status);
        if (copy.Required != (nuint)expected || copy.Bytes is not { } bytes || bytes.Length != expected)
        {
            throw Context.ViolateContract(ReadOperation, $"copied the {name} with length {copy.Required} ({copy.Bytes?.Length} bytes), but its info reported {expected}");
        }

        return bytes;
    }
}
