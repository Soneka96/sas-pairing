using SasPairing.Interop;

namespace SasPairing;

/// <summary>
/// One exact native ceremony run of one <see cref="SasPairingConnection"/> (P9-D-004). Every drive event and
/// local action that names the same native run carries this same object: a run is identified by its native
/// run, never by its request ID, and is never retargeted.
/// </summary>
/// <remarks>
/// <para>
/// <b>Every step is explicit.</b> Each method makes exactly one native call and chains nothing:
/// <see cref="AuthorizeExposure"/> does not expose the key, <see cref="ApproveSas"/> does not emit
/// BOOTSTRAP_MAC, <see cref="EmitBootstrapMac"/> does not emit INITIATOR_FINISH, and nothing drives the host.
/// A retained frame (<see cref="SasPairingLocalAction.WritePending"/>) is written by the native library on a
/// later <see cref="SasPairingHost.Drive"/>. The native library also confirms the final ACK itself; there is
/// no API for it.
/// </para>
/// <para>
/// <b>Two kinds of "write pending".</b> A <see cref="SasPairingNativeException"/> with
/// <see cref="SasPairingStatus.WritePending"/> (205) means the requested action did NOT run, because the
/// connection still retains an earlier frame: drive, then retry only if the application still wants to.
/// <see cref="SasPairingLocalAction.WritePending"/> on a returned action means the action DID run and its
/// frame waits for a later drive. Nothing is retried or driven automatically.
/// </para>
/// <para>
/// <b>Lifetime.</b> <see cref="IsEnded"/> becomes true when the package has OBSERVED that the run ended: a
/// local action ended it (reject, cancel, or a deadline), a drive event made its end visible (including a
/// result), native reported <see cref="SasPairingStatus.RunEnded"/>, or its connection, owner loop, listener,
/// host, or a parent ended. A run can also end without anything visible; <see cref="IsEnded"/> then stays
/// false and the next native call reports <see cref="SasPairingStatus.RunEnded"/> as a
/// <see cref="SasPairingNativeException"/>, after which it is true. False therefore never proves that the
/// native run is still live. A method of a run known to have ended throws
/// <see cref="SasPairingRunEndedException"/> without a native call. A run is not disposable: ABI v1 has no run
/// destroy, and the run owns no connection, host, or result.
/// </para>
/// <para>
/// Statuses are operation outcomes, never trust verdicts. A refusal such as
/// <see cref="SasPairingStatus.NotInitiator"/> or <see cref="SasPairingStatus.CeremonyIdentityMismatch"/>
/// leaves the run as it is (the native core alone knows whether it ended).
/// </para>
/// </remarks>
public sealed class SasPairingRun
{
    private const string AuthorizeOperation = "SasPairingRun.AuthorizeExposure";
    private const string ExposeOperation = "SasPairingRun.ExposeKey";
    private const string PresentationOperation = "SasPairingRun.Presentation";
    private const string ApproveOperation = "SasPairingRun.ApproveSas";
    private const string BootstrapMacOperation = "SasPairingRun.EmitBootstrapMac";
    private const string RejectOperation = "SasPairingRun.RejectSas";
    private const string CancelOperation = "SasPairingRun.CancelSas";
    private const string FinishOperation = "SasPairingRun.EmitInitiatorFinish";

    private readonly SasPairingConnection _connection;

    internal SasPairingRun(SasPairingConnection connection, NativeRunRef reference)
    {
        _connection = connection;
        Ref = reference;
    }

    /// <summary>
    /// Whether the package has observed that this run ended. False does not guarantee that the native run is
    /// still live (see the remarks of <see cref="SasPairingRun"/>).
    /// </summary>
    public bool IsEnded
    {
        get
        {
            lock (Gate)
            {
                return !Ref.IsValid;
            }
        }
    }

    /// <summary>The exact native run reference. Internal only; its handle is never exposed or printed.</summary>
    internal NativeRunRef Ref { get; }

    /// <summary>The connection of this run.</summary>
    internal SasPairingConnection Connection => _connection;

    private Lock Gate => _connection.Host.Authority.Runtime.Gate;

    /// <summary>
    /// Records fresh, ceremony-specific exposure authorization for exactly this run, from its host's own
    /// authority. It exposes, reserves, spends, and sends nothing: <see cref="ExposeKey"/> is the separate,
    /// security-spending step.
    /// </summary>
    /// <returns><see cref="SasPairingLocalEvent.ExposureAuthorized"/> on this run, or <see cref="SasPairingLocalEvent.Deadline"/>.</returns>
    /// <exception cref="SasPairingRunEndedException">The run is known to have ended (no native call).</exception>
    /// <exception cref="SasPairingNativeException">The native action was refused.</exception>
    /// <exception cref="SasPairingContractException">The native library broke the ABI v1 contract, now or earlier in this process.</exception>
    public SasPairingLocalAction AuthorizeExposure() =>
        Act(AuthorizeOperation, CeremonyControl.AuthorizeOutcomes, static (api, target, _) => api.AuthorizeExposure(target.Runtime, target.Host, target.Connection, target.Run), null);

    /// <summary>
    /// <b>The security-spending step.</b> The native core consumes this run's fresh authorization, atomically
    /// reserves the authority's guard and spends one opportunity, then produces this role's key, retained for a
    /// later drive. Nothing refunds the opportunity, and this package keeps no budget of its own. Without a
    /// fresh authorization: <see cref="SasPairingStatus.MissingAuthorization"/>; also
    /// <see cref="SasPairingStatus.Busy"/> or <see cref="SasPairingStatus.Exhausted"/>.
    /// </summary>
    /// <returns><see cref="SasPairingLocalEvent.KeyExposed"/> with <c>WritePending</c> on this run, or <see cref="SasPairingLocalEvent.Deadline"/>.</returns>
    /// <exception cref="SasPairingRunEndedException">The run is known to have ended (no native call).</exception>
    /// <exception cref="SasPairingNativeException">The native action was refused.</exception>
    /// <exception cref="SasPairingContractException">The native library broke the ABI v1 contract, now or earlier in this process.</exception>
    public SasPairingLocalAction ExposeKey() =>
        Act(ExposeOperation, CeremonyControl.ExposeOutcomes, static (api, target, _) => api.ExposeKey(target.Runtime, target.Host, target.Connection, target.Run), null);

    /// <summary>
    /// Reads this run's live SAS for local comparison, or null when the live run presents none (not established
    /// yet, already decided locally, or expiring). Read-only: it changes no state, refreshes no deadline, sends
    /// nothing, and also reaches the native library while the connection retains a frame.
    /// </summary>
    /// <returns>The presentation, or null.</returns>
    /// <exception cref="SasPairingRunEndedException">The run is known to have ended (no native call).</exception>
    /// <exception cref="SasPairingNativeException">The native read was refused, for example <see cref="SasPairingStatus.RunEnded"/>.</exception>
    /// <exception cref="SasPairingContractException">The native library broke the ABI v1 contract, now or earlier in this process.</exception>
    public SasPairingSasPresentation? Presentation()
    {
        lock (Gate)
        {
            CeremonyTarget target = Admit(PresentationOperation);
            NativePresentationOutcome outcome = Context.Ceremony.Presentation(target.Runtime, target.Host, target.Connection, target.Run);
            return CeremonyControl.SettlePresentation(PresentationOperation, outcome, this);
        }
    }

    /// <summary>
    /// Local MATCH for exactly <paramref name="ceremonyIdentity"/>. Records the approval only: it sends nothing
    /// and does NOT emit BOOTSTRAP_MAC (<see cref="EmitBootstrapMac"/> is separate). Call it only after the user
    /// (or trusted-local policy) chose MATCH for the displayed SAS. The identity is passed to the native core
    /// unchanged; an identity that is not this run's live one is refused natively with
    /// <see cref="SasPairingStatus.CeremonyIdentityMismatch"/>, and nothing changes.
    /// </summary>
    /// <param name="ceremonyIdentity">The identity of the presentation the user decided on.</param>
    /// <returns><see cref="SasPairingLocalEvent.SasApproved"/> or <see cref="SasPairingLocalEvent.SasAlreadyApproved"/> on this run, or <see cref="SasPairingLocalEvent.Deadline"/>.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="ceremonyIdentity"/> is null.</exception>
    /// <exception cref="SasPairingRunEndedException">The run is known to have ended (no native call).</exception>
    /// <exception cref="SasPairingNativeException">The native decision was refused.</exception>
    /// <exception cref="SasPairingContractException">The native library broke the ABI v1 contract, now or earlier in this process.</exception>
    public SasPairingLocalAction ApproveSas(SasPairingCeremonyIdentity ceremonyIdentity)
    {
        ArgumentNullException.ThrowIfNull(ceremonyIdentity);
        return Act(ApproveOperation, CeremonyControl.ApproveOutcomes, static (api, target, identity) => api.ApproveSas(target.Runtime, target.Host, target.Connection, target.Run, identity!.Bytes), ceremonyIdentity);
    }

    /// <summary>
    /// Produces this run's own BOOTSTRAP_MAC once, after its local MATCH
    /// (<see cref="SasPairingStatus.NotLocallyApproved"/> before it), retained for a later drive. It does not
    /// approve and does NOT emit INITIATOR_FINISH.
    /// </summary>
    /// <returns>
    /// <see cref="SasPairingLocalEvent.BootstrapMacEmitted"/> with <c>WritePending</c>, or
    /// <see cref="SasPairingLocalEvent.BootstrapMacAlreadyEmitted"/> on a repeat, on this run; or
    /// <see cref="SasPairingLocalEvent.Deadline"/>.
    /// </returns>
    /// <exception cref="SasPairingRunEndedException">The run is known to have ended (no native call).</exception>
    /// <exception cref="SasPairingNativeException">The native action was refused.</exception>
    /// <exception cref="SasPairingContractException">The native library broke the ABI v1 contract, now or earlier in this process.</exception>
    public SasPairingLocalAction EmitBootstrapMac() =>
        Act(BootstrapMacOperation, CeremonyControl.BootstrapMacOutcomes, static (api, target, _) => api.EmitBootstrapMac(target.Runtime, target.Host, target.Connection, target.Run), null);

    /// <summary>
    /// Local MISMATCH for exactly <paramref name="ceremonyIdentity"/>: the run ends at once with no result, and
    /// its spent opportunity is not refunded. A best-effort authenticated CANCEL may be retained
    /// (<c>WritePending</c>); drive to write it. The connection stays open. Not a judgement about the peer.
    /// </summary>
    /// <param name="ceremonyIdentity">The identity of the presentation the user decided on.</param>
    /// <returns><see cref="SasPairingLocalEvent.SasRejected"/> (or <see cref="SasPairingLocalEvent.Deadline"/>) with no run; this run then reports <see cref="IsEnded"/>.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="ceremonyIdentity"/> is null.</exception>
    /// <exception cref="SasPairingRunEndedException">The run is known to have ended (no native call).</exception>
    /// <exception cref="SasPairingNativeException">The native decision was refused.</exception>
    /// <exception cref="SasPairingContractException">The native library broke the ABI v1 contract, now or earlier in this process.</exception>
    public SasPairingLocalAction RejectSas(SasPairingCeremonyIdentity ceremonyIdentity)
    {
        ArgumentNullException.ThrowIfNull(ceremonyIdentity);
        return Act(RejectOperation, CeremonyControl.RejectOutcomes, static (api, target, identity) => api.RejectSas(target.Runtime, target.Host, target.Connection, target.Run, identity!.Bytes), ceremonyIdentity);
    }

    /// <summary>
    /// Local CANCEL for exactly <paramref name="ceremonyIdentity"/>: as <see cref="RejectSas"/>, with the
    /// distinct user-cancellation reason. The connection stays open.
    /// </summary>
    /// <param name="ceremonyIdentity">The identity of the presentation the user decided on.</param>
    /// <returns><see cref="SasPairingLocalEvent.SasCancelled"/> (or <see cref="SasPairingLocalEvent.Deadline"/>) with no run; this run then reports <see cref="IsEnded"/>.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="ceremonyIdentity"/> is null.</exception>
    /// <exception cref="SasPairingRunEndedException">The run is known to have ended (no native call).</exception>
    /// <exception cref="SasPairingNativeException">The native decision was refused.</exception>
    /// <exception cref="SasPairingContractException">The native library broke the ABI v1 contract, now or earlier in this process.</exception>
    public SasPairingLocalAction CancelSas(SasPairingCeremonyIdentity ceremonyIdentity)
    {
        ArgumentNullException.ThrowIfNull(ceremonyIdentity);
        return Act(CancelOperation, CeremonyControl.CancelOutcomes, static (api, target, identity) => api.CancelSas(target.Runtime, target.Host, target.Connection, target.Run, identity!.Bytes), ceremonyIdentity);
    }

    /// <summary>
    /// Produces the Initiator's INITIATOR_FINISH once, after both approvals are authenticated
    /// (<see cref="SasPairingStatus.ApprovalsNotAuthenticated"/> before), retained for a later drive. A Responder
    /// run gets <see cref="SasPairingStatus.NotInitiator"/> and continues. There is no result yet: the native
    /// library writes the frames and confirms the final ACK itself, and the local result arrives on a later drive.
    /// </summary>
    /// <returns>
    /// <see cref="SasPairingLocalEvent.InitiatorFinishEmitted"/> with <c>WritePending</c>, or
    /// <see cref="SasPairingLocalEvent.InitiatorFinishAlreadyEmitted"/> on a repeat, on this run; or
    /// <see cref="SasPairingLocalEvent.Deadline"/>.
    /// </returns>
    /// <exception cref="SasPairingRunEndedException">The run is known to have ended (no native call).</exception>
    /// <exception cref="SasPairingNativeException">The native action was refused.</exception>
    /// <exception cref="SasPairingContractException">The native library broke the ABI v1 contract, now or earlier in this process.</exception>
    public SasPairingLocalAction EmitInitiatorFinish() =>
        Act(FinishOperation, CeremonyControl.FinishOutcomes, static (api, target, _) => api.EmitInitiatorFinish(target.Runtime, target.Host, target.Connection, target.Run), null);

    private NativeProcessContext Context => _connection.Host.Authority.Runtime.Context;

    /// <summary>The known-ended check first, then the process latches (P9-D-004 admission order).</summary>
    private CeremonyTarget Admit(string operation)
    {
        if (!Ref.IsValid)
        {
            throw new SasPairingRunEndedException(operation);
        }

        Context.AdmitNormal(operation);
        SasPairingHost host = _connection.Host;
        return new CeremonyTarget(host.Authority.Runtime.Handle, host.Handle, _connection.Handle, Ref.Handle);
    }

    /// <summary>Exactly one native ceremony call on this run, under the runtime lock, then its one settlement.</summary>
    private SasPairingLocalAction Act(
        string operation,
        CeremonyOutcome[] allowed,
        Func<INativeCeremonyApi, CeremonyTarget, SasPairingCeremonyIdentity?, NativeActionOutcome> call,
        SasPairingCeremonyIdentity? identity)
    {
        lock (Gate)
        {
            CeremonyTarget target = Admit(operation);
            NativeActionOutcome outcome = call(Context.Ceremony, target, identity);
            return CeremonyControl.SettleAction(operation, allowed, outcome, _connection, this);
        }
    }
}
