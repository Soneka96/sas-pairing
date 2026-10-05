namespace SasPairing;

/// <summary>
/// One live SAS of a run, presented for local comparison (P9-D-004). Made only by
/// <see cref="SasPairingRun.Presentation"/>; immutable.
/// </summary>
/// <remarks>
/// Display data only: it authenticates, approves, and trusts nothing, and equal displays are not a decision.
/// The application shows <see cref="DecimalDisplay"/> to the user (or applies its own trusted-local policy) and then
/// calls <see cref="SasPairingRun.ApproveSas"/>, <see cref="SasPairingRun.RejectSas"/>, or
/// <see cref="SasPairingRun.CancelSas"/> with exactly <see cref="CeremonyIdentity"/>. This package never
/// compares displays and never decides MATCH.
/// </remarks>
public sealed class SasPairingSasPresentation
{
    internal SasPairingSasPresentation(SasPairingCeremonyIdentity ceremonyIdentity, string decimalDisplay)
    {
        CeremonyIdentity = ceremonyIdentity;
        DecimalDisplay = decimalDisplay;
    }

    /// <summary>The exact identity of the presented ceremony: pass it unchanged to the decision.</summary>
    public SasPairingCeremonyIdentity CeremonyIdentity { get; }

    /// <summary>
    /// The decimal SAS display, exactly <c>NNNN NNNN NNNN</c>: fourteen ASCII characters, three groups of four
    /// digits separated by single spaces. Comparison display data only.
    /// </summary>
    public string DecimalDisplay { get; }
}
