namespace SasPairing;

/// <summary>
/// The exact 32-byte ceremony identity of one presented SAS (P9-D-004): the value a MATCH
/// (<see cref="SasPairingRun.ApproveSas"/>), MISMATCH (<see cref="SasPairingRun.RejectSas"/>), or CANCEL
/// (<see cref="SasPairingRun.CancelSas"/>) decision must name, passed back unchanged.
/// </summary>
/// <remarks>
/// It binds the user's decision to one exact presented ceremony transcript. It is NOT a request ID, a run, a
/// connection, a peer identity, an authority identity, a trust identity, or a secret. It is obtained only from
/// <see cref="SasPairingSasPresentation.CeremonyIdentity"/>; there is no public constructor. Immutable: the bytes
/// are this object's own copy, exposed read-only. Two identities are equal when their bytes are equal.
/// </remarks>
public sealed class SasPairingCeremonyIdentity : IEquatable<SasPairingCeremonyIdentity>
{
    /// <summary>The frozen length of a ceremony identity.</summary>
    internal const int Length = 32;

    private readonly byte[] _bytes;

    internal SasPairingCeremonyIdentity(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length != Length)
        {
            throw new ArgumentException($"A ceremony identity is exactly {Length} bytes.", nameof(bytes));
        }

        _bytes = bytes.ToArray();
    }

    /// <summary>The 32 bytes, as a read-only view of this object's own copy.</summary>
    public ReadOnlySpan<byte> Bytes => _bytes;

    /// <summary>Whether both identities hold the same 32 bytes.</summary>
    public static bool operator ==(SasPairingCeremonyIdentity? left, SasPairingCeremonyIdentity? right) =>
        left is null ? right is null : left.Equals(right);

    /// <summary>Whether the identities differ (or exactly one is null).</summary>
    public static bool operator !=(SasPairingCeremonyIdentity? left, SasPairingCeremonyIdentity? right) => !(left == right);

    /// <summary>Whether <paramref name="other"/> holds the same 32 bytes.</summary>
    /// <param name="other">The identity to compare with.</param>
    /// <returns>True for equal bytes.</returns>
    public bool Equals(SasPairingCeremonyIdentity? other) => other is not null && _bytes.AsSpan().SequenceEqual(other._bytes);

    /// <inheritdoc/>
    public override bool Equals(object? obj) => Equals(obj as SasPairingCeremonyIdentity);

    /// <inheritdoc/>
    public override int GetHashCode()
    {
        HashCode hash = default;
        hash.AddBytes(_bytes);
        return hash.ToHashCode();
    }
}
