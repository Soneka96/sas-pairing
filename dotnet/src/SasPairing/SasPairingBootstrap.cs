using SasPairing.Interop;

namespace SasPairing;

/// <summary>
/// One Bootstrap configuration: four immutable binary fields (P9-D-003). It is input only, given to
/// <see cref="SasPairingHost.AttachWindowsListener"/> as the host's own Responder configuration or as the exact
/// expected peer Bootstrap.
/// </summary>
/// <remarks>
/// The fields are arbitrary bytes, never text: there is no encoding, terminator, or NUL rule. The constructor
/// copies them, so later changes to the caller's memory do not change this object, and the properties are
/// read-only views of the package's copies. The package does not validate a Bootstrap: the native core alone
/// decides whether one is valid, and refuses an invalid one with <see cref="SasPairingStatus.InvalidBootstrap"/>.
/// A Bootstrap is configuration, not a peer identity, authority identity, or trust decision.
/// </remarks>
public sealed class SasPairingBootstrap
{
    private readonly NativeBootstrapBytes _bytes;

    /// <summary>Copies the four fields of one Bootstrap configuration.</summary>
    /// <param name="applicationIdentity">The application identity bytes.</param>
    /// <param name="keyAlgorithm">The key algorithm bytes.</param>
    /// <param name="publicKey">The public key bytes.</param>
    /// <param name="sharedContext">The shared context bytes (may be empty).</param>
    public SasPairingBootstrap(ReadOnlySpan<byte> applicationIdentity, ReadOnlySpan<byte> keyAlgorithm, ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> sharedContext)
    {
        _bytes = new NativeBootstrapBytes(applicationIdentity.ToArray(), keyAlgorithm.ToArray(), publicKey.ToArray(), sharedContext.ToArray());
    }

    /// <summary>The application identity bytes (a read-only view of the package's copy).</summary>
    public ReadOnlySpan<byte> ApplicationIdentity => _bytes.ApplicationIdentity;

    /// <summary>The key algorithm bytes (a read-only view of the package's copy).</summary>
    public ReadOnlySpan<byte> KeyAlgorithm => _bytes.KeyAlgorithm;

    /// <summary>The public key bytes (a read-only view of the package's copy).</summary>
    public ReadOnlySpan<byte> PublicKey => _bytes.PublicKey;

    /// <summary>The shared context bytes (a read-only view of the package's copy).</summary>
    public ReadOnlySpan<byte> SharedContext => _bytes.SharedContext;

    /// <summary>The package-owned copies, for the one Bootstrap marshalling path.</summary>
    internal NativeBootstrapBytes Native => _bytes;
}
