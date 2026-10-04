namespace SasPairing.Interop;

/// <summary>
/// The one Bootstrap marshalling path (P9-D-003, reused by P9-D-004): pins the four fields of the local
/// Bootstrap and of the optional expected peer Bootstrap for exactly one synchronous native call and builds
/// their <see cref="sas_pairing_bootstrap_view_t"/> records. A field of length 0 is <c>data = NULL, len = 0</c>;
/// any other field is its exact pinned address and length. No expected Bootstrap is a null view pointer. The
/// views and the pinned memory never outlive <see cref="Call"/>, and the library copies the bytes. Listener
/// attach and Initiator start both pass their Bootstraps through here.
/// </summary>
// UNSAFE: a Bootstrap view is four raw byte pointers into memory pinned here for one call.
internal static unsafe class NativeBootstrapMarshalling
{
    private static readonly NativeBootstrapBytes NoBootstrap = new([], [], [], []);

    /// <summary>One native call over the two views: <paramref name="expected"/> is null for no expected Bootstrap.</summary>
    internal delegate int ViewsCall(sas_pairing_bootstrap_view_t* local, sas_pairing_bootstrap_view_t* expected);

    /// <summary>Pins both Bootstraps, builds their views, and makes exactly one <paramref name="call"/> over them.</summary>
    internal static int Call(NativeBootstrapBytes local, NativeBootstrapBytes? expected, ViewsCall call)
    {
        NativeBootstrapBytes peer = expected ?? NoBootstrap;

        // Every field is pinned only for this call; an empty field pins nothing and is passed as NULL with length 0.
        fixed (byte* la = local.ApplicationIdentity, lk = local.KeyAlgorithm, lp = local.PublicKey, ls = local.SharedContext)
        fixed (byte* ea = peer.ApplicationIdentity, ek = peer.KeyAlgorithm, ep = peer.PublicKey, es = peer.SharedContext)
        {
            sas_pairing_bootstrap_view_t localView = View(local, la, lk, lp, ls);
            sas_pairing_bootstrap_view_t expectedView = View(peer, ea, ek, ep, es);
            return call(&localView, expected is null ? null : &expectedView);
        }
    }

    /// <summary>The view over the four pinned fields of <paramref name="bytes"/>.</summary>
    private static sas_pairing_bootstrap_view_t View(NativeBootstrapBytes bytes, byte* applicationIdentity, byte* keyAlgorithm, byte* publicKey, byte* sharedContext) => new()
    {
        application_identity = Field(applicationIdentity, bytes.ApplicationIdentity.Length),
        key_algorithm = Field(keyAlgorithm, bytes.KeyAlgorithm.Length),
        public_key = Field(publicKey, bytes.PublicKey.Length),
        shared_context = Field(sharedContext, bytes.SharedContext.Length),
    };

    private static sas_pairing_bytes_view_t Field(byte* pinned, int length) => new()
    {
        data = length == 0 ? null : pinned,
        len = (nuint)length,
    };
}
