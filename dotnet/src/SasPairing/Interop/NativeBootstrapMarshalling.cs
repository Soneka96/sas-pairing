namespace SasPairing.Interop;

/// <summary>
/// The one Bootstrap marshalling path (P9-D-003): builds a <see cref="sas_pairing_bootstrap_view_t"/> from
/// four field pointers that the caller pinned for exactly one synchronous native call. A field of length 0
/// is <c>data = NULL, len = 0</c>; any other field is its exact pinned address and length. The view never
/// outlives the <c>fixed</c> statement of the call that built it, and the library copies the bytes.
/// </summary>
// UNSAFE: a Bootstrap view is four raw byte pointers into memory pinned by the caller for one call.
internal static unsafe class NativeBootstrapMarshalling
{
    /// <summary>The view over the four pinned fields of <paramref name="bytes"/>.</summary>
    internal static sas_pairing_bootstrap_view_t View(NativeBootstrapBytes bytes, byte* applicationIdentity, byte* keyAlgorithm, byte* publicKey, byte* sharedContext) => new()
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
