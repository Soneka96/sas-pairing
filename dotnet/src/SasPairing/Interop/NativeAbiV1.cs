namespace SasPairing.Interop;

/// <summary>
/// The one verified native ABI v1 binding of the process (P9-D-001): the retained image, its 25-export
/// function table, and the version it reported (always 1). Created only by <see cref="NativeAbiV1Loader"/>
/// after every check passed, and returned unchanged by every later successful initialization. It owns no
/// native resource that could be released: there is no unload, dispose, or finalizer, and the image stays
/// loaded until the OS process exits (P7-D-002).
/// </summary>
internal sealed class NativeAbiV1
{
    internal NativeAbiV1(string libraryPath, INativeImage image, AbiV1FunctionTable functions, uint abiVersion)
    {
        LibraryPath = libraryPath;
        Image = image;
        Functions = functions;
        AbiVersion = abiVersion;
    }

    /// <summary>The canonical absolute path the image was loaded from.</summary>
    internal string LibraryPath { get; }

    /// <summary>The loaded image, strongly referenced for the rest of the process and never freed.</summary>
    internal INativeImage Image { get; }

    /// <summary>The exact 25-export function table over <see cref="Image"/>.</summary>
    internal AbiV1FunctionTable Functions { get; }

    /// <summary>The ABI version the image reported: <see cref="AbiV1Constants.SAS_PAIRING_ABI_VERSION"/>.</summary>
    internal uint AbiVersion { get; }
}
