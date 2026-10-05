using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using SasPairing.Interop;

namespace SasPairing.Tests.Support;

/// <summary>
/// Real unmanaged C-convention functions that stand in for native exports, so the loader's real function
/// table and its real <c>sas_pairing_abi_version()</c> call can be exercised without a native library. Only
/// the version functions are ever expected to be called; every other fake export counts as unexpected.
/// </summary>
internal static unsafe class FakeExports
{
    private static int s_versionCalls;
    private static int s_unexpectedCalls;

    internal static int VersionCalls => Volatile.Read(ref s_versionCalls);

    internal static int UnexpectedCalls => Volatile.Read(ref s_unexpectedCalls);

    internal static nint Version0 => (nint)(delegate* unmanaged[Cdecl]<uint>)&ReturnVersion0;

    internal static nint Version1 => (nint)(delegate* unmanaged[Cdecl]<uint>)&ReturnVersion1;

    internal static nint Version2 => (nint)(delegate* unmanaged[Cdecl]<uint>)&ReturnVersion2;

    internal static nint Unexpected => (nint)(delegate* unmanaged[Cdecl]<int>)&RecordUnexpected;

    internal static void Reset()
    {
        Volatile.Write(ref s_versionCalls, 0);
        Volatile.Write(ref s_unexpectedCalls, 0);
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static uint ReturnVersion0()
    {
        Interlocked.Increment(ref s_versionCalls);
        return 0;
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static uint ReturnVersion1()
    {
        Interlocked.Increment(ref s_versionCalls);
        return 1;
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static uint ReturnVersion2()
    {
        Interlocked.Increment(ref s_versionCalls);
        return 2;
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static int RecordUnexpected()
    {
        Interlocked.Increment(ref s_unexpectedCalls);
        return 900;
    }
}

/// <summary>A fake loaded image: a symbol table plus a log of every lookup.</summary>
internal sealed class FakeImage : INativeImage
{
    private readonly Dictionary<string, nint> _exports;
    private readonly List<string> _lookups = [];

    internal FakeImage(Dictionary<string, nint> exports)
    {
        _exports = exports;
    }

    /// <summary>When set, lookups of these names fail from the given lookup count on (a flaky binding).</summary>
    internal (string Name, int FailFromLookup)? FlakyExport { get; init; }

    internal IReadOnlyList<string> Lookups => _lookups;

    /// <summary>An image exporting all 25 frozen symbols, with the given version function.</summary>
    internal static FakeImage Complete(nint version, params string[] without)
    {
        Dictionary<string, nint> exports = [];
        foreach (string name in AbiV1Exports.Names)
        {
            if (!without.Contains(name))
            {
                exports[name] = name == "sas_pairing_abi_version" ? version : FakeExports.Unexpected;
            }
        }

        return new FakeImage(exports);
    }

    public bool TryGetExport(string name, out nint address)
    {
        _lookups.Add(name);
        if (FlakyExport is { } flaky && flaky.Name == name && _lookups.Count(n => n == name) >= flaky.FailFromLookup)
        {
            address = 0;
            return false;
        }

        return _exports.TryGetValue(name, out address);
    }
}

/// <summary>A fake platform recording every path validation and every open.</summary>
internal sealed class FakePlatform : INativePlatform
{
    private readonly Func<string, INativeImage> _open;
    private readonly List<string> _resolved = [];
    private readonly List<string> _opened = [];

    internal FakePlatform(Func<string, INativeImage> open)
    {
        _open = open;
    }

    public int PointerSize { get; set; } = 8;

    /// <summary>Paths that fail validation as invalid.</summary>
    internal HashSet<string> InvalidPaths { get; } = [];

    /// <summary>Paths whose open throws the OS-load error <see cref="DllNotFoundException"/>.</summary>
    internal HashSet<string> UnloadablePaths { get; } = [];

    internal IReadOnlyList<string> Resolved => _resolved;

    internal IReadOnlyList<string> Opened => _opened;

    public string ResolveLibraryPath(string libraryPath)
    {
        _resolved.Add(libraryPath);
        if (InvalidPaths.Contains(libraryPath))
        {
            throw new NativeInitializationException(NativeInitializationFailure.InvalidLibraryPath, $"fake invalid path {libraryPath}");
        }

        return libraryPath;
    }

    public INativeImage Open(string path)
    {
        _opened.Add(path);
        if (UnloadablePaths.Contains(path))
        {
            throw new DllNotFoundException($"fake load failure for {path}");
        }

        return _open(path);
    }
}

/// <summary>Wraps a platform (usually the real one) and counts its opens.</summary>
internal sealed class CountingPlatform(INativePlatform inner) : INativePlatform
{
    private readonly List<string> _opened = [];

    internal IReadOnlyList<string> Opened => _opened;

    public int PointerSize => inner.PointerSize;

    public string ResolveLibraryPath(string libraryPath) => inner.ResolveLibraryPath(libraryPath);

    public INativeImage Open(string path)
    {
        _opened.Add(path);
        return inner.Open(path);
    }
}
