using System.Reflection;
using System.Runtime.InteropServices;
using SasPairing.Interop;
using SasPairing.Tests.Support;

namespace SasPairing.Tests;

/// <summary>
/// The production loader over real native images. The sas-pairing artifact is supplied explicitly by the
/// absolute path in <c>SAS_PAIRING_NATIVE_LIBRARY</c> (Windows <c>sas_pairing_core.dll</c>, Linux
/// <c>libsas_pairing_core.so</c>, built from the same commit in CI). Without it the artifact tests are skipped
/// locally and fail under CI. Only <c>sas_pairing_abi_version()</c> is ever called: no lifecycle or pairing
/// operation. Loading the Linux library proves ABI loading only, not Linux pairing support.
/// </summary>
[Collection(RealNativeTests.Name)]
public sealed class NativeArtifactTests
{
    private const string ArtifactVariable = "SAS_PAIRING_NATIVE_LIBRARY";

    internal static string ArtifactPath()
    {
        string? path = Environment.GetEnvironmentVariable(ArtifactVariable);
        if (string.IsNullOrEmpty(path))
        {
            Assert.False(
                string.Equals(Environment.GetEnvironmentVariable("CI"), "true", StringComparison.OrdinalIgnoreCase),
                $"{ArtifactVariable} must name the native artifact under CI.");
            Assert.Skip($"{ArtifactVariable} is not set: the real native artifact tests need an absolute library path.");
        }

        Assert.True(Path.IsPathFullyQualified(path), $"{ArtifactVariable} must be an absolute path: {path}");
        Assert.True(File.Exists(path), $"{ArtifactVariable} names no file: {path}");
        return path;
    }

    /// <summary>A real shared library that is not sas-pairing and exports none of its symbols.</summary>
    private static string ForeignLibrary()
    {
        if (OperatingSystem.IsWindows())
        {
            return Path.Combine(Environment.SystemDirectory, "kernel32.dll");
        }

        string[] candidates = ["/lib/x86_64-linux-gnu/libc.so.6", "/usr/lib/x86_64-linux-gnu/libc.so.6", "/lib64/libc.so.6", "/usr/lib64/libc.so.6"];
        return candidates.FirstOrDefault(File.Exists) ?? throw new InvalidOperationException("No libc.so.6 found for the foreign-image test.");
    }

    [Fact]
    public void TheRealArtifactLoadsThroughTheProcessLoaderWithAbiVersionOne()
    {
        string path = ArtifactPath();

        NativeAbiV1 abi = NativeAbiV1Loader.Process.Initialize(path);

        Assert.Equal(1u, abi.AbiVersion);
        Assert.Equal(AbiV1Constants.SAS_PAIRING_ABI_VERSION, abi.AbiVersion);
        Assert.Equal(1u, abi.Functions.QueryAbiVersion());
        Assert.Equal(NativeLoaderState.Ready, NativeAbiV1Loader.Process.State);
        Assert.Same(abi.Image, NativeAbiV1Loader.Process.RetainedImage);
        Assert.True(Path.IsPathFullyQualified(abi.LibraryPath));

        // The same call returns the same loaded object, for the same path and for any other path.
        Assert.Same(abi, NativeAbiV1Loader.Process.Initialize(path));
        Assert.Same(abi, NativeAbiV1Loader.Process.Initialize(ForeignLibrary()));
        Assert.Same(abi, NativeAbiV1Loader.Process.Initialize("sas_pairing_core"));
    }

    [Fact]
    public void TheRealArtifactExportsAllTwentyFiveFrozenSymbolsByExactName()
    {
        string path = ArtifactPath();
        NativeAbiV1 abi = NativeAbiV1Loader.Process.Initialize(path);

        foreach (string export in AbiV1Exports.Names)
        {
            Assert.True(abi.Image.TryGetExport(export, out nint address), $"missing {export}");
            Assert.NotEqual(0, address);
        }

        // Every function-table field is bound to its own export's address.
        FieldInfo[] fields = AbiV1ExportTests.TableFields();
        Assert.Equal(25, fields.Length);
        foreach (FieldInfo field in fields)
        {
            Assert.True(abi.Image.TryGetExport(field.Name, out nint address));
            Assert.Equal(address, AbiV1ExportTests.ReadFunctionPointer(field, abi.Functions));
        }

        Assert.False(abi.Image.TryGetExport("sas_pairing_future_magic", out _));
    }

    [Fact]
    public void ARealLoaderOpensTheArtifactOnceAcrossRepeatedInitialization()
    {
        string path = ArtifactPath();
        CountingPlatform platform = new(ProcessNativePlatform.Instance);
        NativeAbiV1Loader loader = new(platform);

        NativeAbiV1 first = loader.Initialize(path);

        Assert.Same(first, loader.Initialize(path));
        Assert.Same(first, loader.Initialize(ForeignLibrary()));
        Assert.Single(platform.Opened);
        Assert.Equal(1u, first.AbiVersion);
    }

    [Fact]
    public void RealPreLoadFailuresLeaveTheLoaderRetryable()
    {
        string path = ArtifactPath();
        CountingPlatform platform = new(ProcessNativePlatform.Instance);
        NativeAbiV1Loader loader = new(platform);
        string directory = Path.GetDirectoryName(path)!;

        Assert.Equal(NativeInitializationFailure.InvalidLibraryPath, Assert.Throws<NativeInitializationException>(() => loader.Initialize(Path.GetFileName(path))).Failure);
        Assert.Equal(NativeInitializationFailure.InvalidLibraryPath, Assert.Throws<NativeInitializationException>(() => loader.Initialize(Path.Combine(directory, "no-such-library.bin"))).Failure);
        Assert.Equal(NativeInitializationFailure.InvalidLibraryPath, Assert.Throws<NativeInitializationException>(() => loader.Initialize(directory)).Failure);
        Assert.Empty(platform.Opened);

        // A real file that the OS cannot load as a library: an OS load failure, before any image exists.
        string notALibrary = FrozenAbi.PathOf("core", "include", "sas_pairing.h");
        NativeInitializationException openFailed = Assert.Throws<NativeInitializationException>(() => loader.Initialize(notALibrary));
        Assert.Equal(NativeInitializationFailure.OpenFailed, openFailed.Failure);
        Assert.Equal(NativeLoaderState.Uninitialized, loader.State);
        Assert.Null(loader.RetainedImage);

        Assert.Equal(1u, loader.Initialize(path).AbiVersion);
        Assert.Equal(NativeLoaderState.Ready, loader.State);
    }

    [Fact]
    public void ARealForeignImagePoisonsTheLoaderAndNoSecondImageIsEverLoaded()
    {
        CountingPlatform platform = new(ProcessNativePlatform.Instance);
        NativeAbiV1Loader loader = new(platform);
        string foreign = ForeignLibrary();

        NativeInitializationException failure = Assert.Throws<NativeInitializationException>(() => loader.Initialize(foreign));

        Assert.Equal(NativeInitializationFailure.MissingSymbol, failure.Failure);
        Assert.Contains("lacks 25 of the 25", failure.Message, StringComparison.Ordinal);
        Assert.True(failure.ProcessRestartRequired);
        Assert.Equal(NativeLoaderState.PermanentlyFailedAfterLoad, loader.State);
        Assert.NotNull(loader.RetainedImage);

        // Neither the same nor an alternate path (the real artifact, when present) is ever loaded again.
        string alternate = Environment.GetEnvironmentVariable(ArtifactVariable) is { Length: > 0 } artifact ? artifact : foreign;
        Assert.Same(failure, Assert.Throws<NativeInitializationException>(() => loader.Initialize(alternate)));
        Assert.Same(failure, Assert.Throws<NativeInitializationException>(() => loader.Initialize(foreign)));
        Assert.Single(platform.Opened);
    }

    [Fact]
    public void TheRealPlatformRequiresFullyQualifiedExistingFiles()
    {
        ProcessNativePlatform platform = ProcessNativePlatform.Instance;
        string[] invalid = ["", "sas_pairing_core", "sas_pairing_core.dll", "libsas_pairing_core.so", "./sas_pairing_core.dll", Path.Combine("relative", "x.dll")];
        foreach (string path in invalid)
        {
            Assert.Equal(NativeInitializationFailure.InvalidLibraryPath, Assert.Throws<NativeInitializationException>(() => platform.ResolveLibraryPath(path)).Failure);
        }

        if (OperatingSystem.IsWindows())
        {
            // Drive-relative and rooted-but-not-qualified forms would let Windows resolve against a current directory.
            Assert.Throws<NativeInitializationException>(() => platform.ResolveLibraryPath(@"C:sas_pairing_core.dll"));
            Assert.Throws<NativeInitializationException>(() => platform.ResolveLibraryPath(@"\sas_pairing_core.dll"));
        }

        string header = FrozenAbi.PathOf("core", "include", "sas_pairing.h");
        Assert.Equal(Path.GetFullPath(header), platform.ResolveLibraryPath(header));
        Assert.True(RuntimeInformation.ProcessArchitecture is Architecture.X64 or Architecture.Arm64);
    }
}
