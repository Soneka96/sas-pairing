using SasPairing.Interop;
using SasPairing.Tests.Support;

namespace SasPairing.Tests;

/// <summary>
/// The P9-D-001 loader state machine over a fake platform whose images export real unmanaged C functions:
/// the real function table is built and the real <c>sas_pairing_abi_version()</c> call is made. These loaders
/// are private to each test and never touch <see cref="NativeAbiV1Loader.Process"/>.
/// </summary>
public sealed class NativeLoaderTests
{
    private const string LibraryA = "/fake/a/sas_pairing_core";
    private const string LibraryB = "/fake/b/sas_pairing_core";

    public NativeLoaderTests()
    {
        FakeExports.Reset();
    }

    private static (NativeAbiV1Loader Loader, FakePlatform Platform) LoaderWith(Func<string, INativeImage> open)
    {
        FakePlatform platform = new(open);
        return (new NativeAbiV1Loader(platform), platform);
    }

    [Fact]
    public void VersionOneSucceedsAndCallsOnlyTheVersionQuery()
    {
        FakeImage image = FakeImage.Complete(FakeExports.Version1);
        (NativeAbiV1Loader loader, FakePlatform platform) = LoaderWith(_ => image);

        NativeAbiV1 abi = loader.Initialize(LibraryA);

        Assert.Equal(1u, abi.AbiVersion);
        Assert.Equal(LibraryA, abi.LibraryPath);
        Assert.Same(image, abi.Image);
        Assert.Same(image, loader.RetainedImage);
        Assert.Equal(NativeLoaderState.Ready, loader.State);
        Assert.Equal([LibraryA], platform.Opened);
        Assert.Equal(1, FakeExports.VersionCalls);
        Assert.Equal(0, FakeExports.UnexpectedCalls);

        // Preflight of all 25 names, then one binding lookup of each: nothing else is looked up.
        Assert.Equal([.. AbiV1Exports.Names, .. AbiV1Exports.Names], image.Lookups);
    }

    [Fact]
    public void SuccessfulReinitializationReturnsTheSameBindingWithoutInspectingAnyPath()
    {
        (NativeAbiV1Loader loader, FakePlatform platform) = LoaderWith(_ => FakeImage.Complete(FakeExports.Version1));
        NativeAbiV1 first = loader.Initialize(LibraryA);

        Assert.Same(first, loader.Initialize(LibraryA));
        Assert.Same(first, loader.Initialize(LibraryB));
        Assert.Same(first, loader.Initialize(""));

        Assert.Equal([LibraryA], platform.Resolved);
        Assert.Equal([LibraryA], platform.Opened);
        Assert.Equal(1, FakeExports.VersionCalls);
    }

    [Theory]
    [InlineData(0u)]
    [InlineData(2u)]
    public void AnyVersionOtherThanOneIsAPermanentPostLoadFailure(uint version)
    {
        NativeInitializationFailure expected = version == 0 ? NativeInitializationFailure.AbiVersionQueryFailed : NativeInitializationFailure.AbiVersionMismatch;
        FakeImage image = FakeImage.Complete(version == 0 ? FakeExports.Version0 : FakeExports.Version2);
        (NativeAbiV1Loader loader, FakePlatform platform) = LoaderWith(_ => image);

        NativeInitializationException failure = Assert.Throws<NativeInitializationException>(() => loader.Initialize(LibraryA));

        Assert.Equal(expected, failure.Failure);
        Assert.True(failure.ProcessRestartRequired);
        Assert.Contains("restart the OS process", failure.Message, StringComparison.Ordinal);
        Assert.Equal(NativeLoaderState.PermanentlyFailedAfterLoad, loader.State);
        Assert.Same(image, loader.RetainedImage);

        // No fallback: the same failure for the same path, another path, or a valid image elsewhere.
        Assert.Same(failure, Assert.Throws<NativeInitializationException>(() => loader.Initialize(LibraryA)));
        Assert.Same(failure, Assert.Throws<NativeInitializationException>(() => loader.Initialize(LibraryB)));
        Assert.Equal([LibraryA], platform.Resolved);
        Assert.Equal([LibraryA], platform.Opened);
        Assert.Equal(1, FakeExports.VersionCalls);
        Assert.Equal(0, FakeExports.UnexpectedCalls);
    }

    [Fact]
    public void AMissingRequiredExportIsAPermanentPostLoadFailureThatKeepsTheImage()
    {
        FakeImage broken = FakeImage.Complete(FakeExports.Version1, "sas_pairing_run_emit_initiator_finish");
        (NativeAbiV1Loader loader, FakePlatform platform) = LoaderWith(path => path == LibraryA ? broken : FakeImage.Complete(FakeExports.Version1));

        NativeInitializationException failure = Assert.Throws<NativeInitializationException>(() => loader.Initialize(LibraryA));

        Assert.Equal(NativeInitializationFailure.MissingSymbol, failure.Failure);
        Assert.Contains("sas_pairing_run_emit_initiator_finish", failure.Message, StringComparison.Ordinal);
        Assert.Contains("lacks 1 of the 25", failure.Message, StringComparison.Ordinal);
        Assert.Equal(NativeLoaderState.PermanentlyFailedAfterLoad, loader.State);
        Assert.Same(broken, loader.RetainedImage);
        Assert.Equal(0, FakeExports.VersionCalls); // nothing is called on an incomplete image

        // A correct image at another path is never inspected or loaded: one image per process.
        Assert.Same(failure, Assert.Throws<NativeInitializationException>(() => loader.Initialize(LibraryB)));
        Assert.Equal([LibraryA], platform.Opened);
        Assert.Equal([LibraryA], platform.Resolved);
        Assert.Same(broken, loader.RetainedImage);
    }

    [Fact]
    public void ANullExportAddressCountsAsMissing()
    {
        Dictionary<string, nint> exports = AbiV1Exports.Names.ToDictionary(n => n, _ => FakeExports.Unexpected);
        exports["sas_pairing_abi_version"] = 0;
        (NativeAbiV1Loader loader, _) = LoaderWith(_ => new FakeImage(exports));

        NativeInitializationException failure = Assert.Throws<NativeInitializationException>(() => loader.Initialize(LibraryA));

        Assert.Equal(NativeInitializationFailure.MissingSymbol, failure.Failure);
        Assert.Equal(NativeLoaderState.PermanentlyFailedAfterLoad, loader.State);
    }

    [Fact]
    public void AFunctionTableBindFailureIsAPermanentPostLoadFailure()
    {
        // The preflight finds the symbol, but the binding lookup of it then fails.
        FakeImage flaky = new(AbiV1Exports.Names.ToDictionary(n => n, n => n == "sas_pairing_abi_version" ? FakeExports.Version1 : FakeExports.Unexpected))
        {
            FlakyExport = ("sas_pairing_host_drive", 2),
        };
        (NativeAbiV1Loader loader, FakePlatform platform) = LoaderWith(_ => flaky);

        NativeInitializationException failure = Assert.Throws<NativeInitializationException>(() => loader.Initialize(LibraryA));

        Assert.Equal(NativeInitializationFailure.BindingFailed, failure.Failure);
        Assert.IsType<AbiV1BindingException>(failure.InnerException);
        Assert.True(failure.ProcessRestartRequired);
        Assert.Same(flaky, loader.RetainedImage);
        Assert.Same(failure, Assert.Throws<NativeInitializationException>(() => loader.Initialize(LibraryB)));
        Assert.Equal([LibraryA], platform.Opened);
        Assert.Equal(0, FakeExports.VersionCalls);
    }

    [Fact]
    public void AnInvalidPathFailsBeforeLoadAndALaterValidPathInitializes()
    {
        (NativeAbiV1Loader loader, FakePlatform platform) = LoaderWith(_ => FakeImage.Complete(FakeExports.Version1));
        platform.InvalidPaths.Add("relative/sas_pairing_core");

        NativeInitializationException failure = Assert.Throws<NativeInitializationException>(() => loader.Initialize("relative/sas_pairing_core"));

        Assert.Equal(NativeInitializationFailure.InvalidLibraryPath, failure.Failure);
        Assert.False(failure.ProcessRestartRequired);
        Assert.Equal(NativeLoaderState.Uninitialized, loader.State);
        Assert.Null(loader.RetainedImage);
        Assert.Empty(platform.Opened);

        NativeAbiV1 abi = loader.Initialize(LibraryA);
        Assert.Equal(1u, abi.AbiVersion);
        Assert.Equal(NativeLoaderState.Ready, loader.State);
        Assert.Equal([LibraryA], platform.Opened);
    }

    [Fact]
    public void AnOpenFailureFailsBeforeLoadAndMayBeRetried()
    {
        (NativeAbiV1Loader loader, FakePlatform platform) = LoaderWith(_ => FakeImage.Complete(FakeExports.Version1));
        platform.UnloadablePaths.Add(LibraryA);

        NativeInitializationException failure = Assert.Throws<NativeInitializationException>(() => loader.Initialize(LibraryA));

        Assert.Equal(NativeInitializationFailure.OpenFailed, failure.Failure);
        Assert.IsType<DllNotFoundException>(failure.InnerException);
        Assert.False(failure.ProcessRestartRequired);
        Assert.Equal(NativeLoaderState.Uninitialized, loader.State);
        Assert.Null(loader.RetainedImage);

        platform.UnloadablePaths.Clear();
        Assert.Equal(1u, loader.Initialize(LibraryA).AbiVersion);
        Assert.Equal([LibraryA, LibraryA], platform.Opened);
    }

    [Fact]
    public void AnUnsupportedPointerWidthFailsBeforeAnyPathWorkAndMayBeRetried()
    {
        (NativeAbiV1Loader loader, FakePlatform platform) = LoaderWith(_ => FakeImage.Complete(FakeExports.Version1));
        platform.PointerSize = 4;

        NativeInitializationException failure = Assert.Throws<NativeInitializationException>(() => loader.Initialize(LibraryA));

        Assert.Equal(NativeInitializationFailure.UnsupportedPointerWidth, failure.Failure);
        Assert.False(failure.ProcessRestartRequired);
        Assert.Empty(platform.Resolved);
        Assert.Empty(platform.Opened);
        Assert.Equal(NativeLoaderState.Uninitialized, loader.State);

        platform.PointerSize = 8;
        Assert.Equal(1u, loader.Initialize(LibraryA).AbiVersion);
    }

    [Fact]
    public void ConcurrentInitializationLoadsOneImage()
    {
        (NativeAbiV1Loader loader, FakePlatform platform) = LoaderWith(_ => FakeImage.Complete(FakeExports.Version1));
        NativeAbiV1?[] results = new NativeAbiV1?[16];
        Exception?[] errors = new Exception?[results.Length];
        using Barrier barrier = new(results.Length);
        Thread[] threads =
        [
            .. Enumerable.Range(0, results.Length).Select(i => new Thread(() =>
            {
                barrier.SignalAndWait();
                try
                {
                    results[i] = loader.Initialize(i % 2 == 0 ? LibraryA : LibraryB);
                }
                catch (NativeInitializationException error)
                {
                    // Recorded and asserted below: an exception escaping a worker thread would end the test host.
                    errors[i] = error;
                }
            })),
        ];
        foreach (Thread thread in threads)
        {
            thread.Start();
        }

        foreach (Thread thread in threads)
        {
            thread.Join();
        }

        Assert.All(errors, Assert.Null);
        Assert.Single(platform.Opened);
        Assert.NotNull(results[0]);
        Assert.All(results, r => Assert.Same(results[0], r));
        Assert.Equal(1, FakeExports.VersionCalls);
    }

    [Fact]
    public void FailureCategoriesSplitExactlyIntoPreLoadAndPostLoad()
    {
        NativeInitializationFailure[] preLoad = [NativeInitializationFailure.UnsupportedPointerWidth, NativeInitializationFailure.InvalidLibraryPath, NativeInitializationFailure.OpenFailed];
        NativeInitializationFailure[] postLoad = [NativeInitializationFailure.MissingSymbol, NativeInitializationFailure.BindingFailed, NativeInitializationFailure.AbiVersionQueryFailed, NativeInitializationFailure.AbiVersionMismatch];
        Assert.Equal(Enum.GetValues<NativeInitializationFailure>().Order(), preLoad.Concat(postLoad).Order());
        Assert.All(preLoad, f => Assert.False(f.IsPostLoad()));
        Assert.All(postLoad, f => Assert.True(f.IsPostLoad()));
        Assert.Equal([NativeLoaderState.Uninitialized, NativeLoaderState.Ready, NativeLoaderState.PermanentlyFailedAfterLoad], Enum.GetValues<NativeLoaderState>());
    }

    [Fact]
    public void TheProcessLoaderIsOneInstanceOverTheRealPlatform()
    {
        Assert.Same(NativeAbiV1Loader.Process, NativeAbiV1Loader.Process);
        Assert.Equal(8, ProcessNativePlatform.Instance.PointerSize);
        Assert.Equal(IntPtr.Size, ProcessNativePlatform.Instance.PointerSize);
    }
}
