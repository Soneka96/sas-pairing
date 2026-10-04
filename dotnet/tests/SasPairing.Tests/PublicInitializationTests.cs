using SasPairing.Interop;
using SasPairing.Tests.Support;

namespace SasPairing.Tests;

/// <summary>
/// The public initialization error surface of P9-D-002 over the real P9.1 loader state machine: a private
/// loader per test over a fake platform whose images export real unmanaged functions, and a fake lifecycle
/// service. The process loader and the production process context are never touched.
/// </summary>
public sealed class PublicInitializationTests
{
    private const string LibraryA = "/fake/a/sas_pairing_core";
    private const string LibraryB = "/fake/b/sas_pairing_core";

    public PublicInitializationTests()
    {
        FakeExports.Reset();
    }

    private static (NativeProcessContextSource Source, FakePlatform Platform, List<FakeLifecycleApi> Services) SourceWith(Func<string, INativeImage> open)
    {
        FakePlatform platform = new(open);
        List<FakeLifecycleApi> services = [];
        NativeProcessContextSource source = new(new NativeAbiV1Loader(platform), _ =>
        {
            FakeLifecycleApi service = new();
            services.Add(service);
            return service;
        });
        return (source, platform, services);
    }

    /// <summary>Drives the real loader into each of the seven failure categories through the public factory.</summary>
    private static (SasPairingInitializationException Failure, FakePlatform Platform, NativeProcessContextSource Source) Fail(string category)
    {
        FakeImage image = category switch
        {
            "MissingSymbol" => FakeImage.Complete(FakeExports.Version1, "sas_pairing_host_destroy"),
            "BindingFailed" => new FakeImage(AbiV1Exports.Names.ToDictionary(n => n, n => n == "sas_pairing_abi_version" ? FakeExports.Version1 : FakeExports.Unexpected)) { FlakyExport = ("sas_pairing_host_create", 2) },
            "AbiVersionQueryFailed" => FakeImage.Complete(FakeExports.Version0),
            "AbiVersionMismatch" => FakeImage.Complete(FakeExports.Version2),
            _ => FakeImage.Complete(FakeExports.Version1),
        };
        (NativeProcessContextSource source, FakePlatform platform, List<FakeLifecycleApi> services) = SourceWith(_ => image);
        switch (category)
        {
            case "UnsupportedPointerWidth":
                platform.PointerSize = 4;
                break;
            case "InvalidLibraryPath":
                platform.InvalidPaths.Add(LibraryA);
                break;
            case "OpenFailed":
                platform.UnloadablePaths.Add(LibraryA);
                break;
        }

        // Caught as the public type only: callers never need SasPairing.Interop.
        SasPairingInitializationException failure = Assert.Throws<SasPairingInitializationException>(() => SasPairingRuntime.Create(source, LibraryA));
        Assert.Empty(services);
        return (failure, platform, source);
    }

    [Theory]
    [InlineData("UnsupportedPointerWidth", false, "8-byte pointers")]
    [InlineData("InvalidLibraryPath", false, "fake invalid path")]
    [InlineData("OpenFailed", false, "Could not load the native library")]
    [InlineData("MissingSymbol", true, "sas_pairing_host_destroy")]
    [InlineData("BindingFailed", true, "sas_pairing_host_create")]
    [InlineData("AbiVersionQueryFailed", true, "returned 0")]
    [InlineData("AbiVersionMismatch", true, "implements ABI version 2")]
    public void EveryLoaderFailureBecomesThePublicExceptionWithItsRestartClassAndMessage(string category, bool restart, string detail)
    {
        (SasPairingInitializationException failure, _, _) = Fail(category);

        Assert.Equal(Enum.Parse<SasPairingInitializationFailure>(category), failure.Failure);
        Assert.Equal(restart, failure.ProcessRestartRequired);
        Assert.Contains(detail, failure.Message, StringComparison.Ordinal);
        if (restart)
        {
            Assert.Contains("restart the OS process", failure.Message, StringComparison.Ordinal);
        }

        // The private loader exception is neither the thrown type nor kept as the inner exception.
        Assert.IsType<SasPairingInitializationException>(failure, exactMatch: true);
        Assert.Null(failure.InnerException);
    }

    [Fact]
    public void TheTranslationIsExhaustiveOneToOneAndByName()
    {
        NativeInitializationFailure[] internalCategories = Enum.GetValues<NativeInitializationFailure>();
        SasPairingInitializationFailure[] publicCategories = Enum.GetValues<SasPairingInitializationFailure>();
        Assert.Equal(7, internalCategories.Length);
        Assert.Equal(
            ["UnsupportedPointerWidth", "InvalidLibraryPath", "OpenFailed", "MissingSymbol", "BindingFailed", "AbiVersionQueryFailed", "AbiVersionMismatch"],
            Enum.GetNames<SasPairingInitializationFailure>());

        SasPairingInitializationFailure[] translated = [.. internalCategories.Select(NativeProcessContextSource.Translate)];
        Assert.Equal(publicCategories.Order(), translated.Order());
        foreach (NativeInitializationFailure category in internalCategories)
        {
            SasPairingInitializationFailure mapped = NativeProcessContextSource.Translate(category);
            Assert.Equal(category.ToString(), mapped.ToString());
            Assert.Equal(category.IsPostLoad(), new SasPairingInitializationException(mapped, "m").ProcessRestartRequired);
        }

        // A category without a public meaning fails loudly instead of defaulting to another category.
        Assert.Throws<ArgumentOutOfRangeException>(() => NativeProcessContextSource.Translate((NativeInitializationFailure)99));
        Assert.True(new SasPairingInitializationException((SasPairingInitializationFailure)99, "m").ProcessRestartRequired);
    }

    [Fact]
    public void ThePublicInitializationSurfaceLivesInThePublicNamespace()
    {
        Assert.Equal("SasPairing", typeof(SasPairingInitializationException).Namespace);
        Assert.True(typeof(SasPairingInitializationException).IsPublic);
        Assert.True(typeof(SasPairingInitializationFailure).IsPublic);
        Assert.Equal(typeof(SasPairingInitializationFailure), typeof(SasPairingInitializationException).GetProperty(nameof(SasPairingInitializationException.Failure))!.PropertyType);
        Assert.True(typeof(Exception).IsAssignableFrom(typeof(SasPairingInitializationException)));
        Assert.False(typeof(NativeInitializationException).IsAssignableFrom(typeof(SasPairingInitializationException)));
    }

    [Fact]
    public void APreLoadFailureMayBeRetriedAndALaterValidInitializationCreatesARuntime()
    {
        (SasPairingInitializationException failure, FakePlatform platform, NativeProcessContextSource source) = Fail("InvalidLibraryPath");
        Assert.Equal(SasPairingInitializationFailure.InvalidLibraryPath, failure.Failure);
        Assert.False(failure.ProcessRestartRequired);
        Assert.Empty(platform.Opened);

        using SasPairingRuntime runtime = SasPairingRuntime.Create(source, LibraryB);

        Assert.Equal([LibraryB], platform.Opened);
        Assert.NotNull(runtime.Context.Binding);
        Assert.Equal(1u, runtime.Context.Binding!.AbiVersion);
    }

    [Fact]
    public void APostLoadFailureIsPermanentAndNoAlternateImageIsLoaded()
    {
        (SasPairingInitializationException failure, FakePlatform platform, NativeProcessContextSource source) = Fail("AbiVersionMismatch");
        Assert.True(failure.ProcessRestartRequired);

        SasPairingInitializationException again = Assert.Throws<SasPairingInitializationException>(() => SasPairingRuntime.Create(source, LibraryB));

        Assert.Equal(SasPairingInitializationFailure.AbiVersionMismatch, again.Failure);
        Assert.True(again.ProcessRestartRequired);
        Assert.Equal([LibraryA], platform.Opened);
        Assert.Equal(1, FakeExports.VersionCalls);
    }

    [Fact]
    public void RuntimeRecreationReusesTheOneImageAndTheOneProcessContext()
    {
        (NativeProcessContextSource source, FakePlatform platform, List<FakeLifecycleApi> services) = SourceWith(_ => FakeImage.Complete(FakeExports.Version1));

        SasPairingRuntime first = SasPairingRuntime.Create(source, LibraryA);
        first.Dispose();
        using SasPairingRuntime second = SasPairingRuntime.Create(source, LibraryB);

        Assert.Same(first.Context, second.Context);
        Assert.Single(services);
        Assert.Equal([LibraryA], platform.Opened);
        Assert.Equal(1, FakeExports.VersionCalls);
        Assert.Equal(2, services[0].Count(FakeLifecycleApi.RuntimeCreateExport));
    }

    [Fact]
    public void AfterFatalAndRuntimeDisposalANewCreateFailsLocallyWithNoLoadAndNoNativeCall()
    {
        (NativeProcessContextSource source, FakePlatform platform, List<FakeLifecycleApi> services) = SourceWith(_ => FakeImage.Complete(FakeExports.Version1));
        SasPairingRuntime runtime = SasPairingRuntime.Create(source, LibraryA);
        FakeLifecycleApi native = Assert.Single(services);
        SasPairingAuthority authority = runtime.RegisterAuthority([0x01]);
        native.AuthorityStatusOutcome = () => new NativeAuthorityStatusOutcome(AbiV1Constants.SAS_PAIRING_FATAL, 0, 0);
        Assert.Throws<SasPairingNativeException>(() => authority.GetStatus());
        runtime.Dispose();
        int calls = native.Total;

        SasPairingNativeException refused = Assert.Throws<SasPairingNativeException>(() => SasPairingRuntime.Create(source, LibraryB));

        Assert.Equal(SasPairingStatus.Fatal, refused.KnownStatus);
        Assert.True(refused.ProcessRestartRequired);
        Assert.Equal(calls, native.Total);
        Assert.Equal([LibraryA], platform.Opened);
        Assert.Single(services);
    }

    [Fact]
    public void ANullPathIsAnArgumentErrorBeforeAnyInitialization()
    {
        Assert.Throws<ArgumentNullException>(() => SasPairingRuntime.Create(null!));
    }
}
