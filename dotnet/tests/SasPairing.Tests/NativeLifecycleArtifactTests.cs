using SasPairing.Interop;

namespace SasPairing.Tests;

/// <summary>
/// The real native tests share one process loader, one native image, one native runtime slot, and the
/// process-lifetime authority accounting. They run in this one non-parallel collection (the whole suite is
/// sequential as well), and every test disposes the runtime it creates. Nothing is ever reset.
/// </summary>
[CollectionDefinition(Name, DisableParallelization = true)]
public sealed class RealNativeTests
{
    internal const string Name = "Real native library";
}

/// <summary>
/// The P9.2 lifecycle through the PUBLIC API against the real native library named by
/// <c>SAS_PAIRING_NATIVE_LIBRARY</c> (built from the same commit in CI). On Windows: runtime, a binary-scope
/// authority, hosts, status, and the disposal cascade. On Linux: the runtime exists and authority registration
/// fails closed with <see cref="SasPairingStatus.UnsupportedPlatform"/>; that is not Linux pairing support. No
/// listener, network, or ceremony operation is made.
/// </summary>
[Collection(RealNativeTests.Name)]
public sealed class NativeLifecycleArtifactTests
{
    /// <summary>A scope unique to this test run, containing NUL, 0x80, and 0xFF bytes: binary, not text.</summary>
    private static byte[] UniqueBinaryScope() => [.. "sas-pairing-dotnet-p9.2-"u8, 0x00, 0x80, 0xFF, .. Guid.NewGuid().ToByteArray(), 0x00];

    [Fact]
    public void ThePublicLifecycleRunsAgainstTheRealLibraryAsThePlatformDefines()
    {
        string path = NativeArtifactTests.ArtifactPath();
        SasPairingRuntime runtime = SasPairingRuntime.Create(path);
        try
        {
            Assert.False(runtime.IsDisposed);
            Assert.Same(NativeAbiV1Loader.Process.Initialize(path), runtime.Context.Binding);
            byte[] scope = UniqueBinaryScope();

            if (OperatingSystem.IsWindows())
            {
                SasPairingAuthority authority = runtime.RegisterAuthority(scope);
                Assert.Equal(new SasPairingAuthorityStatus(SasPairingAuthorityState.Ready, 10), authority.GetStatus());

                SasPairingHost a = authority.CreateHost();
                SasPairingHost b = authority.CreateHost();
                a.Dispose();
                Assert.True(a.IsDisposed);
                Assert.False(b.IsDisposed);

                // Host creation and destruction are accounting neutral.
                Assert.Equal(new SasPairingAuthorityStatus(SasPairingAuthorityState.Ready, 10), authority.GetStatus());

                authority.Dispose();
                Assert.True(authority.IsDisposed);
                Assert.True(b.IsDisposed); // by the native release cascade, without a destroy call of its own
                b.Dispose();
                Assert.Throws<ObjectDisposedException>(() => authority.GetStatus());
                Assert.Throws<ObjectDisposedException>(() => authority.CreateHost());

                // The same binary scope registers again after the release (the OS ownership was released).
                SasPairingAuthority again = runtime.RegisterAuthority(scope);
                SasPairingHost c = again.CreateHost();
                runtime.Dispose();
                Assert.True(again.IsDisposed);
                Assert.True(c.IsDisposed);
            }
            else
            {
                SasPairingNativeException failure = Assert.Throws<SasPairingNativeException>(() => runtime.RegisterAuthority(scope));
                Assert.Equal("SasPairingRuntime.RegisterAuthority", failure.Operation);
                Assert.Equal(103, failure.StatusCode);
                Assert.Equal(SasPairingStatus.UnsupportedPlatform, failure.KnownStatus);
                Assert.False(failure.ProcessRestartRequired);
                Assert.False(runtime.IsDisposed);
                runtime.Dispose();
            }

            Assert.True(runtime.IsDisposed);
            Assert.False(runtime.Context.IsFatal);
            Assert.False(runtime.Context.IsContractViolated);
        }
        finally
        {
            runtime.Dispose();
        }
    }

    [Fact]
    public void TheRealLibraryAnswersAnEmptyScopeWithInvalidScope()
    {
        using SasPairingRuntime runtime = SasPairingRuntime.Create(NativeArtifactTests.ArtifactPath());

        SasPairingNativeException failure = Assert.Throws<SasPairingNativeException>(() => runtime.RegisterAuthority([]));

        Assert.Equal(SasPairingStatus.InvalidScope, failure.KnownStatus);
        Assert.False(runtime.Context.IsFatal);
    }

    [Fact]
    public void ASecondLiveRuntimeIsRefusedNativelyAndRecreationReusesTheImageAndTheProcessContext()
    {
        string path = NativeArtifactTests.ArtifactPath();
        INativeImage? image;
        SasPairingRuntime first = SasPairingRuntime.Create(path);
        try
        {
            image = NativeAbiV1Loader.Process.RetainedImage;
            Assert.NotNull(image);

            SasPairingNativeException second = Assert.Throws<SasPairingNativeException>(() => SasPairingRuntime.Create(path));
            Assert.Equal(SasPairingStatus.AlreadyInitialized, second.KnownStatus);
            Assert.False(second.ProcessRestartRequired);
            Assert.False(first.IsDisposed);
        }
        finally
        {
            first.Dispose();
        }

        // A runtime created after a clean dispose uses the same image and process context: no reload, no
        // fresh security session, no latch reset.
        using SasPairingRuntime recreated = SasPairingRuntime.Create(path);
        Assert.Same(first.Context, recreated.Context);
        Assert.Same(image, NativeAbiV1Loader.Process.RetainedImage);
        Assert.Equal(NativeLoaderState.Ready, NativeAbiV1Loader.Process.State);
        Assert.Throws<ObjectDisposedException>(() => first.RegisterAuthority(UniqueBinaryScope()));
    }

    [Fact]
    public void RegisteringTheSameScopeTwiceIsRefusedByTheRealLibraryOnWindows()
    {
        using SasPairingRuntime runtime = SasPairingRuntime.Create(NativeArtifactTests.ArtifactPath());
        byte[] scope = UniqueBinaryScope();

        if (OperatingSystem.IsWindows())
        {
            using SasPairingAuthority authority = runtime.RegisterAuthority(scope);
            SasPairingNativeException duplicate = Assert.Throws<SasPairingNativeException>(() => runtime.RegisterAuthority(scope));
            Assert.Equal(SasPairingStatus.AlreadyRegistered, duplicate.KnownStatus);
            Assert.Equal(SasPairingAuthorityState.Ready, authority.GetStatus().State);
        }
        else
        {
            Assert.Equal(SasPairingStatus.UnsupportedPlatform, Assert.Throws<SasPairingNativeException>(() => runtime.RegisterAuthority(scope)).KnownStatus);
        }
    }
}
