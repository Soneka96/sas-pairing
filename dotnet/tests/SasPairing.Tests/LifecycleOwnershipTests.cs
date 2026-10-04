using SasPairing.Interop;
using SasPairing.Tests.Support;
using static SasPairing.Tests.Support.FakeLifecycleApi;

namespace SasPairing.Tests;

/// <summary>
/// P9-D-002 ownership and disposal over a fake lifecycle-native service: exact arguments, one native cleanup
/// call per <c>Dispose</c>, native-cascade mirroring without child cleanup calls, consuming cleanup failures,
/// idempotent disposal, and local <see cref="ObjectDisposedException"/> refusal with no native call.
/// </summary>
public sealed class LifecycleOwnershipTests
{
    private static readonly byte[] Scope = [0x73, 0x00, 0x80, 0xFF, 0x01];

    [Fact]
    public void RuntimeCreateMakesOneCallAndKeepsTheExactNonZeroHandle()
    {
        (NativeProcessContext context, FakeLifecycleApi native) = FakeContext.Create();

        using SasPairingRuntime runtime = SasPairingRuntime.CreateIn(context);

        Assert.Equal(1, native.Count(RuntimeCreateExport));
        Assert.Equal(1, native.Total);
        Assert.NotEqual(0ul, runtime.Handle);
        Assert.Same(context, runtime.Context);
        Assert.False(runtime.IsDisposed);
    }

    [Fact]
    public void AFailedRuntimeCreateBuildsNoWrapperAndIgnoresTheOutputHandle()
    {
        (NativeProcessContext context, FakeLifecycleApi native) = FakeContext.Create();
        native.RuntimeCreateOutcome = () => new NativeCreateOutcome(AbiV1Constants.SAS_PAIRING_HANDLES_EXHAUSTED, 0x77);

        SasPairingNativeException failure = Assert.Throws<SasPairingNativeException>(() => SasPairingRuntime.CreateIn(context));

        Assert.Equal("SasPairingRuntime.Create", failure.Operation);
        Assert.Equal(SasPairingStatus.HandlesExhausted, failure.KnownStatus);
        Assert.False(failure.ProcessRestartRequired);
        Assert.False(context.IsFatal);
        Assert.False(context.IsContractViolated);
    }

    [Fact]
    public void ASecondLiveRuntimeSurfacesTheNativeAlreadyInitializedAndNeverAliasesTheFirst()
    {
        (NativeProcessContext context, FakeLifecycleApi native) = FakeContext.Create();
        SasPairingRuntime first = SasPairingRuntime.CreateIn(context);

        SasPairingNativeException second = Assert.Throws<SasPairingNativeException>(() => SasPairingRuntime.CreateIn(context));

        Assert.Equal(SasPairingStatus.AlreadyInitialized, second.KnownStatus);
        Assert.Equal(2, native.Count(RuntimeCreateExport));
        Assert.False(first.IsDisposed);

        // After a clean dispose another runtime may be created over the same context.
        first.Dispose();
        using SasPairingRuntime again = SasPairingRuntime.CreateIn(context);
        Assert.NotSame(first, again);
        Assert.Same(first.Context, again.Context);
        Assert.NotEqual(first.Handle, again.Handle);
    }

    [Fact]
    public void RegisterAuthorityPassesTheRuntimeHandleAndTheExactBinaryScope()
    {
        (NativeProcessContext context, FakeLifecycleApi native) = FakeContext.Create();
        using SasPairingRuntime runtime = SasPairingRuntime.CreateIn(context);

        SasPairingAuthority authority = runtime.RegisterAuthority(Scope);

        Assert.Equal([runtime.Handle, (ulong)Scope.Length], native.ArgumentsOf(AuthorityRegisterExport));
        Assert.Equal(Scope, Assert.Single(native.Scopes));
        Assert.Equal(5, native.Scopes[0].Length); // the NUL bytes are data: nothing is truncated or terminated
        Assert.NotEqual(0ul, authority.Handle);
        Assert.Same(runtime, authority.Runtime);
        Assert.Equal(1, runtime.AuthorityCount);
    }

    [Fact]
    public void AnEmptyScopeIsPassedAsLengthZeroAndTheNativeAnswerIsSurfaced()
    {
        (NativeProcessContext context, FakeLifecycleApi native) = FakeContext.Create();
        using SasPairingRuntime runtime = SasPairingRuntime.CreateIn(context);
        native.AuthorityRegisterOutcome = () => new NativeCreateOutcome(AbiV1Constants.SAS_PAIRING_INVALID_SCOPE, 0);

        SasPairingNativeException failure = Assert.Throws<SasPairingNativeException>(() => runtime.RegisterAuthority([]));

        Assert.Equal(SasPairingStatus.InvalidScope, failure.KnownStatus);
        Assert.Empty(Assert.Single(native.Scopes));
        Assert.Equal(0, runtime.AuthorityCount);
    }

    [Fact]
    public void CreateHostPassesTheRuntimeAndAuthorityHandles()
    {
        (NativeProcessContext context, FakeLifecycleApi native) = FakeContext.Create();
        using SasPairingRuntime runtime = SasPairingRuntime.CreateIn(context);
        SasPairingAuthority authority = runtime.RegisterAuthority(Scope);

        SasPairingHost host = authority.CreateHost();

        Assert.Equal([runtime.Handle, authority.Handle], native.ArgumentsOf(HostCreateExport));
        Assert.NotEqual(0ul, host.Handle);
        Assert.Same(authority, host.Authority);
        Assert.Equal(1, authority.HostCount);
        Assert.Equal([runtime.Handle, authority.Handle], native.Calls.Single(c => c.Export == HostCreateExport).Arguments);
    }

    [Fact]
    public void HostDisposeMakesExactlyOneDestroyCallAndIsIdempotent()
    {
        (NativeProcessContext context, FakeLifecycleApi native) = FakeContext.Create();
        using SasPairingRuntime runtime = SasPairingRuntime.CreateIn(context);
        SasPairingAuthority authority = runtime.RegisterAuthority(Scope);
        SasPairingHost a = authority.CreateHost();
        SasPairingHost b = authority.CreateHost();

        a.Dispose();
        a.Dispose();

        Assert.True(a.IsDisposed);
        Assert.Equal(1, native.Count(HostDestroyExport));
        Assert.Equal([runtime.Handle, a.Handle], native.ArgumentsOf(HostDestroyExport));
        Assert.False(b.IsDisposed);
        Assert.False(authority.IsDisposed);
        Assert.Equal(1, authority.HostCount);
        Assert.Equal(SasPairingAuthorityState.Ready, authority.GetStatus().State);
    }

    [Fact]
    public void AuthorityDisposeMakesOneReleaseCallAndNoHostCallAndInvalidatesItsHosts()
    {
        (NativeProcessContext context, FakeLifecycleApi native) = FakeContext.Create();
        using SasPairingRuntime runtime = SasPairingRuntime.CreateIn(context);
        SasPairingAuthority authority = runtime.RegisterAuthority(Scope);
        SasPairingHost a = authority.CreateHost();
        SasPairingHost b = authority.CreateHost();

        authority.Dispose();

        Assert.Equal(1, native.Count(AuthorityReleaseExport));
        Assert.Equal([runtime.Handle, authority.Handle], native.ArgumentsOf(AuthorityReleaseExport));
        Assert.Equal(0, native.Count(HostDestroyExport));
        Assert.True(authority.IsDisposed);
        Assert.True(a.IsDisposed);
        Assert.True(b.IsDisposed);
        Assert.Equal(0, authority.HostCount);
        Assert.Equal(0, runtime.AuthorityCount);

        // A cascaded child and the authority itself are no-ops from now on.
        int calls = native.Total;
        a.Dispose();
        b.Dispose();
        authority.Dispose();
        Assert.Equal(calls, native.Total);
        Assert.Equal(1, native.Count(AuthorityReleaseExport));
    }

    [Fact]
    public void RuntimeDisposeMakesOneDestroyCallAndNoDescendantCallAndInvalidatesTheWholeTree()
    {
        (NativeProcessContext context, FakeLifecycleApi native) = FakeContext.Create();
        SasPairingRuntime runtime = SasPairingRuntime.CreateIn(context);
        SasPairingAuthority first = runtime.RegisterAuthority(Scope);
        SasPairingAuthority second = runtime.RegisterAuthority([0xFF]);
        SasPairingHost[] hosts = [first.CreateHost(), first.CreateHost(), second.CreateHost()];

        runtime.Dispose();

        Assert.Equal(1, native.Count(RuntimeDestroyExport));
        Assert.Equal([runtime.Handle], native.ArgumentsOf(RuntimeDestroyExport));
        Assert.Equal(0, native.Count(AuthorityReleaseExport));
        Assert.Equal(0, native.Count(HostDestroyExport));
        Assert.True(runtime.IsDisposed);
        Assert.True(first.IsDisposed);
        Assert.True(second.IsDisposed);
        Assert.All(hosts, host => Assert.True(host.IsDisposed));
        Assert.Equal(0, runtime.AuthorityCount);
        Assert.Equal(0, first.HostCount);

        int calls = native.Total;
        foreach (SasPairingHost host in hosts)
        {
            host.Dispose();
        }

        first.Dispose();
        second.Dispose();
        runtime.Dispose();
        Assert.Equal(calls, native.Total);
    }

    [Theory]
    [InlineData(AbiV1Constants.SAS_PAIRING_OWNERSHIP_UNCERTAIN)]
    [InlineData(AbiV1Constants.SAS_PAIRING_INVALID_HANDLE)]
    [InlineData(777)]
    public void AFailedAuthorityReleaseIsConsumingAndNeverRetried(int status)
    {
        (NativeProcessContext context, FakeLifecycleApi native) = FakeContext.Create();
        using SasPairingRuntime runtime = SasPairingRuntime.CreateIn(context);
        SasPairingAuthority authority = runtime.RegisterAuthority(Scope);
        SasPairingHost a = authority.CreateHost();
        SasPairingHost b = authority.CreateHost();
        native.AuthorityReleaseStatus = status;

        SasPairingNativeException failure = Assert.Throws<SasPairingNativeException>(authority.Dispose);

        Assert.Equal("SasPairingAuthority.Dispose", failure.Operation);
        Assert.Equal(status, failure.StatusCode);
        Assert.True(authority.IsDisposed);
        Assert.True(a.IsDisposed);
        Assert.True(b.IsDisposed);
        Assert.Equal(0, runtime.AuthorityCount);

        authority.Dispose();
        a.Dispose();
        Assert.Equal(1, native.Count(AuthorityReleaseExport));
        Assert.Equal(0, native.Count(HostDestroyExport));
        Assert.False(context.IsFatal);
    }

    [Fact]
    public void AFailedHostDestroyIsConsumingAndNeverRetried()
    {
        (NativeProcessContext context, FakeLifecycleApi native) = FakeContext.Create();
        using SasPairingRuntime runtime = SasPairingRuntime.CreateIn(context);
        SasPairingAuthority authority = runtime.RegisterAuthority(Scope);
        SasPairingHost host = authority.CreateHost();
        native.HostDestroyStatus = AbiV1Constants.SAS_PAIRING_OWNERSHIP_UNCERTAIN;

        SasPairingNativeException failure = Assert.Throws<SasPairingNativeException>(host.Dispose);

        Assert.Equal(SasPairingStatus.OwnershipUncertain, failure.KnownStatus);
        Assert.Equal("SasPairingHost.Dispose", failure.Operation);
        Assert.True(host.IsDisposed);
        Assert.Equal(0, authority.HostCount);
        host.Dispose();
        Assert.Equal(1, native.Count(HostDestroyExport));

        // The authority stays usable and its release no longer involves the failed host.
        Assert.False(authority.IsDisposed);
        authority.Dispose();
        Assert.Equal(1, native.Count(AuthorityReleaseExport));
    }

    [Fact]
    public void AFailedRuntimeDestroyIsConsumingAndNeverRetried()
    {
        (NativeProcessContext context, FakeLifecycleApi native) = FakeContext.Create();
        SasPairingRuntime runtime = SasPairingRuntime.CreateIn(context);
        SasPairingAuthority authority = runtime.RegisterAuthority(Scope);
        SasPairingHost host = authority.CreateHost();
        native.RuntimeDestroyStatus = AbiV1Constants.SAS_PAIRING_INVALID_HANDLE;

        SasPairingNativeException failure = Assert.Throws<SasPairingNativeException>(runtime.Dispose);

        Assert.Equal("SasPairingRuntime.Dispose", failure.Operation);
        Assert.Equal(SasPairingStatus.InvalidHandle, failure.KnownStatus);
        Assert.True(runtime.IsDisposed);
        Assert.True(authority.IsDisposed);
        Assert.True(host.IsDisposed);
        runtime.Dispose();
        host.Dispose();
        authority.Dispose();
        Assert.Equal(1, native.Count(RuntimeDestroyExport));
        Assert.Equal(0, native.Count(AuthorityReleaseExport));
        Assert.Equal(0, native.Count(HostDestroyExport));
    }

    [Fact]
    public void EveryNormalOperationOnADisposedWrapperFailsLocallyWithoutANativeCall()
    {
        (NativeProcessContext context, FakeLifecycleApi native) = FakeContext.Create();
        SasPairingRuntime runtime = SasPairingRuntime.CreateIn(context);
        SasPairingAuthority released = runtime.RegisterAuthority(Scope);
        SasPairingAuthority cascaded = runtime.RegisterAuthority([0x02]);
        released.Dispose();
        runtime.Dispose();
        int calls = native.Total;

        Assert.Throws<ObjectDisposedException>(() => runtime.RegisterAuthority(Scope));
        Assert.Throws<ObjectDisposedException>(() => released.GetStatus());
        Assert.Throws<ObjectDisposedException>(() => released.CreateHost());
        Assert.Throws<ObjectDisposedException>(() => cascaded.GetStatus());
        Assert.Throws<ObjectDisposedException>(() => cascaded.CreateHost());

        Assert.Equal(calls, native.Total);
        Assert.Equal(typeof(SasPairingRuntime).FullName, Assert.Throws<ObjectDisposedException>(() => runtime.RegisterAuthority(Scope)).ObjectName);
    }

    [Fact]
    public void ConcurrentDisposeMakesOneNativeCall()
    {
        (NativeProcessContext context, FakeLifecycleApi native) = FakeContext.Create();
        using SasPairingRuntime runtime = SasPairingRuntime.CreateIn(context);
        SasPairingAuthority authority = runtime.RegisterAuthority(Scope);
        SasPairingHost host = authority.CreateHost();
        Exception?[] errors = new Exception?[16];
        using Barrier barrier = new(errors.Length);
        Thread[] threads =
        [
            .. Enumerable.Range(0, errors.Length).Select(i => new Thread(() =>
            {
                barrier.SignalAndWait();
                try
                {
                    if (i % 2 == 0)
                    {
                        host.Dispose();
                    }
                    else
                    {
                        authority.Dispose();
                    }
                }
                catch (Exception error)
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
        Assert.Equal(1, native.Count(AuthorityReleaseExport));
        Assert.True(native.Count(HostDestroyExport) <= 1);
        Assert.True(host.IsDisposed);
        Assert.True(authority.IsDisposed);
    }

    [Fact]
    public void WrappersUseReferenceIdentityAndNeverPrintAHandleOrScope()
    {
        (NativeProcessContext context, FakeLifecycleApi native) = FakeContext.Create();
        using SasPairingRuntime runtime = SasPairingRuntime.CreateIn(context);
        SasPairingAuthority authority = runtime.RegisterAuthority(Scope);
        SasPairingHost host = authority.CreateHost();
        native.AuthorityStatusOutcome = () => new NativeAuthorityStatusOutcome(AbiV1Constants.SAS_PAIRING_RESOURCE_LIMITED, 0, 0);

        Assert.Equal(typeof(object), typeof(SasPairingRuntime).GetMethod(nameof(Equals), [typeof(object)])!.DeclaringType);
        Assert.Equal(typeof(object), typeof(SasPairingAuthority).GetMethod(nameof(GetHashCode), Type.EmptyTypes)!.DeclaringType);
        Assert.Equal(typeof(object), typeof(SasPairingHost).GetMethod(nameof(ToString), Type.EmptyTypes)!.DeclaringType);

        string[] texts =
        [
            runtime.ToString()!, authority.ToString()!, host.ToString()!,
            Assert.Throws<SasPairingNativeException>(() => authority.GetStatus()).ToString(),
        ];
        foreach (ulong handle in new[] { runtime.Handle, authority.Handle, host.Handle })
        {
            foreach (string text in texts)
            {
                Assert.DoesNotContain(handle.ToString(System.Globalization.CultureInfo.InvariantCulture), text, StringComparison.Ordinal);
                Assert.DoesNotContain(handle.ToString("x", System.Globalization.CultureInfo.InvariantCulture), text, StringComparison.OrdinalIgnoreCase);
            }
        }

        Assert.DoesNotContain(Convert.ToHexString(Scope), texts[3], StringComparison.OrdinalIgnoreCase);
    }
}
