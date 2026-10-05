using SasPairing.Interop;
using SasPairing.Tests.Support;
using static SasPairing.Tests.Support.FakeLifecycleApi;

namespace SasPairing.Tests;

/// <summary>
/// P9-D-002 fail-closed state over a fake lifecycle-native service: the authority status success contract
/// (READY 1 to 10, BUSY 0, EXHAUSTED 0) checked per snapshot, unknown statuses, the process FATAL latch, the
/// process contract-violation latch, their admission order, and cleanup that stays allowed after both.
/// </summary>
public sealed class FailClosedStateTests
{
    private static readonly byte[] Scope = [0x00, 0x80, 0xFF];

    private static (NativeProcessContext Context, FakeLifecycleApi Native, SasPairingRuntime Runtime, SasPairingAuthority Authority, SasPairingHost Host) Tree()
    {
        (NativeProcessContext context, FakeLifecycleApi native) = FakeContext.Create();
        SasPairingRuntime runtime = SasPairingRuntime.CreateIn(context);
        SasPairingAuthority authority = runtime.RegisterAuthority(Scope);
        SasPairingHost host = authority.CreateHost();
        return (context, native, runtime, authority, host);
    }

    private static NativeAuthorityStatusOutcome Ok(uint state, uint remaining) => new(AbiV1Constants.SAS_PAIRING_OK, state, remaining);

    /// <summary>Every normal operation reachable on the tree, each of which must be refused locally.</summary>
    private static void AssertNormalWorkIsRefusedLocally<TException>(NativeProcessContext context, FakeLifecycleApi native, SasPairingRuntime runtime, SasPairingAuthority authority)
        where TException : Exception
    {
        int calls = native.Total;
        Assert.Throws<TException>(() => authority.GetStatus());
        Assert.Throws<TException>(() => authority.CreateHost());
        Assert.Throws<TException>(() => runtime.RegisterAuthority(Scope));
        Assert.Throws<TException>(() => SasPairingRuntime.CreateIn(context));
        Assert.Equal(calls, native.Total);
    }

    [Theory]
    [InlineData(1u)]
    [InlineData(4u)]
    [InlineData(10u)]
    public void ReadyAcceptsExactlyOneToTen(uint remaining)
    {
        (_, FakeLifecycleApi native, SasPairingRuntime runtime, SasPairingAuthority authority, _) = Tree();
        using SasPairingRuntime owner = runtime;
        native.AuthorityStatusOutcome = () => Ok(AbiV1Constants.SAS_PAIRING_AUTHORITY_READY, remaining);

        Assert.Equal(new SasPairingAuthorityStatus(SasPairingAuthorityState.Ready, remaining), authority.GetStatus());
        Assert.Equal([runtime.Handle, authority.Handle], native.ArgumentsOf(AuthorityStatusExport));
    }

    [Fact]
    public void BusyAndExhaustedRequireZero()
    {
        (_, FakeLifecycleApi native, SasPairingRuntime runtime, SasPairingAuthority authority, _) = Tree();
        using SasPairingRuntime owner = runtime;

        native.AuthorityStatusOutcome = () => Ok(AbiV1Constants.SAS_PAIRING_AUTHORITY_BUSY, 0);
        Assert.Equal(new SasPairingAuthorityStatus(SasPairingAuthorityState.Busy, 0), authority.GetStatus());
        native.AuthorityStatusOutcome = () => Ok(AbiV1Constants.SAS_PAIRING_AUTHORITY_EXHAUSTED, 0);
        Assert.Equal(new SasPairingAuthorityStatus(SasPairingAuthorityState.Exhausted, 0), authority.GetStatus());
    }

    [Fact]
    public void EachSnapshotIsValidatedAloneWithNoAccountingOfItsOwn()
    {
        (NativeProcessContext context, FakeLifecycleApi native, SasPairingRuntime runtime, SasPairingAuthority authority, _) = Tree();
        using SasPairingRuntime owner = runtime;
        Queue<uint> sequence = new([1u, 10u, 4u, 10u]);
        native.AuthorityStatusOutcome = () => Ok(AbiV1Constants.SAS_PAIRING_AUTHORITY_READY, sequence.Dequeue());

        uint[] seen = [.. Enumerable.Range(0, 4).Select(_ => authority.GetStatus().RemainingOpportunities)];

        Assert.Equal([1u, 10u, 4u, 10u], seen);
        Assert.False(context.IsContractViolated);
    }

    [Theory]
    [InlineData("runtime_create OK + handle 0")]
    [InlineData("authority_register OK + handle 0")]
    [InlineData("host_create OK + handle 0")]
    [InlineData("status OK + INVALID state")]
    [InlineData("status OK + unknown state")]
    [InlineData("READY + 0")]
    [InlineData("READY + 11")]
    [InlineData("READY + uint.MaxValue")]
    [InlineData("BUSY + 1")]
    [InlineData("EXHAUSTED + 1")]
    public void AnImpossibleSuccessOutputLatchesTheContractViolationAndOnlyCleanupContinues(string violation)
    {
        (NativeProcessContext context, FakeLifecycleApi native) = FakeContext.Create();
        SasPairingRuntime? runtime = violation.StartsWith("runtime_create", StringComparison.Ordinal) ? null : SasPairingRuntime.CreateIn(context);
        SasPairingAuthority? authority = violation.StartsWith("runtime_create", StringComparison.Ordinal) || violation.StartsWith("authority_register", StringComparison.Ordinal) ? null : runtime!.RegisterAuthority(Scope);
        SasPairingHost? host = authority?.CreateHost();
        NativeAuthorityStatusOutcome? status = violation switch
        {
            "status OK + INVALID state" => Ok(AbiV1Constants.SAS_PAIRING_AUTHORITY_STATE_INVALID, 0),
            "status OK + unknown state" => Ok(4, 1),
            "READY + 0" => Ok(AbiV1Constants.SAS_PAIRING_AUTHORITY_READY, 0),
            "READY + 11" => Ok(AbiV1Constants.SAS_PAIRING_AUTHORITY_READY, 11),
            "READY + uint.MaxValue" => Ok(AbiV1Constants.SAS_PAIRING_AUTHORITY_READY, uint.MaxValue),
            "BUSY + 1" => Ok(AbiV1Constants.SAS_PAIRING_AUTHORITY_BUSY, 1),
            "EXHAUSTED + 1" => Ok(AbiV1Constants.SAS_PAIRING_AUTHORITY_EXHAUSTED, 1),
            _ => null,
        };
        NativeCreateOutcome zero = new(AbiV1Constants.SAS_PAIRING_OK, 0);
        native.RuntimeCreateOutcome = violation.StartsWith("runtime_create", StringComparison.Ordinal) ? () => zero : null;
        native.AuthorityRegisterOutcome = () => zero;
        native.HostCreateOutcome = () => zero;
        native.AuthorityStatusOutcome = status is { } s ? () => s : null;
        Action act = violation switch
        {
            "runtime_create OK + handle 0" => () => SasPairingRuntime.CreateIn(context),
            "authority_register OK + handle 0" => () => runtime!.RegisterAuthority(Scope),
            "host_create OK + handle 0" => () => authority!.CreateHost(),
            _ => () => authority!.GetStatus(),
        };
        int hostsBefore = authority?.HostCount ?? 0;
        int authoritiesBefore = runtime?.AuthorityCount ?? 0;

        SasPairingContractException failure = Assert.Throws<SasPairingContractException>(act);

        Assert.True(failure.ProcessRestartRequired);
        Assert.Contains("reported success", failure.Message, StringComparison.Ordinal);
        Assert.True(context.IsContractViolated);
        Assert.False(context.IsFatal);
        Assert.Equal(hostsBefore, authority?.HostCount ?? 0); // no wrapper was built from an impossible output
        Assert.Equal(authoritiesBefore, runtime?.AuthorityCount ?? 0);

        // Later normal work is refused locally, with no native call...
        native.RuntimeCreateOutcome = null;
        native.AuthorityStatusOutcome = null;
        int calls = native.Total;
        Assert.Throws<SasPairingContractException>(() => SasPairingRuntime.CreateIn(context));
        if (runtime is not null)
        {
            Assert.Throws<SasPairingContractException>(() => runtime.RegisterAuthority(Scope));
        }

        if (authority is not null)
        {
            Assert.Throws<SasPairingContractException>(() => authority.GetStatus());
            Assert.Throws<SasPairingContractException>(() => authority.CreateHost());
        }

        Assert.Equal(calls, native.Total);

        // ...while cleanup of every existing wrapper still makes its one native call.
        host?.Dispose();
        authority?.Dispose();
        runtime?.Dispose();
        Assert.Equal(host is null ? 0 : 1, native.Count(HostDestroyExport));
        Assert.Equal(authority is null ? 0 : 1, native.Count(AuthorityReleaseExport));
        Assert.Equal(runtime is null ? 0 : 1, native.Count(RuntimeDestroyExport));
        Assert.True(context.IsContractViolated);
    }

    [Fact]
    public void AnUnknownStatusIsAPreservedFailureThatIsNeitherSuccessNorFatal()
    {
        (NativeProcessContext context, FakeLifecycleApi native, SasPairingRuntime runtime, SasPairingAuthority authority, _) = Tree();
        using SasPairingRuntime owner = runtime;
        native.AuthorityStatusOutcome = () => new NativeAuthorityStatusOutcome(777, AbiV1Constants.SAS_PAIRING_AUTHORITY_READY, 10);

        SasPairingNativeException failure = Assert.Throws<SasPairingNativeException>(() => authority.GetStatus());

        Assert.Equal(777, failure.StatusCode);
        Assert.Null(failure.KnownStatus);
        Assert.False(failure.ProcessRestartRequired);
        Assert.Contains("unknown status 777", failure.Message, StringComparison.Ordinal);
        Assert.False(context.IsFatal);
        Assert.False(context.IsContractViolated);

        // Not latched: the next normal call reaches the native library again.
        native.AuthorityStatusOutcome = null;
        int calls = native.Count(AuthorityStatusExport);
        Assert.Equal(SasPairingAuthorityState.Ready, authority.GetStatus().State);
        Assert.Equal(calls + 1, native.Count(AuthorityStatusExport));
    }

    [Theory]
    [InlineData("status")]
    [InlineData("register")]
    [InlineData("host_create")]
    public void NativeFatalFromANormalOperationLatchesAndRefusesEveryLaterNormalOperationLocally(string operation)
    {
        (NativeProcessContext context, FakeLifecycleApi native, SasPairingRuntime runtime, SasPairingAuthority authority, SasPairingHost host) = Tree();
        NativeCreateOutcome fatal = new(AbiV1Constants.SAS_PAIRING_FATAL, 0x99);
        native.AuthorityStatusOutcome = () => new NativeAuthorityStatusOutcome(AbiV1Constants.SAS_PAIRING_FATAL, 0, 0);
        native.AuthorityRegisterOutcome = () => fatal;
        native.HostCreateOutcome = () => fatal;
        Action act = operation switch
        {
            "status" => () => authority.GetStatus(),
            "register" => () => runtime.RegisterAuthority(Scope),
            _ => () => authority.CreateHost(),
        };

        SasPairingNativeException failure = Assert.Throws<SasPairingNativeException>(act);

        Assert.Equal(900, failure.StatusCode);
        Assert.Equal(SasPairingStatus.Fatal, failure.KnownStatus);
        Assert.True(failure.ProcessRestartRequired);
        Assert.True(context.IsFatal);

        int calls = native.Total;
        SasPairingNativeException refused = Assert.Throws<SasPairingNativeException>(() => authority.GetStatus());
        Assert.Equal(SasPairingStatus.Fatal, refused.KnownStatus);
        Assert.True(refused.ProcessRestartRequired);
        Assert.Contains("without entering the native library", refused.Message, StringComparison.Ordinal);
        Assert.Equal(calls, native.Total);
        AssertNormalWorkIsRefusedLocally<SasPairingNativeException>(context, native, runtime, authority);

        // Cleanup still enters the native library, once per undisposed wrapper, without admission.
        host.Dispose();
        authority.Dispose();
        runtime.Dispose();
        Assert.Equal(1, native.Count(HostDestroyExport));
        Assert.Equal(1, native.Count(AuthorityReleaseExport));
        Assert.Equal(1, native.Count(RuntimeDestroyExport));
        Assert.True(context.IsFatal);
    }

    [Fact]
    public void NativeFatalFromCleanupStillDisposesTheWrapperAndLatches()
    {
        (NativeProcessContext context, FakeLifecycleApi native, SasPairingRuntime runtime, SasPairingAuthority authority, SasPairingHost host) = Tree();
        native.HostDestroyStatus = AbiV1Constants.SAS_PAIRING_FATAL;

        SasPairingNativeException failure = Assert.Throws<SasPairingNativeException>(host.Dispose);

        Assert.True(failure.ProcessRestartRequired);
        Assert.True(host.IsDisposed);
        Assert.True(context.IsFatal);
        AssertNormalWorkIsRefusedLocally<SasPairingNativeException>(context, native, runtime, authority);

        native.AuthorityReleaseStatus = AbiV1Constants.SAS_PAIRING_FATAL;
        Assert.Throws<SasPairingNativeException>(authority.Dispose);
        Assert.True(authority.IsDisposed);
        runtime.Dispose();
        Assert.Equal(1, native.Count(RuntimeDestroyExport));
        Assert.True(context.IsFatal);
    }

    [Fact]
    public void RecreatingTheRuntimeNeverClearsEitherLatch()
    {
        (NativeProcessContext context, FakeLifecycleApi native) = FakeContext.Create();
        SasPairingRuntime runtime = SasPairingRuntime.CreateIn(context);
        SasPairingAuthority authority = runtime.RegisterAuthority(Scope);
        native.AuthorityStatusOutcome = () => new NativeAuthorityStatusOutcome(AbiV1Constants.SAS_PAIRING_FATAL, 0, 0);
        Assert.Throws<SasPairingNativeException>(() => authority.GetStatus());
        runtime.Dispose();
        int creates = native.Count(RuntimeCreateExport);

        SasPairingNativeException refused = Assert.Throws<SasPairingNativeException>(() => SasPairingRuntime.CreateIn(context));

        Assert.Equal(SasPairingStatus.Fatal, refused.KnownStatus);
        Assert.Equal(creates, native.Count(RuntimeCreateExport));
        Assert.True(context.IsFatal);
    }

    [Fact]
    public void AdmissionOrderIsDisposedThenContractThenFatal()
    {
        (NativeProcessContext context, FakeLifecycleApi native, SasPairingRuntime runtime, SasPairingAuthority authority, _) = Tree();
        SasPairingAuthority released = runtime.RegisterAuthority([0x01]);
        released.Dispose();
        native.AuthorityStatusOutcome = () => new NativeAuthorityStatusOutcome(AbiV1Constants.SAS_PAIRING_FATAL, 0, 0);
        Assert.Throws<SasPairingNativeException>(() => authority.GetStatus());
        native.HostCreateOutcome = () => new NativeCreateOutcome(AbiV1Constants.SAS_PAIRING_OK, 0);

        // Fatal alone is latched: a fatal refusal, no native call (so no contract violation can be observed).
        Assert.Equal(SasPairingStatus.Fatal, Assert.Throws<SasPairingNativeException>(() => authority.CreateHost()).KnownStatus);
        Assert.False(context.IsContractViolated);

        // With both latched the contract violation wins; a disposed wrapper fails before either.
        context.ViolateContract("test", "simulated");
        int calls = native.Total;
        Assert.Throws<SasPairingContractException>(() => authority.GetStatus());
        Assert.Throws<ObjectDisposedException>(() => released.GetStatus());
        Assert.Equal(calls, native.Total);
        runtime.Dispose();
        Assert.Equal(1, native.Count(RuntimeDestroyExport));
    }
}
