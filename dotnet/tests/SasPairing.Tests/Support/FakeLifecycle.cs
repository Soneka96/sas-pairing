using SasPairing.Interop;

namespace SasPairing.Tests.Support;

/// <summary>
/// A fake lifecycle-native service that models the native single-runtime rule and records every call with its
/// exact arguments. By default every create succeeds with a fresh distinctive handle and every status is
/// READY 10; each operation can be overridden. Nothing native is loaded.
/// </summary>
internal sealed class FakeLifecycleApi : INativeLifecycleApi
{
    internal const string RuntimeCreateExport = "sas_pairing_runtime_create";
    internal const string RuntimeDestroyExport = "sas_pairing_runtime_destroy";
    internal const string AuthorityRegisterExport = "sas_pairing_authority_register";
    internal const string AuthorityReleaseExport = "sas_pairing_authority_release";
    internal const string AuthorityStatusExport = "sas_pairing_authority_status";
    internal const string HostCreateExport = "sas_pairing_host_create";
    internal const string HostDestroyExport = "sas_pairing_host_destroy";

    // Distinctive handle values, so that a leak into a message or ToString can be searched for.
    private ulong _next = 0x5A5A_0000_0000_1000;
    private ulong _activeRuntime;

    internal List<(string Export, ulong[] Arguments)> Calls { get; } = [];

    /// <summary>The exact scope bytes of every register call, copied during the call.</summary>
    internal List<byte[]> Scopes { get; } = [];

    internal Func<NativeCreateOutcome>? RuntimeCreateOutcome { get; set; }

    internal Func<NativeCreateOutcome>? AuthorityRegisterOutcome { get; set; }

    internal Func<NativeCreateOutcome>? HostCreateOutcome { get; set; }

    internal Func<NativeAuthorityStatusOutcome>? AuthorityStatusOutcome { get; set; }

    internal int RuntimeDestroyStatus { get; set; }

    internal int AuthorityReleaseStatus { get; set; }

    internal int HostDestroyStatus { get; set; }

    internal int Count(string export) => Calls.Count(c => c.Export == export);

    internal int Total => Calls.Count;

    internal ulong[] ArgumentsOf(string export, int index = 0) => Calls.Where(c => c.Export == export).ElementAt(index).Arguments;

    internal ulong NextHandle() => _next++;

    public NativeCreateOutcome RuntimeCreate()
    {
        Calls.Add((RuntimeCreateExport, []));
        if (RuntimeCreateOutcome is { } outcome)
        {
            return outcome();
        }

        if (_activeRuntime != 0)
        {
            return new NativeCreateOutcome(AbiV1Constants.SAS_PAIRING_ALREADY_INITIALIZED, 0);
        }

        _activeRuntime = NextHandle();
        return new NativeCreateOutcome(AbiV1Constants.SAS_PAIRING_OK, _activeRuntime);
    }

    public int RuntimeDestroy(ulong runtime)
    {
        Calls.Add((RuntimeDestroyExport, [runtime]));
        if (runtime == _activeRuntime)
        {
            _activeRuntime = 0;
        }

        return RuntimeDestroyStatus;
    }

    public NativeCreateOutcome AuthorityRegister(ulong runtime, ReadOnlySpan<byte> scope)
    {
        Calls.Add((AuthorityRegisterExport, [runtime, (ulong)scope.Length]));
        Scopes.Add(scope.ToArray());
        return AuthorityRegisterOutcome?.Invoke() ?? new NativeCreateOutcome(AbiV1Constants.SAS_PAIRING_OK, NextHandle());
    }

    public int AuthorityRelease(ulong runtime, ulong authority)
    {
        Calls.Add((AuthorityReleaseExport, [runtime, authority]));
        return AuthorityReleaseStatus;
    }

    public NativeAuthorityStatusOutcome AuthorityStatus(ulong runtime, ulong authority)
    {
        Calls.Add((AuthorityStatusExport, [runtime, authority]));
        return AuthorityStatusOutcome?.Invoke() ?? new NativeAuthorityStatusOutcome(AbiV1Constants.SAS_PAIRING_OK, AbiV1Constants.SAS_PAIRING_AUTHORITY_READY, 10);
    }

    public NativeCreateOutcome HostCreate(ulong runtime, ulong authority)
    {
        Calls.Add((HostCreateExport, [runtime, authority]));
        return HostCreateOutcome?.Invoke() ?? new NativeCreateOutcome(AbiV1Constants.SAS_PAIRING_OK, NextHandle());
    }

    public int HostDestroy(ulong runtime, ulong host)
    {
        Calls.Add((HostDestroyExport, [runtime, host]));
        return HostDestroyStatus;
    }
}

/// <summary>
/// A fresh test process context over a <see cref="FakeLifecycleApi"/>, a <see cref="FakeNetworkApi"/>
/// (reachable as <c>(FakeNetworkApi)context.Network</c>), a <see cref="FakeCeremonyApi"/> (reachable as
/// <c>(FakeCeremonyApi)context.Ceremony</c>), and a <see cref="FakeResultApi"/> (reachable as
/// <c>(FakeResultApi)context.Results</c>), never the production one.
/// </summary>
internal static class FakeContext
{
    internal static (NativeProcessContext Context, FakeLifecycleApi Native) Create()
    {
        FakeLifecycleApi native = new();
        return (new NativeProcessContext(native, new FakeNetworkApi(), new FakeCeremonyApi(), new FakeResultApi()), native);
    }
}
