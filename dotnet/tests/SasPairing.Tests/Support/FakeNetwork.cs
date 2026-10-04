using SasPairing.Interop;

namespace SasPairing.Tests.Support;

/// <summary>One recorded call of the fake network service.</summary>
internal sealed record FakeNetworkCall(string Export, ulong[] Arguments, nuint Socket = 0, NativeBootstrapBytes? Local = null, NativeBootstrapBytes? Expected = null, bool ExpectedGiven = false);

/// <summary>
/// A fake network-native service with deterministic outcomes and an exact call log. By default attach adopts
/// the socket (<c>OK</c>, slot <c>INVALID</c>), detach and close return <c>OK</c>, and a drive or recheck
/// returns <c>OK</c> with no event and no failure; each can be overridden, and drives can be queued.
/// </summary>
internal sealed class FakeNetworkApi : INativeNetworkApi
{
    internal const string AttachExport = "sas_pairing_host_attach_windows_listener";
    internal const string DetachExport = "sas_pairing_host_detach_listener";
    internal const string DriveExport = "sas_pairing_host_drive";
    internal const string RecheckExport = "sas_pairing_host_recheck_after_resume";
    internal const string CloseExport = "sas_pairing_connection_close";

    private readonly Queue<NativeDriveOutcome> _drives = new();

    internal List<FakeNetworkCall> Calls { get; } = [];

    /// <summary>The attach outcome from the offered socket value (default: adopted with <c>OK</c>).</summary>
    internal Func<nuint, NativeAttachOutcome> AttachOutcome { get; set; } = _ => new NativeAttachOutcome(0, AbiV1Constants.SAS_PAIRING_SOCKET_INVALID);

    /// <summary>Runs inside the attach call (used to hold an attach in flight).</summary>
    internal Action? DuringAttach { get; set; }

    internal int DetachStatus { get; set; }

    internal int CloseStatus { get; set; }

    internal int Count(string export) => Calls.Count(c => c.Export == export);

    internal int Total => Calls.Count;

    /// <summary>Queues the outcome of the next drive or recheck.</summary>
    internal void Next(int status, int failure, params NativeEventRecord[] events) =>
        _drives.Enqueue(new NativeDriveOutcome(status, (nuint)events.Length, failure, events));

    internal void NextRaw(NativeDriveOutcome outcome) => _drives.Enqueue(outcome);

    public NativeAttachOutcome AttachWindowsListener(ulong runtime, ulong host, nuint listener, NativeBootstrapBytes local, NativeBootstrapBytes? expected)
    {
        Calls.Add(new FakeNetworkCall(AttachExport, [runtime, host], listener, local, expected, expected is not null));
        DuringAttach?.Invoke();
        return AttachOutcome(listener);
    }

    public int DetachListener(ulong runtime, ulong host)
    {
        Calls.Add(new FakeNetworkCall(DetachExport, [runtime, host]));
        return DetachStatus;
    }

    public NativeDriveOutcome Drive(ulong runtime, ulong host)
    {
        Calls.Add(new FakeNetworkCall(DriveExport, [runtime, host]));
        return _drives.TryDequeue(out NativeDriveOutcome? outcome) ? outcome : new NativeDriveOutcome(0, 0, 0, []);
    }

    public NativeDriveOutcome RecheckAfterResume(ulong runtime, ulong host)
    {
        Calls.Add(new FakeNetworkCall(RecheckExport, [runtime, host]));
        return _drives.TryDequeue(out NativeDriveOutcome? outcome) ? outcome : new NativeDriveOutcome(0, 0, 0, []);
    }

    public int ConnectionClose(ulong runtime, ulong host, ulong connection)
    {
        Calls.Add(new FakeNetworkCall(CloseExport, [runtime, host, connection]));
        return CloseStatus;
    }
}

/// <summary>
/// A fake socket resource for the listener token, usable on every platform: it records whether the caller
/// side closed it or it was released to native ownership.
/// </summary>
internal sealed class FakeListenerResource(nuint value) : IListenerSocketResource
{
    public nuint Value { get; } = value;

    internal int Closes { get; private set; }

    internal int Releases { get; private set; }

    public void Close() => Closes++;

    public void ReleaseToNative() => Releases++;
}

/// <summary>Builders of raw native event records (all 64 request ID bytes, zero past the length).</summary>
internal static class Records
{
    internal static NativeEventRecord Event(
        uint kind,
        ulong connection = 0,
        uint step = 0,
        uint protocol = 0,
        uint reason = 0,
        uint deadline = 0,
        uint cancelState = 0,
        uint cancelReason = 0,
        uint flags = 0,
        ulong run = 0,
        ulong result = 0,
        byte[]? requestId = null,
        uint? requestIdLength = null,
        uint reserved = 0)
    {
        byte[] id = new byte[64];
        requestId?.CopyTo(id, 0);
        return new NativeEventRecord(kind, step, protocol, reason, deadline, cancelState, cancelReason, flags, connection, run, result, requestIdLength ?? (uint)(requestId?.Length ?? 0), reserved, id);
    }

    internal static NativeEventRecord Accepted(ulong connection) => Event(AbiV1Constants.SAS_PAIRING_EVENT_CONNECTION_ACCEPTED, connection);

    internal static NativeEventRecord Closed(ulong connection, uint reason = AbiV1Constants.SAS_PAIRING_EVENT_REASON_PEER_CLOSED) =>
        Event(AbiV1Constants.SAS_PAIRING_EVENT_CONNECTION_CLOSED, connection, reason: reason);

    internal static NativeEventRecord ListenerDisabled() =>
        Event(AbiV1Constants.SAS_PAIRING_EVENT_LISTENER_DISABLED, reason: AbiV1Constants.SAS_PAIRING_EVENT_REASON_LISTENER_IO);

    internal static NativeEventRecord Refused() =>
        Event(AbiV1Constants.SAS_PAIRING_EVENT_ACCEPT_REFUSED, reason: AbiV1Constants.SAS_PAIRING_EVENT_REASON_RESOURCE_LIMITED);

    internal static NativeEventRecord Step(ulong connection, uint step = AbiV1Constants.SAS_PAIRING_STEP_WRITTEN, uint protocol = 0, ulong run = 0, ulong result = 0, byte[]? requestId = null, uint flags = 0) =>
        Event(AbiV1Constants.SAS_PAIRING_EVENT_CONNECTION_STEP, connection, step, protocol, run: run, result: result, requestId: requestId, flags: flags);

    internal static NativeEventRecord Inbound(ulong connection, uint protocol, byte[] requestId, ulong run = 0, ulong result = 0, uint flags = 0) =>
        Step(connection, AbiV1Constants.SAS_PAIRING_STEP_INBOUND, protocol, run, result, requestId, flags);
}

/// <summary>A fake host tree over one fake context: runtime, authority, host, and the fake services.</summary>
internal sealed class FakeTree
{
    internal FakeTree()
    {
        (Context, Lifecycle) = FakeContext.Create();
        Network = (FakeNetworkApi)Context.Network;
        Ceremony = (FakeCeremonyApi)Context.Ceremony;
        Runtime = SasPairingRuntime.CreateIn(Context);
        Authority = Runtime.RegisterAuthority([1, 2, 3]);
        Host = Authority.CreateHost();
    }

    internal NativeProcessContext Context { get; }

    internal FakeLifecycleApi Lifecycle { get; }

    internal FakeNetworkApi Network { get; }

    internal FakeCeremonyApi Ceremony { get; }

    internal SasPairingRuntime Runtime { get; }

    internal SasPairingAuthority Authority { get; }

    internal SasPairingHost Host { get; }

    internal static SasPairingBootstrap Bootstrap(byte seed = 1) => new([seed, 0x00, 0x80, 0xFF], "x25519"u8, [.. Enumerable.Repeat(seed, 32)], []);

    internal static SasPairingWindowsListenerSocket Token(nuint value = 0x1234) => SasPairingWindowsListenerSocket.FromResource(new FakeListenerResource(value));

    /// <summary>Attaches a fresh token with the default (adopting) attach outcome.</summary>
    internal void Attach() => Host.AttachWindowsListener(Token(), Bootstrap());

    /// <summary>Attaches, then accepts the given connections with one drive; returns their wrappers.</summary>
    internal SasPairingConnection[] AttachWithConnections(params ulong[] handles)
    {
        Attach();
        Network.Next(0, 0, [.. handles.Select(Records.Accepted)]);
        return [.. Host.Drive().Events.Select(e => e.Connection!)];
    }
}
