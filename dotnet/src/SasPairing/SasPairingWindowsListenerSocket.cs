using System.Net.Sockets;
using System.Runtime.Versioning;
using SasPairing.Interop;

namespace SasPairing;

/// <summary>
/// A one-use ownership-handoff token for an already-bound, already-listening Windows TCP socket, offered to a
/// host by <see cref="SasPairingHost.AttachWindowsListener"/> (P9-D-003).
/// </summary>
/// <remarks>
/// <para>
/// The package never binds or listens: the application chooses the address, interface, port, backlog, and
/// IP version, and creates, binds, and starts listening on the <see cref="Socket"/> itself. <b>Trusted caller
/// precondition</b> (the package cannot check it): the socket is a valid Windows socket, already bound, already
/// listening, owned exclusively by the caller, never used for asynchronous operations, and not used or closed
/// by anyone else while <see cref="FromSocket"/> runs. The socket, its address, and its port are not peer
/// identity, protocol identity, authenticated identity, or trust material.
/// </para>
/// <para>
/// <see cref="FromSocket"/> takes the socket: it moves the listening socket into a package-owned descriptor
/// and closes the caller's <see cref="Socket"/> object (disposing that object again later does nothing). From
/// then on the caller owns the listening socket through this token: until <see cref="IsTransferred"/> becomes
/// true, also after a failed attach, <see cref="Dispose"/> closes it. Once <see cref="IsTransferred"/> is true
/// the native library owns the socket (or has already closed it): the package never closes, uses, or hands it
/// on again, its managed handle is invalidated without closing the OS socket, and <see cref="Dispose"/> does
/// nothing. No raw socket value or handle can be read from this object.
/// </para>
/// <para>
/// One token is offered to at most one attach at a time. Pairing networking exists on Windows only: elsewhere
/// <see cref="FromSocket"/> throws <see cref="PlatformNotSupportedException"/> and the socket stays the caller's.
/// </para>
/// </remarks>
public sealed class SasPairingWindowsListenerSocket : IDisposable
{
    private readonly Lock _gate = new();
    private IListenerSocketResource? _resource;
    private bool _inFlight;
    private bool _transferred;
    private bool _disposeRequested;

    private SasPairingWindowsListenerSocket(IListenerSocketResource resource)
    {
        _resource = resource;
    }

    /// <summary>
    /// Whether the native library has taken ownership of the socket. Once true, the socket is the native
    /// library's: the token can never be attached again and disposing it does nothing.
    /// </summary>
    public bool IsTransferred
    {
        get
        {
            lock (_gate)
            {
                return _transferred;
            }
        }
    }

    /// <summary>
    /// Takes the caller's already-bound, already-listening Windows <paramref name="listener"/> for one later
    /// ownership handoff. The caller's <see cref="Socket"/> object is closed (the listening socket itself
    /// lives on in the token); never use that object again.
    /// </summary>
    /// <param name="listener">The application's listening socket.</param>
    /// <returns>The token that now owns the listening socket.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="listener"/> is null.</exception>
    /// <exception cref="PlatformNotSupportedException">The platform is not Windows; the socket was not touched.</exception>
    /// <exception cref="ObjectDisposedException"><paramref name="listener"/> was already disposed.</exception>
    /// <exception cref="SocketException">The socket could not be moved into the token.</exception>
    public static SasPairingWindowsListenerSocket FromSocket(Socket listener)
    {
        ArgumentNullException.ThrowIfNull(listener);
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("A Windows listener socket can be handed to the native library only on Windows; pairing networking is not supported on this platform. The socket was not touched.");
        }

        return new SasPairingWindowsListenerSocket(WindowsListenerSocketResource.Take(listener));
    }

    /// <summary>
    /// Closes the listening socket if the native library has not taken it; does nothing after the transfer
    /// and on later calls. A call that races an attach in progress takes effect when that attach ends, and
    /// only if the native library did not adopt the socket.
    /// </summary>
    public void Dispose()
    {
        IListenerSocketResource? close;
        lock (_gate)
        {
            if (_transferred || _disposeRequested)
            {
                return;
            }

            _disposeRequested = true;
            if (_inFlight)
            {
                return;
            }

            close = _resource;
            _resource = null;
        }

        close?.Close();
    }

    /// <summary>A token over another socket resource (tests use fake resources on every platform).</summary>
    internal static SasPairingWindowsListenerSocket FromResource(IListenerSocketResource resource) =>
        resource.Value != AbiV1Constants.SAS_PAIRING_SOCKET_INVALID
            ? new SasPairingWindowsListenerSocket(resource)
            : throw new ArgumentException("INVALID_SOCKET is never a socket.", nameof(resource));

    /// <summary>
    /// Opens the token's one attach attempt and returns the socket value to offer, or throws without any native
    /// call: <see cref="InvalidOperationException"/> after the transfer or while another attempt is in flight,
    /// <see cref="ObjectDisposedException"/> after disposal.
    /// </summary>
    internal nuint BeginAttempt()
    {
        lock (_gate)
        {
            if (_transferred)
            {
                throw new InvalidOperationException("This SasPairingWindowsListenerSocket was already transferred to the native library; it cannot be attached again.");
            }

            ObjectDisposedException.ThrowIf(_disposeRequested, this);
            if (_inFlight)
            {
                throw new InvalidOperationException("This SasPairingWindowsListenerSocket is being attached by another call; a token is offered to one attach at a time.");
            }

            _inFlight = true;
            return _resource!.Value;
        }
    }

    /// <summary>Ends an attempt that made no native call: the caller still owns the socket.</summary>
    internal void AbandonAttempt() => Finish(consumed: false);

    /// <summary>
    /// Ends the attempt from the in/out slot's value after the native call: <c>SAS_PAIRING_SOCKET_INVALID</c>
    /// transfers the socket; the offered value keeps it the caller's; anything else is impossible and consumes
    /// the token conservatively (a possible leak instead of a possible double close).
    /// </summary>
    internal ListenerSlotTransition CompleteAttempt(nuint offered, nuint after)
    {
        ListenerSlotTransition transition =
            after == AbiV1Constants.SAS_PAIRING_SOCKET_INVALID ? ListenerSlotTransition.Adopted
            : after == offered ? ListenerSlotTransition.Retained
            : ListenerSlotTransition.Impossible;
        Finish(consumed: transition != ListenerSlotTransition.Retained);
        return transition;
    }

    private void Finish(bool consumed)
    {
        IListenerSocketResource? close = null;
        lock (_gate)
        {
            _inFlight = false;
            if (consumed)
            {
                // The native library owns (or may own) the socket from now on: the managed handle is
                // invalidated without closing it, and the token keeps no reference to it.
                _transferred = true;
                _resource!.ReleaseToNative();
                _resource = null;
            }
            else if (_disposeRequested)
            {
                close = _resource;
                _resource = null;
            }
        }

        close?.Close();
    }
}

/// <summary>How the in/out socket slot changed in one native attach.</summary>
internal enum ListenerSlotTransition
{
    /// <summary>The slot still holds the offered socket: not adopted, still the caller's.</summary>
    Retained,

    /// <summary>The slot reads <c>SAS_PAIRING_SOCKET_INVALID</c>: the native library owns the socket.</summary>
    Adopted,

    /// <summary>The slot holds another value, which ABI v1 forbids.</summary>
    Impossible,
}

/// <summary>
/// The OS socket a <see cref="SasPairingWindowsListenerSocket"/> owns until the transfer: its raw value, its
/// caller-side close, and its release to native ownership. Production uses
/// <see cref="WindowsListenerSocketResource"/>; tests use fakes on every platform.
/// </summary>
internal interface IListenerSocketResource
{
    /// <summary>The raw socket value offered in the in/out slot.</summary>
    nuint Value { get; }

    /// <summary>Closes the socket; only while the caller owns it.</summary>
    void Close();

    /// <summary>The native library owns the socket now: make every managed close of it impossible, without closing it.</summary>
    void ReleaseToNative();
}

/// <summary>
/// The package-owned handoff descriptor of a caller's listening <see cref="Socket"/> (P9-D-003 W).
/// </summary>
/// <remarks>
/// <see cref="Socket.DuplicateAndClose"/> for this process plus <see cref="Socket(SocketInformation)"/> give a
/// second descriptor of the same listening socket and close the caller's descriptor through .NET's normal
/// close, so the caller's <see cref="Socket"/> object never shares a descriptor with the native library. On
/// transfer, only this descriptor's handle is invalidated with <c>SetHandleAsInvalid</c>, which marks it
/// closed without closing the OS socket and suppresses its release; this object is then never disposed
/// (disposing a <see cref="Socket"/> whose handle was invalidated never returns in .NET 10) and is dropped.
/// </remarks>
[SupportedOSPlatform("windows")]
internal sealed class WindowsListenerSocketResource : IListenerSocketResource
{
    private readonly Socket _handoff;

    private WindowsListenerSocketResource(Socket handoff)
    {
        _handoff = handoff;
        Value = (nuint)(nint)handoff.Handle;
    }

    public nuint Value { get; }

    internal static WindowsListenerSocketResource Take(Socket listener) =>
        new(new Socket(listener.DuplicateAndClose(Environment.ProcessId)));

    public void Close() => _handoff.Dispose();

    public void ReleaseToNative() => _handoff.SafeHandle.SetHandleAsInvalid();
}
