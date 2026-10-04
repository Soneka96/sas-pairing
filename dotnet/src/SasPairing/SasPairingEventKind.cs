namespace SasPairing;

/// <summary>
/// The kind of one drive event, with its frozen native value. The native invalid kind (0) is never a public event.
/// </summary>
public enum SasPairingEventKind
{
    /// <summary>A new connection was accepted; the event carries its <see cref="SasPairingConnection"/>. No I/O happened on it yet.</summary>
    ConnectionAccepted = 1,

    /// <summary>An accepted socket was dropped without becoming a connection; see <see cref="SasPairingEvent.Reason"/>.</summary>
    AcceptRefused = 2,

    /// <summary>The listening socket was dropped; existing connections continue. The host is now <see cref="SasPairingHostNetworkState.ListenerDisabled"/>.</summary>
    ListenerDisabled = 3,

    /// <summary>One step of a connection; see <see cref="SasPairingEvent.StepKind"/> and the step's fields.</summary>
    ConnectionStep = 4,

    /// <summary>The connection ended; its <see cref="SasPairingConnection"/> is already disposed.</summary>
    ConnectionClosed = 5,
}
