namespace SasPairing;

/// <summary>
/// The network state of one <see cref="SasPairingHost"/> (P9-D-003). The four states are distinct and never collapsed.
/// </summary>
public enum SasPairingHostNetworkState
{
    /// <summary>No listener context: before any attach, after <see cref="SasPairingHost.DetachListener"/>, after an attach whose socket the native library adopted but could not set up, and after the host or a parent was disposed.</summary>
    Detached = 0,

    /// <summary>A listener is attached and its owner loop runs when the host is driven.</summary>
    Attached = 1,

    /// <summary>The listening socket was dropped (a <see cref="SasPairingEventKind.ListenerDisabled"/> event): nothing new is accepted, but existing connections continue and may still be driven. To replace the listener, detach it and attach a new one.</summary>
    ListenerDisabled = 2,

    /// <summary>The owner loop failed closed: the listener and every connection are gone and every <see cref="SasPairingConnection"/> of the host is disposed. Consume the batch that reported it, then detach the listener or dispose the host.</summary>
    FailedClosed = 3,
}
