namespace TnProto;

/// <summary>
/// Event data raised when an SDK operation explicitly weakens a security guarantee.
/// </summary>
public sealed class TnSecurityWarningEventArgs : EventArgs
{
    /// <summary>Initializes warning event data for <paramref name="notice"/>.</summary>
    public TnSecurityWarningEventArgs(UnsafeOperationNotice notice)
    {
        ArgumentNullException.ThrowIfNull(notice);
        Notice = notice;
    }

    /// <summary>The shared structured notice for the unsafe operation.</summary>
    public UnsafeOperationNotice Notice { get; }
}
