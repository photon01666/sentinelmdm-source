namespace SentinelRemoteAssist;

/// <summary>
/// On-screen alert for an autonomous EDR action (RansomwareGuard.cs) — this product's ethos is
/// visible-consent, not stealth (see ConsentDialog.cs for the interactive-Connect equivalent), so
/// an autonomous kill/isolate must never happen silently. Uses WTSSendMessage rather than a
/// WinForms MessageBox/Form because --edr-watch runs as a SYSTEM scheduled task — on a real
/// Windows box that's Session 0, with no interactive desktop of its own, so a plain MessageBox
/// would never be seen by the actual logged-in user. Fire-and-forget (bWait:false) — the
/// autonomous action itself is already complete by the time this is called; nothing should block
/// waiting for someone to click OK.
/// </summary>
internal static class SecurityNotification
{
    private const uint MB_ICONWARNING = 0x30;
    private const uint MB_TOPMOST = 0x40000;

    public static void Show(string title, string message)
    {
        try
        {
            var sessionId = Win32Native.WTSGetActiveConsoleSessionId();
            if (sessionId < 0) return; // no interactive session right now (locked/no user logged in) — nothing to show
            // WTSSendMessage's *Length params are BYTE counts, not character counts — with
            // CharSet.Unicode marshaling (2 bytes/char) passing title.Length/message.Length directly
            // truncates both strings to roughly their first half (e.g. "Sentinel Security Alert"
            // rendered as "Sentinel Se"). Include the null terminator's 2 bytes too, matching the
            // buffer WTSSendMessage actually walks.
            Win32Native.WTSSendMessage(IntPtr.Zero, sessionId, title, (title.Length + 1) * 2,
                message, (message.Length + 1) * 2, MB_ICONWARNING | MB_TOPMOST, 0, out _, false);
        }
        catch
        {
            // Best-effort — a notification failure must never block or roll back the actual
            // kill/isolate response it's reporting on.
        }
    }
}
