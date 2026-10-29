namespace SentinelRemoteAssist;

/// <summary>
/// Customer-visible session activity log for <b>ephemeral CONNECT</b> sessions only.
/// Records session start/end, consent acceptance, technician identity, and UI-level actions.
/// Survives uninstall by being copied to the customer's Desktop (ProgramData is wiped).
/// Not used when "Start automatically" (unattended) is enabled — that path is standing access
/// by explicit opt-in and has a different lifecycle.
/// </summary>
internal static class SessionAuditLog
{
    private static readonly object Gate = new();
    private static bool _active;
    private static string? _desktopCopyPath;
    private static DateTime _sessionStartedLocal;

    /// <summary>True after <see cref="BeginEphemeralSession"/> until <see cref="EndAndPublish"/>.</summary>
    public static bool IsActive
    {
        get { lock (Gate) return _active; }
    }

    /// <summary>Desktop path of the published log (set after EndAndPublish), or null.</summary>
    public static string? DesktopCopyPath
    {
        get { lock (Gate) return _desktopCopyPath; }
    }

    public static void BeginEphemeralSession()
    {
        lock (Gate)
        {
            if (_active) return;
            _active = true;
            _sessionStartedLocal = DateTime.Now;
            _desktopCopyPath = null;
            try
            {
                Directory.CreateDirectory(Config.SessionKeyDir);
                // Fresh log for this open window (reconnects append within the same process).
                File.WriteAllText(Config.SessionAuditLogPath, "");
            }
            catch { /* best-effort */ }
        }

        var label = string.IsNullOrEmpty(SessionEmbedded.SessionLabel)
            ? "(unlabeled session build)"
            : SessionEmbedded.SessionLabel;
        var created = string.IsNullOrEmpty(SessionEmbedded.SessionCreatedUtc)
            ? "(unknown)"
            : SessionEmbedded.SessionCreatedUtc;

        Write("SESSION START");
        Write($"  Mode:              Ephemeral CONNECT (not unattended / Start-auto)");
        Write($"  Technician:        {Config.TechnicianDisplayName}");
        Write($"  Session label:     {label}");
        Write($"  Session minted:    {created} (UTC, build time)");
        Write($"  Bastion:           {SessionEmbedded.BastionHost}:{SessionEmbedded.BastionPort}");
        Write($"  Forward port:      {SessionEmbedded.ForwardPort}");
        Write($"  Machine:           {Environment.MachineName}");
        Write($"  Windows user:      {Environment.UserName}");
        Write($"  App:               {Application.ExecutablePath}");
        Write($"  Agreement version: {Config.ConsentAgreementVersion}");
        Write("---");
        Write("This log is written so you (the customer) can see what this support tool did.");
        Write("It records local app events only (connect, setup, disconnect, cleanup).");
        Write("It does not capture keystrokes, screenshots, or remote shell command output.");
        Write("---");
    }

    public static void LogConsentAccepted()
    {
        Write($"CONSENT ACCEPTED  agreement={Config.ConsentAgreementVersion}  "
            + $"technician={Config.TechnicianDisplayName}  "
            + $"by_windows_user={Environment.UserName}");
    }

    public static void LogConsentDeclined()
    {
        Write($"CONSENT DECLINED  agreement={Config.ConsentAgreementVersion}");
    }

    public static void LogAction(string action)
    {
        if (string.IsNullOrWhiteSpace(action)) return;
        Write(action.Trim());
    }

    /// <summary>
    /// Finalizes the log, copies it to the customer's Desktop (survives ProgramData wipe),
    /// and deactivates. Safe to call multiple times. Returns the Desktop path if published.
    /// </summary>
    public static string? EndAndPublish(string reason)
    {
        lock (Gate)
        {
            if (!_active && !File.Exists(Config.SessionAuditLogPath))
                return _desktopCopyPath;
        }

        var ended = DateTime.Now;
        TimeSpan duration;
        lock (Gate)
        {
            duration = ended - _sessionStartedLocal;
        }

        Write("---");
        Write($"SESSION END  reason={reason}");
        Write($"  Ended local:       {ended:yyyy-MM-dd HH:mm:ss} (local)");
        Write($"  Duration:          {FormatDuration(duration)}");
        Write($"  Technician:        {Config.TechnicianDisplayName}");
        Write("---");
        Write("If you have questions about this session, contact Sentinel support and quote");
        Write("the session label and timestamps above.");

        var path = PublishToDesktop();
        lock (Gate)
        {
            _active = false;
            if (path is not null) _desktopCopyPath = path;
        }
        return path;
    }

    /// <summary>
    /// Copies the in-progress ProgramData log to Desktop without ending the session
    /// (used by elevated uninstall so the wipe can still leave a customer-visible trail).
    /// </summary>
    public static string? PublishToDesktop()
    {
        try
        {
            if (!File.Exists(Config.SessionAuditLogPath)) return null;
            var desktop = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
            if (string.IsNullOrEmpty(desktop) || !Directory.Exists(desktop))
            {
                // SYSTEM / headless fallback — still leave something readable.
                desktop = Environment.GetFolderPath(Environment.SpecialFolder.CommonDesktopDirectory);
            }
            if (string.IsNullOrEmpty(desktop))
                desktop = Config.SessionKeyDir;

            var stamp = DateTime.Now.ToString("yyyyMMdd-HHmmss");
            var label = string.IsNullOrEmpty(SessionEmbedded.SessionLabel)
                ? "session"
                : SessionEmbedded.SessionLabel;
            // Sanitize for filesystem (label is already a safe slug, but be defensive).
            foreach (var c in Path.GetInvalidFileNameChars())
                label = label.Replace(c, '_');

            var dest = Path.Combine(desktop, $"Sentinel-Support-Session-{label}-{stamp}.txt");
            File.Copy(Config.SessionAuditLogPath, dest, overwrite: true);
            return dest;
        }
        catch
        {
            return null;
        }
    }

    private static void Write(string line)
    {
        lock (Gate)
        {
            if (!_active && !File.Exists(Config.SessionAuditLogPath))
            {
                // Allow a late write during teardown after End cleared the flag if the file still exists.
            }
            try
            {
                Directory.CreateDirectory(Config.SessionKeyDir);
                var stamped = $"{DateTime.Now:yyyy-MM-dd HH:mm:ss}  {line}{Environment.NewLine}";
                File.AppendAllText(Config.SessionAuditLogPath, stamped);
            }
            catch { /* best-effort — never break support for a log failure */ }
        }
    }

    private static string FormatDuration(TimeSpan t)
    {
        if (t.TotalHours >= 1)
            return $"{(int)t.TotalHours}h {t.Minutes}m {t.Seconds}s";
        if (t.TotalMinutes >= 1)
            return $"{t.Minutes}m {t.Seconds}s";
        return $"{Math.Max(0, (int)t.TotalSeconds)}s";
    }
}
