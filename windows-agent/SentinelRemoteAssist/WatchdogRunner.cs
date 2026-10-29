using System.Diagnostics;

namespace SentinelRemoteAssist;

/// <summary>
/// Dead-man's-switch for the local admin account SetupRunner creates. As long as this app's
/// process is alive, a SYSTEM-run scheduled task (registered by SetupRunner, see its "5. Unattended
/// cleanup watchdog" step) checks once a minute that <see cref="Config.AppPidFilePath"/> still
/// points at a live SentinelRemoteAssist process.
///
/// - App closed normally (X button): MainForm's FormClosing already removed the account and the
///   whole ProgramData directory (including this PID marker) before the process exits — the next
///   tick finds nothing and unregisters itself.
/// - App killed / crashed / machine lost power: the marker is still there, pointing at a PID that
///   no longer exists. The task performs the same removal unattended (it runs as SYSTEM — no UAC
///   prompt needed) and then unregisters itself.
///
/// Either way, "account left behind on the customer's PC" is bounded to at most ~1 minute after the
/// process actually stops running (Task Scheduler resumes a repeating trigger after a reboot too,
/// so even a power-loss case self-heals once the machine is back up).
/// </summary>
internal static class WatchdogRunner
{
    /// <summary>Called once at every normal (non --setup/--uninstall/--watchdog-check) launch,
    /// before the UI starts — marks "this process is the current live instance."</summary>
    public static void WriteAlivePidMarker()
    {
        try
        {
            Directory.CreateDirectory(Config.SessionKeyDir);
            File.WriteAllText(Config.AppPidFilePath, Environment.ProcessId.ToString());
        }
        catch { /* best-effort — worst case the watchdog just finds no marker to act on */ }
    }

    /// <summary>Entry point for the "--watchdog-check" scheduled-task invocation. Runs as SYSTEM,
    /// silently, once a minute — must never throw or block.</summary>
    public static int CheckAndMaybeCleanup()
    {
        try
        {
            // Requirement-3 fix — check the AutoConnect=1 flag (HKLM, via AutoStartManager.IsEnabled)
            // FIRST, before ANY dead-PID / missing-marker logic. In unattended mode the customer has
            // explicitly asked the tool to persist across reboots, and the tunnel is owned by the
            // SYSTEM AtStartup / --unattended-tunnel process, NOT by a UI process — so a dead
            // app.pid (there is no UI process before login) is expected, not a crash. The watchdog
            // must gracefully SKIP the whole uninstall routine here; otherwise it would tear the
            // unattended tunnel down on the very first tick after boot, exactly the
            // aggressive-uninstall bug this guards against.
            //
            // BUT: do NOT bare-return. Task Scheduler's RestartOnFailure on the Tunnel task only
            // applies to runs started by the AtStartup *trigger* — a Start-ScheduledTask / Run
            // kick (which is how setup and the WebUI remote-update cutover start the tunnel) does
            // NOT get auto-restarted after a Task-Manager force-kill. Proved live 2026-07-11 on
            // the reference host: force-kill left an orphaned ssh.exe holding the bastion reverse-port green
            // (WebUI still showed Connected) while the .NET supervisor stayed dead forever —
            // RestartOnFailure never fired, and this early-return used to skip any heal. Use the
            // once-a-minute watchdog tick to re-kick EnsureUnattendedTunnelRunning instead.
            if (AutoStartManager.IsEnabled)
            {
                try { AutoStartManager.EnsureUnattendedTunnelRunning(); }
                catch { /* best-effort — next tick retries */ }
                return 0;
            }

            if (!File.Exists(Config.AppPidFilePath))
            {
                // Already cleaned up gracefully (or never set up) — nothing to watch anymore.
                UnregisterSelf();
                return 0;
            }

            var text = File.ReadAllText(Config.AppPidFilePath).Trim();
            if (int.TryParse(text, out var pid) && IsOurProcessAlive(pid))
            {
                return 0; // still running — connected or not doesn't matter — stay armed.
            }

            // Marker exists but the process behind it is gone without going through the graceful
            // FormClosing cleanup — treat this exactly like a forced kill/crash.
            var result = UninstallRunner.RunUninstall();
            UnregisterSelf();
            return result;
        }
        catch
        {
            // Never let a tick throw/crash visibly — it's silent and unattended; a transient
            // failure just means it tries again next minute.
            return 1;
        }
    }

    private static bool IsOurProcessAlive(int pid)
    {
        try
        {
            using var proc = Process.GetProcessById(pid);
            // Match by process name prefix/suffix — every session's exe is deliberately renamed
            // per customer. Supported shapes:
            //   • Legacy:  SentinelRemoteAssist-<label>.exe  → ProcessName "SentinelRemoteAssist-…"
            //   • Current: <label>_Remote_Assist.exe         → ProcessName "…_Remote_Assist"
            //   • Installed autostart copy: Sentinel.exe (ProgramData) — was SentinelRemoteAssist.exe
            //     before the 3.0.0 process rename. Matching the shorter "Sentinel" prefix covers
            //     BOTH names in one check ("SentinelRemoteAssist" itself starts with "Sentinel"),
            //     so an already-deployed pre-3.0.0 box's watchdog is unaffected either way.
            // An exact-match against the bare string made the watchdog treat every session as
            // "dead" on its first tick and tear down the account within ~1 minute (2026-07-09).
            var name = proc.ProcessName;
            return name.StartsWith("Sentinel", StringComparison.OrdinalIgnoreCase)
                || name.EndsWith("_Remote_Assist", StringComparison.OrdinalIgnoreCase);
        }
        catch (ArgumentException)
        {
            return false; // no process with that PID anymore
        }
    }

    private static void UnregisterSelf()
    {
        try
        {
            var psi = new ProcessStartInfo("schtasks.exe", $"/Delete /TN \"{Config.WatchdogTaskName}\" /F")
            {
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            using var p = Process.Start(psi);
            p?.WaitForExit();
        }
        catch { /* best-effort */ }
    }
}
