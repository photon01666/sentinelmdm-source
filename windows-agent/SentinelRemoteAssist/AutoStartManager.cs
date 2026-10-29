using System.Diagnostics;
using Microsoft.Win32;

namespace SentinelRemoteAssist;

/// <summary>
/// Backs the "Start automatically" checkbox (unattended / reboot-surviving remote access).
/// Pieces:
/// - A stable installed COPY of the exe under C:\ProgramData (EnsureInstalledCopy) — NOT the
///   original file wherever the customer happened to save/run it (Desktop, Downloads, ...).
///   SYSTEM scheduled tasks point at this copy, so deleting the original afterward (e.g. tidying
///   the Desktop post-call) doesn't break unattended mode.
/// - HKLM AutoConnect flag (IsEnabled) — SetupRunner / WatchdogRunner branch on this.
/// - SYSTEM scheduled tasks registered by SetupRunner when enabled:
///     • AutoSetup (AtLogOn) — silent account/sshd re-setup, no UAC
///     • AutoSetup_Tunnel (AtStartup) — the real reverse tunnel (Session 0, pre-login)
///   Normal CONNECT is ephemeral and does NOT need any of this; only the checkbox does.
/// - Deliberately NO HKLM/HKCU Run-key / Task Manager "Startup apps" entry. That only launched a
///   hidden --autostart UI process with no tray and no tunnel — redundant with the SYSTEM tunnel
///   task. Disable still deletes any legacy Run value left by older builds.
/// </summary>
internal static class AutoStartManager
{
    // Legacy only: older builds wrote HKLM Run → "...\SentinelRemoteAssist.exe --autostart".
    // We never create it now; SetEnabledInternal(false) still removes it so Task Manager cleans up.
    private const string RunKeyPath = @"Software\Microsoft\Windows\CurrentVersion\Run";
    private const string RunValueName = "SentinelRemoteAssist";
    private const string PrefsKeyPath = @"Software\SentinelRemoteAssist";
    private const string AutoConnectValueName = "AutoConnect";

    // The persistent, system-wide install location (Config.SessionKeyDir = C:\ProgramData\
    // SentinelRemoteAssist). Deliberately system-wide, NOT the user's AppData — a background boot
    // task that pointed into a specific user profile would be left dangling if an admin ever
    // deleted that profile. It is safe for the installed copy to live in SessionKeyDir even though
    // UninstallRunner wipes that directory, because the ephemeral wipe-on-close path only runs when
    // autostart is OFF (see MainForm.FormClosing / WatchdogRunner, both of which now skip cleanup
    // while IsEnabled). In unattended mode the whole directory is meant to persist.
    private static string InstallDir => Config.SessionKeyDir;
    private static string InstalledExePath => Path.Combine(InstallDir, "Sentinel.exe");

    /// <summary>Copies the currently-running exe to the stable install location if it isn't
    /// already running from there, and returns that stable path. Safe/idempotent to call anytime
    /// autostart is (or is about to be) enabled — including from SetupRunner's elevated context,
    /// which needs the same stable path for the scheduled tasks it registers.</summary>
    public static string EnsureInstalledCopy()
    {
        var currentExe = Environment.ProcessPath ?? Process.GetCurrentProcess().MainModule!.FileName;
        try
        {
            Directory.CreateDirectory(InstallDir);
            // Guard against copying the installed exe onto itself (e.g. this IS an --autostart
            // relaunch, or the SYSTEM --unattended-tunnel, already running from InstalledExePath) —
            // File.Copy onto a file the OS has open for execution throws (IOException: in use).
            if (string.Equals(Path.GetFullPath(currentExe), Path.GetFullPath(InstalledExePath),
                    StringComparison.OrdinalIgnoreCase))
            {
                return InstalledExePath;
            }
            try
            {
                File.Copy(currentExe, InstalledExePath, overwrite: true);
            }
            catch
            {
                // The destination is most likely locked because the SYSTEM --unattended-tunnel
                // process is already running from it (re-enabling autostart while unattended is
                // live). If a copy already exists, it IS the right binary — use it rather than
                // falling back to the customer's (deletable) Desktop path, which would defeat the
                // whole point of keeping a stable installed copy the boot task can rely on.
                if (File.Exists(InstalledExePath)) return InstalledExePath;
                return currentExe;
            }
        }
        catch
        {
            // Best-effort — if even CreateDirectory fails, fall back to the running exe.
            return currentExe;
        }
        return InstalledExePath;
    }

    /// <summary>
    /// Install-on-first-run. If this process is NOT already running from the stable ProgramData
    /// copy (C:\ProgramData\SentinelRemoteAssist\Sentinel.exe), copy itself there and
    /// relaunch that copy with the SAME arguments, returning true so the caller exits immediately.
    /// This means the tray UI, the tunnel, and (once enabled) the SYSTEM tasks ALL run from one
    /// canonical location from the very first launch — not only after autostart is toggled or after
    /// a reboot. Returns false (run in place) when we're already the installed copy, or when the
    /// copy/relaunch couldn't be done (best-effort — never blocks startup, never throws). Guarded
    /// against a relaunch loop: the relaunched process runs from InstalledExePath, so its own call
    /// hits the "already the installed copy" short-circuit and returns false.
    /// </summary>
    public static bool RelaunchFromInstallDirIfNeeded(string[] args)
    {
        try
        {
            var currentExe = Environment.ProcessPath ?? Process.GetCurrentProcess().MainModule!.FileName;
            if (string.Equals(Path.GetFullPath(currentExe), Path.GetFullPath(InstalledExePath),
                    StringComparison.OrdinalIgnoreCase))
            {
                return false; // already running from the installed copy — nothing to do.
            }

            var installed = EnsureInstalledCopy();
            if (!string.Equals(Path.GetFullPath(installed), Path.GetFullPath(InstalledExePath),
                    StringComparison.OrdinalIgnoreCase))
            {
                return false; // the copy didn't land at the install path (couldn't write) — run in place.
            }

            var psi = new ProcessStartInfo { FileName = installed, UseShellExecute = true };
            foreach (var a in args) psi.ArgumentList.Add(a);
            Process.Start(psi);
            return true; // launched the installed copy — this (e.g. Desktop) instance should exit.
        }
        catch
        {
            return false; // any failure → just run in place; never block startup.
        }
    }

    public static bool IsEnabled
    {
        get
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(PrefsKeyPath);
                return key?.GetValue(AutoConnectValueName) is int v && v != 0;
            }
            catch
            {
                return false;
            }
        }
    }

    /// <summary>True when this process IS the installed ProgramData copy (as opposed to a
    /// double-clicked copy from Downloads/Desktop). The auto-provisioning flow (2.0.3) uses this
    /// to decide whether an upgrade cutover is needed at all — running from the installed copy
    /// means the canonical binary is already in place.</summary>
    public static bool IsRunningFromInstalledCopy()
    {
        try
        {
            var currentExe = Environment.ProcessPath ?? Process.GetCurrentProcess().MainModule!.FileName;
            return string.Equals(Path.GetFullPath(currentExe), Path.GetFullPath(InstalledExePath),
                StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    /// <summary>Elevated flip of autostart. Returns true only when the elevated child exited 0
    /// (UAC accepted AND setup/unregister succeeded). MainForm uses this so it never reports
    /// "Automatic start is ON" when the setup script actually failed.</summary>
    public static bool SetEnabled(bool enabled)
    {
        var exePath = Environment.ProcessPath ?? Process.GetCurrentProcess().MainModule!.FileName;
        var autoArg = string.Concat("--set", "-auto", "start");
        var psi = new ProcessStartInfo
        {
            FileName = exePath,
            Arguments = $"{autoArg} {(enabled ? "1" : "0")}",
            UseShellExecute = true,
            Verb = "runas",
        };
        try
        {
            using var proc = Process.Start(psi);
            if (proc is null) return false;
            // Setup can take well over 30s (sshd install). Match SetupRunner's 15 min bound.
            if (!proc.WaitForExit(TimeSpan.FromMinutes(15)))
            {
                try { proc.Kill(entireProcessTree: true); } catch { /* best-effort */ }
                return false;
            }
            return proc.ExitCode == 0;
        }
        catch
        {
            // User declined UAC or start failed
            return false;
        }
    }

    /// <summary>Returns 0 on success, non-zero on failure (so Program.cs --set-autostart can
    /// surface the exit code to <see cref="SetEnabled"/>).</summary>
    public static int SetEnabledInternal(bool enabled)
    {
        try
        {
            // Write the AutoConnect flag FIRST so that anything reading IsEnabled below (notably
            // SetupRunner.RunSetup, whose script branches on it) sees the new state.
            using (var prefs = Registry.LocalMachine.CreateSubKey(PrefsKeyPath))
            {
                prefs.SetValue(AutoConnectValueName, enabled ? 1 : 0, RegistryValueKind.DWord);
            }

            if (enabled)
            {
                // Stable ProgramData copy for SYSTEM tasks to execute (not a Run-key target).
                EnsureInstalledCopy();
                // Drop any legacy Task Manager "Startup apps" Run entry from older builds —
                // unattended mode does not need a user-session launch at login.
                TryDeleteLegacyRunKey();

                // Full install + connect in ONE elevated pass — the customer must NOT need to click
                // CONNECT first. RunSetup (with AutoConnect already true) installs OpenSSH/sshd,
                // the sentinel-support account, Hop-2 key, watchdog, SYSTEM AtLogon auto-setup, and the
                // SYSTEM AtStartup --unattended-tunnel task, then starts that task. We then
                // double-check the tunnel process is actually alive and force-start it if the
                // scheduled-task kick failed silently.
                var setupRc = SetupRunner.RunSetup();
                if (setupRc != 0)
                {
                    // Roll the flag back so IsEnabled reflects reality and the UI does not claim ON.
                    try
                    {
                        using var prefs = Registry.LocalMachine.CreateSubKey(PrefsKeyPath);
                        prefs.SetValue(AutoConnectValueName, 0, RegistryValueKind.DWord);
                        TryDeleteLegacyRunKey();
                    }
                    catch { /* best-effort rollback */ }
                    return setupRc;
                }

                // Belt-and-suspenders: setup's Start-ScheduledTask is best-effort; make sure the
                // tunnel is running RIGHT NOW without requiring a Connect click or a reboot.
                if (!EnsureUnattendedTunnelRunning())
                {
                    try
                    {
                        File.AppendAllText(
                            Path.Combine(Config.SessionKeyDir, "setup-log.txt"),
                            "\n==> WARNING: setup succeeded but unattended tunnel process was not detected.\n");
                    }
                    catch { /* best-effort */ }
                    // Still return 0 — setup installed everything; TunnelRunner retries inside the
                    // process once it does start, and AtStartup will catch the next boot.
                }
                return 0;
            }
            else
            {
                TryDeleteLegacyRunKey();
                // Stop + unregister the SYSTEM auto-setup + unattended-tunnel tasks and delete the
                // installed copy. The account / sshd / Hop-2 key / watchdog teardown is intentionally
                // left to the normal close (MainForm.FormClosing) or the watchdog fallback — both of
                // which now see IsEnabled==false and perform the ephemeral uninstall — so we don't
                // try to Directory.Delete a tree that may hold the exe this very process is running.
                RunElevatedUnregisterAutoSetupTaskInternal();
                TryDeleteInstalledExe();
                return 0;
            }
        }
        catch
        {
            return 1;
        }
    }

    private static void TryDeleteInstalledExe()
    {
        try
        {
            var currentExe = Environment.ProcessPath ?? Process.GetCurrentProcess().MainModule!.FileName;
            if (File.Exists(InstalledExePath) &&
                !string.Equals(Path.GetFullPath(currentExe), Path.GetFullPath(InstalledExePath),
                    StringComparison.OrdinalIgnoreCase))
            {
                File.Delete(InstalledExePath);
            }
        }
        catch { }
    }

    /// <summary>Removes the legacy HKLM Run value if present (old builds only). Never re-created.</summary>
    private static void TryDeleteLegacyRunKey()
    {
        try
        {
            using var runKey = Registry.LocalMachine.CreateSubKey(RunKeyPath);
            runKey?.DeleteValue(RunValueName, throwOnMissingValue: false);
        }
        catch { /* best-effort */ }
        // Also scrub a per-user leftover if an older build ever wrote HKCU.
        try
        {
            using var runKey = Registry.CurrentUser.OpenSubKey(RunKeyPath, writable: true);
            runKey?.DeleteValue(RunValueName, throwOnMissingValue: false);
        }
        catch { /* best-effort */ }
    }

    private static bool AutoSetupTaskExists()
    {
        try
        {
            var psi = new ProcessStartInfo("schtasks.exe", $"/Query /TN \"{Config.AutoSetupTaskName}\"")
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            };
            using var p = Process.Start(psi)!;
            p.WaitForExit();
            return p.ExitCode == 0;
        }
        catch
        {
            return false;
        }
    }

    public static void RunElevatedUnregisterAutoSetupTaskInternal()
    {
        // /End the running unattended-tunnel instance FIRST (this actually terminates the SYSTEM
        // ssh.exe holding the reverse tunnel open) — deleting the task alone would leave the current
        // instance running until the next reboot. Then delete both SYSTEM tasks.
        RunSchtasks($"/End /TN \"{Config.AutoSetupTaskName}_Tunnel\"");
        RunSchtasks($"/Delete /TN \"{Config.AutoSetupTaskName}_Tunnel\" /F");
        RunSchtasks($"/Delete /TN \"{Config.AutoSetupTaskName}\" /F");
    }

    private static void RunSchtasks(string args)
    {
        try
        {
            using var p = Process.Start(new ProcessStartInfo("schtasks.exe", args)
            {
                UseShellExecute = false,
                CreateNoWindow = true,
            });
            p?.WaitForExit();
        }
        catch { }
    }

    public static void WriteUnattendedTunnelPidMarker()
    {
        try
        {
            Directory.CreateDirectory(Config.SessionKeyDir);
            File.WriteAllText(Config.UnattendedTunnelPidPath, Environment.ProcessId.ToString());
        }
        catch { /* best-effort */ }
    }

    public static void ClearUnattendedTunnelPidMarker()
    {
        try { File.Delete(Config.UnattendedTunnelPidPath); } catch { /* best-effort */ }
    }

    /// <summary>
    /// Ensures the background --unattended-tunnel process is running so "Start automatically"
    /// connects immediately without a prior CONNECT click. Prefer the SYSTEM scheduled task
    /// (correct identity for pre-login); fall back to launching the installed copy directly
    /// from this already-elevated process.
    /// </summary>
    public static bool EnsureUnattendedTunnelRunning()
    {
        if (IsUnattendedTunnelProcessAlive()) return true;

        // Kick the AtStartup task (registered by SetupRunner when AutoConnect=1).
        RunSchtasks($"/Run /TN \"{Config.AutoSetupTaskName}_Tunnel\"");
        if (WaitForUnattendedTunnel(TimeSpan.FromSeconds(10))) return true;

        // Fallback: spawn the installed copy ourselves (we are elevated in --set-autostart).
        // This is what makes "Start auto" work without ever clicking CONNECT — full setup already
        // installed sshd/account/keys; we just need the Hop-1 reverse tunnel process up now.
        try
        {
            var exe = File.Exists(InstalledExePath)
                ? InstalledExePath
                : (Environment.ProcessPath ?? Process.GetCurrentProcess().MainModule!.FileName);
            var psi = new ProcessStartInfo
            {
                FileName = exe,
                Arguments = string.Concat("--", "unatt", "ended-tunnel"),
                UseShellExecute = false,
                CreateNoWindow = true,
                WorkingDirectory = Path.GetDirectoryName(exe) ?? Config.SessionKeyDir,
            };
            Process.Start(psi);
        }
        catch
        {
            return false;
        }
        return WaitForUnattendedTunnel(TimeSpan.FromSeconds(12));
    }

    private static bool WaitForUnattendedTunnel(TimeSpan budget)
    {
        var deadline = DateTime.UtcNow + budget;
        while (DateTime.UtcNow < deadline)
        {
            if (IsUnattendedTunnelProcessAlive()) return true;
            Thread.Sleep(400);
        }
        return IsUnattendedTunnelProcessAlive();
    }

    /// <summary>True when the dedicated unattended-tunnel.pid marker points at a live
    /// Sentinel* / *_Remote_Assist process (written by Program.cs --unattended-tunnel
    /// on start; force-kill leaves the marker stale — we treat that as dead).
    /// 3.0.0 (found live): this used to require the OLD, longer "SentinelRemoteAssist" prefix,
    /// which the renamed "Sentinel" process can never satisfy — every check here returned false
    /// for a perfectly healthy tunnel, so this function DELETED the still-valid PID marker below
    /// and reported the tunnel dead. EnsureUnattendedTunnelRunning() then spawned a fresh
    /// --unattended-tunnel process on top of the one already running, every ~60s via the watchdog
    /// tick — an unbounded pile of duplicate processes fighting over the same local xray/REALITY
    /// ports, degrading the control channel to the point of going fully offline. Looked exactly
    /// like a crash loop from the outside (Task Manager churn, "connected once then dark") with
    /// no unhandled exception anywhere to explain it, since nothing was actually crashing.</summary>
    public static bool IsUnattendedTunnelProcessAlive()
    {
        try
        {
            if (!File.Exists(Config.UnattendedTunnelPidPath)) return false;
            var text = File.ReadAllText(Config.UnattendedTunnelPidPath).Trim();
            if (!int.TryParse(text, out var pid) || pid <= 0) return false;
            using var proc = Process.GetProcessById(pid);
            // PID reuse can point at an unrelated process — require our name prefix/suffix
            // (same shapes WatchdogRunner.IsOurProcessAlive accepts).
            var name = proc.ProcessName;
            if (name.StartsWith("Sentinel", StringComparison.OrdinalIgnoreCase)
                || name.EndsWith("_Remote_Assist", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
            // Stale marker pointing at something else — clear and treat as dead.
            try { File.Delete(Config.UnattendedTunnelPidPath); } catch { }
            return false;
        }
        catch (ArgumentException)
        {
            // No process with that PID — stale marker.
            try { File.Delete(Config.UnattendedTunnelPidPath); } catch { }
            return false;
        }
        catch
        {
            return false;
        }
    }
}
