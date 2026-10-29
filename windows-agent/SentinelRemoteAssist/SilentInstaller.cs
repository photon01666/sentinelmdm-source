using System.Diagnostics;

namespace SentinelRemoteAssist;

/// <summary>
/// Fully silent, headless install/uninstall entry point — no UI, no ToS, no UAC prompt.
/// Intended for scripted/batch deployment (SCCM, Intune, manual admin deploy, or the bastion's
/// own provisioning pipeline when the customer's box is already reachable over Hop-2).
///
/// Usage (from an elevated command prompt or SYSTEM context):
///   Sentinel.exe --silent-install [--ticket &lt;enrollment-ticket&gt;]
///   Sentinel.exe --silent-uninstall
///   Sentinel.exe --silent-status
///
/// Exit codes:
///   0  = success
///   1  = generic failure (check setup-log.txt / setup-error.txt for detail)
///   2  = not running elevated (admin required)
///   3  = already installed (idempotent — returns 0, not an error)
///   4  = setup script failed (exit code from sentinel-setup.ps1)
/// </summary>
internal static class SilentInstaller
{
    private static readonly string LogPath = Path.Combine(Config.SessionKeyDir, "silent-install.log");

    private static void Log(string message)
    {
        try
        {
            Directory.CreateDirectory(Config.SessionKeyDir);
            File.AppendAllText(LogPath, $"{DateTime.Now:O}  {message}{Environment.NewLine}");
        }
        catch { /* best-effort */ }
    }

    /// <summary>
    /// Full silent install: copy exe, run setup, register tasks, optionally enroll.
    /// Must run elevated (admin or SYSTEM). Returns 0 on success.
    /// </summary>
    public static int RunSilentInstall(string? enrollmentTicket)
    {
        Log($"=== Silent install starting (pid {Environment.ProcessId}, user {Environment.UserName}) ===");

        // 1. Elevation check
        if (!AutoProvisionFlow.IsElevated())
        {
            Log("FATAL: not running elevated. Run from an elevated command prompt or as SYSTEM.");
            return 2;
        }

        // 2. Idempotency — already set up? Just verify tasks and return.
        if (File.Exists(Config.SetupCompleteMarkerPath) && AccountLinkedSession.IsPreviouslyEnrolled)
        {
            Log("Already installed and enrolled. Verifying tasks are registered...");
            EnsureTasksRegistered();
            Log("Tasks verified. Nothing to do.");
            return 3;
        }

        try
        {
            // 3. Stop any old agent processes (except this one and our parent)
            StopOldProcesses();
            Log("Old processes stopped.");

            // 4. Ensure ProgramData dir exists and copy this exe there
            AutoStartManager.EnsureInstalledCopy();
            Log($"Installed copy at {Config.SessionKeyDir}");

            // 5. Harden the directory ACL
            Config.HardenSessionDir();
            Log("Directory ACL hardened.");

            // 6. Set AutoConnect = 1 in registry
            try
            {
                using var prefs = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(@"Software\SentinelRemoteAssist");
                prefs.SetValue("AutoConnect", 1, Microsoft.Win32.RegistryValueKind.DWord);
            }
            catch (Exception ex)
            {
                Log($"WARNING: could not set AutoConnect registry key: {ex.Message}");
            }
            Log("AutoConnect set to 1.");

            // 7. Run the full setup (sshd, sentinel-support, Hop-2 keys, tasks, watchdog)
            var setupRc = SetupRunner.RunSetup();
            if (setupRc != 0)
            {
                Log($"FATAL: SetupRunner.RunSetup() returned {setupRc}");
                return 4;
            }
            Log("SetupRunner completed successfully.");

            // 8. Ensure the SYSTEM tasks are registered
            EnsureTasksRegistered();
            Log("SYSTEM tasks registered.");

            // 9. Start the unattended tunnel NOW
            var tunnelStarted = AutoStartManager.EnsureUnattendedTunnelRunning();
            Log(tunnelStarted
                ? "Unattended tunnel process confirmed running."
                : "WARNING: unattended tunnel process not detected (will start on next boot).");

            // 10. Enrollment note
            if (!string.IsNullOrEmpty(enrollmentTicket))
            {
                Log($"Enrollment ticket provided (length={enrollmentTicket.Length}). The device will enroll on next launch or can be enrolled via the dashboard.");
            }
            else
            {
                Log("No enrollment ticket provided. Device must be enrolled separately (via dashboard or login).");
            }

            Log("=== Silent install completed successfully ===");
            return 0;
        }
        catch (Exception ex)
        {
            Log($"FATAL: unhandled exception: {ex}");
            return 1;
        }
    }

    /// <summary>
    /// Silent uninstall — tears down everything: kills processes, removes tasks, deletes ProgramData.
    /// Must run elevated. Returns 0 on success.
    /// </summary>
    public static int RunSilentUninstall()
    {
        Log("=== Silent uninstall starting ===");

        if (!AutoProvisionFlow.IsElevated())
        {
            Log("FATAL: not running elevated.");
            return 2;
        }

        try
        {
            // Stop all running SentinelRemoteAssist processes
            StopOldProcesses();

            // End + unregister SYSTEM tasks
            AutoStartManager.RunElevatedUnregisterAutoSetupTaskInternal();
            EndWatcherTasks();
            UnregisterWatchdogTask();
            UnregisterTrayLaunchTask();
            Log("Tasks unregistered.");

            // Run the full uninstaller (removes sshd config, sentinel-support account, firewall rules, etc.)
            UninstallRunner.RunUninstall();
            Log("UninstallRunner completed.");

            // Clear the AutoConnect flag
            try
            {
                using var prefs = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(@"Software\SentinelRemoteAssist");
                prefs.SetValue("AutoConnect", 0, Microsoft.Win32.RegistryValueKind.DWord);
            }
            catch { /* best-effort */ }
            Log("AutoConnect cleared.");

            // Delete the installed copy
            try
            {
                var installedPath = Path.Combine(Config.SessionKeyDir, "Sentinel.exe");
                var currentPath = Environment.ProcessPath ?? Process.GetCurrentProcess().MainModule!.FileName;
                if (File.Exists(installedPath) &&
                    !string.Equals(Path.GetFullPath(installedPath), Path.GetFullPath(currentPath),
                        StringComparison.OrdinalIgnoreCase))
                {
                    File.Delete(installedPath);
                }
            }
            catch { /* best-effort */ }

            Log("=== Silent uninstall completed successfully ===");
            return 0;
        }
        catch (Exception ex)
        {
            Log($"FATAL: unhandled exception during uninstall: {ex}");
            return 1;
        }
    }

    /// <summary>
    /// Reports current install status to stdout (for scripting). Returns 0.
    /// </summary>
    public static int RunSilentStatus()
    {
        var installed = File.Exists(Config.SetupCompleteMarkerPath);
        var enrolled = AccountLinkedSession.IsPreviouslyEnrolled;
        var autoConnect = AutoStartManager.IsEnabled;
        var exeExists = File.Exists(Path.Combine(Config.SessionKeyDir, "Sentinel.exe"));
        var tunnelAlive = AutoStartManager.IsUnattendedTunnelProcessAlive();

        Console.WriteLine($"Installed:    {installed}");
        Console.WriteLine($"Enrolled:     {enrolled}");
        Console.WriteLine($"AutoConnect:  {autoConnect}");
        Console.WriteLine($"ExeExists:    {exeExists}");
        Console.WriteLine($"TunnelAlive:  {tunnelAlive}");
        Console.WriteLine($"AgentVersion: {Config.AgentVersion}");
        Console.WriteLine($"ProgramData:  {Config.SessionKeyDir}");

        return 0;
    }

    private static void StopOldProcesses()
    {
        var self = Environment.ProcessId;
        try
        {
            foreach (var proc in Process.GetProcesses())
            {
                try
                {
                    var name = proc.ProcessName;
                    var isOurs = name.StartsWith("Sentinel", StringComparison.OrdinalIgnoreCase)
                                 || name.EndsWith("_Remote_Assist", StringComparison.OrdinalIgnoreCase);
                    if (!isOurs || proc.Id == self) continue;
                    proc.Kill(entireProcessTree: true);
                    proc.WaitForExit(TimeSpan.FromSeconds(5));
                }
                catch { /* already exited / access denied / not ours */ }
            }
        }
        catch { /* best-effort */ }
    }

    private static void EnsureTasksRegistered()
    {
        // The setup script registers AutoSetup + AutoSetup_Tunnel + Watchdog.
        // If they're missing (partial install), re-run setup to regenerate them.
        if (!AutoSetupTaskExists(Config.AutoSetupTaskName))
        {
            Log("AutoSetup task missing — re-running setup to register it.");
            SetupRunner.RunSetup();
        }
    }

    private static bool AutoSetupTaskExists(string taskName)
    {
        try
        {
            var psi = new ProcessStartInfo("schtasks.exe", $"/Query /TN \"{taskName}\"")
            {
                UseShellExecute = false, CreateNoWindow = true,
                RedirectStandardOutput = true, RedirectStandardError = true,
            };
            using var p = Process.Start(psi)!;
            p.WaitForExit();
            return p.ExitCode == 0;
        }
        catch { return false; }
    }

    private static void EndWatcherTasks()
    {
        foreach (var task in new[] { "SentinelRemoteAssist-EdrWatch", "SentinelRemoteAssist-AppControlWatch" })
        {
            try
            {
                using var p = Process.Start(new ProcessStartInfo("schtasks.exe", $"/End /TN \"{task}\"")
                {
                    UseShellExecute = false, CreateNoWindow = true,
                });
                p?.WaitForExit();
            }
            catch { /* best-effort */ }
        }
    }

    private static void UnregisterWatchdogTask()
    {
        try
        {
            using var p = Process.Start(new ProcessStartInfo("schtasks.exe",
                $"/Delete /TN \"{Config.WatchdogTaskName}\" /F")
            {
                UseShellExecute = false, CreateNoWindow = true,
            });
            p?.WaitForExit();
        }
        catch { /* best-effort */ }
    }

    private static void UnregisterTrayLaunchTask()
    {
        try
        {
            using var p = Process.Start(new ProcessStartInfo("schtasks.exe",
                $"/Delete /TN \"{Config.AutoSetupTaskName}_TrayLaunch\" /F")
            {
                UseShellExecute = false, CreateNoWindow = true,
            });
            p?.WaitForExit();
        }
        catch { /* best-effort */ }
    }
}
