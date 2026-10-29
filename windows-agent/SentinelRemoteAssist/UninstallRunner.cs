using System.Diagnostics;
using System.IO.Compression;
using System.Reflection;
using System.Text;

namespace SentinelRemoteAssist;

/// <summary>
/// Removes everything SetupRunner installs on the customer's machine: the local admin account,
/// its key from administrators_authorized_keys, the sshd service (stopped + disabled, not
/// uninstalled — the customer may have an unrelated use for Windows OpenSSH), scheduled tasks
/// (watchdog + any leftover AutoSetup/Tunnel), OpenSSH firewall rules we may have created, and
/// this app's ProgramData directory. After removal, a verification pass confirms nothing was
/// left behind (leftover SentinelRemoteAssist-Watchdog tasks are exactly the kind of residue that
/// gets mistaken for an implant later).
///
/// Two entry points: <see cref="RunElevatedUninstall"/> for the interactive path (MainForm's
/// FormClosing — relaunches elevated via UAC, mirroring SetupRunner.RunElevatedSetup), and
/// <see cref="RunUninstall"/> called directly when already privileged (the "--uninstall" relaunch
/// itself, or WatchdogRunner running as SYSTEM via the scheduled task).
/// </summary>
internal static class UninstallRunner
{
    public static bool RunElevatedUninstall()
    {
        // Publish the customer-visible session log BEFORE elevation so a declined UAC still leaves
        // a trail of what happened. EndAndPublish is also safe if audit was never started.
        try { SessionAuditLog.EndAndPublish("uninstall-requested"); } catch { /* best-effort */ }

        var exePath = Environment.ProcessPath ?? Process.GetCurrentProcess().MainModule!.FileName;
        var psi = new ProcessStartInfo
        {
            FileName = exePath,
            Arguments = string.Concat("--", "unins", "tall"),
            UseShellExecute = true,
            Verb = "runas",
        };
        try
        {
            using var proc = Process.Start(psi)
                ?? throw new InvalidOperationException("Failed to start elevated uninstall process.");
            var exited = proc.WaitForExit(TimeSpan.FromMinutes(2));
            if (!exited)
            {
                try { proc.Kill(entireProcessTree: true); } catch { /* best-effort */ }
                return false;
            }
            return proc.ExitCode == 0;
        }
        catch
        {
            // e.g. the user declined the UAC prompt. Not fatal — the watchdog task is only
            // unregistered on a SUCCESSFUL uninstall, so it stays armed and will catch this within
            // about a minute once this process actually exits, same as a forced kill/crash.
            return false;
        }
    }

    /// <summary>The actual privileged logic — runs inside the elevated "--uninstall" relaunch, or
    /// directly from WatchdogRunner (already SYSTEM, no relaunch needed).</summary>
    public static int RunUninstall()
    {
        try
        {
            // Preserve the audit log to Desktop before any wipe of ProgramData.
            try { SessionAuditLog.PublishToDesktop(); } catch { /* best-effort */ }

            var script = BuildScript();
            var scriptPath = Path.Combine(Path.GetTempPath(), $"sentinel-uninstall-{Guid.NewGuid():N}.ps1");
            // UTF-8 WITH BOM — Windows PowerShell 5.1 requires it (see SetupRunner comment).
            File.WriteAllText(scriptPath, script, new UTF8Encoding(encoderShouldEmitUTF8Identifier: true));

            var psi = new ProcessStartInfo
            {
                FileName = Config.PowerShellExe,
                Arguments = $"-NoProfile -ExecutionPolicy Bypass -File \"{scriptPath}\"",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
            };
            using var proc = Process.Start(psi)!;
            // Read both streams concurrently — see SetupRunner's identical comment on why
            // sequential ReadToEnd() risks a pipe deadlock.
            var stdoutTask = proc.StandardOutput.ReadToEndAsync();
            var stderrTask = proc.StandardError.ReadToEndAsync();
            var exited = proc.WaitForExit(TimeSpan.FromMinutes(2));
            if (!exited)
            {
                try { proc.Kill(entireProcessTree: true); } catch { /* best-effort */ }
                try { File.Delete(scriptPath); } catch { /* best-effort */ }
                return 1;
            }
            var stdout = stdoutTask.GetAwaiter().GetResult();
            var stderr = stderrTask.GetAwaiter().GetResult();
            try { File.Delete(scriptPath); } catch { /* best-effort */ }

            // Always try to write the cleanup report (even on partial failure) so the customer
            // can show their security team what was/wasn't removed.
            WriteCleanupReport(stdout, stderr, proc.ExitCode);

            if (proc.ExitCode != 0) return proc.ExitCode;

            // Wipe the whole per-app directory last (pid marker, setup-complete marker, logs, the
            // bundled OpenSSH copy) — only once the PowerShell removal above actually succeeded.
            // The Desktop audit log + cleanup report already live outside this directory.
            try { Directory.Delete(Config.SessionKeyDir, recursive: true); } catch { /* best-effort */ }

            return 0;
        }
        catch
        {
            return 1;
        }
    }

    private static void WriteCleanupReport(string stdout, string stderr, int exitCode)
    {
        try
        {
            var desktop = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
            if (string.IsNullOrEmpty(desktop) || !Directory.Exists(desktop))
                desktop = Environment.GetFolderPath(Environment.SpecialFolder.CommonDesktopDirectory);
            if (string.IsNullOrEmpty(desktop))
                desktop = Path.GetTempPath();

            var stamp = DateTime.Now.ToString("yyyyMMdd-HHmmss");
            var path = Path.Combine(desktop, $"Sentinel-Support-Cleanup-Report-{stamp}.txt");
            var sb = new StringBuilder();
            sb.AppendLine("SENTINEL REMOTE ASSIST — CLEANUP VERIFICATION REPORT");
            sb.AppendLine($"Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss} (local)");
            sb.AppendLine($"Technician: {Config.TechnicianDisplayName}");
            sb.AppendLine($"Session label: {(string.IsNullOrEmpty(SessionEmbedded.SessionLabel) ? "(none)" : SessionEmbedded.SessionLabel)}");
            sb.AppendLine($"Uninstall exit code: {exitCode} {(exitCode == 0 ? "(success)" : "(FAILED — review below)")}");
            sb.AppendLine();
            sb.AppendLine("This report confirms whether temporary support components were removed");
            sb.AppendLine("after the ephemeral CONNECT session ended. Keep it with your session log.");
            sb.AppendLine();
            sb.AppendLine("=== Uninstall script output ===");
            sb.AppendLine(stdout ?? "");
            if (!string.IsNullOrWhiteSpace(stderr))
            {
                sb.AppendLine("=== stderr ===");
                sb.AppendLine(stderr);
            }
            File.WriteAllText(path, sb.ToString());
        }
        catch { /* best-effort */ }
    }

    private static string ReadEmbeddedScript(string resourceName)
    {
        var asm = Assembly.GetExecutingAssembly();
        var fullName = $"SentinelRemoteAssist.{resourceName}";
        using var stream = asm.GetManifestResourceStream(fullName)
            ?? throw new InvalidOperationException($"Embedded resource '{resourceName}' not found.");
        using var gz = new GZipStream(stream, CompressionMode.Decompress);
        using var reader = new StreamReader(gz, Encoding.UTF8);
        return reader.ReadToEnd();
    }

    private static string BuildScript()
    {
        var script = ReadEmbeddedScript("sentinel-uninstall.ps1.gz");
        script = script.Replace("__ACCOUNT__", Config.LocalAccountName);
        script = script.Replace("__ADMIN_PUBKEY__", Config.AdminHopTwoPublicKey);
        script = script.Replace("__WATCHDOG_TASKNAME__", Config.WatchdogTaskName);
        script = script.Replace("__AUTOSETUP_TASKNAME__", Config.AutoSetupTaskName);
        script = script.Replace("__TUNNEL_TASKNAME__", Config.UnattendedTunnelTaskName);
        return script;
    }
}
