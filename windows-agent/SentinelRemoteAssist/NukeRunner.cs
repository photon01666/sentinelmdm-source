using System.Diagnostics;
using Microsoft.Win32;

namespace SentinelRemoteAssist;

/// <summary>
/// TOTAL nuke (2.0.3) — removes the agent and EVERYTHING it ever placed on the box, as opposed to
/// UninstallRunner's ephemeral-session cleanup (which only tears down the current session's
/// account/keys and keeps the standing install). Triggered remotely from the WebUI (bastion
/// _AGENT_NUKE_PS1 kicks a SYSTEM one-shot task running the installed exe with --nuke) or manually
/// from an elevated prompt. Removes:
///   - every running agent process (this one excluded) + orphaned xray/ssh children
///   - EVERY Sentinel* scheduled task (auto-setup, tunnel, tray-launch, watchdog, EDR/appcontrol
///     watchers, SentryWatch, telemetry/WU refresh tasks, USB-lockdown tasks, one-shot helpers)
///   - the sentinel-support account, the bundled sshd service (ONLY if not pre-existing — the
///     sshd-preexisted.marker the setup wrote decides), and the restored sshd_config
///   - registry: HKLM\Software\SentinelRemoteAssist, the legacy HKLM Run value, the IFEO sshd.exe
///     key the setup created
///   - firewall: every Sentinel-Isolation-* rule (netsh-created names)
///   - files: every canary (canary-state.json paths + machine-wide tier), the canary state itself,
///     the whole ProgramData\SentinelRemoteAssist / SentinelEdr / SentinelAppControl /
///     SentinelRemoteAssistIdentity / BackupVault trees, C:\Users\Public\SentinelScreenSnap.exe,
///     and (2.1.2) the WHOLE C:\ProgramData\ssh tree — host keys, sshd_config, logs,
///     administrators_authorized_keys, all of it — when sshd was NOT pre-existing (we installed
///     it, so all of it is ours). When sshd pre-existed, only the Hop-2 key we added to
///     administrators_authorized_keys is touched (restored from the pre-sentinel backup); the
///     rest of C:\ProgramData\ssh belongs to the system and is left alone.
/// The running exe is deleted by a detached delayed cmd on the way out (a process can't delete
/// itself), so NOTHING of the agent remains on disk. 2.1.1 also kills every agent-owned process
/// by executable PATH (the bundled ssh.exe/sshd.exe/sshd-session.exe/ssh-agent.exe from our
/// OpenSSH-Win64 tree held the folders locked — found live 2026-08-05, the nuke on VM-Test-1111
/// left the folders behind because only SentinelRemoteAssist*/xray were killed by name). 2.1.2
/// (post-rename to Sentinel.exe): the by-name half of that same check was still anchored to the
/// old, longer "SentinelRemoteAssist" prefix, which a process literally named "Sentinel" can never
/// start with — widened to match any "Sentinel*" process name, and C:\ProgramData\ssh's own host
/// keys/sshd_config/logs (previously never deleted anywhere, only administrators_authorized_keys
/// was ever removed) now get wiped wholesale in the not-pre-existing branch — see
/// DeleteOwnedAuthorizedKeys() below; found live, the ssh folder survived every prior nuke. Feature-
/// level reverts that are PowerShell-territory (AppLocker policy, Defender exclusions, telemetry/
/// WU blocks, USB-lockdown GP) run in the bastion's _AGENT_NUKE_PS1 BEFORE this task, while the
/// Hop-2 channel is still alive — see the support service.
/// </summary>
internal static class NukeRunner
{
    /// <summary>Every ProgramData tree the agent ever writes to — contents are cleared and the
    /// trees themselves removed. SentinelRemoteAssistIdentity (device id + hop1 keys) was missing
    /// from the nuke entirely until 2.1.1.</summary>
    private static readonly string[] OurTrees =
    {
        Config.SessionKeyDir,
        Config.EdrDir,
        Config.AppControlDir,
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "SentinelRemoteAssistIdentity"),
    };

    public static int RunNuke()
    {
        var exePath = Environment.ProcessPath ?? Process.GetCurrentProcess().MainModule!.FileName;
        var log = Path.Combine(Path.GetTempPath(), "sentinel-nuke.log");
        try
        {
            File.AppendAllText(log, $"{DateTime.Now:O}  nuke starting (pid {Environment.ProcessId})\n");

            KillAgentProcesses();
            DeleteSentinelTasks();
            RemoveSshRootAccount();
            RemoveBundledSshd();
            RestoreSshdConfig();
            RemoveRegistryFootprint();
            RemoveFirewallRules();
            DeleteCanaries();
            DeleteProgramDataTrees(exePath);
            DeleteOwnedAuthorizedKeys();
            RemoveBackupVaultIfEmpty();
            File.AppendAllText(log, $"{DateTime.Now:O}  nuke complete — self-deleting\n");
            ScheduleSelfDelete(exePath);
            return 0;
        }
        catch (Exception ex)
        {
            try { File.AppendAllText(log, $"{DateTime.Now:O}  nuke failed: {ex}\n"); } catch { /* best-effort */ }
            return 1;
        }
    }

    private static void KillAgentProcesses()
    {
        var self = Environment.ProcessId;
        try
        {
            foreach (var p in Process.GetProcesses())
            {
                var name = SafeName(p);
                var isOurs = name.StartsWith("Sentinel", StringComparison.OrdinalIgnoreCase)
                             || name.EndsWith("_Remote_Assist", StringComparison.OrdinalIgnoreCase)
                             || name.Equals("xray", StringComparison.OrdinalIgnoreCase);
                // The bundled OpenSSH binaries (ssh.exe, sshd.exe, sshd-session.exe, ssh-agent.exe)
                // run from OUR ProgramData\SentinelRemoteAssist\OpenSSH-Win64 tree. They are NOT
                // caught by the name checks above, and killing by bare name would murder a stock
                // C:\Windows\System32\OpenSSH\sshd.exe — so match by executable path under our own
                // dirs instead (2.1.1, found live 2026-08-05 on VM-Test-1111: the nuke left every
                // folder behind because a running sshd.exe/ssh-session.exe held OpenSSH-Win64 +
                // SentinelRemoteAssist locked and the self-delete rmdir failed).
                if (!isOurs && !PathIsUnderOurDirs(ExePath(p))) continue;
                if (p.Id == self) continue;
                try { p.Kill(entireProcessTree: true); } catch { /* already gone */ }
            }
        }
        catch { /* best-effort */ }
    }

    /// <summary>Executable path of a process, or null when unreadable (elevated/other-user).</summary>
    private static string? ExePath(Process p)
    {
        try { return p.MainModule?.FileName; } catch { return null; }
    }

    /// <summary>True when the executable lives under one of our ProgramData trees (SessionKeyDir,
    /// EdrDir, AppControlDir, IdentityDir).</summary>
    private static bool PathIsUnderOurDirs(string? path)
    {
        if (string.IsNullOrEmpty(path)) return false;
        foreach (var root in OurTrees)
        {
            if (path.StartsWith(root, StringComparison.OrdinalIgnoreCase)) return true;
        }
        return false;
    }

    private static void DeleteSentinelTasks()
    {
        try
        {
            var psi = new ProcessStartInfo("schtasks.exe", "/Query /FO CSV /NH")
            {
                UseShellExecute = false, CreateNoWindow = true,
                RedirectStandardOutput = true, RedirectStandardError = true,
            };
            using var p = Process.Start(psi)!;
            var output = p.StandardOutput.ReadToEnd();
            p.WaitForExit(TimeSpan.FromSeconds(30));
            foreach (var line in output.Split('\n'))
            {
                var parts = line.Split(',');
                if (parts.Length < 2) continue;
                var name = parts[0].Trim().Trim('"');
                if (!name.StartsWith("Sentinel", StringComparison.OrdinalIgnoreCase)) continue;
                try
                {
                    using var d = Process.Start(new ProcessStartInfo("schtasks.exe", $"/Delete /TN \"{name}\" /F")
                    {
                        UseShellExecute = false, CreateNoWindow = true,
                    });
                    d?.WaitForExit(TimeSpan.FromSeconds(15));
                }
                catch { /* best-effort per task */ }
            }
        }
        catch { /* best-effort */ }
    }

    private static void RemoveSshRootAccount()
    {
        try
        {
            using var p = Process.Start(new ProcessStartInfo("net.exe", "user sentinel-support /delete")
            {
                UseShellExecute = false, CreateNoWindow = true,
                RedirectStandardOutput = true, RedirectStandardError = true,
            });
            p?.WaitForExit(TimeSpan.FromSeconds(30));
        }
        catch { /* best-effort */ }
    }

    private static void RemoveBundledSshd()
    {
        try
        {
            var ourSshdMarker = Path.Combine(Config.SessionKeyDir, "sshd-preexisted.marker");
            var sshdWasPreexisting = File.Exists(ourSshdMarker);
            var ourOpenSshDir = Path.Combine(Config.SessionKeyDir, "OpenSSH-Win64");

            if (!sshdWasPreexisting)
            {
                RunSc("stop sshd");
                RunSc("delete sshd");
            }
            // ssh-agent: only delete if it is OURS (binPath under our OpenSSH dir). A stock
            // Windows ssh-agent (or an unrelated install) must never be touched.
            if (ServiceBinPathUses("ssh-agent", ourOpenSshDir))
            {
                RunSc("stop ssh-agent");
                RunSc("delete ssh-agent");
            }
        }
        catch { /* best-effort */ }
    }

    private static bool ServiceBinPathUses(string service, string dirFragment)
    {
        try
        {
            var psi = new ProcessStartInfo("sc.exe", $"qc {service}")
            {
                UseShellExecute = false, CreateNoWindow = true,
                RedirectStandardOutput = true, RedirectStandardError = true,
            };
            using var p = Process.Start(psi)!;
            var output = p.StandardOutput.ReadToEnd();
            p.WaitForExit(TimeSpan.FromSeconds(15));
            return output.Contains(dirFragment, StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    private static void RunSc(string args)
    {
        try
        {
            using var p = Process.Start(new ProcessStartInfo("sc.exe", args)
            {
                UseShellExecute = false, CreateNoWindow = true,
            });
            p?.WaitForExit(TimeSpan.FromSeconds(30));
        }
        catch { /* best-effort */ }
    }

    private static void RestoreSshdConfig()
    {
        try
        {
            var bak = Path.Combine(Config.SessionKeyDir, "sshd_config.pre-sentinel.bak");
            var target = @"C:\ProgramData\ssh\sshd_config";
            if (File.Exists(bak) && File.Exists(target))
            {
                File.Copy(bak, target, overwrite: true);
            }
        }
        catch { /* best-effort */ }
    }

    private static void RemoveRegistryFootprint()
    {
        try { Registry.LocalMachine.DeleteSubKeyTree(@"Software\SentinelRemoteAssist", throwOnMissingSubKey: false); } catch { }
        try
        {
            using var runKey = Registry.LocalMachine.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run", writable: true);
            runKey?.DeleteValue("SentinelRemoteAssist", throwOnMissingValue: false);
        }
        catch { }
        // The setup script adds an IFEO entry for sshd.exe (RedirectionGuard). Remove only if ours.
        try
        {
            using var ifeo = Registry.LocalMachine.OpenSubKey(
                @"Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sshd.exe", writable: true);
            if (ifeo?.GetValue("RedirectionGuard") is not null || ifeo?.GetValue("VerifierDlls") is not null)
            {
                ifeo.Close();
                Registry.LocalMachine.DeleteSubKeyTree(
                    @"Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sshd.exe",
                    throwOnMissingSubKey: false);
            }
        }
        catch { /* best-effort */ }
    }

    private static void RemoveFirewallRules()
    {
        // Mirror of LocalIsolation.cs's rule names (netsh-created, deterministic).
        var leaves = new[]
        {
            "Sentinel.exe", "ssh.exe", "sshd.exe", "sshd-session.exe", "xray.exe",
        };
        foreach (var leaf in leaves)
        {
            RunNetsh($"advfirewall firewall delete rule name=\"Sentinel-Isolation-{leaf}-Out\"");
            RunNetsh($"advfirewall firewall delete rule name=\"Sentinel-Isolation-{leaf}-In\"");
        }
        RunNetsh("advfirewall firewall delete rule name=\"Sentinel-Isolation-DNS-Out-UDP-svchost.exe\"");
        RunNetsh("advfirewall firewall delete rule name=\"Sentinel-Isolation-DNS-Out-TCP-svchost.exe\"");
        // Restore default outbound (the isolation set blockinbound,blockoutbound).
        RunNetsh("advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound");
    }

    private static void RunNetsh(string args)
    {
        try
        {
            using var p = Process.Start(new ProcessStartInfo("netsh.exe", args)
            {
                UseShellExecute = false, CreateNoWindow = true,
            });
            p?.WaitForExit(TimeSpan.FromSeconds(30));
        }
        catch { /* best-effort */ }
    }

    private static void DeleteCanaries()
    {
        var deleted = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        void Del(string path)
        {
            if (string.IsNullOrEmpty(path) || !deleted.Add(path)) return;
            try { if (File.Exists(path)) File.Delete(path); } catch { /* best-effort */ }
        }

        // 1) Every tracked canary (canary-state.json is a flat path->hash dict).
        try
        {
            var state = Path.Combine(Config.EdrDir, "canary-state.json");
            if (File.Exists(state))
            {
                using var doc = System.Text.Json.JsonDocument.Parse(File.ReadAllText(state));
                foreach (var prop in doc.RootElement.EnumerateObject()) Del(prop.Name);
            }
        }
        catch { /* best-effort */ }

        // 2) Machine-wide tier + user-profile canaries by name+content (collision-safe).
        var names = new[] { "Passwords.docx", "Tax Documents 2025.pdf", "Family Budget.xlsx", "Backup - Do Not Delete.docx", "Photos Backup Archive.zip" };
        foreach (var root in new[] { @"C:\Users\Public\Documents", @"C:\Users\Public\Downloads", @"C:\ProgramData\BackupVault" })
        {
            foreach (var n in names)
            {
                var path = Path.Combine(root, n);
                try
                {
                    if (!File.Exists(path)) continue;
                    if (new FileInfo(path).Length > 4096) continue;
                    if (File.ReadAllText(path).StartsWith("This is a Sentinel security decoy", StringComparison.Ordinal)) Del(path);
                }
                catch { /* best-effort */ }
            }
        }
    }

    private static void DeleteProgramDataTrees(string exePath)
    {
        foreach (var dir in OurTrees)
        {
            try
            {
                if (!Directory.Exists(dir)) continue;
                foreach (var entry in Directory.EnumerateFileSystemEntries(dir))
                {
                    if (string.Equals(entry, exePath, StringComparison.OrdinalIgnoreCase)) continue;
                    try
                    {
                        if (File.Exists(entry)) File.Delete(entry);
                        else if (Directory.Exists(entry)) Directory.Delete(entry, recursive: true);
                    }
                    catch { /* best-effort per entry — self-delete handles the exe */ }
                }
                // 2.1.1: the dir itself used to survive (only its contents were emptied) — every
                // box kept empty SentinelEdr/SentinelAppControl/SentinelRemoteAssistIdentity
                // folders forever. Delete the now-empty tree; SessionKeyDir is retried below
                // because the running exe may still hold it until self-delete.
                try { Directory.Delete(dir, recursive: true); } catch { /* locked — self-delete retries */ }
            }
            catch { /* best-effort per dir */ }
        }
        try { if (File.Exists(@"C:\Users\Public\SentinelScreenSnap.exe")) File.Delete(@"C:\Users\Public\SentinelScreenSnap.exe"); } catch { }
    }

    /// <summary>Remove the Hop-2 keys we added to administrators_authorized_keys. The file lives
    /// in the STOCK C:\ProgramData\ssh dir, so it is only wholly ours (safe to delete) when we
    /// also installed sshd ourselves (no preexisting marker). When sshd pre-existed, restore the
    /// pre-sentinel backup the setup takes (2.1.1 — same backup pattern as sshd_config), so any
    /// real pre-existing admin keys survive while our added keys disappear. Boxes set up before
    /// the backup existed get the file deleted only when sshd was ours; a pre-existing-sshd box
    /// from before 2.1.1 keeps its file (keys were unidentifiable), documented limitation.
    ///
    /// 2.1.2 (found live): when sshd was NOT pre-existing, this used to delete only
    /// administrators_authorized_keys and then remove C:\ProgramData\ssh ONLY if it came up
    /// empty afterwards — but the host keys (ssh_host_*_key), sshd_config, and sshd's own logs
    /// that Windows OpenSSH writes there on first start are never deleted anywhere else in this
    /// pipeline, so the directory was never actually empty and that check never fired: the whole
    /// C:\ProgramData\ssh tree survived every nuke. Since the directory was entirely OUR doing in
    /// this branch (we installed sshd, it generated its own host keys, we wrote sshd_config), the
    /// fix is to remove the whole tree wholesale instead of trying to empty it file-by-file.</summary>
    private static void DeleteOwnedAuthorizedKeys()
    {
        const string authKeys = @"C:\ProgramData\ssh\administrators_authorized_keys";
        const string authKeysBackup = @"C:\ProgramData\ssh\administrators_authorized_keys.pre-sentinel.bak";
        const string sshDir = @"C:\ProgramData\ssh";
        try
        {
            var preexistingSshd = File.Exists(Path.Combine(Config.SessionKeyDir, "sshd-preexisted.marker"));
            if (!preexistingSshd)
            {
                // The whole folder is ours — host keys, sshd_config, logs, authorized_keys.
                if (Directory.Exists(sshDir))
                {
                    try { Directory.Delete(sshDir, recursive: true); }
                    catch { /* best-effort — a not-yet-dead sshd/sshd-session process may still hold it */ }
                }
                return;
            }
            // sshd pre-existed on this box — only ever touch the key WE added, restore any real
            // admin keys that were there before us, and leave sshd_config/host keys/logs alone
            // (they belong to the system, not to us).
            if (File.Exists(authKeys))
            {
                if (File.Exists(authKeysBackup))
                {
                    File.Copy(authKeysBackup, authKeys, overwrite: true);
                    // The backup itself is OUR file — remove it so no pre-sentinel copy lingers.
                    try { File.Delete(authKeysBackup); } catch { /* best-effort */ }
                }
                // else: pre-2.1.1 box — cannot distinguish our keys from real admin keys, leave alone.
            }
        }
        catch { /* best-effort */ }
    }

    /// <summary>The RansomwareGuard machine-wide canary root — only ours while it was created
    /// empty and only ever held our canaries (real-data collision doctrine in RansomwareGuard.cs),
    /// so once the canaries are deleted the folder is ours to remove.</summary>
    private static void RemoveBackupVaultIfEmpty()
    {
        const string backupVault = @"C:\ProgramData\BackupVault";
        try
        {
            if (!Directory.Exists(backupVault)) return;
            if (Directory.EnumerateFileSystemEntries(backupVault).Any()) return; // foreign data — leave it
            Directory.Delete(backupVault, recursive: true);
        }
        catch { /* best-effort */ }
    }

    /// <summary>Windows won't let a process delete its own exe — spawn a detached delayed cmd that
    /// removes it after this process has exited, then retries the folder removal (the first rmdir
    /// can race the process teardown; ping-delay then looped del+rmdir clears it).</summary>
    private static void ScheduleSelfDelete(string exePath)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "cmd.exe",
                Arguments = $"/c ping 127.0.0.1 -n 4 >nul & del /f /q \"{exePath}\" & for /l %i in (1,1,10) do @(rmdir /s /q \"{Path.GetDirectoryName(exePath)}\" 2>nul & if not exist \"{Path.GetDirectoryName(exePath)}\" exit /b 0 & ping 127.0.0.1 -n 2 >nul)",
                UseShellExecute = true,
                CreateNoWindow = true,
                WindowStyle = ProcessWindowStyle.Hidden,
            };
            Process.Start(psi);
        }
        catch { /* best-effort — a stale exe in ProgramData may remain */ }
    }

    private static string SafeName(Process p)
    {
        try { return p.ProcessName ?? ""; }
        catch { return ""; }
    }
}
