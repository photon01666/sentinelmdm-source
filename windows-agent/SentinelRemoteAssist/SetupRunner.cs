using System.Diagnostics;
using System.IO.Compression;
using System.Reflection;
using System.Text;

namespace SentinelRemoteAssist;

/// <summary>
/// One-time, elevated local setup: installs Windows OpenSSH Server, creates the local
/// "sentinel-support" admin account with a throwaway password (never stored/shown — auth is key-only),
/// locks sshd to loopback + key-only auth, and installs the admin's Hop-2 public key into
/// administrators_authorized_keys. Runs only inside the elevated relaunch (Program.cs "--setup"
/// path) — the main UI process never itself holds admin rights.
/// </summary>
internal static class SetupRunner
{
    public static bool IsSetupComplete => File.Exists(Config.SetupCompleteMarkerPath);

    /// <summary>Relaunches this same .exe elevated (UAC prompt) to run <see cref="RunSetup"/>, and
    /// waits for it (bounded — Add-WindowsCapability can legitimately take a couple of minutes on
    /// a slow connection, but must not be able to hang this UI forever). Returns true if the
    /// elevated process reported success (exit code 0) within the timeout.
    ///
    /// From the unattended (Session 0, no interactive desktop) process this must NOT do a raw
    /// runas relaunch — real bug found live 2026-07-14: every dashboard "Start Session" click
    /// pushes a fresh Hop-2 key, RemoteAssistSocket's "remote_assist_ssh_key" handler calls this
    /// on every push, and a runas prompt with nobody at the keyboard to click it either hangs
    /// forever or (if the scheduled task happens to be running in a session that does have a
    /// desktop) pops a UAC dialog on every single session start. Routes through the
    /// already-registered SentinelRemoteAssist-AutoSetup scheduled task instead (SYSTEM,
    /// RunLevel Highest — registered once during the original elevated --setup run, see
    /// sentinel-setup.ps1's "Unattended / reboot-survive support" section), which needs no
    /// interactive consent at all.</summary>
    public static bool RunElevatedSetup()
    {
        // The Session-0 --unattended-tunnel process is ALREADY SYSTEM/elevated (launched by the
        // SYSTEM AtStartup scheduled task). It must run setup IN-PROCESS: no UAC prompt (nobody's
        // at the screen anyway), and AccountLinkedSession.PendingSshPublicKeys is LIVE in this same
        // process — no cross-process file hand-off, no scheduled-task indirection.
        //
        // History (why not the old scheduled-task hop): RunElevatedSetup used to route the SYSTEM
        // process through a `schtasks /Run SentinelRemoteAssist-AutoSetup` trigger. Proven broken
        // live 2026-07-15 — that on-demand trigger returns "SUCCESS: attempted to run" but the task
        // never actually executes (Task Scheduler LastRun stays "never"), so the completion marker
        // never advances and the caller fell back to `runas` → a UAC prompt on EVERY dashboard
        // session start. It also lost the pushed key across the spawned-process boundary. Running
        // RunSetup() directly here is both reliable and simpler.
        //
        // In autostart mode the interactive UI no longer holds the control channel (MainForm hands
        // it to this SYSTEM process), so this SYSTEM path is the one that receives every
        // remote_assist_ssh_key push — which is exactly why it must be UAC-free and reliable.
        // Persist BEFORE running setup, on BOTH paths — see MergePendingKeysWithDisk().
        MergePendingKeysWithDisk();

        if (AccountLinkedSession.IsUnattendedProcess)
        {
            var rc = RunSetup();
            if (rc == 0) ClearPersistedPendingKeys();
            return rc == 0;
        }

        // Interactive process, autostart OFF (ephemeral / first-time setup): a person is at the
        // keyboard to approve the one UAC prompt. The `runas` child is a FRESH process with empty
        // statics, so it relies on the file MergePendingKeysWithDisk() just wrote.
        var exePath = Environment.ProcessPath ?? Process.GetCurrentProcess().MainModule!.FileName;
        var psi = new ProcessStartInfo
        {
            FileName = exePath,
            Arguments = "--setup",
            UseShellExecute = true,
            Verb = "runas",
        };
        using var proc = Process.Start(psi) ?? throw new InvalidOperationException("Failed to start elevated setup process.");
        var exited = proc.WaitForExit(TimeSpan.FromMinutes(15));
        if (!exited)
        {
            try { proc.Kill(entireProcessTree: true); } catch { /* best-effort */ }
            return false;
        }
        if (proc.ExitCode == 0) ClearPersistedPendingKeys();
        return proc.ExitCode == 0;
    }

    /// <summary>Unions the on-disk pending-key file into the in-memory set, writes the union back,
    /// and returns it newline-joined.
    ///
    /// ⚠️ 2.0.8 — pending keys used to live ONLY in process memory, and only the interactive
    /// `runas` path ever wrote the file. The unattended SYSTEM process is the one that actually
    /// receives every push on an autostart box, so a restart of THAT process silently discarded
    /// every key that had been pushed but not yet installed. Seen live 2026-08-03: three keys were
    /// pushed at 06:18:47, the 2.0.7 agent update killed that process at 06:22:22, and the fresh
    /// process ran setup at 06:22:40 with an empty set — correctly logging "no session key was
    /// supplied" while the customer's connect.sh kept failing. Any restart does this: agent
    /// update, reboot, crash, xray flap.
    ///
    /// Union rather than overwrite: a brand-new push must not drop keys an earlier push persisted
    /// but never got to install.</summary>
    private static string MergePendingKeysWithDisk()
    {
        try
        {
            if (File.Exists(Config.ExtraPubKeyPath))
            {
                foreach (var line in File.ReadAllLines(Config.ExtraPubKeyPath))
                    AccountLinkedSession.AddPendingSshPublicKey(line);
            }
        }
        catch { /* unreadable — fall back to whatever is in memory */ }

        var joined = AccountLinkedSession.PendingSshPublicKeysJoined;
        if (!string.IsNullOrEmpty(joined))
        {
            try { File.WriteAllText(Config.ExtraPubKeyPath, joined); }
            catch { /* best-effort — in-memory set still drives THIS run */ }
        }
        return joined;
    }

    /// <summary>Drops the persisted pending-key file after a setup run reported success — the keys
    /// are in administrators_authorized_keys by then, so re-processing them on every subsequent
    /// setup run just grows the file without bound (every Regen Private Key mints a new key).
    /// Deliberately ONLY on exit code 0: a failed run must keep its keys pending, which is the
    /// whole point of persisting them. The in-memory set is left alone — it is cheap, and keeping
    /// it lets a later run re-assert the same keys if something external truncates the file.</summary>
    private static void ClearPersistedPendingKeys()
    {
        try { if (File.Exists(Config.ExtraPubKeyPath)) File.Delete(Config.ExtraPubKeyPath); }
        catch { /* best-effort */ }
    }

    /// <summary>The actual setup logic — only ever runs inside the elevated child process.</summary>
    public static int RunSetup()
    {
        try
        {
            // Locks down the directory's ACL BEFORE anything (including the Hop-1 private key,
            // written later by TunnelRunner) is ever created inside it — see Config.HardenSessionDir.
            Config.HardenSessionDir();

            // Checking only sshd.exe here (pre-2026-07-22) let a PARTIALLY-populated extraction
            // look "already installed" forever -- found live on a real device where sftp-server.exe
            // specifically ended up missing from this folder (most likely Defender real-time
            // protection acting on it before an exclusion existed) while sshd.exe survived, since
            // sshd.exe alone is enough to keep the reverse tunnel and plain `ssh -EncodedCommand`
            // execution working. Every OTHER RA feature that deploys a script via scp (Defender
            // Exclusion, Telemetry block, forensics collection, File Backup, ...) depends on the
            // SFTP subsystem specifically, so a missing sftp-server.exe silently broke all of them
            // with "scp: Connection closed" while looking completely healthy from Hop-1's PoV and
            // even from simple Hop-2 command-execution tests -- re-running --setup did nothing to
            // fix it because this check never noticed anything was wrong. Now requires BOTH files.
            var sshDir = Path.Combine(Config.SessionKeyDir, "OpenSSH-Win64");
            if (!Directory.Exists(sshDir) || !File.Exists(Path.Combine(sshDir, "sshd.exe")) || !File.Exists(Path.Combine(sshDir, "sftp-server.exe")))
            {
                using var stream = System.Reflection.Assembly.GetExecutingAssembly().GetManifestResourceStream("SentinelRemoteAssist.OpenSSH-Win64.zip");
                if (stream != null)
                {
                    var zipPath = Path.Combine(Config.SessionKeyDir, "OpenSSH-Win64.zip");
                    using (var fs = new FileStream(zipPath, FileMode.Create))
                    {
                        stream.CopyTo(fs);
                    }
                    // Extract to a fresh TEMP directory, then copy each file into place individually
                    // (never a Directory.Delete(sshDir, true) + ExtractToDirectory on the live path).
                    // Found live 2026-07-22: this repair path can itself run WHILE the current Hop-2
                    // SSH session's own worker process (sshd-session.exe) has sshd.exe's own
                    // libcrypto.dll loaded in memory -- deleting the whole directory threw
                    // UnauthorizedAccessException on that one in-use file, aborting the repair before
                    // the actually-missing file (sftp-server.exe) ever got restored. Copying file-by-
                    // file and tolerating a locked destination (skip it -- if it's locked, it's
                    // currently in use, which means it's already present and working) fixes exactly
                    // the missing file without disturbing anything the live session depends on.
                    var tempExtractDir = Path.Combine(Config.SessionKeyDir, $"OpenSSH-Win64-extract-{Guid.NewGuid():N}");
                    System.IO.Compression.ZipFile.ExtractToDirectory(zipPath, tempExtractDir);
                    var extractedSshDir = Path.Combine(tempExtractDir, "OpenSSH-Win64");
                    Directory.CreateDirectory(sshDir);
                    foreach (var srcFile in Directory.GetFiles(extractedSshDir, "*", SearchOption.AllDirectories))
                    {
                        var relPath = Path.GetRelativePath(extractedSshDir, srcFile);
                        var destFile = Path.Combine(sshDir, relPath);
                        try
                        {
                            Directory.CreateDirectory(Path.GetDirectoryName(destFile)!);
                            File.Copy(srcFile, destFile, overwrite: true);
                        }
                        catch (IOException) { /* destination locked (in active use) -- already present, skip */ }
                        catch (UnauthorizedAccessException) { /* same -- locked/in-use file, already present */ }
                    }
                    Directory.Delete(tempExtractDir, true);
                    File.Delete(zipPath);
                }
            }

            var script = BuildScript();
            var scriptPath = Path.Combine(Path.GetTempPath(), $"sentinel-setup-{Guid.NewGuid():N}.ps1");
            // UTF-8 WITH BOM is mandatory for Windows PowerShell 5.1: without a BOM it reads the
            // file as the system ANSI code page, and any multi-byte UTF-8 byte (or a prior bad
            // write) can desync the parser into "Missing closing '}' / Try missing Catch" on a
            // script that is brace-balanced. Keep the body ASCII-only too (see RawScript).
            File.WriteAllText(scriptPath, script, new System.Text.UTF8Encoding(encoderShouldEmitUTF8Identifier: true));

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
            // Read both streams CONCURRENTLY, not sequentially (ReadToEnd() on stdout then stderr
            // is a classic .NET deadlock: if the child fills the stderr pipe buffer before stdout
            // hits EOF, it blocks writing to stderr while we're still blocked reading stdout, and
            // neither side ever proceeds. Add-WindowsCapability is chatty enough to trigger this
            // in practice — this was the actual cause of "UAC prompt, then nothing happens".
            var stdoutTask = proc.StandardOutput.ReadToEndAsync();
            var stderrTask = proc.StandardError.ReadToEndAsync();
            var exited = proc.WaitForExit(TimeSpan.FromMinutes(15));
            if (!exited)
            {
                try { proc.Kill(entireProcessTree: true); } catch { /* best-effort */ }
                File.Delete(scriptPath);
                File.WriteAllText(Path.Combine(Config.SessionKeyDir, "setup-log.txt"),
                    "Setup script timed out after 15 minutes and was killed.");
                return 1;
            }
            var stdout = stdoutTask.GetAwaiter().GetResult();
            var stderr = stderrTask.GetAwaiter().GetResult();

            File.Delete(scriptPath);

            var logPath = Path.Combine(Config.SessionKeyDir, "setup-log.txt");
            File.WriteAllText(logPath, stdout + "\n---STDERR---\n" + stderr);

            if (proc.ExitCode != 0) return proc.ExitCode;

            File.WriteAllText(Config.SetupCompleteMarkerPath, DateTime.UtcNow.ToString("O"));
            return 0;
        }
        catch (Exception ex)
        {
            try
            {
                File.WriteAllText(Path.Combine(Config.SessionKeyDir, "setup-error.txt"), ex.ToString());
            }
            catch { /* best-effort diagnostics only */ }
            return 1;
        }
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
        var script = ReadEmbeddedScript("sentinel-setup.ps1.gz");
        script = script.Replace("__ACCOUNT__", Config.LocalAccountName);
        script = script.Replace("__ADMIN_PUBKEY__", Config.AdminHopTwoPublicKey);
        // SentinelMDM dashboard integration — see sentinel-setup.ps1's step 4 comment. Both default
        // to "no-op" (empty extra key, admin key NOT excluded) for the legacy ad hoc build, which
        // never populates AccountLinkedSession.
        //
        // PendingSshPublicKeys accumulates every key pushed by the browser key push handler. When the
        // CURRENT process is already elevated (SYSTEM/Session 0), this value is live and correct.
        // But when RunSetupViaScheduledTask() spawns a NEW process with --setup, that child's
        // static defaults are all null — so the scheduled-task path must persist the value into a
        // file first (see the write in RunElevatedSetup) and read it back here as a fallback.
        // ALL pending keys, newline-separated — sentinel-setup.ps1 splits and installs each.
        // Was a single value, which silently discarded the browser key whenever the server's
        // second push (standing support key) landed first; see AccountLinkedSession for forensics.
        //
        // Goes through MergePendingKeysWithDisk() rather than reading the file only as a fallback:
        // this method also runs in the `--setup` CHILD process, whose in-memory set is empty by
        // definition, and a union means a child that DOES have some keys in memory still picks up
        // anything an earlier, interrupted run had persisted.
        var extraPubKey = MergePendingKeysWithDisk();
        // ⚠️ This value is MULTI-LINE (one pushed key per line) since 2.0.6, and Replace() hits
        // EVERY occurrence — so the token must appear exactly once in the script, at its
        // assignment. A second occurrence inside a `#` comment stops being a comment after the
        // first substituted line and the rest is parsed as code; that broke setup live on
        // 2026-08-03 ("The term 'when' is not recognized", line 151) and, because it aborted
        // before the key-install block, looked identical to the key simply not being installed.
        // Fail loudly here instead of shipping a script that dies at parse time on the device.
        var extraTokenCount = System.Text.RegularExpressions.Regex.Matches(script, "__EXTRA_PUBKEY__").Count;
        if (extraTokenCount != 1)
            throw new InvalidOperationException(
                $"sentinel-setup.ps1 must contain __EXTRA_PUBKEY__ exactly once (found {extraTokenCount}) — "
                + "a second occurrence (e.g. in a comment) breaks the script once the multi-line key value is substituted.");
        script = script.Replace("__EXTRA_PUBKEY__", extraPubKey ?? "");
        script = script.Replace("__EXCLUDE_ADMIN_KEY__", AccountLinkedSession.ExcludeSharedOperatorKey ? "1" : "0");
        script = script.Replace("__WATCHDOG_TASKNAME__", Config.WatchdogTaskName);
        script = script.Replace("__AUTOSETUP_TASKNAME__", Config.AutoSetupTaskName);
        script = script.Replace("__REGISTER_AUTOSETUP__", AutoStartManager.IsEnabled ? "1" : "0");
        // Both scheduled tasks below (watchdog + autosetup) must point at a path that survives
        // the customer deleting whatever file they originally ran (Desktop, Downloads, ...) — so
        // when autostart is enabled, use the stable installed copy (AutoStartManager also points
        // the Run key at this same path) instead of wherever THIS particular process happens to
        // be running from right now.
        var exePathForTasks = AutoStartManager.IsEnabled
            ? AutoStartManager.EnsureInstalledCopy()
            : Environment.ProcessPath ?? Process.GetCurrentProcess().MainModule!.FileName;
        script = script.Replace("__EXE_PATH__", exePathForTasks);
        return script;
    }
}
