using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace SentinelRemoteAssist;

/// <summary>
/// S3 Bucket Network Drive — mounts two S3 prefixes as real local folders (Private + Public),
/// each `subst`-mapped to its own drive letter, kept in sync via `rclone bisync`. Modeled on
/// VpnManager.cs: receives a pushed config over the RA control channel, persists it, reevaluates
/// desired state, reports status. UNLIKE VpnManager's plaintext vpn-config.json, this file holds
/// real secrets (S3 secret key + rclone-obscured share passwords) so it's DPAPI-protected at
/// LocalMachine scope, same as DeviceIdentity.cs's private key store — the manager runs both
/// interactively and as SYSTEM (WatchdogRunner, the unattended-tunnel task), and both must be
/// able to read the same config.
///
/// ⚠️ NOT yet live-verified against a real Windows box + real rclone binary (no Windows test
/// environment was available while this was written) — the rclone `crypt` connection-string
/// chaining syntax (wrapping an on-the-fly S3 remote inside an on-the-fly crypt remote, no
/// rclone.conf ever written to disk) follows rclone's documented format but has not been run
/// live. Verify end-to-end on the QEMU Windows 11 test VM before trusting in production, same
/// posture as this codebase's other best-effort-but-unverified features (ARP sweep, Telemetry
/// v1's lesson, HollowingWatcher, RansomwareGuard's mass-file-mod heuristic).
///
/// Direct-to-S3 by design: rclone runs ON this box and talks to S3 directly — nothing in this
/// class ever routes through the bastion or the SentinelMDM server; only the lightweight config
/// (bucket/keys/passwords) arrives over the existing RA Socket.IO control channel.
/// </summary>
internal sealed class S3DriveManager
{
    private static readonly string ConfigPath = Path.Combine(Config.SessionKeyDir, "s3drive-config.dat");
    private static readonly string RootDir = Path.Combine(Config.SessionKeyDir, "s3drive");
    private static readonly string PrivateDir = Path.Combine(RootDir, "Private");
    private static readonly string PublicDir = Path.Combine(RootDir, "Public");
    private static readonly string RcloneDir = Path.Combine(Config.SessionKeyDir, "rclone");
    private const string SubstTaskName = "SentinelRemoteAssist-S3DriveSubst";
    private static readonly TimeSpan SyncInterval = TimeSpan.FromMinutes(3);

    private readonly object _stateLock = new();
    private bool _enabled;
    private string _endpoint = "", _bucket = "", _accessKey = "", _secretKey = "", _region = "";
    private int _bandwidthMbps = 10;
    private string? _publicPasswordObscured, _privatePasswordObscured;
    private string _privatePrefix = "", _publicPrefix = "public/";
    private bool _privateNeedsResync = true, _publicNeedsResync = true;
    private string? _privateDriveLetter, _publicDriveLetter;
    private System.Threading.Timer? _syncTimer;
    private bool _syncing;

    public event Action? StatusUpdated;

    public string? PrivateDriveLetter => _privateDriveLetter;
    public string? PublicDriveLetter => _publicDriveLetter;
    public DateTime? PrivateLastSyncAt { get; private set; }
    public DateTime? PublicLastSyncAt { get; private set; }
    public string? PrivateLastError { get; private set; }
    public string? PublicLastError { get; private set; }

    public void Start()
    {
        LoadPrefs();
        Reevaluate();
    }

    // Only ever called from Reevaluate()'s disabled/unconfigured branch (nothing in Program.cs/
    // MainForm.cs calls this directly) — a brief RA tunnel disconnect must NOT unmount the drives,
    // only an explicit disable (or missing S3 config) should. Found live 2026-07-20: the original
    // version of this method only disposed the sync timer, leaving the drive letters mounted in
    // Windows Explorer (and the per-user logon task still registered, which would have re-mounted
    // them again at the NEXT logon) even after the WebUI toggle was switched off.
    public void Stop()
    {
        _syncTimer?.Dispose();
        _syncTimer = null;
        TeardownDriveLetters();
    }

    /// <summary>Called from RemoteAssistSocket's `set_s3_drive` command handler. Raw passwords are
    /// obscured immediately and only the obscured form is persisted — the raw password never
    /// touches disk.</summary>
    public void ReceiveConfig(bool enabled, string? endpoint, string? bucket, string? accessKey, string? secretKey,
        string? region, int bandwidthMbps, string? publicPassword, string? privatePassword,
        string? privatePrefix, string? publicPrefix, bool resync)
    {
        lock (_stateLock)
        {
            _enabled = enabled;
            _endpoint = endpoint ?? "";
            _bucket = bucket ?? "";
            _accessKey = accessKey ?? "";
            _secretKey = secretKey ?? "";
            _region = string.IsNullOrEmpty(region) ? "us-east-1" : region;
            _bandwidthMbps = bandwidthMbps > 0 ? bandwidthMbps : 10;
            if (!string.IsNullOrEmpty(privatePrefix)) _privatePrefix = privatePrefix;
            if (!string.IsNullOrEmpty(publicPrefix)) _publicPrefix = publicPrefix;

            // Reflects server truth exactly — the server always resolves+resends the live value on
            // every push, so null genuinely means "not set" right now, not a stale/racy signal.
            if (!string.IsNullOrEmpty(publicPassword))
            {
                var obs = TryObscure(publicPassword);
                if (obs is not null) _publicPasswordObscured = obs;
            }
            else _publicPasswordObscured = null;

            if (!string.IsNullOrEmpty(privatePassword))
            {
                var obs = TryObscure(privatePassword);
                if (obs is not null) _privatePasswordObscured = obs;
            }
            else _privatePasswordObscured = null;

            if (resync) { _privateNeedsResync = true; _publicNeedsResync = true; }
            SavePrefs();
        }
        Reevaluate();
    }

    private void Reevaluate()
    {
        bool enabled; string bucket, accessKey, secretKey;
        lock (_stateLock) { enabled = _enabled; bucket = _bucket; accessKey = _accessKey; secretKey = _secretKey; }
        if (!enabled || string.IsNullOrEmpty(bucket) || string.IsNullOrEmpty(accessKey) || string.IsNullOrEmpty(secretKey))
        {
            Stop();
            return;
        }
        try
        {
            Directory.CreateDirectory(PrivateDir);
            Directory.CreateDirectory(PublicDir);
        }
        catch (Exception ex) { StatusUpdated?.Invoke(); PrivateLastError = PublicLastError = $"Failed to create local folders: {ex.Message}"; return; }

        if (!TryExtractRclone(out _))
        {
            PrivateLastError = PublicLastError = "This build is missing its bundled rclone.exe";
            StatusUpdated?.Invoke();
            return;
        }

        EnsureDriveLettersAndPersistence();
        StartSyncTimer();
    }

    private void StartSyncTimer()
    {
        if (_syncTimer is not null) return; // already running
        _syncTimer = new System.Threading.Timer(_ => RunSyncCycle(), null, TimeSpan.FromSeconds(15), SyncInterval);
    }

    private void RunSyncCycle()
    {
        // A cycle can legitimately overrun the interval on a slow link — never let two overlap.
        lock (_stateLock) { if (_syncing) return; _syncing = true; }
        try
        {
            string bucket, endpoint, accessKey, secretKey, region, privatePrefix, publicPrefix;
            string? publicPw, privatePw;
            int bwMbps;
            bool needResyncPrivate, needResyncPublic;
            lock (_stateLock)
            {
                bucket = _bucket; endpoint = _endpoint; accessKey = _accessKey; secretKey = _secretKey; region = _region;
                privatePrefix = _privatePrefix; publicPrefix = _publicPrefix; bwMbps = _bandwidthMbps;
                publicPw = _publicPasswordObscured; privatePw = _privatePasswordObscured;
                needResyncPrivate = _privateNeedsResync; needResyncPublic = _publicNeedsResync;
            }

            var s3Env = BuildS3Env(endpoint, accessKey, secretKey, region);

            if (!string.IsNullOrEmpty(privatePw))
            {
                var remote = BuildCryptRemote(bucket, privatePrefix, privatePw);
                var (ok, err) = RunBisync(PrivateDir, remote, s3Env, bwMbps, needResyncPrivate);
                if (ok) { PrivateLastSyncAt = DateTime.UtcNow; PrivateLastError = null; lock (_stateLock) { _privateNeedsResync = false; SavePrefs(); } }
                else PrivateLastError = err;
            }
            else { PrivateLastError = "No Private share password set for this device yet"; }

            if (!string.IsNullOrEmpty(publicPw))
            {
                var remote = BuildCryptRemote(bucket, publicPrefix, publicPw);
                var (ok, err) = RunBisync(PublicDir, remote, s3Env, bwMbps, needResyncPublic);
                if (ok) { PublicLastSyncAt = DateTime.UtcNow; PublicLastError = null; lock (_stateLock) { _publicNeedsResync = false; SavePrefs(); } }
                else PublicLastError = err;
            }
            else { PublicLastError = "No Public share password set on this account yet"; }
        }
        catch (Exception ex) { StatusUpdated?.Invoke(); PrivateLastError = PublicLastError = ex.Message; }
        finally
        {
            lock (_stateLock) { _syncing = false; }
            StatusUpdated?.Invoke();
        }
    }

    // S3 backend options (endpoint/keys/region) go through RCLONE_S3_* environment variables, NOT
    // embedded in the connection string. Found live 2026-07-20: an endpoint value containing "://"
    // (every real S3-compatible endpoint URL) breaks rclone's connection-string grammar even when
    // individually quoted — colons are structurally significant delimiters in that grammar
    // (`:type,params:path`), and nesting a quoted value containing its own colons inside an
    // already-quoted outer `remote="..."` value doesn't survive the SECOND, recursive parse of
    // that inner string. Confirmed via a local rclone repro: the exact same connection string
    // failed with "Custom endpoint `https` was not a valid URI" (truncated at the first colon)
    // until endpoint/access_key_id/secret_access_key/region were moved to env vars instead —
    // after that fix the same command reached a REAL HTTP round-trip to the actual R2 endpoint.
    // Env vars have no delimiter grammar at all, so this class of bug structurally can't recur.
    private static Dictionary<string, string> BuildS3Env(string endpoint, string accessKey, string secretKey, string region)
    {
        var env = new Dictionary<string, string>
        {
            ["RCLONE_S3_PROVIDER"] = "Other",
            ["RCLONE_S3_ACCESS_KEY_ID"] = accessKey,
            ["RCLONE_S3_SECRET_ACCESS_KEY"] = secretKey,
            ["RCLONE_S3_REGION"] = string.IsNullOrEmpty(region) ? "us-east-1" : region,
        };
        if (!string.IsNullOrEmpty(endpoint)) env["RCLONE_S3_ENDPOINT"] = endpoint;
        return env;
    }

    // rclone connection-string chaining — crypt wraps the on-the-fly S3 remote inline, no
    // rclone.conf ever written to disk (same "no credentials/config on disk" property
    // the support service's File Backup code already maintains for its own openssl+rclone pipeline).
    // Only the bucket/prefix path lives here now — no values containing colons, so no escaping
    // concerns (see BuildS3Env's doc comment for why the S3 connection options moved out).
    private static string BuildCryptRemote(string bucket, string prefix, string obscuredPassword)
    {
        // ⚠️ MUST keep a trailing slash on the bucket path. S3 has no real directories — a prefix
        // with zero objects under it (the case for EVERY brand-new share, since nothing has ever
        // synced yet) can't be `Stat`-ed as "a directory" the way a real filesystem path can.
        // Without a trailing slash, rclone can't tell whether "bucket/private/<id>" is meant to be
        // a directory-style prefix or a nonexistent single object, and bisync's precondition check
        // (both sides must resolve to the same type) fails with "Source doesn't exist or is a
        // directory and destination is a file" — found live 2026-07-20 on the very first real sync
        // attempt against a genuinely empty prefix. A trailing slash forces rclone to resolve the
        // path as a directory/container unambiguously, which is the documented convention for
        // bucket-based remotes. Do NOT trim this back to a bare Trim('/').
        var cleanPrefix = prefix.Trim('/');
        var s3Remote = $":s3:{bucket}/{cleanPrefix}/";
        return $":crypt,remote=\"{s3Remote}\",password={obscuredPassword}:";
    }

    private (bool ok, string? error) RunBisync(string localDir, string remote, Dictionary<string, string> s3Env, int bwMbps, bool resync)
    {
        var rclonePath = Path.Combine(RcloneDir, "rclone.exe");
        if (!File.Exists(rclonePath)) return (false, "rclone.exe not extracted");
        var args = new List<string> { "bisync", localDir, remote, $"--bwlimit={bwMbps}M", "--fast-list" };
        if (resync) args.Add("--resync");
        return RunRclone(rclonePath, args, s3Env, TimeSpan.FromMinutes(30));
    }

    private static (bool ok, string? error) RunRclone(string rclonePath, List<string> args, Dictionary<string, string>? env, TimeSpan timeout)
    {
        var psi = new ProcessStartInfo(rclonePath)
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };
        foreach (var a in args) psi.ArgumentList.Add(a); // ArgumentList handles win32 argv escaping — no manual quoting needed
        if (env is not null) foreach (var kv in env) psi.Environment[kv.Key] = kv.Value;
        try
        {
            using var proc = Process.Start(psi);
            if (proc is null) return (false, "Failed to start rclone");
            var stderrTask = proc.StandardError.ReadToEndAsync();
            var stdoutTask = proc.StandardOutput.ReadToEndAsync();
            if (!proc.WaitForExit((int)timeout.TotalMilliseconds))
            {
                try { proc.Kill(entireProcessTree: true); } catch { }
                return (false, "rclone timed out");
            }
            if (proc.ExitCode == 0) return (true, null);
            var stderr = stderrTask.Result.Trim();
            return (false, string.IsNullOrEmpty(stderr) ? $"rclone exited {proc.ExitCode}" : stderr.Length > 400 ? stderr[..400] : stderr);
        }
        catch (Exception ex) { return (false, ex.Message); }
    }

    private static string? TryObscure(string password)
    {
        var rclonePath = Path.Combine(RcloneDir, "rclone.exe");
        if (!File.Exists(rclonePath) && !TryExtractRclone(out rclonePath!)) return null;
        var (ok, output) = RunRcloneCapture(rclonePath, new List<string> { "obscure", password });
        return ok ? output?.Trim() : null;
    }

    private static (bool ok, string? output) RunRcloneCapture(string rclonePath, List<string> args)
    {
        var psi = new ProcessStartInfo(rclonePath)
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };
        foreach (var a in args) psi.ArgumentList.Add(a);
        try
        {
            using var proc = Process.Start(psi);
            if (proc is null) return (false, null);
            var output = proc.StandardOutput.ReadToEnd();
            proc.WaitForExit(10000);
            return (proc.ExitCode == 0, output);
        }
        catch { return (false, null); }
    }

    private static bool TryExtractRclone(out string exePath)
    {
        exePath = Path.Combine(RcloneDir, "rclone.exe");
        if (File.Exists(exePath)) return true;
        try
        {
            var asm = System.Reflection.Assembly.GetExecutingAssembly();
            using var stream = asm.GetManifestResourceStream("SentinelRemoteAssist.rclone.exe.gz");
            if (stream is null) return false;
            Directory.CreateDirectory(RcloneDir);
            // Embedded as gzip (2.1.2 — see the csproj's CompressNativeBinaries target; the raw
            // 79 MB binary compressed to ~27 MB). Decompress here so rclone.exe on disk is
            // byte-identical to a non-compressed build.
            using (var gz = new System.IO.Compression.GZipStream(stream, System.IO.Compression.CompressionMode.Decompress))
            using (var fs = new FileStream(exePath, FileMode.Create)) gz.CopyTo(fs);
            return true;
        }
        catch { return false; }
    }

    // ── Drive-letter assignment + cross-session visibility ──────────────────────────────────────
    // `subst` only affects the CALLING process's own session. This agent runs either as the
    // interactive user (ephemeral Connect) or as SYSTEM (autostart tasks — Session 0), and a
    // SYSTEM-run subst is invisible in the logged-in user's Explorer (same Session-0-isolation
    // problem docs/ARCHITECTURE.md's "How to take screenshots over SSH on Windows" section documents
    // elsewhere in this codebase). Fix: register a per-interactive-user AtLogOn scheduled task
    // (discovering the interactive username the same way — Win32_ComputerSystem.UserName) that
    // runs `subst` in THAT user's own session, plus a best-effort immediate subst in case this
    // process is already the interactive one.
    private void EnsureDriveLettersAndPersistence()
    {
        try
        {
            var reserved = new HashSet<char>();
            var priv = PickDriveLetter(_privateDriveLetter, reserved);
            if (priv is not null) reserved.Add(priv[0]);
            var pub = PickDriveLetter(_publicDriveLetter, reserved);
            bool changed = priv != _privateDriveLetter || pub != _publicDriveLetter;
            _privateDriveLetter = priv;
            _publicDriveLetter = pub;
            if (changed) SavePrefs();

            TrySubstCurrentSession();
            RegisterPerUserLogonTask();
        }
        catch (Exception ex) { StatusUpdated?.Invoke(); PrivateLastError = PublicLastError = $"Drive-letter setup failed: {ex.Message}"; }
    }

    private static string? PickDriveLetter(string? current, HashSet<char> reserved)
    {
        var logical = Environment.GetLogicalDrives().Select(d => char.ToUpperInvariant(d[0])).ToHashSet();
        if (current is { Length: > 0 })
        {
            var c = char.ToUpperInvariant(current[0]);
            // Keep the existing assignment if it's free OR already substituted (by us, presumably —
            // GetLogicalDrives() can't distinguish, but a stale/foreign occupant showing up on a
            // letter we previously claimed is rare enough to accept as a known limitation here).
            if (!reserved.Contains(c)) return c.ToString();
        }
        for (var c = 'Z'; c >= 'D'; c--)
        {
            if (reserved.Contains(c) || logical.Contains(c)) continue;
            return c.ToString();
        }
        return null; // no free letter — extremely unlikely
    }

    private void TrySubstCurrentSession()
    {
        try
        {
            if (_privateDriveLetter is not null) { RunSubst(_privateDriveLetter, PrivateDir); SetDriveLabel(_privateDriveLetter, "Private"); }
            if (_publicDriveLetter is not null) { RunSubst(_publicDriveLetter, PublicDir); SetDriveLabel(_publicDriveLetter, "Public"); }
        }
        catch { /* best-effort — a SYSTEM/Session-0 context has no visible session to subst into */ }
    }

    private static void RunSubst(string letter, string path)
    {
        var psi = new ProcessStartInfo("subst.exe")
        {
            UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true,
        };
        psi.ArgumentList.Add($"{letter}:");
        psi.ArgumentList.Add(path);
        try { using var p = Process.Start(psi); p?.WaitForExit(5000); } catch { }
    }

    private void TeardownDriveLetters()
    {
        try
        {
            if (_privateDriveLetter is not null) { RunSubstRemove(_privateDriveLetter); RemoveDriveLabel(_privateDriveLetter); }
            if (_publicDriveLetter is not null) { RunSubstRemove(_publicDriveLetter); RemoveDriveLabel(_publicDriveLetter); }
            UnregisterLogonTask();
        }
        catch { /* best-effort */ }
    }

    private static void RunSubstRemove(string letter)
    {
        var psi = new ProcessStartInfo("subst.exe")
        {
            UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true,
        };
        psi.ArgumentList.Add($"{letter}:");
        psi.ArgumentList.Add("/D");
        try { using var p = Process.Start(psi); p?.WaitForExit(5000); } catch { }
    }

    // Registry-based per-user drive label override (Explorer shows "Local Disk (Z:)" for any
    // subst'd/mapped drive by default — there's no real volume label to set since it isn't a real
    // filesystem). Standard, well-documented technique: an unnamed (Default) string value under
    // DriveIcons\<Letter>\DefaultLabel. Takes effect at next Explorer read (naturally covered here
    // since this runs at logon, before/alongside explorer.exe starting).
    private static void SetDriveLabel(string letter, string label)
    {
        var key = $"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\DriveIcons\\{letter}\\DefaultLabel";
        RunRegAdd(key, label);
    }

    private static void RemoveDriveLabel(string letter)
    {
        // Removes the WHOLE DriveIcons\<Letter> subtree (not just \DefaultLabel) so a re-used
        // letter never inherits a stale "Private"/"Public" name from a previous assignment.
        var key = $"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\DriveIcons\\{letter}";
        RunRegDelete(key);
    }

    private static void RunRegAdd(string key, string value)
    {
        var psi = new ProcessStartInfo("reg.exe") { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
        psi.ArgumentList.Add("add"); psi.ArgumentList.Add(key);
        psi.ArgumentList.Add("/ve"); psi.ArgumentList.Add("/d"); psi.ArgumentList.Add(value); psi.ArgumentList.Add("/f");
        try { using var p = Process.Start(psi); p?.WaitForExit(5000); } catch { }
    }

    private static void RunRegDelete(string key)
    {
        var psi = new ProcessStartInfo("reg.exe") { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
        psi.ArgumentList.Add("delete"); psi.ArgumentList.Add(key); psi.ArgumentList.Add("/f");
        try { using var p = Process.Start(psi); p?.WaitForExit(5000); } catch { }
    }

    private static void UnregisterLogonTask()
    {
        var scriptPath = Path.Combine(Config.SessionKeyDir, "s3drive-unregister-task.ps1");
        try
        {
            File.WriteAllText(scriptPath,
                $"Unregister-ScheduledTask -TaskName '{SubstTaskName}' -Confirm:$false -ErrorAction SilentlyContinue\r\n",
                new UTF8Encoding(encoderShouldEmitUTF8Identifier: true));
            var psi = new ProcessStartInfo
            {
                FileName = Config.PowerShellExe,
                Arguments = $"-NoProfile -ExecutionPolicy Bypass -File \"{scriptPath}\"",
                UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true,
            };
            using var p = Process.Start(psi);
            p?.WaitForExit(10000);
        }
        catch { /* best-effort */ }
    }

    private void RegisterPerUserLogonTask()
    {
        var userName = GetInteractiveUserName();
        if (string.IsNullOrEmpty(userName)) return; // no one logged on yet — current-session best-effort above is all we can do right now
        if (_privateDriveLetter is null && _publicDriveLetter is null) return;

        var sb = new StringBuilder();
        sb.AppendLine("$ErrorActionPreference = 'SilentlyContinue'");
        if (_privateDriveLetter is not null)
        {
            sb.AppendLine($"subst {_privateDriveLetter}: \"{PrivateDir}\"");
            sb.AppendLine($"reg.exe add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\DriveIcons\\{_privateDriveLetter}\\DefaultLabel\" /ve /d \"Private\" /f | Out-Null");
        }
        if (_publicDriveLetter is not null)
        {
            sb.AppendLine($"subst {_publicDriveLetter}: \"{PublicDir}\"");
            sb.AppendLine($"reg.exe add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\DriveIcons\\{_publicDriveLetter}\\DefaultLabel\" /ve /d \"Public\" /f | Out-Null");
        }
        var substScriptPath = Path.Combine(Config.SessionKeyDir, "s3drive-subst.ps1");
        // UTF-8 WITH BOM is mandatory for Windows PowerShell 5.1 — same requirement documented in
        // SetupRunner.cs's BuildScript()/RunSetup() for the exact same reason.
        File.WriteAllText(substScriptPath, sb.ToString(), new UTF8Encoding(encoderShouldEmitUTF8Identifier: true));

        // ⚠️ `powershell.exe -WindowStyle Hidden` is NOT reliable at suppressing the window on
        // Windows 11 when Windows Terminal is the default console host (a known regression from
        // the legacy conhost.exe behavior) — found live 2026-07-20: the console visibly flashed for
        // 3-4s at every logon despite -WindowStyle Hidden being set. The standard, reliable fix:
        // launch through a tiny VBScript wrapper using WScript.Shell.Run(cmd, 0, True) — the `0`
        // window-style argument to WScript.Shell.Run is a completely different, much more reliably
        // honored code path than PowerShell's own -WindowStyle flag, since wscript.exe itself has
        // no console window to begin with. The scheduled task launches wscript.exe, not
        // powershell.exe, directly.
        var vbsWrapperPath = Path.Combine(Config.SessionKeyDir, "s3drive-subst-launcher.vbs");
        var vbsContent = "Set objShell = CreateObject(\"WScript.Shell\")\r\n" +
            $"objShell.Run \"powershell.exe -NoProfile -ExecutionPolicy Bypass -File \"\"{substScriptPath}\"\"\", 0, True\r\n";
        File.WriteAllText(vbsWrapperPath, vbsContent, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));

        var registerScript = $@"
$ErrorActionPreference = 'Stop'
$action = New-ScheduledTaskAction -Execute 'wscript.exe' -Argument '""{vbsWrapperPath}""'
$trigger = New-ScheduledTaskTrigger -AtLogOn -User '{userName}'
$principal = New-ScheduledTaskPrincipal -UserId '{userName}' -LogonType Interactive
Register-ScheduledTask -TaskName '{SubstTaskName}' -Action $action -Trigger $trigger -Principal $principal -Force | Out-Null
";
        var registerScriptPath = Path.Combine(Config.SessionKeyDir, "s3drive-register-task.ps1");
        File.WriteAllText(registerScriptPath, registerScript, new UTF8Encoding(encoderShouldEmitUTF8Identifier: true));
        var psi = new ProcessStartInfo
        {
            FileName = Config.PowerShellExe,
            Arguments = $"-NoProfile -ExecutionPolicy Bypass -File \"{registerScriptPath}\"",
            UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true,
        };
        try { using var p = Process.Start(psi); p?.WaitForExit(15000); } catch { /* best-effort — the immediate subst above still worked if this process was already interactive */ }
    }

    // Same SYSTEM->interactive-session bridging technique documented in docs/ARCHITECTURE.md's screenshot
    // section — a Session-0 process cannot enumerate "who's logged in" any other simple way.
    private static string? GetInteractiveUserName()
    {
        var psi = new ProcessStartInfo
        {
            FileName = Config.PowerShellExe,
            Arguments = "-NoProfile -NonInteractive -Command \"(Get-CimInstance Win32_ComputerSystem).UserName\"",
            UseShellExecute = false, RedirectStandardOutput = true, CreateNoWindow = true,
        };
        try
        {
            using var p = Process.Start(psi);
            if (p is null) return null;
            var output = p.StandardOutput.ReadToEnd().Trim();
            p.WaitForExit(5000);
            return string.IsNullOrWhiteSpace(output) ? null : output;
        }
        catch { return null; }
    }

    // ── Persistence (DPAPI-protected — this file holds a real S3 secret key + obscured share
    // passwords, a bigger blast radius than VpnManager's single-use egress UUID, so it gets the
    // stronger treatment DeviceIdentity.cs already uses for its own private key store) ──────────
    private void SavePrefs()
    {
        try
        {
            Directory.CreateDirectory(Config.SessionKeyDir);
            var prefs = new
            {
                enabled = _enabled, endpoint = _endpoint, bucket = _bucket, accessKey = _accessKey, secretKey = _secretKey,
                region = _region, bandwidthMbps = _bandwidthMbps,
                publicPasswordObscured = _publicPasswordObscured, privatePasswordObscured = _privatePasswordObscured,
                privatePrefix = _privatePrefix, publicPrefix = _publicPrefix,
                privateNeedsResync = _privateNeedsResync, publicNeedsResync = _publicNeedsResync,
                privateDriveLetter = _privateDriveLetter, publicDriveLetter = _publicDriveLetter,
            };
            var json = JsonSerializer.Serialize(prefs);
            var protectedBytes = ProtectedData.Protect(Encoding.UTF8.GetBytes(json), null, DataProtectionScope.LocalMachine);
            File.WriteAllBytes(ConfigPath, protectedBytes);
            Config.HardenDirectory(Config.SessionKeyDir);
        }
        catch { /* best-effort persistence — worst case config gets re-pushed on next reconnect */ }
    }

    private void LoadPrefs()
    {
        try
        {
            if (!File.Exists(ConfigPath)) return;
            var protectedBytes = File.ReadAllBytes(ConfigPath);
            var json = Encoding.UTF8.GetString(ProtectedData.Unprotect(protectedBytes, null, DataProtectionScope.LocalMachine));
            var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            string? Str(string name) => root.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
            _enabled = root.TryGetProperty("enabled", out var e) && e.GetBoolean();
            _endpoint = Str("endpoint") ?? "";
            _bucket = Str("bucket") ?? "";
            _accessKey = Str("accessKey") ?? "";
            _secretKey = Str("secretKey") ?? "";
            _region = Str("region") ?? "us-east-1";
            _bandwidthMbps = root.TryGetProperty("bandwidthMbps", out var bw) && bw.TryGetInt32(out var bwv) ? bwv : 10;
            _publicPasswordObscured = Str("publicPasswordObscured");
            _privatePasswordObscured = Str("privatePasswordObscured");
            _privatePrefix = Str("privatePrefix") ?? "";
            _publicPrefix = Str("publicPrefix") ?? "public/";
            _privateNeedsResync = !root.TryGetProperty("privateNeedsResync", out var pnr) || pnr.GetBoolean();
            _publicNeedsResync = !root.TryGetProperty("publicNeedsResync", out var punr) || punr.GetBoolean();
            _privateDriveLetter = Str("privateDriveLetter");
            _publicDriveLetter = Str("publicDriveLetter");
        }
        catch { /* corrupt/unreadable — fall back to defaults, server will re-push on next reconnect */ }
    }
}
