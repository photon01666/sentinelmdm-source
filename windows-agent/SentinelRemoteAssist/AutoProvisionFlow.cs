using System.Diagnostics;
using System.Text.Json;

namespace SentinelRemoteAssist;

/// <summary>
/// Auto-provisioning installer variant (2.0.3) — the "double-click to install, no login" flow.
/// A per-account exe (bastion-builder /build-installer) bakes the owning account's multi-use,
/// bind-any-device enrollment ticket + server URL + ToS version (AutoProvisionEmbedded.cs). The
/// first run on the target PC:
///   1. ToS/MSA dialog — text fetched live from the server (GET /api/ra/tos, versioned; falls
///      back to baked placeholder copy + link if unreachable). Acceptance is recorded server-side
///      (POST /api/ra/consent, best-effort) and locally per version, so an UPGRADE over an
///      already-consenting install never re-prompts for the same version.
///   2. Elevated cutover + install (UAC, --ap-install): kills any running old-agent processes and
///      SYSTEM tasks, copies THIS (new) exe over the ProgramData install — the old
///      EnsureInstalledCopy fallback silently kept the OLD binary when the installed copy was
///      locked by a running SYSTEM tunnel, which would make an upgrade-over-old install a no-op —
///      then sets AutoConnect + re-runs SetupRunner (sshd, sentinel-support, SYSTEM AtStartup tunnel task,
///      watchdog). Persistence is the same SYSTEM-task machinery the account-linked build uses.
///   3. Enrollment: the caller (MainForm) hands the baked ticket to RemoteAssistSocket's handshake
///      (BuildAuthPayload branch 2) — one ticket use consumed, the server binds the device to the
///      account and pushes transport + Hop-2 key. No login is ever shown on the target PC.
/// Devices already enrolled (upgrade/reboot) skip ToS + ticket entirely and reconnect via the
/// existing signed-auth path (IsPreviouslyEnrolled).
/// </summary>
internal static class AutoProvisionFlow
{
    public static bool IsConfigured => Config.AutoProvisionBuild && AutoProvisionEmbedded.IsConfigured;

    private static string WebBase => string.IsNullOrEmpty(AutoProvisionEmbedded.WebUrl)
        ? "https://app.example.com"
        : AutoProvisionEmbedded.WebUrl;

    // ── ToS / consent ──────────────────────────────────────────────────────────

    private sealed record TosDoc(string Version, string Title, string Body, string TermsUrl);

    /// <summary>Fetches the current ToS/MSA from the server; on any failure returns the baked
    /// placeholder + link so the install can never be blocked by a network hiccup.</summary>
    private static TosDoc FetchTos()
    {
        try
        {
            using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(10) };
            var resp = http.GetAsync($"{WebBase}/api/ra/tos").GetAwaiter().GetResult();
            if (resp.IsSuccessStatusCode)
            {
                using var doc = JsonDocument.Parse(resp.Content.ReadAsStringAsync().GetAwaiter().GetResult());
                var root = doc.RootElement;
                var version = root.TryGetProperty("version", out var v) ? v.GetString() : "";
                var title = root.TryGetProperty("title", out var t) ? t.GetString() : "";
                var body = root.TryGetProperty("body", out var b) ? b.GetString() : "";
                var url = root.TryGetProperty("terms_url", out var u) ? u.GetString() : "";
                if (!string.IsNullOrEmpty(version) && !string.IsNullOrEmpty(body))
                    return new TosDoc(version, string.IsNullOrEmpty(title) ? "Sentinel Terms of Service && Master Service Agreement" : title, body, url);
            }
        }
        catch { /* unreachable — fall back to baked copy below */ }

        return new TosDoc(
            AutoProvisionEmbedded.TosVersion,
            "Sentinel Terms of Service && Master Service Agreement",
            "Sentinel Remote Assist will be installed on this computer and will maintain secure remote " +
            "access on behalf of the account that requested it. The account holder is responsible for " +
            "this device.\r\n\r\n" +
            "By accepting, you agree to the Sentinel Terms of Service and Master Service Agreement. " +
            "Remote sessions are recorded and access is limited to authorized support personnel.\r\n\r\n" +
            $"Agreement version: {AutoProvisionEmbedded.TosVersion}\r\n" +
            $"Full terms: {WebBase}/terms",
            $"{WebBase}/terms");
    }

    private static string ConsentMarkerPath(string version) =>
        Path.Combine(Config.SessionKeyDir, $"tos-accepted-{Sanitize(version)}.marker");

    private static string Sanitize(string s) => string.Concat((s ?? "").Where(char.IsLetterOrDigit)).ToLowerInvariant();

    /// <summary>True when THIS device already accepted THIS ToS version (a reinstall/upgrade of
    /// the same version must not re-prompt).</summary>
    public static bool ConsentAlreadyOnFile(string version)
    {
        try { return File.Exists(ConsentMarkerPath(version)); }
        catch { return false; }
    }

    private static void RecordConsentLocal(string version)
    {
        try
        {
            Directory.CreateDirectory(Config.SessionKeyDir);
            File.WriteAllText(ConsentMarkerPath(version), DateTimeOffset.UtcNow.ToString("O"));
        }
        catch { /* best-effort — server record still happens */ }
    }

    /// <summary>Best-effort server-side consent record (deviceId + ToS version), fired once per
    /// accept. Never blocks the install.</summary>
    private static void RecordConsentRemote(string version)
    {
        try
        {
            using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(10) };
            var body = JsonSerializer.Serialize(new
            {
                deviceId = DeviceIdentity.DeviceId,
                tosVersion = version,
                accepted = true,
            });
            _ = http.PostAsync($"{WebBase}/api/ra/consent",
                new StringContent(body, System.Text.Encoding.UTF8, "application/json")).GetAwaiter().GetResult();
        }
        catch { /* best-effort */ }
    }

    // ── Orchestration (called from Program.Main BEFORE the UI — see Program.cs) ──

    /// <summary>Enrollment ticket cached by EnsureProvisioned for MainForm to consume when it
    /// starts the control channel (Main runs the whole sequence before the window exists).</summary>
    public static string? LastTicket { get; private set; }

    /// <summary>
    /// Runs the auto-provisioning sequence. Returns the enrollment ticket the caller must pass
    /// to StartControlChannelInteractive (null = already enrolled — connect with the existing
    /// identity; empty string = declined/failed — caller should exit).
    /// Called from Program.Main BEFORE the UI mutex so the elevated cutover can kill the OLD
    /// instance (old binary — which holds the UI mutex and locks the ProgramData copy) before the
    /// new UI ever tries to start.
    /// </summary>
    public static string? EnsureProvisioned(IWin32Window? owner, Action<string> log)
    {
        LastTicket = null;
        if (AccountLinkedSession.IsPreviouslyEnrolled)
        {
            // Upgrade over an already-enrolled install: no ToS, no ticket — but the binary
            // cutover is still REQUIRED (old binary -> this new one). The elevated ap-install
            // kills the old processes and replaces the ProgramData copy.
            log("Already enrolled on this device — performing the agent cutover (old -> new).");
            if (!RunElevatedInstall(log)) return "";
            return null; // signed-auth reconnect path
        }

        // ToS skipped — silent auto-provision goes straight to install.
        var tos = FetchTos();
        RecordConsentLocal(tos.Version);
        RecordConsentRemote(tos.Version);
        log($"ToS consent auto-recorded (version {tos.Version}).");

        if (!RunElevatedInstall(log)) return "";

        log("Installed. Enrolling with the baked account ticket...");
        LastTicket = AutoProvisionEmbedded.EnrollmentTicket;
        return LastTicket;
    }

    // ── Headless post-install handoff (Program.Main, after EnsureProvisioned) ──

    /// <summary>
    /// Auto-provisioning builds have NO UI at all (2.0.3 user decision — not even tray-only).
    /// This process's only remaining job: enroll the device with the baked ticket (a brief control-
    /// channel socket connection — the server binds the device + pushes transport/Hop-2 key), then
    /// hand the control channel to the SYSTEM tunnel task and EXIT. Enrolled upgrades (LastTicket
    /// null) need nothing — the cutover already re-started the SYSTEM tunnel on the new binary.
    /// Everything after this point is managed from the WebUI; nothing ever shows on the target PC.
    /// </summary>
    public static int RunHeadlessAfterProvision()
    {
        var log = Path.Combine(Config.SessionKeyDir, "headless-enroll.log");
        void Log(string s) { try { File.AppendAllText(log, $"{DateTime.Now:O}  {s}{Environment.NewLine}"); } catch { /* best-effort */ } }
        try
        {
            if (LastTicket is null)
            {
                Log("already enrolled — the SYSTEM tunnel task owns the connection; exiting");
                return 0;
            }

            Log("enrolling with the baked account ticket...");
            if (!SingleInstance.TryAcquireControlChannel())
            {
                Log("control channel busy — the SYSTEM tunnel will retry on its own; exiting");
                return 0;
            }

            var xray = new XrayTransportManager();
            var vpn = new VpnManager(xray);
            vpn.Start();
            xray.StartControlChannel();
            // Enroll-only connection: no S3 drive / capture / input services (ctor allows nulls) —
            // the process exits as soon as the device is registered.
            var socket = new RemoteAssistSocket(vpn, xray);
            socket.Connect(LastTicket);

            var enrolled = false;
            var deadline = DateTime.UtcNow.AddSeconds(90);
            while (DateTime.UtcNow < deadline)
            {
                if (AccountLinkedSession.IsPreviouslyEnrolled) { enrolled = true; break; }
                Thread.Sleep(1000);
            }

            try { socket.Disconnect(); } catch { /* best-effort */ }
            try { vpn.Stop(); } catch { /* best-effort */ }
            try { xray.Stop(); } catch { /* best-effort */ }
            SingleInstance.ReleaseControlChannel();

            if (!enrolled)
            {
                Log("enrollment did not complete within 90s — the device may not appear; re-run the installer to retry");
                return 1;
            }

            Log("enrolled — handing the control channel to the SYSTEM tunnel task");
            AutoStartManager.EnsureUnattendedTunnelRunning();
            return 0;
        }
        catch (Exception ex)
        {
            Log($"headless enroll failed: {ex}");
            return 1;
        }
    }

    // ── Elevated cutover + install (Program.cs --ap-install) ──────────────────

    /// <summary>True when the current process runs with a full (unfiltered) administrator token —
    /// the precondition for installing services/accounts/HKLM keys.</summary>
    public static bool IsElevated()
    {
        try
        {
            var principal = new System.Security.Principal.WindowsPrincipal(System.Security.Principal.WindowsIdentity.GetCurrent());
            return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
        }
        catch
        {
            return false;
        }
    }

    /// <summary>UAC-relaunches the --ap-install branch (this process cannot elevate itself without
    /// a fresh process) and waits for it. Returns true on exit code 0. The parent's own pid is
    /// passed along so the elevated child never kills the process that launched it.</summary>
    private static bool RunElevatedInstall(Action<string> log)
    {
        var exePath = Environment.ProcessPath ?? Process.GetCurrentProcess().MainModule!.FileName;
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = exePath,
                Arguments = $"--ap-install {Environment.ProcessId}",
                UseShellExecute = true,
                Verb = "runas",
            };
            using var proc = Process.Start(psi);
            if (proc is null)
            {
                log("Failed to launch elevated install (UAC cancelled?).");
                return false;
            }
            if (!proc.WaitForExit(TimeSpan.FromMinutes(15)))
            {
                try { proc.Kill(entireProcessTree: true); } catch { /* best-effort */ }
                log("Elevated install timed out.");
                return false;
            }
            if (proc.ExitCode == 3)
            {
                // The UAC relaunch produced a NON-elevated child (the account answering UAC was
                // not an administrator) — tell the user what's actually wrong instead of the
                // generic failure (found live 2026-08-03 on a clean box whose only account was a
                // standard user with no admin password: no UAC prompt can elevate, ever).
                log("Windows blocked administrator elevation — an administrator account is required.");
                System.Windows.Forms.MessageBox.Show(
                    "Windows blocked administrator elevation for this installer.\n\n" +
                    "The account that approved the UAC prompt is not an administrator, so no " +
                    "elevation is possible. Fix the account once (any of these), then run this " +
                    "installer again:\n\n" +
                    "  • From an admin context (e.g. Safe Mode's built-in Administrator, blank " +
                    "password):  net localgroup administrators User /add\n" +
                    "  • Or give the built-in Administrator a password (net user Administrator <pw>) " +
                    "and use it at the UAC prompt\n\n" +
                    "An administrator account with a blank password still works — the UAC consent " +
                    "prompt (Yes/No) needs no password.",
                    "Sentinel Remote Assist", System.Windows.Forms.MessageBoxButtons.OK, System.Windows.Forms.MessageBoxIcon.Warning);
                return false;
            }
            if (proc.ExitCode != 0)
            {
                log($"Elevated install failed (exit {proc.ExitCode}).");
                return false;
            }
            return true;
        }
        catch
        {
            log("Elevated install could not start (UAC declined?).");
            return false;
        }
    }

    /// <summary>
    /// Runs elevated (Program.cs --ap-install). Does the cutover + install in ONE pass:
    ///   1. stop every running old-agent process (tray UI, SYSTEM tunnel, watchers) and end the
    ///      SYSTEM tasks — the installed ProgramData copy is locked while any of them run;
    ///   2. copy THIS (new) exe over the ProgramData install — the guaranteed-new-binary step the
    ///      old EnsureInstalledCopy fallback silently skipped when the destination was locked;
    ///   3. set AutoConnect + run SetupRunner (sshd/sentinel-support/SYSTEM tasks/watchdog) and make sure
    ///      the unattended tunnel task is running — the same enable path as
    ///      AutoStartManager.SetEnabledInternal(true).
    /// Idempotent: safe on a fresh box AND on an upgrade over any older build (account-linked or
    /// ad hoc) of any version.
    /// </summary>
    public static int RunElevatedInstallInternal(int? parentPid)
    {
        // Elevation self-assert — found live 2026-08-03 on a clean box: the UAC runas relaunch
        // produced a NON-elevated child (the account answering UAC wasn't an administrator), and
        // the setup then failed at the first privileged step ("Access is denied" on Set-Service
        // sshd / HKLM write) leaving the box half-installed with a confusing setup.log. The child
        // now records its elevation state for the parent and aborts cleanly (exit 3) when not
        // elevated, so the user gets the real instruction instead of a broken install.
        var elevated = IsElevated();
        try
        {
            Directory.CreateDirectory(Config.SessionKeyDir);
            File.WriteAllText(Path.Combine(Config.SessionKeyDir, "ap-install-elevated.txt"), elevated ? "True" : "False");
        }
        catch { /* best-effort — the setup-log elevation line is the fallback diagnostic */ }
        if (!elevated)
        {
            try
            {
                File.AppendAllText(Path.Combine(Config.SessionKeyDir, "setup-log.txt"),
                    $"\n==> FATAL: --ap-install is not running elevated — an administrator is required. " +
                    "Run the installer as an administrator or provide administrator credentials at the UAC prompt.\n");
            }
            catch { /* best-effort */ }
            return 3; // distinctive: "elevation blocked" — RunElevatedInstall maps this to the right message
        }

        try
        {
            // 1. Stop old instances first — the ProgramData exe is locked while the SYSTEM
            //    --unattended-tunnel (or an old tray) runs from it, and the old
            //    EnsureInstalledCopy fallback used to silently keep the OLD binary in that case.
            //    Never kill this process's own parent (the interactive launcher that is waiting
            //    on us — found live 2026-08-03: the first upgrade attempt killed its own
            //    launcher, so the flow after the cutover never ran).
            StopOldAgentProcesses(parentPid);
            AutoStartManager.RunElevatedUnregisterAutoSetupTaskInternal(); // /End tunnel task + delete both auto tasks
            EndWatcherTasks();

            // 2. Stable installed copy of THIS exe (now unlocked).
            AutoStartManager.EnsureInstalledCopy();

            // 3. Enable path (AutoConnect flag first — RunSetup branches on it).
            using (var prefs = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(@"Software\SentinelRemoteAssist"))
            {
                prefs.SetValue("AutoConnect", 1, Microsoft.Win32.RegistryValueKind.DWord);
            }
            var setupRc = SetupRunner.RunSetup();
            if (setupRc != 0) return setupRc;
            AutoStartManager.EnsureUnattendedTunnelRunning();
            return 0;
        }
        catch
        {
            return 1;
        }
    }

    private static void StopOldAgentProcesses(int? parentPid)
    {
        var self = Environment.ProcessId;
        try
        {
            foreach (var p in Process.GetProcesses())
            {
                var name = SafeProcessName(p);
                var isOurs = name.StartsWith("Sentinel", StringComparison.OrdinalIgnoreCase)
                             || name.EndsWith("_Remote_Assist", StringComparison.OrdinalIgnoreCase);
                if (!isOurs) continue;
                if (p.Id == self) continue;
                if (parentPid is not null && p.Id == parentPid.Value) continue; // the interactive launcher
                try { p.Kill(entireProcessTree: true); } catch { /* already gone */ }
                try { p.WaitForExit(TimeSpan.FromSeconds(5)); } catch { /* best-effort */ }
            }
        }
        catch { /* best-effort — setup below tolerates leftovers */ }
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

    private static string SafeProcessName(Process p)
    {
        try { return p.ProcessName ?? ""; }
        catch { return ""; }
    }
}
