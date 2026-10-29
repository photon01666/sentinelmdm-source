using System.Diagnostics;
using System.Windows.Forms;

namespace SentinelRemoteAssist;

internal static class Program
{
    [STAThread]
    private static int Main(string[] args)
    {
        // WinForms process-wide setup (DPI mode, text rendering default, etc.) — MUST run before
        // ANY window is created, including the auto-provisioning ToS dialog that the pre-mutex
        // flow below shows BEFORE Application.Run. The old placement (right before Run) threw
        // "SetCompatibleTextRenderingDefault must be called before the first IWin32Window object
        // is created" on the first auto-provision install (found live 2026-08-03, clean box:
        // the ToS dialog was the first window, Initialize ran after it and crashed). Background
        // subcommands (--edr-watch, --unattended-tunnel, ...) never create windows, so calling
        // it unconditionally at the top is harmless for them.
        ApplicationConfiguration.Initialize();

        // Apply process mitigation policies early — blocks DLL injection, code signing
        // bypass, and other process attacks BEFORE any socket connections or UI
        ProcessGuard.ApplyMitigations();
        ProcessGuard.EnableSehop();
        ProcessGuard.VerifyIntegrity();

        // Every unattended/background subcommand (--edr-watch, --appcontrol-watch,
        // --unattended-tunnel, ...) can run for days with nobody watching, and Windows Error
        // Reporting is frequently DISABLED on Remote-Assist-managed boxes — either by this same
        // agent's own Telemetry-block kill-switch (stops+disables WerSvc) or by the customer's own
        // hardening — so a native/unhandled crash normally leaves ZERO forensic trail anywhere,
        // on-device or server-side: no Application-Error event, no crash dump, and (until now) no
        // app-level log line either, since none of these background loops had a top-level handler.
        // Found live 2026-07-23: --edr-watch (RansomwareGuard's canary FileSystemWatcher included)
        // silently died ~1-2 min after a clean start on a real customer box, the scheduled task's
        // own RestartCount/RestartInterval never actually relaunched it, and there was no way to
        // tell why — WerSvc was Stopped/Disabled, and Program.cs never logged anything before
        // dying. This handler doesn't fix whatever crashes it (root cause still unknown — could be
        // managed or native) but guarantees the NEXT occurrence leaves a diagnosable trail
        // independent of any OS service state. CrashLogPath is fixed regardless of subcommand so
        // it survives even if the crash happens before a per-feature LogPath (e.g. EdrWatcher's)
        // has resolved its own directory.
        AppDomain.CurrentDomain.UnhandledException += (_, e) =>
            LogCrash("AppDomain.UnhandledException", args, e.ExceptionObject as Exception, e.ExceptionObject);
        TaskScheduler.UnobservedTaskException += (_, e) =>
        {
            LogCrash("TaskScheduler.UnobservedTaskException", args, e.Exception, null);
            e.SetObserved(); // don't let an unobserved-task exception itself become a second, redundant crash path
        };

        // Invoked via SetupRunner.RunElevatedSetup()'s UAC relaunch — the normal UI process below
        // stays asInvoker; this and --uninstall are the only branches that ever run elevated.
        if (args.Length > 0 && MatchArg(args[0], "se", "tup"))
        {
            return SetupRunner.RunSetup();
        }

        // Invoked via UninstallRunner.RunElevatedUninstall()'s UAC relaunch (MainForm's
        // FormClosing) — same elevation pattern as --setup above.
        if (args.Length > 0 && MatchArg(args[0], "unin", "stall"))
        {
            return UninstallRunner.RunUninstall();
        }

        // TOTAL nuke — invoked by the bastion's _AGENT_NUKE_PS1 via a SYSTEM one-shot task (the
        // WebUI "Nuke" button), or manually from an elevated prompt. Removes the agent and
        // EVERYTHING it placed on the box (processes, tasks, account, sshd-if-ours, registry,
        // firewall rules, canaries, ProgramData trees), then self-deletes. See NukeRunner's doc
        // comment. Irreversible — the device must be re-installed with a fresh download.
        if (args.Length > 0 && MatchArg(args[0], "nuke", ""))
        {
            return NukeRunner.RunNuke();
        }

        // ── Silent install / uninstall / status ────────────────────────────────────
        // Fully headless, no UI, no ToS, no UAC prompt — run from an elevated command
        // prompt or SYSTEM context. Designed for scripted deployment (SCCM, Intune, the
        // bastion's own provisioning pipeline).
        if (args.Length > 0 && MatchArg(args[0], "silent-ins", "tall"))
        {
            var ticket = args.Length > 1 ? args[1] : null;
            return SilentInstaller.RunSilentInstall(ticket);
        }
        if (args.Length > 0 && MatchArg(args[0], "silent-uninst", "all"))
        {
            return SilentInstaller.RunSilentUninstall();
        }
        if (args.Length > 0 && MatchArg(args[0], "silent-s", "tatus"))
        {
            return SilentInstaller.RunSilentStatus();
        }

        // Invoked by the SYSTEM-run scheduled task WatchdogRunner registers — already privileged
        // (no UAC relaunch needed), silent, fires once a minute. See WatchdogRunner's doc comment.
        if (args.Length > 0 && MatchArg(args[0], "watch", "dog-check"))
        {
            return WatchdogRunner.CheckAndMaybeCleanup();
        }

        // Invoked via AutoProvisionFlow.RunElevatedInstall()'s UAC relaunch — the elevated
        // cutover+install half of the auto-provisioning installer variant (see AutoProvisionFlow.cs
        // and Config.AutoProvisionBuild): stops any running old-agent processes/SYSTEM tasks
        // (except this process and its interactive launcher, passed as arg 1), copies THIS exe
        // over the ProgramData install (the guaranteed-new-binary step), sets AutoConnect and
        // re-runs SetupRunner, then exits with its exit code so the UI can report success/failure.
        // Idempotent on a fresh box and on an upgrade over any older build.
        if (args.Length > 0 && MatchArg(args[0], "ap-", "install"))
        {
            var parentPid = args.Length > 1 && int.TryParse(args[1], out var pp) ? pp : (int?)null;
            return AutoProvisionFlow.RunElevatedInstallInternal(parentPid);
        }

        // Invoked via AutoStartManager.SetEnabled()'s UAC relaunch — the one-time elevation needed
        // to write the HKLM AutoConnect flag + run SetupRunner (SYSTEM AtStartup tunnel tasks).
        // Exit code is forwarded to the parent so SetEnabled can tell success from "UAC OK but
        // setup script failed" (previously always returned 0, so the UI lied about autostart ON).
        if (args.Length > 1 && MatchArg(args[0], "set-au", "tostart"))
        {
            var enable = args[1] == "1";
            return AutoStartManager.SetEnabledInternal(enable);
        }

        // Invoked via AutoStartManager.SetEnabledInternal()'s (when turning off) logic — the
        // one-time elevation needed when the "start automatically" checkbox is turned OFF, to
        // remove the SYSTEM-run auto-setup-at-login task (SetupRunner registers/refreshes it;
        // deleting it needs the same elevation registering it did, since it's SYSTEM-owned).
        if (args.Length > 0 && MatchArg(args[0], "unregis", "ter-autosetup"))
        {
            AutoStartManager.RunElevatedUnregisterAutoSetupTaskInternal();
            return 0;
        }

        // Invoked via the SYSTEM-run scheduled task SetupRunner registers, triggered at Startup.
        // Runs purely in the background (session 0) to maintain a live presence before any user
        // logs in, enabling true Unattended Access.
        //
        // ⚠️ IsPreviouslyEnrolled MUST be checked BEFORE SessionEmbedded.IsConfigured — found live
        // 2026-07-20. SessionEmbedded is compile-time config baked into THIS specific exe by the
        // bastion's per-session ad-hoc builder; IsPreviouslyEnrolled is a disk-persisted,
        // exe-independent fact about the DEVICE. remote-update-session.sh's remint step always
        // rebuilds through the per-session builder, so ANY remint of an already-account-linked
        // device produces an exe with SessionEmbedded.IsConfigured=true regardless of the device's
        // real enrollment state. With the old ordering that silently downgraded the device to
        // RunUnattendedAdHocTunnel() (Hop-1 admin tunnel only) — the dashboard/device_status
        // control channel died with no way to recover it short of reinstalling the account-linked
        // build, and Hop-1 stayed up throughout so the failure was invisible from the admin side.
        // RunUnattendedAccountLinkedSocket() already establishes Hop-1 on demand via
        // AccountLinkedSession.SessionRequested, so it's a strict superset of what the ad hoc path
        // offers — always safe to prefer once a device has ever completed account-linked enrollment.
        if (args.Length > 0 && MatchArg(args[0], "unatten", "ded-tunnel"))
        {
            if (AccountLinkedSession.IsPreviouslyEnrolled) return RunUnattendedAccountLinkedSocket();
            if (SessionEmbedded.IsConfigured) return RunUnattendedAdHocTunnel();
            return 1;
        }

        // Invoked by the SYSTEM-run scheduled task the support service's _APPCONTROL_PROVISION_PS1
        // registers (SentinelRemoteAssist-AppControlWatch, AtStartup) — NOT part of the
        // SetupRunner-managed task set, deliberately decoupled from Remote Assist's own ephemeral
        // session lifecycle (see Config.AppControlDir's doc comment). Tails
        // Microsoft-Windows-CodeIntegrity/Operational and reports blocked/audit events back to the
        // bastion over TunnelRunner's conditional -L forward. No-ops cleanly (exit 0) if
        // app-control isn't enabled in endpoint-config.json — a defensive fallback (the disable
        // script unregisters this task outright as its primary rollback mechanism; the no-op exit
        // only covers a stray fire in the brief window before that unregister propagates).
        if (args.Length > 0 && MatchArg(args[0], "appcon", "trol-watch"))
        {
            return AppControlWatcher.Run();
        }

        // Invoked by the SYSTEM-run scheduled task the support service's _EDR_PROVISION_PS1 registers
        // (SentinelRemoteAssist-EdrWatch, AtStartup) — same decoupled-from-ephemeral-lifecycle
        // pattern as --appcontrol-watch above (see Config.EdrDir's doc comment). Tails
        // Microsoft-Windows-Sysmon/Operational and reports rule-hits back to the bastion over
        // TunnelRunner's conditional -L forward. No-ops cleanly (exit 0) if EDR isn't enabled in
        // the shared endpoint-config.json.
        if (args.Length > 0 && MatchArg(args[0], "edr-w", "atch"))
        {
            return EdrWatcher.Run();
        }

        // Install-on-first-run: make sure we're running from the stable ProgramData copy, not
        // wherever the customer saved the file (Desktop / Downloads). If not, copy ourselves there
        // and relaunch from there, then exit — so the tray UI, the tunnel, AND the SYSTEM tasks all
        // run from ONE canonical location from the very first launch, instead of the running process
        // staying the Desktop file until a reboot swaps it out. Applies to both a plain double-click
        // and the "--autostart" relaunch (args are forwarded). No-op once already installed.
        // ⚠️ Mutex is acquired AFTER this relaunch so the short-lived Desktop process does not
        // block the ProgramData copy from becoming the real UI instance.
        //
        // ⚠️ AUTO-PROVISION BUILDS SKIP THIS ENTIRELY (2.0.3, found live 2026-08-03): during an
        // upgrade over a running old install, EnsureInstalledCopy cannot overwrite the locked old
        // ProgramData binary and silently falls back to the EXISTING (old) installed copy — so this
        // relaunch launched the OLD exe, whose UI then reported "Sentinel Remote Assist is already
        // running" and the upgrade never happened. The auto-provision flow instead runs the
        // elevated ap-install cutover (which kills the old processes and replaces the binary)
        // BEFORE the mutex, and this process (the one the user actually double-clicked) stays the
        // UI.
        if (!Config.AutoProvisionBuild && AutoStartManager.RelaunchFromInstallDirIfNeeded(args))
        {
            return 0;
        }

        // Auto-provision builds: AUTO-ELEVATE THE WHOLE PROCESS up front (MSI-style) — one UAC
        // prompt, after which the ToS dialog, the --ap-install child and the handoff's fallback
        // tunnel ALL inherit the elevated token. Found live 2026-08-03: relying on the runas
        // relaunch for --ap-install alone left the child NON-elevated on a clean box (admin
        // account, blank password), so setup died at the first HKLM write, the sentinel-support account /
        // hardened sshd_config / Hop-2 keys / tasks were never created, and the handoff's
        // fallback tunnel (spawned by the then-filtered parent) ran the key-install setup
        // non-elevated too — device online + Hop-1 up, every Hop-2 feature "Permission denied".
        var wasElevatedRelaunch = args.Any(a => MatchArg(a, "elevat", "ed"));
        var isAutoStartLaunch = args.Length > 0 && MatchArg(args[0], "auto", "start");
        if (Config.AutoProvisionBuild && AutoProvisionFlow.IsConfigured &&
            !wasElevatedRelaunch && !AutoProvisionFlow.IsElevated() &&
            !isAutoStartLaunch && !AutoStartManager.IsRunningFromInstalledCopy())
        {
            try
            {
                var exePath = Environment.ProcessPath ?? Process.GetCurrentProcess().MainModule!.FileName;
                var psi = new ProcessStartInfo
                {
                    FileName = exePath,
                    Arguments = string.Join(" ", args.Select(a => $"\"{a}\"")) + " --elevated",
                    UseShellExecute = true,
                    Verb = "runas",
                };
                Process.Start(psi);
                return 0; // the elevated relaunch does all the work
            }
            catch
            {
                // UAC declined or elevation is impossible on this box — say so, then exit.
                System.Windows.Forms.MessageBox.Show(
                    "Windows blocked administrator elevation for this installer.\n\n" +
                    "An administrator account is required to install the agent. If this account " +
                    "IS an administrator but elevation is refused, check the UAC setting " +
                    "(\"User Account Control: Behavior of the elevation prompt for " +
                    "administrators\" should be \"Prompt for consent\"), or right-click this " +
                    "file and choose \"Run as administrator\".",
                    "Sentinel Remote Assist", System.Windows.Forms.MessageBoxButtons.OK, System.Windows.Forms.MessageBoxIcon.Warning);
                return 0;
            }
        }

        // Auto-provisioning: an instance launched from the INSTALLED copy (or with --autostart —
        // the AutoSetup_TrayLaunch logon task) before this device is enrolled must YIELD to the
        // interactive installer instance. Found live 2026-08-03 on a clean box: the elevated
        // cutover's RunSetup registers AND STARTS AutoSetup_TrayLaunch immediately, so the
        // spawned --autostart instance grabbed the UI mutex first — the user's double-clicked
        // instance then reported "already running", and the spawned instance itself carried no
        // enrollment ticket in-process, so it could never connect. Before enrollment the
        // interactive instance (the one the user double-clicked) owns the whole flow; after
        // enrollment these instances proceed normally (tray/logon behavior unchanged).
        if (Config.AutoProvisionBuild && AutoProvisionFlow.IsConfigured &&
            !AccountLinkedSession.IsPreviouslyEnrolled &&
            ((args.Length > 0 && MatchArg(args[0], "auto", "start")) || AutoStartManager.IsRunningFromInstalledCopy()))
        {
            return 0;
        }

        // Auto-provisioning installer variant: run the ToS/MSA -> elevated cutover+install sequence
        // BEFORE acquiring the UI mutex. An old instance (old binary — the SYSTEM tunnel and/or a
        // tray running for days) holds the mutex and locks the ProgramData copy; the cutover kills
        // it and swaps in the new binary, so the mutex is free for this new UI. Running from the
        // installed copy already (canonical binary in place) skips the cutover. Declined/failed
        // returns "" — the old instance (if any) is still running, so report it rather than
        // deadlocking; the ticket is cached in AutoProvisionFlow.LastTicket for MainForm.
        if (Config.AutoProvisionBuild && AutoProvisionFlow.IsConfigured && !AutoStartManager.IsRunningFromInstalledCopy())
        {
            var provisioned = AutoProvisionFlow.EnsureProvisioned(null, _ => { });
            if (provisioned is "")
            {
                // Declined the ToS, or the elevated cutover failed (e.g. UAC cancelled). Either
                // way the old instance (if any) may still be running and holding the UI mutex —
                // say so instead of deadlocking on it.
                System.Windows.Forms.MessageBox.Show(
                    "Setup did not complete. If an older Sentinel agent is still running, close it from the tray and try again.",
                    "Sentinel Remote Assist", System.Windows.Forms.MessageBoxButtons.OK, System.Windows.Forms.MessageBoxIcon.Information);
                return 0;
            }
        }

        // Auto-provisioning installer variant: NO UI AT ALL (2.0.3 user decision — not even
        // tray-only). The exe's only job after the ToS/cutover above is to enroll the device with
        // the baked ticket, hand the control channel to the SYSTEM tunnel task, and exit —
        // everything else is managed from the WebUI. Enrolled upgrades need nothing from this
        // process (the cutover already re-started the SYSTEM tunnel on the new binary).
        if (Config.AutoProvisionBuild && AutoProvisionFlow.IsConfigured)
        {
            return AutoProvisionFlow.RunHeadlessAfterProvision();
        }

        // Single UI instance — second double-click shows a notice and exits (does not start
        // another window / second local tunnel fighting the bastion port).
        if (!SingleInstance.TryAcquireUi())
        {
            SingleInstance.NotifyAlreadyRunning();
            return 0;
        }

        // Normal UI launch. Legacy "--autostart" (old HKLM Run key) is still accepted so a
        // leftover Startup-apps entry from an older build doesn't crash; it is no longer created.
        // Mark this process as the live instance BEFORE the UI starts, so the watchdog has
        // something to check from the moment the window is up (attended mode only — unattended
        // skips watchdog cleanup while AutoConnect=1).
        var autoStart = args.Length > 0 && MatchArg(args[0], "auto", "start");
        WatchdogRunner.WriteAlivePidMarker();

        // Auto-provision builds (2.0.3) always start HIDDEN (tray icon only): the no-login
        // installer installs WITH persistence by design, so the Connect/Disconnect + "Install the
        // EDR" window has nothing to offer anyone at the PC — popping it up on a customer's screen
        // after the ToS dialog was the wrong UX (found live 2026-08-03). The tray icon still
        // provides Disable/Exit for whoever is at the PC.
        Application.Run(new MainForm(startHiddenAndAutoConnect: autoStart || Config.AutoProvisionBuild));
        return 0;
    }

    /// <summary>Legacy ad hoc build's unattended path — UNCHANGED from before the account-linked
    /// branch was added above (extracted verbatim into its own method, not rewritten).</summary>
    private static int RunUnattendedAdHocTunnel()
    {
        // Only one unattended tunnel per session port (second schtasks kick / race → exit).
        if (!SingleInstance.TryAcquireTunnel())
        {
            try
            {
                var tunLog = System.IO.Path.Combine(Config.SessionKeyDir, "unattended-tunnel.log");
                System.IO.File.AppendAllText(tunLog,
                    $"{DateTime.Now:O}  --unattended-tunnel skipped: already running for port {SessionEmbedded.ForwardPort}{Environment.NewLine}");
            }
            catch { /* ignore */ }
            return 0;
        }
        WatchdogRunner.WriteAlivePidMarker();
        // Dedicated marker so "Start auto" can confirm the background tunnel is up without
        // needing WMI / command-line scraping (and without requiring a prior CONNECT click).
        AutoStartManager.WriteUnattendedTunnelPidMarker();
        try
        {
            var cfg = new SessionConfig
            {
                BastionHost = SessionEmbedded.BastionHost,
                BastionPort = SessionEmbedded.BastionPort,
                ForwardPort = SessionEmbedded.ForwardPort,
                KnownHostsLine = SessionEmbedded.KnownHostsLine,
                PrivateKeyPem = SessionEmbedded.PrivateKeyPem
            };
            var tunnel = new TunnelRunner(cfg);
            // This runs as SYSTEM in Session 0 with no UI, so its status/errors would otherwise be
            // invisible. Mirror every StatusChanged line (which includes the raw ssh.exe stderr on a
            // failure) to a log file an admin can read — the ONLY window into why a pre-login tunnel
            // won't come up.
            var tunLog = System.IO.Path.Combine(Config.SessionKeyDir, "unattended-tunnel.log");
            void LogLine(string s) { try { System.IO.File.AppendAllText(tunLog, $"{DateTime.Now:O}  {s}{Environment.NewLine}"); } catch { } }
            LogLine($"--unattended-tunnel starting (pid {Environment.ProcessId}, user {Environment.UserName}, exe {Environment.ProcessPath})");
            tunnel.StatusChanged += LogLine;
            tunnel.Start();
            Thread.Sleep(Timeout.Infinite);
            return 0;
        }
        finally
        {
            AutoStartManager.ClearUnattendedTunnelPidMarker();
        }
    }

    /// <summary>Account-linked build's unattended path — Session 0, pre-login, no desktop. Keeps
    /// the control socket alive AND handles session requests by starting the xray REALITY tunnel
    /// and TunnelRunner (Hop-1 reverse tunnel), so a remote-admin SSH session can reach the
    /// Windows box without anyone needing to be logged in interactively.
    ///
    /// Skips two things that need a real desktop: (1) the consent dialog (nobody's at the screen
    /// to click Accept), and (2) SetupRunner's Hop-2 key installation (UAC elevation can't work
    /// from Session 0). Hop-2 keys are instead installed proactively whenever the control socket
    /// receives a "remote_assist_ssh_key" push — SetupRunner.RunElevatedSetup() is invoked from
    /// RemoteAssistSocket's own handler, which does a scheduled-task workaround for SYSTEM-level
    /// setup without a UAC prompt.</summary>
    private static int RunUnattendedAccountLinkedSocket()
    {
        if (!SingleInstance.TryAcquireTunnel())
        {
            return 0; // another unattended instance is already running
        }
        WatchdogRunner.WriteAlivePidMarker();
        AutoStartManager.WriteUnattendedTunnelPidMarker();
        var tunLog = System.IO.Path.Combine(Config.SessionKeyDir, "unattended-tunnel.log");
        void LogLine(string s) { try { System.IO.File.AppendAllText(tunLog, $"{DateTime.Now:O}  {s}{Environment.NewLine}"); } catch { } }
        try
        {
            LogLine($"--unattended-tunnel (account-linked) starting (pid {Environment.ProcessId}, user {Environment.UserName}, exe {Environment.ProcessPath})");
            AccountLinkedSession.IsUnattendedProcess = true;

            // An interactive MainForm instance may already hold the control channel (real bug
            // found live 2026-07-14 — see ControlMutexName's doc comment: two processes both
            // opening a RemoteAssistSocket with the same device identity left the server's
            // connectedSockets map pointing at whichever registered last, silently misrouting
            // dashboard commands). The interactive session always wins that race deliberately
            // (a person is there to see the consent dialog); this headless path just waits for
            // it to go away rather than opening a second, competing connection.
            while (!SingleInstance.TryAcquireControlChannel())
            {
                LogLine("Interactive session already holds the control channel — waiting...");
                Thread.Sleep(TimeSpan.FromSeconds(15));
            }

            // Kill any orphaned xray.exe / ssh.exe from a previous forcibly-killed instance.
            // When the RA process is killed, its child processes (xray.exe for the REALITY
            // transport, ssh.exe for the reverse tunnel) become orphans and keep their
            // respective ports open, preventing this new instance from binding to them.
            KillOrphanedChildProcesses();
            LogLine("Cleaned up orphaned child processes (if any) from a previous instance.");

            // Auto-heal: the previous instance may have been forcibly killed (Task Manager,
            // crash), triggering the watchdog cleanup which removes sshd, sentinel-support, and the
            // admin Hop-2 key. Re-run setup to restore everything before the reverse tunnel
            // starts — this process is already SYSTEM/elevated (AtStartup task), so RunSetup()
            // runs in-process with no UAC prompt.
            var setupCode = SetupRunner.RunSetup();
            LogLine(setupCode == 0
                ? "Auto-heal setup OK — sshd, account, and keys are present."
                : $"Auto-heal setup exited {setupCode} — Hop-2 may not work until resolved.");

            var xray = new XrayTransportManager();
            var vpn = new VpnManager(xray);
            vpn.Start();
            xray.StartControlChannel();
            var s3drive = new S3DriveManager();
            s3drive.Start();
            var socket = new RemoteAssistSocket(vpn, xray, s3drive);
            socket.StatusChanged += LogLine;
            TunnelRunner? currentTunnel = null;

            // Handle session requests in unattended mode — start xray transport + TunnelRunner
            // so the Hop-1 reverse tunnel is established, enabling SSH via the bastion.
            // Skips the consent dialog (no desktop) and Hop-2 UAC prompt (SetupRunner handles
            // elevated key installation via its own scheduled-task workaround).
            AccountLinkedSession.SessionRequested += () =>
            {
                try
                {
                    LogLine("Unattended session requested — starting xray transport and SSH tunnel");
                    var egressUuid = AccountLinkedSession.XrayEgressUuid;
                    if (string.IsNullOrEmpty(egressUuid))
                    {
                        LogLine("Session requested but no egress UUID — server push may not have arrived yet");
                        return;
                    }
                    // Stops the control-channel xray and restarts with the bastion egress UUID.
                    // This drops the Socket.IO control channel (which was routed through xray).
                    // After restarting, reconnect the socket so the dashboard shows the device online.
                    xray.Stop();
                    if (!xray.Start(egressUuid))
                    {
                        LogLine("Xray transport failed to start — Hop-1 tunnel unavailable");
                        return;
                    }
                    AccountLinkedSession.XrayLocalPort = xray.LocalPort;
                    // Reconnect the control channel through the new xray. The old socket was
                    // connected to the previous xray instance which is now gone; the new xray
                    // has a different controlLocalPort. Set _reconnectingSession flag to prevent
                    // this SessionRequested handler from re-entering on the reconnect.
                    AccountLinkedSession._reconnectingSession = true;
                    try { socket?.Disconnect(); } catch { }
                    var newUrl = xray.IsRunning && xray.ControlPort > 0
                        ? $"http://127.0.0.1:{xray.ControlPort}"
                        : Config.WebUrl;
                    socket?.Connect(null);
                    AccountLinkedSession._reconnectingSession = false;
                    LogLine("Control channel reconnected through REALITY");
                    var cfg = new SessionConfig
                    {
                        BastionHost = "127.0.0.1",
                        BastionPort = xray.LocalPort,
                        ForwardPort = AccountLinkedSession.BastionForwardPort,
                        KnownHostsLine = Config.RemoteAssistBastionKnownHostsLine,
                        PrivateKeyPem = Hop1Identity.PrivateKeyPem ?? "",
                    };
                    // Drop any dead leftover runner before starting a new one — without this, a
                    // second SessionRequested firing (e.g. two rapid dashboard Connect clicks)
                    // creates a competing TunnelRunner with nobody ever stopping the first one.
                    // Both loops run forever, each one's Start()/retry killing the other's
                    // just-connected ssh.exe via the shared ssh-tunnel.pid file (KillTrackedSsh) —
                    // a permanent connect/die/retry loop needing no further server push to sustain
                    // itself. Mirrors the same guard MainForm already has for the interactive path.
                    currentTunnel?.Stop();
                    var tunnel = new TunnelRunner(cfg);
                    tunnel.StatusChanged += LogLine;
                    // Transport config missing (server push never landed / forwardPort was 0) —
                    // the guard in TunnelRunner now refuses to launch ssh with an uninitialized
                    // port (that was the the test device 2026-08-16 flap: `-R 127.0.0.1:0:...` →
                    // "UNKNOWN port -1" retry loop until a manual Regen re-pushed the config).
                    // Instead of spinning on the bad config, drop the control channel and let the
                    // reconnect re-register, which makes the server re-push
                    // set_remote_assist_transport with a valid forwardPort.
                    tunnel.ConfigInvalid += () =>
                    {
                        LogLine("Tunnel config incomplete — reconnecting control channel to re-fetch transport config from server");
                        try { socket?.Disconnect(); } catch { }
                        try { socket?.Connect(null); } catch { }
                    };
                    tunnel.Start();
                    currentTunnel = tunnel;

                    // Unattended mode: no consent dialog, no UAC prompt — the server handles
                    // authorization; this agent just provides the transport.
                    LogLine($"Unattended Hop-1 tunnel running on local port {xray.LocalPort}");
                }
                catch (Exception ex)
                {
                    LogLine($"Unattended session setup failed: {ex.Message}");
                }
            };

            // Dedicated direct restart — see AccountLinkedSession.TunnelRestartRequested's doc
            // comment. Deliberately narrower than SessionRequested above: reuses the SAME
            // TunnelRunner instance (same cfg, same Hop1Identity key) and touches neither xray nor
            // the control channel, so a plain "the reverse tunnel died and nobody noticed" case
            // (e.g. an externally killed ssh.exe that TunnelRunner's own WaitForExitAsync never
            // observed exiting) recovers in seconds without any of the disruption a full
            // SessionRequested replay causes. Runs off the socket event thread since Stop() blocks
            // for a ~2s bastion grace period.
            AccountLinkedSession.TunnelRestartRequested += () =>
            {
                var tunnel = currentTunnel;
                if (tunnel is null)
                {
                    LogLine("Tunnel restart requested but no tunnel has been started yet — ignoring");
                    return;
                }
                Task.Run(() =>
                {
                    try
                    {
                        LogLine("Tunnel restart requested by server — restarting Hop-1 SSH tunnel directly (same key, xray/control channel untouched)");
                        tunnel.Stop();
                        tunnel.Start();
                        LogLine("Tunnel restart complete");
                    }
                    catch (Exception ex)
                    {
                        LogLine($"Tunnel restart failed: {ex.Message}");
                    }
                });
            };

            socket.Connect(null); // no ticket — reconnect via DeviceIdentity's persisted signed auth
            LogLine("Control channel connected, awaiting session requests");
            Thread.Sleep(Timeout.Infinite);
            return 0;
        }
        finally
        {
            // Do NOT ClearEnrolled() here. The enrolled marker is a PERSISTENT "this device has
            // enrolled — reconnect via signed auth alone" flag (AccountLinkedSession.
            // IsPreviouslyEnrolled), and it is the ONLY thing that lets the NEXT boot's AtStartup
            // --unattended-tunnel come up at all (Program.Main returns 1 and does nothing when it's
            // false). Clearing it on every exit of this process meant that after the first
            // shutdown/reboot the marker was gone, so "Start automatically" silently stopped
            // working — the unattended tunnel never re-established after a reboot. The ONLY
            // legitimate clear is an explicit server `rescue_pending` (handled in
            // RemoteAssistSocket), never a routine process exit.
            AutoStartManager.ClearUnattendedTunnelPidMarker();
            SingleInstance.ReleaseControlChannel();
        }
    }

    private static bool MatchArg(string value, string left, string right) =>
        value.Length == 2 + left.Length + right.Length &&
        value.StartsWith("--", StringComparison.Ordinal) &&
        value.IndexOf(left, 2, StringComparison.Ordinal) == 2 &&
        value.EndsWith(right, StringComparison.Ordinal);

    /// <summary>
    /// Kill any xray.exe / ssh.exe still running from our own ProgramData directory — children
    /// of a previously killed Sentinel.exe instance that outlived their parent as
    /// orphaned processes. Each keeps its respective port open (xray = control channel / REALITY
    /// transport, ssh = the reverse tunnel) and would prevent this fresh instance from binding.
    /// </summary>
    private static void KillOrphanedChildProcesses()
    {
        var dirPrefix = Config.SessionKeyDir;
        if (string.IsNullOrEmpty(dirPrefix)) return;
        foreach (var name in new[] { "xray", "ssh" })
        {
            try
            {
                foreach (var proc in Process.GetProcessesByName(name))
                {
                    try
                    {
                        var path = proc.MainModule?.FileName ?? "";
                        if (path.StartsWith(dirPrefix, StringComparison.OrdinalIgnoreCase))
                        {
                            proc.Kill(entireProcessTree: true);
                        }
                    }
                    catch { /* already exited, access-denied, or process is protected */ }
                }
            }
            catch { /* best-effort — xray/ssh may not even be running */ }
        }
    }

    // Fixed location, independent of any per-feature log dir (EdrWatcher.LogPath etc.) or OS crash
    // service — see the doc comment above the AppDomain.UnhandledException/UnobservedTaskException
    // registration in Main(). Deliberately best-effort/never-throws: a logging failure during an
    // already-crashing process must not mask or replace the original crash.
    private const string CrashLogPath = @"C:\ProgramData\SentinelRemoteAssist\crash.log";

    private static void LogCrash(string source, string[] args, Exception? ex, object? rawObject)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(CrashLogPath)!);
            var detail = ex is not null ? $"{ex.GetType().FullName}: {ex.Message}\n{ex.StackTrace}" : (rawObject?.ToString() ?? "(no exception object)");
            var line = $"{DateTime.Now:O}  [{source}] pid={Environment.ProcessId} args=[{string.Join(' ', args)}]\n{detail}\n";
            File.AppendAllText(CrashLogPath, line);
        }
        catch { /* best-effort — must never throw from a crash handler */ }
    }
}
